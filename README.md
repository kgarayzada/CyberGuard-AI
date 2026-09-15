# CyberGuard AI

**Source Code Security Assessment & Contextual Risk Prioritization Platform**

A local React/TypeScript and FastAPI application that accepts ZIP source archives, runs real static scanners, normalizes their results into SQLite, and produces prioritized findings and in-app HTML reports. A fresh database contains zero assessments and zero findings. The project name does not imply generative AI: no external LLM is used.

## Start / stop / reset (Windows PowerShell)

Prerequisites: an existing Python 3.10+ (64-bit; scanner wheel availability varies), Node.js 22.12+, and npm. No administrator privileges or global installation is required. Python 3.14 and Node 24 were used during development.

```powershell
.\start.ps1
.\stop.ps1
.\reset-demo.ps1
```

Frontend: http://127.0.0.1:5173
Backend health: http://127.0.0.1:8000/api/health

Startup creates/uses `.venv`, installs missing backend and frontend dependencies, builds the UI, initializes SQLite, and attempts scanner setup once. Downloads require internet on first setup. Tools stay in `.venv` or `.tooling`; PATH, registry, services and global runtimes are untouched. Startup does not repeatedly download scanner binaries. To retry provisioning: `.\scripts\setup-tools.ps1 -Retry`. Gitleaks downloads are SHA-256 checked against the publisher's release checksum file. Python wheels are pinned by scanner version; they are not independently signed by this project.

Reset stops verified project processes, deletes generated database/workspaces and creates an empty database. It preserves the demo ZIP and local tools. Reset leaves services stopped; run start afterward. `-NoBrowser` on start suppresses automatic browser opening.

## Demo

1. Start the application; the dashboard says **No assessments yet**.
2. Select **UPLOAD SOURCE CODE** and choose `demo/cyberguard-vulnerable-demo.zip`.
3. Enter **CyberGuard Vulnerable Demo**. Optionally choose Production / High.
4. Enable OSV lookup if internet access is available, and confirm authorization.
5. Start the assessment. Watch actual scanner stages and coverage results.
6. Inspect Findings: scanner, rule, file/line, withheld evidence, risk factors and remediation.
7. Open the assessment's security report. Stop or reset afterward.

The fixture is intentionally vulnerable, contains only synthetic values, and is never executed. Its editable source is in `demo/source`. No seeded result is attached to it: findings are computed by scanners.

## Real scanning and coverage

- **Semgrep Community Edition 1.177.0**: local native CLI with six reviewed bundled rules for Python and JavaScript/TypeScript: SQL construction, MD5, direct HTML assignment, constructed file paths and shell commands. This is a deliberately limited pattern set, not the complete Semgrep registry. Rules are in `backend/rules/semgrep.yml`. Metrics and version checking are disabled. Uploaded rule files are not used. [Semgrep documentation](https://semgrep.dev/products/community-edition).
- **Gitleaks 8.30.0**: directory scan with default secret rules plus a general credential-assignment rule. No credential testing, git history, or recursive archive scanning. Full match/secret strings are discarded and source evidence is withheld before persistence. [Gitleaks documentation](https://github.com/gitleaks/gitleaks).
- **OSV dependency analysis**: project adapter querying the fixed OSV API for exact versions in `package.json` dependencies/devDependencies and plain `requirements.txt` pins. No install, build, dependency resolution, or registry scripts. Optional internet lookup sends package names/ecosystems/versions only. Ranges, alternate manifests, lockfiles and transitive dependency resolution are outside this MVP's coverage. Unpinned entries are counted as skipped. Advisories are actual OSV responses, never hardcoded. [OSV API](https://google.github.io/osv.dev/post-v1-query/).

Unavailable, failed, timed-out and skipped scanners are visible in assessment history and reports. Partial coverage is **Completed with warnings**. If all scanners fail or are unavailable/skipped, the assessment is **Failed**, with no score. A scanner reporting no findings is different from a scanner that failed. Reports and scores explicitly state their coverage limitations. Unknown advisory severity stays UNKNOWN; CVE, confidence and fixed versions are not invented. Advisory fixed versions may span several release branches; review the advisory before upgrading.

## Architecture and persistence

`frontend/src/main.tsx` uses the existing dark/mint component styling and hash navigation. `scripts/serve-frontend.mjs` serves the built frontend and proxies multipart requests on loopback. `backend/main.py` provides upload, start/status, history, dashboard, findings, triage and report APIs. `backend/archive.py` validates/extracts; `backend/scanners.py` invokes and parses scanners; `backend/engine.py` normalizes and scores.

SQLite tables: assessments, scanner_runs, findings (with assessment index). Metadata and normalized results persist across restart. Source workspaces and transient scanner reports are removed after scanning. Interrupted uploads/scans are marked failed on backend restart and their workspaces removed. Reports are generated from persisted assessment results and current triage status; assessment counts/scores remain the original scan snapshot. A new upload is required to rescan.

## Deterministic scoring

Finding contextual risk = sum of the following, clamped to 0–100:

| Factor | Points | Provenance |
| --- | ---: | --- |
| Critical / High / Medium / Low / Unknown severity | 75 / 60 / 35 / 15 / 25 | Scanner/advisory |
| High confidence, if supplied | +5 | Scanner |
| Credential pattern | +15 | Secret scanner; validity untested |
| Known vulnerable package version | +5 | OSV response |
| Production | +3 | Optional user context |
| Low / Medium / High / Critical business criticality | +0 / +2 / +5 / +8 | Optional user context |

Security score = round(100 − 0.65 × maximum finding risk − min(35, sum(8 × (risk/100)^2))), clamped to 0–100. No detected findings yields 100 only when some scanner completed. A dominant high-risk issue weighs more than a low-risk issue; accumulated findings add a bounded penalty. Scores are indicators, not probabilities or proof of security. Manual triage does not erase detection history. Trend includes real completed scans with the same project name; different context or coverage can make comparisons misleading.

Fingerprints use scanner, rule, normalized file, line, package and version. Exact duplicates within a scan are merged. Ambiguous cross-scanner overlaps remain separate to avoid merging unrelated issues.

## Upload and process safety

ZIP only: 20 MiB upload, 80 MiB expanded, 4 MiB per file, 2,000 entries, maximum 200:1 expansion ratio, 180-character paths. Stored/deflate compression only. Reject encrypted ZIPs, malformed/empty archives, traversal, absolute paths, backslashes, Windows device names/alternate streams, special files, symlinks, duplicate case-insensitive paths, and unsafe path components. Files extract only to generated IDs in `data/workspaces`. Filenames do not select filesystem destinations. One assessment runs at a time.

Scanners receive explicit process arguments, trusted local configurations, bounded output and 90-second adapter timeouts. Source text and raw scanner stdout/stderr are never retained in application findings or logs. Evidence is intentionally withheld rather than risking disclosure of secrets missed by a redaction pattern. File paths and dependency metadata remain visible and may themselves be sensitive; this local workspace is for a trusted single user.

The application binds loopback only, restricts browser origins and does not authenticate local operating-system users. Do not expose it to a network or use it as a multi-tenant service. Static analyzers parse untrusted files; keep tools updated and use OS isolation for hostile production workloads. Upload limits bound routine resources; this is not an adversarial denial-of-service hardened hosting platform.

CyberGuard performs static source-code assessment. It does NOT execute uploaded projects. It does NOT prove exploitation. It must only be used on code the user owns or is authorized to assess. It never installs uploaded dependencies, runs build scripts, visits URLs from source, performs port scans, or tests credentials.

## QA

Run `.venv\Scripts\python.exe scripts/verify-api.py` against running services for real uploads, differential scans and invalid archive checks. `node scripts/verify-ui.mjs` exercises the browser with installed Edge and project-local Playwright. QA creates real assessment records; use reset afterward. See `docs/demo-guide.md` and `docs/qa-summary.md` for tested behavior and limitations.
