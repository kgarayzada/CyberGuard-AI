# CyberGuard AI

**Intelligent Vulnerability Assessment & Risk Prioritization Platform**

Security tools often produce fragmented alerts without explaining what to fix first. CyberGuard AI turns findings into understandable priorities, correlated potential attack paths, remediation guidance, and a security assessment report.

This is a complete local final-project demonstration. It opens with a fictional banking portal, four completed assessments, a score of **58/100**, **10 open findings** (1 critical, 3 high, 4 medium, 2 low), and one resolved historical finding.

## Start on Windows

From this project directory in PowerShell:

```powershell
.\start.ps1
```

- Frontend: **http://127.0.0.1:5173**
- API health: **http://127.0.0.1:8000/api/health**
- API schema: **http://127.0.0.1:8000/openapi.json**

Prerequisites: a working **Python 3.10+** runtime (tested with Python 3.14) and **Node.js 22.12+** (tested with Node 24). The script detects the Windows `py` launcher, creates `.venv`, installs local dependencies if missing, builds the frontend if needed, initializes SQLite, starts hidden loopback servers, waits for readiness, and opens your browser. Subsequent presentation startup is offline and reuses installed packages and built assets.

If Windows blocks script execution, use this process-only command; it does not change Windows policy:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\start.ps1
```

First-time dependency installation needs internet access. Runtime does not. No Administrator rights, global installs, system services, environment changes, external scanners or API keys are used. Use `-NoBrowser` for automated startup. If either required port belongs to another service, startup stops safely and asks you to close that service.

## Reset and stop

```powershell
.\reset-demo.ps1
.\stop.ps1
```

Reset stops only processes recorded by this project whose creation time and full script path still match. It clears only the four CyberGuard SQLite tables, reseeds the initial dataset, and restarts the app. Source and dependencies are preserved. Refresh an existing browser tab after reset. Stop preserves all data. Closing the PowerShell window does not stop the hidden servers; use `stop.ps1`.

## Features

- SOC-style dashboard: severity cards, score trend, category risk, top findings and recent scans.
- Asset profile with exposure, criticality, ownership and assessment history.
- A 6.5-second simulated assessment with real persisted scan state, staged progress and immutable finding snapshots. Repeated concurrent starts reuse the active scan.
- Searchable, filterable findings with evidence, CWE, illustrative CVSS, risk breakdown, technical/business impact and practical remediation.
- Persisted OPEN, RESOLVED, ACCEPTED and FALSE POSITIVE dispositions; current counts, analyst responses and active paths reflect triage changes.
- Deterministic local AI-assisted explanations and six focused analyst prompts.
- Two potential attack paths with linked findings and recommended fix order.
- In-application HTML security report and locally saved immutable report snapshots. No PDF generation.
- Responsive layout, keyboard-accessible controls, graceful connection states and local-only assets.

## Technology and architecture

**React 19 + TypeScript + Vite**, Lucide icons, Recharts, custom responsive CSS; **Python + FastAPI + SQLite** using Python's standard SQLite library. No ORM or migration service is necessary for this small dataset.

```text
Browser :5173 → local Node static server / API proxy → FastAPI :8000
                                                       ↓
                                                data/cyberguard.db
                                                       ↕
                                             deterministic rule engine
```

`backend/engine.py` contains fictional fixtures, the risk algorithm, correlation definitions and analyst rules. `backend/main.py` owns initialization, persistence, assessment progress, report snapshots and APIs. `frontend/src/` owns the user interface. The presentation server serves the production build; Vite is needed only for builds or development. `frontend/package-lock.json` and pinned Python requirements preserve dependency versions.

For frontend development: `cd frontend`, then `npm run dev` after stopping the presentation frontend. Keep the backend running. Normal presentations should use `start.ps1`.

## Risk model and interpretation

Risk = severity baseline + internet exposure (8) + high business criticality (5) + confidence adjustment (2 or 5) + applicable credential exposure (15), path participation (8), and related-finding correlation (3 for high findings), bounded to 0–100. High baselines vary by finding type. The critical finding sums to **55 + 8 + 5 + 5 + 15 + 8 = 96**. Every factor is displayed on the finding page.

The score history (43 → 47 → 51 → 58) is an illustrative benchmark, separate from the finding-level risk algorithm. New simulations reproduce a score of 58; starting another scan does not pretend to fix vulnerabilities. Dispositions update current triage, while past assessment snapshots remain unchanged. Confidence is a fixture classification, not an estimated real-world exploit probability.

## Demo workflow and presentation guide

Overview → Assets → Start Security Scan → Findings → Critical finding → Evidence & risk factors → AI-assisted explanation → Remediation → Attack Paths → AI Analyst → Reports.

Follow [the timed 3–5 minute demo guide](docs/demo-guide.md). Reset before presenting. The seeded dates are fixed illustrative historical dates; new assessments use your system's current UTC time and appear first in the recent assessment list.

## Verification

With both services running:

```powershell
.\.venv\Scripts\python.exe scripts\verify-api.py
```

This checks seeded counts, all finding details, exact risk arithmetic, all six analyst questions, concurrent scan deduplication, progress duration, direct SQLite persistence, dispositions, correlation and report snapshot preservation. It creates a scan and report; reset afterward.

Browser verification uses the optional project-local `playwright-core` package and an existing Chrome or Edge installation. It stores its temporary profile under `.tooling/` and does not install a browser:

```powershell
node scripts/verify-ui.mjs
node scripts/capture-screenshots.mjs
```

The browser checks cover all routes at 1440×900, 1366×768 and 390×844, filters, dispositions, scans, all analyst prompts, reports, connection recovery and external-request detection. Six presentation images are in `docs/screenshots/`. Capture after reset to show the clean initial dashboard; capture itself creates one demo scan. Reset again when finished.

## Disclaimer and limitations

CyberGuard AI MVP uses deterministic demonstration assessment data. Findings shown in this demonstration represent a simulated security assessment intended to demonstrate vulnerability management, contextual risk prioritization, correlation, remediation and reporting workflows.

`https://portal.fintrust-demo.local` is fictional and is never contacted. `DEMO_API_KEY=CG_DEMO_NOT_REAL_2026` is not a real credential. No exploitation or external AI request occurs. The local analyst uses rules and templates, not an LLM. This MVP has no authentication and is intended only for trusted, single-user loopback demonstration. It does not assess real systems or validate remediation. Reports remain in the application and SQLite; PDF export is deliberately excluded.
