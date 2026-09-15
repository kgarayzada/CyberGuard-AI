# QA summary — 15 September 2026

## Real assessment evidence

End-to-end API upload of `demo/cyberguard-vulnerable-demo.zip` completed with:

| Scanner | Version | Actual findings |
| --- | --- | ---: |
| Semgrep | 1.177.0 | 4 |
| Gitleaks | 8.30.0 | 1 |
| OSV dependency adapter | API v1 | 5 |

The 10 findings were parsed from actual scanner/advisory results and persisted in SQLite. The local scan stages took roughly 10 seconds in this run; durations are not simulated or guaranteed. OSV counts can change with its database.

A minimal clean Python ZIP returned **zero** findings. A temporary fixture with parameterized SQL removed the `python-sql-concatenation` finding while retaining the other four local findings (OSV disabled for that comparison). No full synthetic credential value appeared in normalized results. Extracted workspaces were deleted after completion.

## Passed checks

- Initial database/dashboard: no assessments and no findings.
- Multipart ZIP upload through the frontend proxy, extraction, real processes, normalization, score, detail APIs and report APIs.
- Persistence: stop/start preserved the original 10 findings, score and report.
- Scanner failure: temporarily unavailable Gitleaks produced a visible warning and four real Semgrep findings; both local scanners unavailable with OSV disabled produced Failed, null score and zero findings. Binaries were restored in finally blocks.
- Invalid uploads: non-ZIP, corrupted ZIP, traversal, absolute paths, reserved Windows names, empty archive, over-limit request and oversized/compression-bomb entry were rejected.
- Eight focused security tests passed: unsafe names, raw backslash ZIP path, encrypted ZIP, symlink, entry count, case-insensitive collision, unavailable scanner, and deterministic scoring/fingerprints.
- Headless Edge: real file selection/upload/start/completion/report flow; overview, upload, assessments, findings, detail and reports at 1440, 1366, 1024 and 390 px widths; no page overflow or console/runtime errors.
- Browser interactions: scanner filter, text search, triage change persisted after reload, and honest all-scanners-unavailable display.
- TypeScript and production Vite build passed.

## Limits

Semgrep uses six local Python/JavaScript/TypeScript rules, not an exhaustive rule registry. Dependency coverage is exact pins in package.json and requirements.txt, with optional internet lookup and no dependency installation. Source evidence is fully withheld for credential protection. Tests demonstrate static detection and application behavior, not exploitation or comprehensive vulnerability coverage.

Reproduce using the scripts listed in README; API integration QA expects an initially empty database. Tests create assessment data and require reset afterward. Browser QA uses the locally installed Edge executable and project-local Playwright, with no global install.

## Final clean handoff

Final reset and subsequent start passed. SQLite contained **0 assessments and 0 findings**, workspaces contained **0 directories**, and the ready-to-upload demo ZIP remained present. Headless Edge verified the empty dashboard and upload page with no browser errors. Startup detected Semgrep 1.177.0 and Gitleaks 8.30.0. Project services were stopped after QA.
