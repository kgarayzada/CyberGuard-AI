# Final-project demonstration

1. Run `.\reset-demo.ps1`, then `.\start.ps1`.
2. Open http://127.0.0.1:5173 and show **No assessments yet**.
3. Click **UPLOAD SOURCE CODE**, choose `demo/cyberguard-vulnerable-demo.zip`, and enter **CyberGuard Vulnerable Demo**.
4. Optionally choose Production and High criticality; these are user assertions, not inferred infrastructure facts.
5. Enable OSV lookup to check the historical lodash version if internet is available. Confirm authorized use and start.
6. Watch backend stages and scanner statuses. Explain any unavailable/failed coverage honestly.
7. Open Findings and investigate a credential or SQL pattern. Show scanner/rule, file/line, withheld evidence, deterministic risk factors, and remediation.
8. Open Reports and select the completed assessment. Show severity counts, prioritized findings, scanner coverage and technical details.
9. Explain that uploaded code was never executed, credentials were never tested, and no exploitation was proven.
10. Stop with `.\stop.ps1`. Reset before the next demonstration; reset does not repopulate anything.

The demo ZIP contains only intentionally vulnerable static fixture code and synthetic data. Finding counts are not promised; they depend on successfully completed scanners and current OSV advisory responses. A clean upload must produce different results. No external LLM is involved.
