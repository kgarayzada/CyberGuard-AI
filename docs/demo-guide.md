# CyberGuard AI — 3–5 minute presentation

Before the presentation, run `.\reset-demo.ps1`. The reset restores 58/100, ten open findings, one resolved finding and four seeded assessments. Keep the browser near 1440×900 or maximize it on a laptop.

## 0:00–0:40 · Explain the problem and show the dashboard

1. Run `.\start.ps1` and open **http://127.0.0.1:5173**.
2. “Security tools produce fragmented alerts. CyberGuard brings them together and explains what we should fix first.”
3. Show **Security Score 58/100**, the Critical/High/Medium/Low cards, and the **51 → 58** improvement.
4. Point to the severity chart, category risk, trend, and top risks. “The initial dataset is ready immediately.”

## 0:40–1:15 · Asset context and an assessment

5. Open **Assets**, then click **FinTrust Customer Portal**.
6. Show its fictional URL, production environment, internet exposure, high criticality and Digital Banking Team owner. “Business context affects priority.”
7. Open **Scans**, then click **START SECURITY SCAN**.
8. Watch the roughly **6.5-second** staged assessment progress. “Discovery is simulated locally, but progress, the scan record and results are really persisted in SQLite.”
9. Click **View assessment results**. Show the new scan ID, completed status and ten open findings.

## 1:15–2:25 · Investigate the critical finding

10. Open **Findings**. Briefly use the severity filter or search if useful.
11. Open **Exposed API Credential in Public Source Map**.
12. Show **CRITICAL**, **96/100**, **98% confidence**, **CWE-798**, and `/assets/app.js.map`.
13. Show `DEMO_API_KEY=CG_DEMO_NOT_REAL_2026` and the explicit fictional credential label. “This is harmless demonstration evidence.”
14. Show the **Contextual risk** panel. Explain the visible sum: baseline, internet exposure, business criticality, confidence, credential exposure and path participation.
15. Scroll to **AI-Assisted Security Analysis**. “Local deterministic rules explain technical and business impact. There is no external LLM or API.”
16. Show **Recommended remediation**: rotate the credential, remove secrets from browser artifacts, disable public production source maps, and review access.

## 2:25–3:10 · Correlate findings

17. Open **Attack Paths**.
18. Trace the main chain: **Public Source Map Exposure → Application Information Disclosure → Exposed Demo API Credential → Potential Unauthorized API Access**.
19. “These are related weaknesses forming a potential exposure chain. We are not claiming exploitation occurred.”
20. Point to the fix order and briefly show the secondary debug/technology disclosure path.

## 3:10–3:45 · Ask the analyst

21. Open **AI Analyst**.
22. Select **What should we fix first?**
23. Show the prioritized response and explain that it uses the current database findings, not a static chat mockup.

## 3:45–4:30 · Finish with the report

24. Open **Reports**, then **GENERATE REPORT**.
25. Show the branded header, executive summary, score, severity distribution and top risks. Scroll briefly through potential paths, remediation priorities and detailed findings.
26. Point to methodology and the simulation disclaimer. “The workflow is complete: Assessment → Findings → Contextual Risk → Analysis → Correlation → Remediation → Report.”

Use `.\stop.ps1` to stop the project after the presentation. Use `.\reset-demo.ps1` to prepare another clean run. A generated report is an immutable local snapshot; **VIEW SECURITY REPORT** opens the current database view.
