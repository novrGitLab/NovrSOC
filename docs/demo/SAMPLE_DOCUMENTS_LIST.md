# Sample Documents Available for Download

Generated client-side in Presentation Mode, Reporting Center → **Sample Documents** tab
(`frontend/src/components/features/ReportingCenter.tsx`, data from `frontend/src/lib/demo/documents.ts`).
Every file is a real PDF, built in the browser from the same seeded demo dataset shown on screen —
no backend call is made. Every title and every page is marked **[SAMPLE]** / SIMULATED.

15 documents total — 5 report types × 3 organisations:

| # | Report Type | LAPO (Banking) | Tazemi (Telecom) | IKEA (Energy) |
|---|---|---|---|---|
| 1 | Executive Security Summary | `sample-lapo-executive-summary.pdf` | `sample-tazemi-executive-summary.pdf` | `sample-ikea-executive-summary.pdf` |
| 2 | Vulnerability Assessment Report | `sample-lapo-vulnerability-assessment.pdf` | `sample-tazemi-vulnerability-assessment.pdf` | `sample-ikea-vulnerability-assessment.pdf` |
| 3 | Threat Intelligence Briefing | `sample-lapo-ti-briefing.pdf` | `sample-tazemi-ti-briefing.pdf` | `sample-ikea-ti-briefing.pdf` |
| 4 | Incident Investigation Report | `sample-lapo-incident-report.pdf` | `sample-tazemi-incident-report.pdf` | `sample-ikea-incident-report.pdf` |
| 5 | CNII Security and Compliance Report | `sample-lapo-cnii-compliance.pdf` | `sample-tazemi-cnii-compliance.pdf` | `sample-ikea-cnii-compliance.pdf` |

Each document contains: organisation name/sector/location, reporting period (trailing 30 days),
an executive summary section, findings specific to that organisation's connected scenario,
supporting evidence (IOCs, CVEs, case references), recommendations, and a methodology/limitations
section that states plainly the document is a sample built from simulated data.

**How to get one:** Admin → Reporting Center → turn on Presentation Mode (header) → select an
organisation → **Sample Documents** tab → **PDF** button next to the report type.

**Not included:** these are not generated through the production report-generation pipeline
(`POST /api/reports/generate`) — that endpoint is intentionally disabled in Presentation Mode and says so
if clicked. These 15 PDFs are the complete, intended way to show a deliverable report during the
walkthrough.
