# NovrSOC Management Demo — Presenter Walkthrough

10–15 minute guided tour of the platform for management, using **Demo Mode** (synthetic data,
real UI). Nothing shown here is live telemetry — every screen carries a persistent
**DEMO MODE — SIMULATED DATA** banner while this is on.

## Before you start

1. Sign in as a staff account (`super_admin`, `soc_manager`, or `analyst`).
2. In the header, click **Demo Mode** to turn it on, then pick an organisation from the dropdown
   next to it (**LAPO**, **Tazemi**, or **IKEA**).
3. The amber banner at the top of the screen confirms Demo Mode is active and shows which
   organisation is selected. Every screen below reads from that same organisation until you
   change it or turn Demo Mode off.

## The three demo organisations

| Org | Sector | Story |
|---|---|---|
| **LAPO** | Banking, Finance & Insurance (Lagos) | Suspicious authentication → correlated alert → incident investigation → executive summary |
| **Tazemi** | ICT & Communications (Lagos) | Firewall activity → network threat intelligence → Nigeria heatmap → CNII exposure |
| **IKEA** | Power & Energy (Lagos) | Critical asset vulnerability → remediation workflow → verification → risk improvement |

Each organisation's data is internally consistent and deterministic — the same asset names, case
numbers, CVEs and addresses appear everywhere that organisation's data shows up, every time.

## Suggested running order (~12 minutes)

1. **Opening overview — Dashboard** (`/admin/dashboard`, ~1 min)
   Start with Demo Mode off to show the real platform shell, then turn it on with **LAPO**
   selected. Point out the banner, the KPI tiles, and the "Onboarded Clients" widget now showing
   the three demo organisations.

2. **Three-org switching** (~1 min)
   Switch the org dropdown from LAPO → Tazemi → IKEA while sitting on the Dashboard. Call out that
   every KPI, chart and table updates together — this is the same screens staff use daily, not a
   separate mock.

3. **Security Command Center / SecOps Cases** (`/admin/secops/cases`, ~2 min, LAPO)
   Open the featured case (`CASE-LAPO-0142` — suspected credential stuffing). Walk through the
   case detail: timeline, IOC, linked threat intelligence. This is the "incident investigation"
   leg of LAPO's scenario.

4. **Threat Intelligence & Nigeria Heatmap** (`/admin/ti/map`, ~2 min, switch to Tazemi)
   Switch to Tazemi. Show the TI matches screen (the flagged indicator `198.51.100.23`), then open
   the Nigeria Threat Heatmap and point out the state-level activity and the simulated event
   detail panel for a selected state.

5. **AI Behavioral Analysis** (`/admin/ti/analyst`, ~1.5 min)
   Scroll to the AI Threat Intelligence & Behavioral Analysis section: baseline-vs-observed
   anomaly scores and the correlated attack-sequence panel. Note the DEMO badges — this is clearly
   framed as a capability preview, not a claim of a live ML engine.

6. **Vulnerability & Remediation workflow** (`/admin/vms/findings` → `/admin/vms/remediation`,
   ~2 min, switch to IKEA)
   Switch to IKEA. Open the featured P1 finding (grid-control gateway, known-exploited CVE), then
   the remediation queue showing it moving toward "fixed — pending verification." This is IKEA's
   scenario: critical vulnerability → remediation → verification → improved risk posture.

7. **CNII Watch** (`/admin/cnii`, ~1.5 min)
   Still on IKEA (Power & Energy sector). Show the sector exposure view and the organisation's
   compliance framework scores (NDPR, NERC CIP).

8. **Collector Management** (`/admin/collectors`, ~1 min)
   Show the demo collector's heartbeat, throughput, and the simulated network event log —
   framed as what collector health monitoring looks like once a real Vector collector is deployed
   (not claiming a live appliance is attached in this session).

9. **Reporting Center — Sample Documents** (`/admin/reports` → **Sample Documents** tab, ~1.5 min)
   Only visible in Demo Mode. Download one or two of the five sample PDFs (Executive Security
   Summary, Vulnerability Assessment, TI Briefing, Incident Investigation Report, CNII
   Compliance Report) to show management what a delivered report looks like, generated instantly
   and client-side.

10. **Close** (~0.5 min)
    Turn Demo Mode off to show the banner disappears and the platform returns to its live,
    normal state — reinforcing that Demo Mode is a presentation layer, not a separate product.

## What's operational today vs. what's a future capability

Be explicit about this distinction during the walkthrough — it is the difference between an
honest demo and an overpromise.

**Operational today (real, when connected to live data/collectors):**
- Security Command Center dashboard, VMS findings/remediation workflow, TI indicator matching,
  SecOps case management, CNII Watch sector/compliance tracking, Reporting Center
  scheduling/delivery, Collector Management health/heartbeat monitoring.

**Demonstrated as a capability preview, not yet a live engine:**
- The AI Behavioral Analysis baseline/anomaly scoring and the automated correlation "attack
  sequence" panel on the TI Analyst page — synthetic, clearly DEMO-badged, illustrating the
  intended UX ahead of a production behavioral-analytics engine.
- The Nigeria Threat Heatmap's per-state "latest event" detail panel — the choropleth counts
  themselves can be real (TI indicator data); the simulated per-event drill-down illustrates
  where real network event detail would surface once available.

## Isolation guarantees worth stating out loud

- Demo Mode never writes to, or reads from, production security, client, or reporting tables.
- Turning Demo Mode on or switching the demo organisation never changes which real organisation a
  staff account is authorised to view — it is a separate, independently-gated layer
  (`lib/demo/state.ts`), not a substitute for `lib/orgContext.ts`.
- Every action button (block IP, generate & deliver, acknowledge, approve, etc.) in Demo Mode
  returns a synthetic success without ever reaching the real backend, Wazuh, or Supabase.
