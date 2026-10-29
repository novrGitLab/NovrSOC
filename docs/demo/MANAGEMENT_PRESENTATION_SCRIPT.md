# NovrSOC Management Presentation — 12-Minute Script

Companion to `MANAGEMENT_DEMO_WALKTHROUGH.md` (the screen-by-screen route). This is the
word-for-word talking track for a presenter. Timings are cumulative. Everything described as
"click" below has a real, observable effect in Presentation Mode for the rest of that browser session —
these are not just visuals; see the callouts marked **[LIVE CLICK]**.

Each section now has a **Navigation** line giving the exact URL path and, where confirmed against
the component source, the exact button/tab label to click. Labels for the three demo-specific
controls (the Presentation Mode toggle, "Verify", "Sample Documents") are drawn directly from the
component source and are exact. Labels for pre-existing screens (case actions, TI pages) match
the source as last read, but were not re-confirmed against a live rendered page — no browser
automation tool was available this session, so the presenter should do one dry run before
presenting live, using this as a close guide rather than a guarantee of pixel-exact wording.

## Presenter prep (do this once, before the room fills up)

The "Verify" click and the case-workbench actions below leave a **real, session-local change**
that persists until Presentation Mode is turned off (or the browser tab closes) — switching between
LAPO/Tazemi/IKEA does **not** reset it. If you rehearse this script and then present later in the
same browser session, the IKEA finding will already show "Verified" and the LAPO case will
already show your rehearsal note. Toggle Presentation Mode off and back on once, right before you present,
to start from the clean seeded state described below.

---

**0:00 — Open (30s)**

> "What you're about to see is the real NovrSOC platform — the same screens our analysts use
> every day. We're going to run it in Presentation Mode, which replaces live client data with three
> fictional organisations, so we can walk through a full security operation without touching any
> real customer's information. Every screen you see carries a yellow banner reminding you it's
> simulated. Nothing we click here sends an email, blocks an IP, or changes anything outside this
> browser tab."

**Navigation:** Sign in → you land on `/admin/dashboard`. In the header, click the amber
**Presentation Mode** button (it reads **Presentation: On** once active, and an organisation `<select>` appears
immediately to its right). Pick **LAPO** from that dropdown. Point at the new amber banner now
running the full width of the page below the header.

---

**0:30 — Three organisations (1 min)**

> "We've set up three organisations so you can see the platform handle a bank, a telecom, and a
> power utility — three of the sectors NCC-CSIRT cares most about. LAPO is a microfinance bank in
> Lagos. Tazemi is a regional telecom operator. IKEA is a power distribution utility. Watch what
> happens when I switch between them."

**Navigation:** Stay on `/admin/dashboard`. Use the same header dropdown to switch
**LAPO → Tazemi → IKEA**, pausing on each for a second. Call out that every KPI tile and chart
updates together, and that the banner's organisation name changes with it.

---

**1:30 — Security Command Center (1.5 min)**

Switch back to **LAPO** (header dropdown, still on `/admin/dashboard`).

> "This is the Security Command Center — the first thing an analyst sees at the start of a shift.
> Open cases, exposure summary, the alert feed. For LAPO, the story we're tracking is a
> credential-stuffing attempt against the customer banking portal."

**Navigation:** Go to `/admin/secops/cases`. The top case in the list is **CASE-LAPO-0142** —
click its row to open the case detail drawer.

> "This case already shows the IOC that triggered it, and the investigation timeline so far."

**[LIVE CLICK]** In the drawer, add a note (the note-entry control) or change the case's status.
"That note/status change just got applied to this case for the rest of this session — this isn't
a static screenshot, it's the real case workbench. Close and reopen the case and it's still
there."

---

**3:00 — Nigeria Threat Heatmap & Threat Intelligence (2 min)**

Switch to **Tazemi** (header dropdown).

> "Tazemi's story starts with firewall activity at the network edge, which our threat
> intelligence correlates against a flagged indicator."

**Navigation:** Go to `/admin/ti/matches` — the top match shows indicator **198.51.100.23**.
Then go to `/admin/ti/map` (or the Nigeria Threat Map widget embedded on the dashboard) and click
any highlighted state.

> "This shows where threat activity concentrates geographically. Selecting a state shows the kind
> of event-level detail a SOC analyst would drill into."

---

**5:00 — AI Behavioral Analysis (1.5 min)**

**Navigation:** Go to `/admin/ti/analyst`. Scroll past the Q&A box and the threat/Nigeria
briefings to the **AI Threat Intelligence & Behavioral Analysis** section (every card in it
carries a small **PREVIEW** badge).

> "This panel is clearly marked PREVIEW because it's showing you where we're headed, not a system
> that's live today: automated baseline-vs-observed anomaly scoring, and a correlated attack
> sequence across a kill chain. The Q&A assistant above it, on the other hand, is real — it
> answers from the platform's actual stored intelligence record, with citations."

---

**6:30 — CNII Watch (1.5 min)**

Switch to **IKEA** (header dropdown).

**Navigation:** Go to `/admin/cnii`.

> "IKEA is a power utility — critical national infrastructure. CNII Watch tracks sector exposure
> and compliance against the frameworks that actually apply: NDPR and the NERC Critical
> Infrastructure Protection standard."

---

**8:00 — Vulnerability & Remediation workflow (2 min)**

**Navigation:** Go to `/admin/vms/findings` — the top finding is on asset `gw07.ikea-demo.test`
(grid-gateway-07), a known-exploited vulnerability, priority **P1**. Then go to
`/admin/vms/remediation`, where the **Awaiting verification** tab (selected by default) lists
that same finding.

> "This is where a finding actually gets closed out — not by someone changing a status field, but
> by evidence: a rescan that confirms the fix. Watch what happens when I click Verify."

**[LIVE CLICK]** Click the **Verify** button on that finding's row (confirm the dialog if one
appears). The finding disappears from **Awaiting verification** and reappears under the
**Verified fixed** tab; the "Awaiting verification" and "Verified fixed (30 days)" KPI tiles at
the top of the page both update immediately.

> "That's a real state change in this session — in production, that same click queues an actual
> rescan. We're skipping the wait here, but the before-and-after is exactly what remediation
> closure looks like."

---

**10:00 — Collector Management (1 min)**

**Navigation:** Go to `/admin/collectors`. Still on IKEA — the one listed collector is named
`ikea-site-1-demo`; click it to show its heartbeat/throughput detail and recent event log.

> "Collector Management is where we monitor the health of the log collectors deployed at a
> client's site — heartbeat, throughput, buffer pressure. This is what operations monitoring
> looks like once a real collector appliance is deployed; today's view is illustrative."

---

**11:00 — Reporting Center — Sample Documents (1 min)**

**Navigation:** Go to `/admin/reports`. A new tab appears in the tab bar only while Presentation Mode is
on, all the way on the right: **Sample Documents**. Click it.

> "Every client we onboard gets scheduled reports delivered automatically. Here are the five
> report types we produce — executive summary, vulnerability assessment, threat intelligence
> briefing, incident report, and CNII compliance. Let me pull one."

**[LIVE CLICK]** Click the **PDF** button next to **Executive Security Summary**. Show the
downloaded file opening.

> "That's a real PDF, generated in your browser just now from this organisation's data — clearly
> marked SAMPLE so no one mistakes it for a delivered client report."

---

**12:00 — Close (30s)**

**Navigation:** In the header, click **Presentation: On** to turn it off.

> "And that's the platform — the banner's gone, we're back to the live system. Everything you saw
> was the real product, run against safe, synthetic data. Happy to go deeper into any one of
> these screens, or talk through what's operational today versus what's still on the roadmap."

---

## If asked "is this real?"

Be direct: yes, the screens and the workflow are the real product. No, the data in front of you
right now is not — it's generated in your browser and never touches a production database,
Wazuh, or a real client's records. The AI Behavioral Analysis panel specifically is a capability
preview, not a live engine; everything else shown is the platform's actual, currently-working
feature set, operating on fictional data for this walkthrough.
