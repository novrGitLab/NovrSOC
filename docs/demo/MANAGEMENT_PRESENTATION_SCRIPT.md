# NovrSOC Management Presentation — 12-Minute Script

Companion to `MANAGEMENT_DEMO_WALKTHROUGH.md` (the screen-by-screen route). This is the
word-for-word talking track for a presenter. Timings are cumulative. Everything described as
"click" below has a real, observable effect in Demo Mode for the rest of that browser session —
these are not just visuals; see the callouts marked **[LIVE CLICK]**.

---

**0:00 — Open (30s)**

> "What you're about to see is the real NovrSOC platform — the same screens our analysts use
> every day. We're going to run it in Demo Mode, which replaces live client data with three
> fictional organisations, so we can walk through a full security operation without touching any
> real customer's information. Every screen you see carries a yellow banner reminding you it's
> simulated. Nothing we click here sends an email, blocks an IP, or changes anything outside this
> browser tab."

Turn on Demo Mode, select **LAPO**. Point at the banner.

---

**0:30 — Three organisations (1 min)**

> "We've set up three organisations so you can see the platform handle a bank, a telecom, and a
> power utility — three of the sectors NCC-CSIRT cares most about. LAPO is a microfinance bank in
> Lagos. Tazemi is a regional telecom operator. IKEA is a power distribution utility. Watch what
> happens when I switch between them."

Switch LAPO → Tazemi → IKEA on the Dashboard. Call out that every KPI tile and chart updates
together.

---

**1:30 — Security Command Center (1.5 min)**

Switch back to **LAPO**.

> "This is the Security Command Center — the first thing an analyst sees at the start of a shift.
> Open cases, exposure summary, the alert feed. For LAPO, the story we're tracking is a
> credential-stuffing attempt against the customer banking portal."

Open the featured case `CASE-LAPO-0142`.

> "This case already shows the IOC that triggered it, and the investigation timeline so far."

**[LIVE CLICK]** Add a note or change the case status. "That note just got added to this case for
the rest of this session — this isn't a static screenshot, it's the real case workbench."

---

**3:00 — Nigeria Threat Heatmap & Threat Intelligence (2 min)**

Switch to **Tazemi**.

> "Tazemi's story starts with firewall activity at the network edge, which our threat
> intelligence correlates against a flagged indicator."

Open TI Matches, point at indicator `198.51.100.23`. Then open the Nigeria Threat Heatmap.

> "This shows where threat activity concentrates geographically. Selecting a state shows the kind
> of event-level detail a SOC analyst would drill into."

---

**5:00 — AI Behavioral Analysis (1.5 min)**

Scroll to the AI Threat Intelligence & Behavioral Analysis section on the TI Analyst page.

> "This panel is clearly marked DEMO because it's showing you where we're headed, not a system
> that's live today: automated baseline-vs-observed anomaly scoring, and a correlated attack
> sequence across a kill chain. The Q&A assistant above it, on the other hand, is real — it
> answers from the platform's actual stored intelligence record, with citations."

---

**6:30 — CNII Watch (1.5 min)**

Switch to **IKEA**.

> "IKEA is a power utility — critical national infrastructure. CNII Watch tracks sector exposure
> and compliance against the frameworks that actually apply: NDPR and the NERC Critical
> Infrastructure Protection standard."

---

**8:00 — Vulnerability & Remediation workflow (2 min)**

Open VMS Findings, show the featured critical finding on `grid-gateway-07` (a known-exploited
vulnerability). Open the Remediation / Verification screen.

> "This is where a finding actually gets closed out — not by someone changing a status field, but
> by evidence: a rescan that confirms the fix. Watch what happens when I click Verify."

**[LIVE CLICK]** Click **Verify** on the finding. It moves from "Awaiting verification" to
"Verified fixed" immediately, and the KPI counts update.

> "That's a real state change in this session — in production, that same click queues an actual
> rescan. We're skipping the wait here, but the before-and-after is exactly what remediation
> closure looks like."

---

**10:00 — Collector Management (1 min)**

> "Collector Management is where we monitor the health of the log collectors deployed at a
> client's site — heartbeat, throughput, buffer pressure. This is what operations monitoring
> looks like once a real collector appliance is deployed; today's view is illustrative."

---

**11:00 — Reporting Center — Sample Documents (1 min)**

Open Reporting Center → **Sample Documents**.

> "Every client we onboard gets scheduled reports delivered automatically. Here are the five
> report types we produce — executive summary, vulnerability assessment, threat intelligence
> briefing, incident report, and CNII compliance. Let me pull one."

**[LIVE CLICK]** Download the Executive Security Summary PDF. Show it opening.

> "That's a real PDF, generated in your browser just now from this organisation's data — clearly
> marked SAMPLE so no one mistakes it for a delivered client report."

---

**12:00 — Close (30s)**

Turn Demo Mode off.

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
