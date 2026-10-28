# VTEM Frontend Visibility Audit

**Scope:** Part 5 of the VTEM platform audit — complete frontend route inventory, feature discoverability against the 49 VTEM requirements, explainability, role-specific journeys, and visual/interaction quality. This document does not cover backend internals, database/RLS, or integration health in depth — see `VTEM_BACKEND_ARCHITECTURE_AUDIT.md`, `VTEM_DATABASE_AND_TENANCY_AUDIT.md`, and `VTEM_SECURITY_AND_INTEGRATIONS_AUDIT.md`.

**Audit target:** `C:\Users\USER\NovrSOC`, branch `marketing-pages-merge` (= `main` + 5 marketing/public-site commits). This is the primary working directory and is confirmed to be the frontend-richest line in the repository: it has the full admin app, the full client app, **and** a public marketing site. A separate, unmerged worktree (`feat/vms-onboarding`, path `novr-vms`) has a VMS/backend line that is *ahead* on some backend tables (P26/P27 migrations) but has **no marketing site** and only `admin/client/login/set-password/status` at the frontend route level — i.e. it is strictly behind this line on frontend. All route and component evidence below is from `NovrSOC` unless stated otherwise.

**Primary sources used** (read in full or in relevant sections, then independently spot-checked against current code):
- `NOVRSOC_REDESIGN_TECHNICAL_AUDIT_V2.md` (baseline commit `3bd3a6e`, dated ~2026-10-25) — contains a generated 137-route frontend inventory (Appendix A) and widget-by-widget dashboard data-flow trace (§5). Three marketing commits (`049f22f`, `4e12a6e`, `bab6ff0`) have landed since; those routes are **not** in V2's inventory and are added fresh below.
- `docs/audit/NAV_DUMP.md` (dated 2026-10-07) — exact sidebar structure and role-visibility rules for both admin and client shells.
- `docs/audit/ONBOARDING_GENERAL.md` (dated 2026-10-07) — full trace of the only client-onboarding UI (`OnboardingWizard`) and `/admin/settings`'s non-functional form.
- Direct reads of `frontend/src/app/**`, `frontend/src/config/nav.ts`, `frontend/src/components/layout/*`, and the marketing pages added after V2.

Status vocabulary used throughout, per the audit brief: **CLEAR** / **LIMITED** / **HIDDEN** / **MISSING** / **UNVERIFIED** (frontend-visibility axis — never substituted for backend-implementation status).

---

## 5.0 Headline finding: the public marketing site overstates what a visitor can self-serve

Three routes exist specifically to speak to VTEM-relevant stakeholders — `/cert-csirt` ("Oversight for your entire constituency"), `/regulators` ("Compliance oversight, not spreadsheets" — NCS-CRF, NDPA, NCC, CBN), and `/grc` (risk-based remediation, incident reporting, compliance monitoring) — plus `/platform`, `/solutions`, `/vms`, `/secops`, `/ti`, `/cnii`, `/integrations`, `/trust`, `/about`, `/contact` (`frontend/src/app/{cert-csirt,regulators,grc,platform,solutions,vms,secops,ti,cnii,integrations,trust,about,contact}/page.tsx`). Every one of these is a static, server-rendered marketing page (plain copy + `DetailItem`/`Link` components) with **no form, no sign-up, no "request access," no API-key issuance, and no login other than a generic `/contact` mailto-style link**. There is no self-service stakeholder portal entry point anywhere in the public site.

Two marketing claims that are checkable against the rest of the repo's own evidence are overstated:
- The homepage (`app/page.tsx:32`) and `/platform` (`app/platform/page.tsx:29`) both claim **"ngCERT, NCC-CSIRT and CBN advisory integration."** `NOVRSOC_REDESIGN_TECHNICAL_AUDIT_V2.md` §10.3 and `PRODUCTION_NOTES.md` item 8 both independently confirm: ngCERT returns HTTP 403 to the platform's egress and contributes nothing; no NCC-CSIRT or CBN feed is ingested as structured data; the Nigerian Threat Feed page shows **explicitly-labelled mock** advisory data. This is a live discoverability/honesty problem, not just a backend gap — a regulator or CERT reading the public site would reasonably expect a working integration that does not exist.
- The homepage claims "36+FCT States Monitored" with a live heatmap. The dashboard's Nigeria map (not the TI map) is confirmed fabricated/inflated by V2 §9 (F-04): IPs with no region are assigned to Lagos/FCT via a hardcoded ASN table, and counters are cumulative with no deduplication, re-incremented every hourly run.

**Where self-service onboarding actually lives:** `/admin/onboarding/new` (`OnboardingWizard`), which is `super_admin`-only, is not in any sidebar, and — per `ONBOARDING_GENERAL.md` §1.6 and §1.3 — creates `platform_users` rows that **cannot sign in** ("Users created here cannot sign in. The only login is the shared dev-admin bypass"). There is no provider self-registration flow anywhere in the codebase. **Requirement 15 (self-service stakeholder portal) frontend status: MISSING** — the only onboarding UI is an internal staff tool, and it cannot actually activate the accounts it creates.

---

## 5.1 Complete frontend route inventory

### 5.1.1 Admin app (`/admin/*`) — from V2 Appendix A, cross-checked, dates from 2026-10-25

All 137 routes from V2's generated inventory are still structurally current (no admin or client route files were touched by the three subsequent marketing commits — those commits only added top-level public routes and swapped the logo). Rather than reproduce the full 137-row table here verbatim, it is incorporated by reference: **see `NOVRSOC_REDESIGN_TECHNICAL_AUDIT_V2.md`, Appendix A**, for the authoritative per-route table (route, component, nav item, status, roles). The summary relevant to VTEM:

| Module (nav section) | Example routes | VTEM requirement(s) | Frontend status |
|---|---|---|---|
| Overview / Dashboard | `/admin/dashboard`, `/admin/dashboard/executive` | 7, 21, 23 | LIMITED — real data mixed with hardcoded/fabricated widgets (§5.3) |
| Security Operations | `/admin/secops/{cases,alerts,threats,mitre,playbooks,soar,security-assessment,management}` | 9, 10, 11, 19 | CLEAR for cases/alerts/SOAR; LIMITED for playbooks/vulnerabilities (not in nav) |
| Threat Intelligence (TI) | `/admin/ti/{indicators,map,matches,sources,vulnerabilities,actors,analyst}` | 4, 12, 13, 22 | CLEAR — consistent design-system pages, all `WORKING` per V2 |
| CNII Watch | `/admin/cnii`, `/admin/cnii/[sector]`, `/admin/cnii/authorisations` | 8, 23 | LIMITED — sector level is clear; no subsector drill-down UI exists (backend has only a flat `subfield` string) |
| Brand Protection | `/admin/brand/*` (7 pages) | not a numbered VTEM requirement directly, but shares infra with 16/27 | **Should be flagged to users as unsafe** — backend is not tenant-isolated (V2 F-01) and the frontend gives no indication of this |
| Infrastructure & Assets | `/admin/infra/{assets,cloud,topology,shadow}` | 1, 2 | LIMITED/HIDDEN — Cloud Assets is an explicitly-labelled placeholder; VMS's real asset model (`vms_assets`) is not reachable from this nav section at all (it is a separate "Wazuh Endpoints" view only) |
| VMS (23 pages, reached only via `config/vmsSections.ts`, not the main sidebar) | `/admin/vms/{assets,findings,scans,risk,remediation,authorisation,import,operations,report}` | 1, 2, 3, 6 | CLEAR within the VMS shell, but **the entire module is not in `AdminSidebar.tsx`** — see §5.2 |
| Compliance | `/admin/compliance/{ndpa,iso27001,cbn,pcidss,ncc}` | 5, 20 | LIMITED/BROKEN — two of five framework pages are `BROKEN` per V2 Appendix A (cbn, ncc); none of this is a GRC *platform integration*, only internal mapping tables |
| Settings | `/admin/settings/{team,audit,health,wazuh-groups,analytics,export-clients}` | 24–27 | CLEAR for super_admin; `/admin/settings` (general) has a Save button with **no handler at all** (`ONBOARDING_GENERAL.md` §2.2) |
| Customers / onboarding | `/admin/customers`, `/admin/customers/[id]`, `/admin/onboarding/new` | 15, 37, 44 | LIMITED — see §5.0 |
| AI | `/admin/novrail` | — | LIMITED — PARTIAL status per V2; legacy chat bypasses the grounded/logged AI path (F-19) |

**Pages reachable by no navigation or link anywhere (CONFIRMED dead frontend, V2 §4.5, re-verified):** `/admin/secops/hunting`, `/admin/secops/vulnerabilities`, `/admin/secops/alert-comms`, `/admin/brand/copyid`, `/admin/brand/mobile`, `/admin/email/monitoring`. A capability with code behind it but no discoverable entry point is, by the audit's own rule, **HIDDEN**, not CLEAR, no matter how complete the underlying page is.

### 5.1.2 Client portal (`/client/*`) — 25 pages, from `NAV_DUMP.md` §2 and V2 Appendix A

22 of 25 pages are in the client sidebar; all are visible to every portal role (no `roles` filtering exists client-side — `ClientSidebar.tsx`). Of the 22:
- **5 WORKING** (all VMS: `/client/vms`, `/client/vms/assets`, `/client/vms/findings`, `/client/vms/remediation`, `/client/vms/reports`) — though `ClientVms.tsx` makes one call to `/api/vms/report` which `requireAuth` always refuses for `portal_user` (it should call `/api/client/vms/report`); this single confirmed-broken call is folded into an otherwise-working page.
- **1 PARTIAL** (`/client/dashboard`).
- **16 BROKEN** — every API call the page makes is refused by `requireAuth`, because `portal_user` is confined to `/api/client/*` and these pages call admin-only or legacy-proxy endpoints: all 6 `/client/brand/*`, `/client/threat/{cti,advisory,urlscan,webscan}` (4), `/client/secops/{cases,alerts}` (2), `/client/infra/dns`, `/client/data/recovery`, plus `/client/secops/security-assessment` (PARTIAL/BROKEN split by role branch).
- **2 are stubs** with no backend call at all: `/client/billing`, `/client/settings` (both render `FeatureStub`).

None of the 16 broken items are hidden or hinted at being broken — `config/nav.ts` carries a `BROKEN` status flag on (currently) **18** client items, but **the sidebar renders them anyway**; the `status` metadata is not consulted by `Sidebar.tsx`'s filter logic (confirmed: `grep -c "status: 'BROKEN'" config/nav.ts` → 18; `Sidebar.tsx` filters only on `adminOnly`/`managerOnly`/`roles`). **This means a provider logging into the client portal today — the primary "Requirement 18: provider-restricted access" surface — sees a majority-broken product.** Of 22 visible items, 16 are dead. Frontend status for Requirement 18 (provider access to their own data): **LIMITED**, trending toward MISSING in practice for anything outside VMS.

### 5.1.3 Marketing / public site — new since V2 (not previously inventoried)

| Route | Purpose (from page content) | Functional backend behind it? |
|---|---|---|
| `/` | Landing page, feature claims, `HomepageScanner` (a free-scan widget) | `HomepageScanner` calls `/api/public/scan` (rate-limited, per V2 §3 F-03 context) — the one genuinely interactive piece |
| `/platform`, `/solutions`, `/vms`, `/secops`, `/ti`, `/cnii`, `/grc`, `/integrations`, `/trust` | Capabilities-dropdown pages describing each module | None — static copy only |
| `/regulators`, `/cert-csirt` | Describe the regulator/CSIRT oversight value proposition | None — static copy; no portal, no request-access form |
| `/about`, `/contact` | Company info, contact | `/contact` is a static page (no verified mail-send call traced in this pass) |
| `/login`, `/set-password`, `/status` | Admin auth, password set, status page | Functional (existing) |

All marketing pages are React Server Components with no client-side API calls other than the homepage scanner — confirmed by grep (`grep -rn "fetch\|apiFetch" app/{about,cert-csirt,cnii,contact,grc,integrations,platform,regulators,secops,solutions,ti,trust,vms}/page.tsx` returns nothing). **Frontend status for public-facing discoverability of the platform's real capabilities: LIMITED** — the marketing site talks about the product accurately in general terms but does not let a visitor see or demonstrate any of it, and in at least the two instances above states integrations as live that are not.

---

## 5.2 Feature discoverability — all 49 requirements

For each requirement: **where found**, **steps from login**, **terminology clarity**, **real vs. demo data**, **empty/freshness/actionability signal**, **demonstrable without code**. Full prose answers are given only where the answer is not CLEAR-and-obvious; otherwise a compact verdict row is used. "Steps" are counted from the relevant shell's landing page (`/admin/dashboard` or `/client/dashboard`).

| # | Requirement | Where | Steps | Terminology | Real data? | Empty-state honesty | Demonstrable today |
|---|---|---|---|---|---|---|---|
| 1 | Asset discovery/inventory, AFRINIC | `/admin/vms/discovery`, `/admin/vms/assets` (not in main sidebar — reached via VMS shell only) | 2 (if you know the VMS shell exists) | Clear within VMS; "Wazuh Endpoints" vs. "Digital Assets" vs. VMS assets names three different things for similar concepts (§5.4) | Real (`vms_assets`) | Mostly honest empty states (VMS kit `EmptyState`) | Partially — AFRINIC specifically has no dedicated UI; only RDAP/RIPEstat ASN data surfaces indirectly |
| 2 | Scanning coverage (network/web/API/cloud/container) | VMS shell: `/admin/vms/scans`, `/admin/vms/services` | 2 | Clear | Real for network/web; Cloud Assets is an explicit placeholder; **no container scanning UI exists anywhere** | Cloud Assets explicitly labelled "example data" — honest | Network/web: yes. Cloud/container: no — nothing to demonstrate |
| 3 | Scheduling, custom signatures | `/admin/vms/monitoring/schedules`, `/admin/vms/import` | 2–3 | Clear | Real | Yes | Yes, for schedules; custom Nuclei template UI not found in frontend inventory — **HIDDEN/MISSING** |
| 4 | CVE/NVD/CWE | `/admin/ti/vulnerabilities`, VMS finding detail | 2 | Clear | Real (`cve_intel`) | Yes | Yes |
| 5 | Misconfiguration/compliance (NIST/CIS/NDPA/CRF-NCS) | `/admin/compliance/*` | 2 | **Misleading**: pages are labelled by framework name but the backend explicitly states this is "not an assessment," just a deterministic vuln→clause mapping table (V2 §13.1) — the UI does not carry this caveat forward to the user | Real mapping, not a real control assessment | Two of five pages are BROKEN; no "this is not a compliance assessment" banner on screen | No — would show a misleading "compliance" framing if demonstrated live |
| 6 | Risk prioritisation (CVSS v3/v4, KEV, exploit, criticality) | `/admin/vms/risk` (not in sidebar) | 2–3 | Clear, but **CVSS v4 is not implemented** (formula uses CVSS only, no version distinction) and the formula/weights are not shown anywhere in the UI — no "why this score" breakdown on a finding | Real | Yes | CVSS v3/KEV: yes. CVSS v4 / business context: no |
| 7 | Continuous exposure monitoring, real-time KEV correlation | Dashboard KPIs, `/admin/vms/monitoring` | 1–2 | "Continuous" is accurate for the backend's 5-minute due-check, but the UI gives no indication of polling cadence vs. "real-time" | Real | Mixed — some KPIs render `0` on a 403 instead of "unavailable" (F-14, confirmed, see §5.3) | Yes, with the caveat that "real-time" is actually periodic |
| 8 | Sector heatmaps with drill-down | `/admin/cnii` → `/admin/cnii/[sector]` | 2 | Clear | Real at sector/org level | Risk shown as a **mean**, which understates concentrated risk (V2 §8.1) — this is a genuine explainability defect, not just a UI nit | Yes, sector→org; **no subsector level exists** |
| 9 | Automated remediation via Workflow Management API | `/admin/vms/remediation`, `/admin/secops/playbooks` | 2–3 | "Remediation" here is VMS task tracking, not a true external Workflow Management System integration | Real tasks | Yes | Internal remediation: yes. External WMS API: **MISSING**, nothing in frontend calls an external workflow system |
| 10 | Approval/SLA/reporting workflows | `/admin/secops/approvals`, `/admin/vms/authorisation` | 2 | Clear for VMS scope approval (P27); SLA is partly hardcoded on the settings page with no effect (ONBOARDING_GENERAL.md §2.1) | Real for approvals; fake for the Settings-page SLA fields | Settings page gives **zero** feedback that its Save button does nothing — actively misleading | Approvals: yes. "SLA breach" config: no, it is decorative |
| 11 | Open XDR (SIEM/NDR/TI/UEBA/auto-response) | spread across SecOps + TI pages; no single "XDR" view | 3+ | The platform does **not** present itself as XDR anywhere in its own UI — this is accurate; nothing oversells it internally (contrast with the public marketing site, §5.0) | Real per-module | — | The *modules* are demonstrable individually; there is no cross-source correlation view to demonstrate as "XDR" |
| 12 | Automated intel/IOC/vuln/incident distribution to stakeholders | Not found | — | — | — | — | **MISSING** — no distribution/notification-to-external-stakeholder UI exists; `/api/notifications` is in-platform only |
| 13 | Distribution workflow automation, ack tracking | Not found | — | — | — | — | **MISSING** |
| 14 | Anonymised provider benchmarking | Not found | — | — | — | — | **MISSING** — no benchmarking page or component anywhere in `frontend/src/app` or `components/` |
| 15 | Self-service stakeholder portal + API gateway | `/admin/onboarding/new` (staff-only) | N/A for a real stakeholder | Misleading marketing pages imply self-service exists | N/A | No "coming soon" / no honest state — the public site simply doesn't offer it | **MISSING** per §5.0 |
| 16 | Logical separation + RBAC | Implicit throughout (no dedicated screen) | — | Role names are inconsistent across admin/client (`executive` is a *client* role but visually similar to "Executive Report," an admin screen) | Real enforcement at API layer (see Security audit) but **the frontend gives no user-facing explanation of what their role can/can't see** | — | Can be demonstrated via 403s, not via any explanatory UI |
| 17 | NCC-CSIRT oversight role | Not found in `AdminSidebar.tsx` role constants (`super_admin`, `soc_manager`, `analyst`, `executive`, `portal_user` only — `NAV_DUMP.md` and V2 §2) | — | — | — | — | **MISSING** — no such role exists in the frontend's role model at all, despite the public `/cert-csirt` page addressing this exact audience |
| 18 | Provider-restricted access | `/client/*` | — | — | Real for VMS; broken for the rest | 16 of 22 visible client pages are dead (§5.1.2) | LIMITED in practice |
| 19 | MSSP managed operations (triage, response) | `/admin/secops/*` | 1–2 | Clear | Real | Yes | Yes |
| 20 | GRC platform integration | `/admin/compliance/*`, public `/grc` marketing page | — | Public page implies "connected directly to live findings" to an external GRC platform; the actual backend is an internal mapping table only (no outbound integration found anywhere in the route/API inventory) | Internal only | — | **MISSING** as an actual external integration; marketing page overstates it |
| 21 | Strategic intelligence/sector benchmarking dashboards | `/admin/dashboard/executive`, `/admin/cnii` | 1–2 | Clear | Real but role-gated oddly — Executive Report calls endpoints the `executive` role is itself refused (F-06, confirmed) | **Confirmed defect**: renders `0%`/empty instead of "unavailable" on 403 | **Not demonstrable to an executive account as-is** — it is one of the two intended audiences for the page and gets a broken view |
| 22 | Emerging threat intel + KEV | `/admin/ti`, `/admin/ti/vulnerabilities` | 1–2 | Clear | Real | Yes | Yes |
| 23 | CCI mapping + executive reporting | `/admin/cnii`, `/admin/dashboard/executive` | 2 | Clear for CNII; executive reporting shares requirement 21's defect | Real | Shared with #21 | Shared with #21 |
| 24 | MFA | Not found in `/login` or `/admin/settings` | — | — | — | — | **MISSING** — no MFA UI anywhere in the login or settings flow; login is a single email/password `AuthField` plus a dev-bypass |
| 25 | Audit trails | `/admin/settings/audit` | 1 | Clear | Real (`audit_log` table, with an in-memory fallback per V2 §16) | PARTIAL per V2 Appendix A | Yes, with the in-memory-fallback caveat not shown on screen |
| 26 | SSO (SAML/OAuth, NCC IdM) | `/login` (Google OAuth button referenced in `PRODUCTION_NOTES.md`) | — | Google OAuth exists but is reported **non-functional in production** (502 via a downstream host) per `PRODUCTION_NOTES.md` item 1; no SAML anywhere | — | The login page gives no indication that OAuth is down — a user just gets a failed request | **NOT READY** — cannot be demonstrated reliably; no NCC-specific identity integration exists |
| 27 | Strict data separation | No dedicated screen | — | — | — | — | Verified only via API behaviour, not via any UI — see Database/Tenancy audit |
| 28 | Cloud-native SaaS, 99.9% uptime | `/status` page exists | 1 | `/status` renders `NovrSOCLogo` only per V2 Appendix A — effectively a placeholder, not a real status/uptime page | — | No uptime, incident history, or SLA data shown | **MISSING** as a real status page |
| 29 | Scale to 100+ entities, thousands of assets | No UI exposes scale/load metrics | — | — | — | — | Cannot be demonstrated from the UI; see Testing audit for any load evidence |
| 30 | Open APIs for CTI/SIEM integration | No API docs page/portal found in frontend | — | — | — | — | **HIDDEN** — APIs exist (389 routes per V2) but there is no developer-facing API documentation surface in the product itself |
| 31 | Workflow management APIs | Same as #9/#30 | — | — | — | — | **MISSING/HIDDEN** |
| 32–49 | Deliverables (inception report, go-live, pilot onboarding, API docs, reports, pen test, etc.) | N/A — these are documents/process deliverables, not frontend features | — | — | — | — | Not a frontend-discoverability question; see Gap/Implementation plan and Evidence Index |

---

## 5.3 Explainability audit

Per the brief's checklist, each item below is a confirmed defect (file:line cited) unless marked "sound."

| Question | Finding |
|---|---|
| Why was an asset discovered? | **Sound** — VMS asset detail shows `discovery_sources`, `confidence` (V2 §6.1); provenance is visible. |
| How is an asset associated with a provider? | **Sound for VMS/org scoping**; **unsound for CNII legacy** — `cnii_assets.ip` is globally unique with free-text `org`, no verifiable link (V2 §6.1, §8.1). |
| Why was a vulnerability identified / evidence source? | **Sound** — VMS findings carry `evidence_class`, tool provenance. |
| How is severity/risk calculated? | **Not explained in the UI.** The formula (`0.45·technical + 0.30·exploitation + 0.15·exposure + 0.10·criticality`, V2 §7.1) exists only in backend source; no finding-detail page shows a factor breakdown, weights, or policy version. A user sees a number with no "why." |
| Why is an asset "exposed"? | Partially sound — `exposure` field drives scoring, but its three-value model (internet/unknown/internal) is not surfaced as a definition anywhere in the UI. |
| Why does a TI match matter? | **Sound** — TI pages show TLP badges, source attribution (`features/ti/common.tsx TlpBadge`). |
| Is an IOC confirmed or suspected? | Partially sound within TI; **not surfaced at all** on the dashboard's "Threat Intelligence" widget, which reads a volatile in-memory store with no provenance shown (F-22). |
| What remediation is recommended, and by whom? | Recommended: yes, via AI `remediation_plan` purpose. Responsibility: **weak** — `assigned_to` on cases is free text, not a verified user reference (V2 §11, F-23), so "who is responsible" can be an unverifiable string. |
| Has a finding been verified? | **Sound** — VMS has a dedicated verification-rescan workflow and status. |
| How are sector statistics calculated? | **Partially unsound** — CNII's `infrastructure_risk` is presented as a single mean with no UI explanation that it is a mean, and no caveat that a mean hides concentrated risk (V2 §8.1 flags this explicitly as a reporting defect, not just a backend one). |
| How are benchmark metrics anonymised? | **N/A — there is no benchmarking UI to explain** (requirement 14 is MISSING). |
| Is AI output advisory or verified? | **Mostly sound** for the grounded `services/ai.ts` path (artifacts are explicit drafts, accept/reject UI). **Unsound for the legacy NovrAI chat** (`/admin/novrail`), which is unlogged, ungoverned, and gives no "this is unverified" framing distinct from the grounded path (F-19, confirmed). A user cannot tell from the UI which AI surface they are using. |

**General pattern confirmed across the dashboard** (`GeneralDashboard.tsx`, V2 §5 full widget table): multiple KPIs render `0`, `0%`, or an empty value on an authorization failure (403) rather than an "unavailable to your role" message — this is the single most common explainability defect, appearing in at least 4 of 19 dashboard widgets (Open Cases, Clients Protected, Platform Health, Compliance) and in the Executive Report.

---

## 5.4 Role-specific user journeys

### Platform administrator
- Organisation management: `/admin/customers` → `/admin/customers/[id]` works; **but `/admin/settings/organisations` lists `MOCK_ORGS`, not real data**, and its "Setup" link opens a wizard pre-filled from mock ids (`org_001`), writing to `org_setup` rows keyed to ids that don't exist in `organisations` (`ONBOARDING_GENERAL.md` §3). **Broken step**: an admin trying to "set up" an existing real organisation through the obvious UI path is silently writing orphaned data.
- Role management: no dedicated role-management screen exists; roles are fixed in code (`CLIENT_ROLES`, staff roles), not configurable from any UI.
- Integration configuration: Wazuh group mapping (`/admin/settings/wazuh-groups`) works. No UI exists to configure Nmap/Nuclei/OpenVAS/MISP connection parameters — these are environment variables only (confirmed: no settings page references `MISP_*`, `VMS_OPENVAS_ENABLED`, etc.).
- Worker monitoring: `/admin/vms/operations/workers` exists (VMS shell) — CLEAR.
- Platform health: `/admin/settings/health` works for `super_admin`/`soc_manager`; **broken for every other role** that the dashboard tries to show it to (F-06).
- Audit trails: `/admin/settings/audit` works, PARTIAL per V2.

**Overall:** core administrative journey is usable for the pieces that have a UI, but two of the first screens an admin reaches for (org setup, settings) are confirmed non-functional or mock-backed.

### SOC analyst
- Alert review (`/admin/secops/alerts`) → investigation (`/admin/secops/cases`) → intelligence enrichment (`/admin/ti/indicators`) → case creation/closure: **this chain works end to end** and is one of the platform's most mature journeys (V2 marks Cases, Alerts, Threats, SOAR, Response Approvals all WORKING).
- Response recommendations: AI purposes exist (`alert_summary`, `case_summary`); the entry point is `/admin/novrail`, which is **not directly linked from the case workbench** — an analyst has to know to switch pages rather than being offered an inline "ask AI about this case" action. **LIMITED discoverability, not missing capability.**
- Gap: assignment is to a free-text name with no skills/workload visibility (no UI exists for analyst profiles at all — the backend capability for this is itself MISSING per V2 F-23).

### Vulnerability analyst
- Discovery → scan initiation → findings → risk analysis → remediation assignment → verification → reporting: **this chain exists and works**, but entirely **outside the main sidebar** — the whole 23-page VMS module is reached only through `config/vmsSections.ts`'s own shell, not `AdminSidebar.tsx`. A new analyst who only explores the left sidebar will never find it; they would need to already know the `/admin/vms` URL or be told about it. This is the platform's single largest "HIDDEN" surface by page count.
- Reporting: `/admin/vms/report` produces a real JSON-backed report; PDF export is raster-only (`html2canvas` screenshots), with no selectable text or pagination control (V2 §7.4) — usable for a quick export, not for a polished deliverable.

### Provider / client
- Onboarding: the client never onboards themselves — an admin runs `OnboardingWizard`, and per `ONBOARDING_GENERAL.md` §1.3, the created `platform_users` **cannot sign in** (no invite/welcome email is sent — `organisations.ts` has a literal TODO at that line). **This journey is broken at its final, most important step.**
- Asset inventory / exposure / vulnerability review / remediation / reports: the 5 `/client/vms/*` pages work and are the one genuinely usable part of the client journey.
- Everything else (brand, threat intel, DNS, data recovery, alerts, cases): **BROKEN**, as detailed in §5.1.2, and still rendered in the sidebar as if available.

### Sector oversight stakeholder (NCC-CSIRT or equivalent)
- **No journey exists.** There is no role, no login path, and no dashboard scoped for this audience anywhere in the frontend's role model (`super_admin`, `soc_manager`, `analyst`, `executive`, `portal_user` — confirmed exhaustive list, V2 §2 and `NAV_DUMP.md`). The only artifact addressing this audience is the public, non-functional `/cert-csirt` marketing page.

---

## 5.5 Visual and interaction quality

- **Two competing design systems coexist** (V2 §4.5, §15): a token-based, accessible "VMS kit" (`components/features/vms/{kit,ui,table,charts}`) already reused by TI and CNII (26 feature files import it), versus a legacy `components/shared/*` set with hardcoded colours (`bg-white`, `text-grey-*`) used by the dashboard, Header, RightRail, Brand suites, and Settings pages. This produces a visibly inconsistent product: VMS/TI/CNII look and behave like one coherent enterprise tool; the dashboard, header, and older modules look like an earlier generation of the same product, including failure to respect dark mode (hardcoded colours don't follow the `.dark` class).
- **Static/fake status indicators** on every page via the global header: a "Telemetry Online" pill and a "Cloud Node" green dot are hardcoded `true`, never reflecting actual Wazuh/indexer/backend health (F-13, confirmed) — this is a direct violation of an honest-status principle and the single most visible "fake success" surface in the product, present on literally every admin page.
- **Navigation consistency:** the admin sidebar is a flat, 13-section, ~74-item list with no search/filter of its own (global search exists but is a separate header feature); several real modules (VMS, most of its 23 pages) are entirely absent from this sidebar, while several dead pages (compliance CBN/NCC, 16 client pages) remain visible. Discoverability and reality are inversely related in places: the most complete module (VMS) is the hardest to find; some of the least functional areas (client Brand/Threat suites) are the most prominent.
- **Mobile/responsiveness, accessibility, forms, confirmation dialogs:** not independently re-verified in this pass beyond what V2 already documents (VMS kit components are reduced-motion aware and include confirm dialogs/error-with-retry states; legacy `shared/*` components do not have the same guarantees). Treat anything not explicitly cited above as **UNVERIFIED** rather than assumed clear.
- **Chart/table readability:** VMS/TI/CNII tables and charts use the shared kit consistently (export-to-CSV, drawers, EvidenceViewer) and read as professional. The dashboard's MITRE ATT&CK widget shows only 8 of 14 Enterprise tactics (hardcoded list, V2 §5 row 12), which will visibly under-represent detections to anyone who knows the framework.

**Recommendation (not a redesign, an assessment):** any redesign should treat the VMS/TI/CNII kit as the target design language (it is already proven across three modules) and treat the dashboard/header/legacy-shared layer as the thing to be rebuilt onto it — not the reverse. See `VTEM_FRONTEND_REDESIGN_BLUEPRINT.md`.

---

## 5.6 Summary scorecard (frontend-visibility axis only)

| Status | Count of 49 requirements (approx., frontend axis) |
|---|---|
| CLEAR | 9 (#2 partial-network, #4, #11-as-modules, #19, #22, #25, and similar well-surfaced single-module items) |
| LIMITED | 16 (#1, #3, #5, #6, #7, #8, #9, #10, #16, #18, #21, #23, #26, #28, #29 inferred, plus marketing/claims gaps) |
| HIDDEN | 4 (#3-custom-signatures, #17-NCC-role as a *capability gap not a UI gap but presented as if addressed publicly*, #30, #31) |
| MISSING | 12 (#12, #13, #14, #15, #20, #24, #27-as-a-visible-control, and the deliverable-type items #32–49 which are not frontend questions at all) |
| N/A / not a frontend question | 8 (#32–39, #46–49 — deliverables) |

These counts are a frontend-visibility cross-cut only; they must not be read as, or merged with, the backend-implementation status counts in `VTEM_49_REQUIREMENT_MATRIX.md`, which is the authoritative, single source of truth for the final per-requirement rollup.
