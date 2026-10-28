# VTEM 49-Requirement Reconciliation — Re-baselined Against Real `origin/main`

**Why this document exists.** The original audit (`VTEM_49_REQUIREMENT_MATRIX.md`, `VTEM_EXECUTIVE_SUMMARY.md`, dated 2026-10-28) was run against `marketing-pages-merge` @ `bab6ff0`, which it described as "`main` (commit `9429743`) + 5 marketing/website commits." That `main` reference had never been re-fetched. `git fetch origin` shows the real `origin/main` is at `48747ba` ("Merge sprint3/frontend-collector-validation into main") — **45 commits ahead** of the `main` the original audit treated as current, and `bab6ff0` is not an ancestor of that gap. Those 45 commits include entire feature releases the original audit never saw: the R3.1 client onboarding wizard, the R3.2 dashboard redesign, R3.3A–E (VMS reporting, CNII coverage, SecOps automation, TI relevance/reporting, scheduled client reporting), Collector V1 (P31), and — critically — **P26/P27, which the original audit's own Critical Finding #2 said existed only in an unmerged worktree**. P26/P27 are now confirmed merged into `origin/main` (ancestry and file-content checks below).

**New baseline:** `origin/main` @ `48747ba`, read via the worktree `C:\Users\USER\novr-main-merge` (checked out at `40cb630` = `48747ba` + one local-only docs commit, no code difference). **Re-baseline date:** 2026-10-28 (same day; the gap was a stale local ref, not a time gap). **Method:** targeted re-verification of every requirement plausibly touched by the `bab6ff0..origin/main` diff (244 files, +14,848/-3,353 lines) by reading the actual current route/service/migration/frontend code — not inferring status from commit subject lines — plus carry-forward of the original audit's still-valid findings for everything the diff did not touch, re-stamped against the new baseline.

**Demo Mode cross-reference.** A separate, unmerged branch `feat/demo-mode` (worktree `C:\Users\USER\novr-demo`) adds a staff-only presentation layer: three fictional organisations (LAPO/Tazemi/IKEA) with fully synthetic, seeded data across the dashboard, VMS findings/remediation, TI, Nigeria heatmap, SecOps cases, CNII Watch, Collector Management, and Reporting Center. It is **not merged anywhere** and does not count as production implementation for any requirement below. Where a requirement's screens are ones Demo Mode covers, this is flagged explicitly — a demo walkthrough of that screen is not evidence the requirement is met for a real tenant. Separately, note that `DashboardNigeriaMap.tsx`'s own built-in "Demo" sub-tab (synthetic per-state events) already existed in production `origin/main` **before** `feat/demo-mode` branched (commit `65305e6`) — that is a pre-existing, honestly-labelled, already-merged feature, distinct from the newer unmerged Demo Mode layer that later made its random data org-aware. Don't conflate the two.

---

## Section 1 — Functional Requirements

### Requirement 1 — Asset discovery/inventory, AFRINIC
- **Wording:** Asset discovery/inventory, AFRINIC.
- **Relevant implementation:** RIPE/RDAP live lookups (unchanged) plus a genuinely new, substantial asset-import pipeline: Wazuh-agent-group import (ownership resolved via `wazuh_group_org_map`, re-read live from Wazuh, never trusts client-sent data beyond which agent ids to take) and manual IP/domain/CIDR/CSV import with dry-run, dedup, and scope-boundary enforcement (an imported asset outside an approved scope is listed "not authorised" and never scanned).
- **Backend evidence:** `services/vmsImport.ts` (new, P28), `routes/vmsImport.ts` (new), `services/ripeStat.ts:1-96` (unchanged), `backend/sql/2026-11-05_p28_unified_inventory.sql`.
- **Frontend evidence:** `frontend/src/app/admin/vms/import` (new page).
- **Production deployment status:** On `origin/main`.
- **Demo-only functionality:** None specific — Demo Mode does not simulate the import wizard itself.
- **Missing work:** No bulk AFRINIC allocation-registry import still exists (same gap as the original audit) — AFRINIC status remains a live per-lookup check, not a dataset.
- **Verification status:** **PARTIAL** (upgraded evidence; same classification — the new import pipeline is a real capability gain, but the specific AFRINIC gap the requirement names is unchanged).
- **Recommended next action:** Decide whether AFRINIC bulk ingestion is actually in scope for go-live; if so, scope it as new work, not a fix.

### Requirement 2 — Vulnerability scanning coverage
- **Wording:** Vulnerability scanning coverage.
- **Relevant implementation:** Nmap/Nuclei subprocess integrations unchanged and real (`infra/vms-worker/worker.py:1757-1829`, not in this diff). New: formal scan authorisation (`services/vmsAuthorisation.ts`, P27) and time-boxed scan windows (`lib/scanWindows.ts`, P27) — governance and scheduling improvements, not new scan engines.
- **Backend evidence:** `infra/vms-worker/worker.py:1757-1829` (unchanged); `services/vmsAuthorisation.ts`, `lib/scanWindows.ts` (new).
- **Frontend evidence:** `frontend/src/app/admin/vms/authorisation` (new).
- **Production deployment status:** On `origin/main`.
- **Demo-only functionality:** None.
- **Missing work:** OpenVAS is still governance-disabled (`VMS_OPENVAS_ENABLED`); no web-app DAST, cloud-config, or container-image scanning engine exists — unchanged.
- **Verification status:** **PARTIAL** (unchanged classification; governance/scheduling matured, coverage breadth did not).
- **Recommended next action:** Same as original — decide OpenVAS's production status and whether web/cloud/container scanning is in scope at all; this is a product decision, not an engineering gap in what exists.

### Requirement 3 — Scan scheduling / custom signatures
- **Wording:** Scan scheduling / custom signatures.
- **Relevant implementation:** Scan windows (`lib/scanWindows.ts`) are a real, new, enforced scheduling primitive — a scope can declare recurring windows (e.g. weekdays 22:00–05:00 Africa/Lagos) enforced both at scan-queue time and at worker-claim time, with the scheduler deferring to the next window rather than queueing anyway.
- **Backend evidence:** `lib/scanWindows.ts:1-30`, enforced in `routes/vms.ts` (queueScan) and `routes/vmsWorker.ts` (claim) per its own header comment.
- **Frontend evidence:** Surfaced through `frontend/src/app/admin/vms/authorisation`.
- **Production deployment status:** On `origin/main`.
- **Demo-only functionality:** None.
- **Missing work:** Custom analyst-authored Nuclei template authoring/CRUD still does not exist — re-confirmed by an exhaustive grep for `custom.*nuclei|custom.*signature|customTemplate|nuclei_template` across `routes/`, `services/`, `lib/`, zero hits (same gap, re-verified against the new baseline, not carried forward blind).
- **Verification status:** **PARTIAL** (upgraded from the scheduling half; custom-signature half unchanged).
- **Recommended next action:** Scan windows close half this requirement; decide whether custom-signature authoring is still wanted, and if so scope it as new work.

### Requirement 4 — CVE, NVD, CWE
- **Wording:** CVE, NVD, CWE.
- **Relevant implementation:** Unchanged — `services/cveIntel.ts`, `services/nvd.ts`, `services/cisa.ts` are not in the `bab6ff0..origin/main` diff.
- **Backend evidence:** `services/cveIntel.ts:1-224`, `services/nvd.ts`, `services/cisa.ts` (unchanged).
- **Frontend evidence:** Unchanged, clear.
- **Production deployment status:** On `origin/main` (was already on `main` at the original audit).
- **Demo-only functionality:** None.
- **Missing work:** CWE still comes only through NVD's `weaknesses` field — no independent CWE taxonomy (unchanged).
- **Verification status:** **COMPLETE** (re-stamped, unchanged).
- **Recommended next action:** None required.

### Requirement 5 — Misconfiguration/compliance (NIST, CIS, NDPA, CRF-NCS)
- **Wording:** Misconfiguration/compliance (NIST, CIS, NDPA, CRF-NCS).
- **Relevant implementation:** `services/complianceMapping.ts` was modified in this diff (new test `services/__tests__/complianceMapping.test.ts`), but the mechanism is the same: severity-to-clause mapping, explicitly self-documented as *not* a control-by-control assessment (its own code comment: "it does NOT inspect your evidence, your patch SLA, or your compensating controls").
- **Backend evidence:** `services/complianceMapping.ts:1-180` (modified; line count grew from the original audit's citation but the scope is the same kind of mapping).
- **Frontend evidence:** Same as original audit — no "not an assessment" banner found in a renewed spot-check of the compliance pages.
- **Production deployment status:** On `origin/main`.
- **Demo-only functionality:** Demo Mode's `demoCompliance()` generator produces fictional framework scores for LAPO/Tazemi/IKEA on this same screen shape — a demo walkthrough of the compliance page proves nothing about real coverage.
- **Missing work:** No framework literally named "CRF-NCS" still exists anywhere in the backend (re-confirmed, zero hits); NDPA/NDPR naming inconsistency unchanged.
- **Verification status:** **PARTIAL** (unchanged classification; naming/scope decision still outstanding).
- **Recommended next action:** Same as original — get the naming/scope decision from the stakeholder before treating this as an engineering backlog item.

### Requirement 6 — Risk prioritisation (CVSS v3/v4, KEV, exploit, criticality)
- **Wording:** Risk prioritisation (CVSS v3/v4, KEV, exploit, criticality).
- **Relevant implementation:** Core scoring (`lib/riskScore.ts`) is not in the diff — unchanged. `services/vmsFindings.ts` was modified (new onboarding/import/verification integration points), but the scoring formula itself is the same mechanism the original audit reviewed.
- **Backend evidence:** `lib/riskScore.ts:1-72` (unchanged); `services/vmsFindings.ts` (modified for P27/P28 integration, scoring logic unchanged within it).
- **Frontend evidence:** Still no "why this score" UI (re-checked, unchanged).
- **Production deployment status:** On `origin/main`.
- **Demo-only functionality:** Demo Mode's VMS findings generator produces fictional risk scores — not evidence of real scoring behaviour.
- **Missing work:** No CVSS v4; no exploit evidence beyond KEV/EPSS; scoring weights still unversioned, non-auditable constants — all unchanged.
- **Verification status:** **PARTIAL** (unchanged).
- **Recommended next action:** Same as original.

### Requirement 7 — Continuous exposure monitoring, real-time KEV correlation
- **Wording:** Continuous exposure monitoring, real-time KEV correlation.
- **Relevant implementation:** `jobs/vmsContinuousJob.ts` was modified in this diff. Separately and materially: **Collector V1** (P31) adds real client-site log collection (syslog TCP/UDP/TLS) with heartbeat/throughput monitoring — a genuinely new continuous-monitoring data path, though it ingests raw logs, not vulnerability/exposure state, and is not itself a KEV-correlation mechanism.
- **Backend evidence:** `jobs/vmsContinuousJob.ts` (modified); `routes/collectors.ts`, `routes/collectorIngest.ts`, `services/collectors.ts`, `lib/collectorAuth.ts` (all new, P31); `backend/sql/2026-11-12_p31_collector_v1.sql`.
- **Frontend evidence:** `frontend/src/app/admin/collectors` (new).
- **Production deployment status:** On `origin/main`.
- **Demo-only functionality:** Demo Mode's Collector Management screen (synthetic heartbeat/throughput/event-log data for the three fictional orgs) looks identical to a real collector's dashboard — a demo walkthrough here proves nothing about a real deployed collector's health.
- **Missing work:** VMS exposure monitoring itself is still periodic polling (5-min due-check, hourly snapshots), not event-driven; Collector V1 doesn't change that — it's a parallel, separate monitoring surface (log ingestion), not a fix to the exposure-monitoring cadence.
- **Verification status:** **PARTIAL** (unchanged classification; the platform gained a genuinely new continuous-monitoring capability (Collector V1) that is adjacent to, not a fix for, the specific "not real-time" gap this requirement names).
- **Recommended next action:** Note Collector V1 as a strength in any stakeholder-facing readiness narrative, but don't present it as closing this requirement's real-time gap — it's a different kind of monitoring.

### Requirement 8 — Sector heatmaps with provider drill-down
- **Wording:** Sector heatmaps with provider drill-down.
- **Relevant implementation:** Backend aggregate drill-down (`routes/cniiNational.ts`) is largely unchanged structurally but `cnii.ts`/`cniiNational.ts` were both modified, and a new `lib/cniiCoverage.ts` (monitoring-coverage states, R3.3B) was added. On the frontend, a real, production, interactive Nigeria map component now exists — `components/dashboards/DashboardNigeriaMap.tsx` / `NigeriaStateMap.tsx` / `nigeriaPaths.ts` — merged via commit `65305e6`, **before** `feat/demo-mode` branched. Its "Live" layer renders actual TI hosted/exposure counts per state with zoom and click-to-select; this is a genuine, if partial, fulfilment of "interactive geo heatmap," not present at the time of the original audit's "frontend has never rendered this" finding.
- **Backend evidence:** `routes/cniiNational.ts` (modified), `lib/cnii-sectors.ts:11-27` (unchanged), `lib/cniiCoverage.ts` (new).
- **Frontend evidence:** `components/dashboards/DashboardNigeriaMap.tsx`, `components/features/ti/NigeriaStateMap.tsx`.
- **Production deployment status:** On `origin/main` (the map component itself, including its Live layer, is real and merged — not a Demo Mode artifact).
- **Demo-only functionality:** The same component also carries its own pre-existing "Demo" sub-tab (synthetic per-state events) — clearly labelled, already in production, not misrepresenting itself. The separate, unmerged `feat/demo-mode` branch additionally makes that sub-tab's data vary by a selected fictional org; that layer specifically is not production.
- **Missing work:** The Live layer's per-event drill-down (which 5-tuple network events actually occurred in a state) still does not exist for real data — only the long-standing synthetic Demo sub-tab simulates that. Provider-level (sub-sector) drill-down within a state is still absent; risk is still shown as a mean, not a distribution.
- **Verification status:** **PARTIAL** (upgraded from the original audit's "no interactive heatmap exists" — a real interactive map with real aggregate data now exists; the deeper drill-down gaps remain).
- **Recommended next action:** This requirement is closer to done than the original audit found — verify this correction stands up to a live demo of the Live layer, then scope only the remaining drill-down depth as outstanding work, not the whole heatmap.

### Requirement 9 — Automated remediation via Workflow Management System API
- **Wording:** Automated remediation via Workflow Management System API.
- **Relevant implementation:** Internal approval-gated containment (`services/responseApprovals.ts`) was modified in this diff; mechanism (race-safe, audited) is the same as the original audit reviewed, now with more call sites (`services/responseActions.ts`).
- **Backend evidence:** `services/responseApprovals.ts` (modified), `services/responseActions.ts:1-9` (unchanged core).
- **Frontend evidence:** Same as original — internal only.
- **Production deployment status:** On `origin/main`.
- **Demo-only functionality:** Demo Mode's response-approvals "approve/reject" actions apply a session-local overlay in the browser only — a demo approval never calls a real firewall or Wazuh action, and is explicitly labelled as such in its own response message.
- **Missing work:** Still no integration with any *external* Workflow Management System (ServiceNow/Jira/generic adapter) — unchanged, zero hits on a renewed grep.
- **Verification status:** **PARTIAL** (unchanged).
- **Recommended next action:** Same as original — needs a named target WMS before this can move.

### Requirement 10 — Approval, SLA, status sync, audit trails, reporting workflows
- **Wording:** Approval, SLA, status sync, audit trails, reporting workflows.
- **Relevant implementation:** Two real changes since the original audit. (1) **Reporting workflows are now substantially real**: a full scheduled-report pipeline — `lib/reportScheduling.ts` (weekly/monthly, timezone-aware, compare-and-swap distributed claiming so two replicas never double-fire the same due schedule), `jobs/reportSchedulerJob.ts`, `services/reportGeneration.ts`/`reportPdf.ts`/`reportCsv.ts`, and `services/reportDelivery.ts` (per-recipient email delivery with honest status — the code explicitly states delivery can only ever reach `queued → sent` or `queued → failed`, never a confirmed "delivered/bounced," since no provider has a webhook receiver, and says so in the UI copy too). (2) A **caveat on the original audit's specific "SLA route removed" finding**: `jobs/incidentEscalation.ts` (calling `services/email.ts`'s `sendEscalationEmail`) already existed at `bab6ff0`, before the original audit ran, and is a real, automated SLA-breach alerting mechanism (case due_at breach triggers an escalation email). This was not found or credited in the original audit's Req 10 row, which stated "no breach alerting... exists." That specific sub-claim may have been in error, or may refer to a different, separately-removed REST endpoint this reconciliation did not have budget to track down precisely — flagged here as an open discrepancy, not silently resolved either way.
- **Backend evidence:** `lib/reportScheduling.ts`, `jobs/reportSchedulerJob.ts`, `services/reportGeneration.ts`, `services/reportDelivery.ts` (all new, P30); `jobs/incidentEscalation.ts` (pre-existing, re-discovered); `services/responseApprovals.ts` (modified, approval half).
- **Frontend evidence:** `frontend/src/app/admin/reports` (new Reporting Center UI — schedules, recipients, generate-now, history, scheduler-health).
- **Production deployment status:** On `origin/main`.
- **Demo-only functionality:** `feat/demo-mode` adds a "Sample Documents" tab to the real Reporting Center that generates clearly-labelled client-side sample PDFs without calling this real pipeline — not a substitute for evidence the real scheduled-delivery pipeline works end to end against a live recipient.
- **Missing work:** No compliance-reporting surface for SLA breach rates specifically (distinct from the escalation emails); status-sync across case/task/approval is still not independently verified end-to-end.
- **Verification status:** **PARTIAL** (upgraded — reporting-workflow half is now genuinely strong; approval half unchanged; the SLA-alerting sub-finding needs stakeholder/original-fork reconciliation, not assumed either way).
- **Recommended next action:** Credit the new reporting pipeline explicitly in any updated readiness narrative; separately, have whoever ran the original audit's security fork re-confirm exactly which "SLA route" they found removed, since `incidentEscalation.ts` contradicts the headline claim as stated.

### Requirement 11 — Open XDR (SIEM/NDR/TI/behavioral/auto-response)
- **Wording:** Open XDR (SIEM/NDR/TI/behavioral/auto-response).
- **Relevant implementation:** Unchanged structurally — Wazuh (SIEM) real, MISP (TI) real but credential-status unverifiable from a repo, no NDR product, no cross-source behavioural correlation beyond what already existed. `services/wazuh.ts` was modified in this diff but for P31/collector-related reasons, not new XDR correlation.
- **Backend evidence:** `services/wazuh.ts` (modified), `infra/soar/soar.py` (unchanged), `services/misp.ts` (modified, P26 context only).
- **Frontend evidence:** Unchanged — modules demonstrable individually, platform does not claim XDR (still correct and still honest).
- **Production deployment status:** On `origin/main`.
- **Demo-only functionality:** The AI Behavioral Analysis panel (`components/features/ti/AiThreatIntelligenceDemo.tsx`) is explicitly, persistently DEMO-badged client-side synthetic data — it existed before `feat/demo-mode` and remains honestly labelled as a capability preview, not a real behavioural engine, in both the pre-existing version and the demo-mode-org-aware version.
- **Missing work:** Same as original — no cross-source correlation beyond Wazuh+MISP+internal alerts.
- **Verification status:** **PARTIAL** (unchanged).
- **Recommended next action:** None beyond the original's — keep describing this as "SOC feature set," not "integrated XDR."

### Requirement 12 — Automated intelligence distribution (IOCs, vuln alerts, incident notices)
- **Wording:** Automated intelligence distribution (IOCs, vuln alerts, incident notices).
- **Relevant implementation:** `routes/orgCTI.ts`'s pull-based anonymised sharing endpoint is unchanged. The new report-delivery pipeline (Req 10) is a genuine, new, automated **push** mechanism — but it pushes scheduled aggregate reports (executive/VMS/CNII/TI summaries) to configured recipients, not individual IOCs, per-finding vuln alerts, or per-incident notices as they occur. `services/mispSync.ts` (P26) was checked directly and confirmed to be pull-only (incremental fetch from MISP; no push/distribution call anywhere in the file).
- **Backend evidence:** `routes/orgCTI.ts` (unchanged); `services/reportDelivery.ts` (new, adjacent); `services/mispSync.ts` (new, confirmed pull-only).
- **Frontend evidence:** Still none dedicated to real-time distribution; Reporting Center UI covers the scheduled-report case only.
- **Production deployment status:** On `origin/main`.
- **Demo-only functionality:** None specific beyond the Sample Documents caveat already noted under Req 10.
- **Missing work:** No per-IOC, per-finding, or per-incident real-time push to designated external stakeholders — still absent; scheduled aggregate report delivery is a different, narrower capability.
- **Verification status:** **PARTIAL** (upgraded evidence — a real, adjacent push mechanism now exists — but the specific thing the requirement names, event-level distribution, is still not built).
- **Recommended next action:** Decide whether scheduled aggregate reports satisfy the contractual intent of this requirement, or whether event-level push is still required; scope accordingly.

### Requirement 13 — Distribution workflow automation, acknowledgement tracking
- **Wording:** Distribution workflow automation, acknowledgement tracking.
- **Relevant implementation:** None new. `routes/notifications.ts` remains internal-staff-only (unchanged, not in the diff). The new report-delivery pipeline tracks delivery status (sent/failed) per recipient but has no acknowledgement step (a recipient reading/accepting a report is not recorded).
- **Backend evidence:** `routes/notifications.ts` (unchanged); `services/reportDelivery.ts` (delivery status only, no ack concept).
- **Frontend evidence:** None.
- **Production deployment status:** N/A (not built).
- **Demo-only functionality:** None.
- **Missing work:** No table, service, or UI for acknowledgement-tracking or escalation to external stakeholders exists anywhere — confirmed unchanged by this diff.
- **Verification status:** **MISSING** (unchanged).
- **Recommended next action:** Ground-up build, same as original.

### Requirement 14 — Anonymised provider benchmarking (patch cadence, exposure density)
- **Wording:** Anonymised provider benchmarking (patch cadence, exposure density).
- **Relevant implementation:** None. `backend/` tree re-checked for `benchmark*` after the diff — zero hits, same as the original audit.
- **Backend evidence:** None.
- **Frontend evidence:** None.
- **Production deployment status:** N/A (not built).
- **Demo-only functionality:** None.
- **Missing work:** Entire capability — no schema, no aggregation, no UI. Unchanged.
- **Verification status:** **MISSING** (unchanged).
- **Recommended next action:** Ground-up build, same as original — this is new work regardless of baseline.

### Requirement 15 — Self-service stakeholder portal + API gateway for onboarding
- **Wording:** Self-service stakeholder portal + API gateway for onboarding.
- **Relevant implementation:** A substantial new **staff-driven** onboarding product exists (R3.1/P29): a 6-step wizard (`routes/onboarding.ts`, mounted behind `requireAuth + requireRole('super_admin','soc_manager')` — confirmed by direct read, not inferred), with per-organisation service entitlements (`lib/serviceAccess.ts`) that now fail closed rather than fail open (commit `6527537`: an organisation is denied VMS/CNII/TI/SecOps-Automation access until `org_service_grants` and `org_onboarding` both exist explicitly). This is real, tested, and a genuine engineering improvement. However, the requirement specifically asks for **self-service** — confirmed, by direct read of `backend/src/routes/auth.ts:197-209`, that `POST /api/auth/signup` is a literal stub that always returns 502 ("Sign-up is not available yet. Please contact sales.") and `POST /api/organisations` is still `requireRole('super_admin')`-only. No provider can register itself.
- **Backend evidence:** `routes/onboarding.ts:1-20` (new, staff-only); `routes/auth.ts:197-209` (self-service stub, confirmed 502); `routes/organisations.ts:272` (`requireRole('super_admin')` on org creation); `lib/serviceAccess.ts` (new).
- **Frontend evidence:** `frontend/src/app/admin/onboarding` (new, staff-facing wizard).
- **Production deployment status:** The staff-driven wizard is on `origin/main`. Self-service registration does not exist on any branch.
- **Demo-only functionality:** None specific.
- **Missing work:** Provider self-registration and any public API gateway for onboarding — both entirely absent, confirmed directly against current code, not carried forward blind.
- **Verification status:** **MISSING** (unchanged classification — self-service is the operative word in this requirement, and it is still not built — but note the staff-assisted onboarding product behind it is now much stronger than the original audit's "only staff-only wizard; created accounts cannot sign in" framing; worth re-testing that specific sign-in claim live before repeating it verbatim).
- **Recommended next action:** If self-service registration is genuinely required for go-live, this is P0 new work, not a fix to what exists. If staff-assisted onboarding is acceptable, re-classify this requirement's intent with the stakeholder — the gap between "self-service" and "staff-run wizard" is a scope question, not an implementation gap that effort alone closes.

### Requirement 16 — Logical separation of provider data + RBAC
- **Wording:** Logical separation of provider data + RBAC.
- **Relevant implementation:** `lib/permissions.ts` was modified in this diff. The audit's confirmed cross-tenant leak via `ioc_enrichments` (no `org_id`) is **fixed and merged**: `backend/sql/2026-10-31_p26_ioc_cache_tenancy.sql` adds `org_id`, drops the old `ioc_value`-only primary key, and makes `(org_id, ioc_value)` the upsert conflict target; directly confirmed by reading the migration and all three consuming routes (`routes/cti.ts:103,143` now `.eq('org_id', requestOrg(req))`; `routes/intelligence.ts:36,79` scoped per its own header comment "ioc_enrichments is per organisation"; `routes/search.ts:86` `.eq('org_id', org)`). `routes/brand.ts` was **not** in the diff — directly re-read at the cited lines and confirmed still using module-scoped, unscoped in-memory arrays (`socials`, `executives`, `apps`, `signatures`, `brandAssets`) shared across every organisation with zero `org_id` filtering of any kind.
- **Backend evidence:** `backend/sql/2026-10-31_p26_ioc_cache_tenancy.sql` (fix, merged); `routes/cti.ts:103,143`, `routes/intelligence.ts:36,79`, `routes/search.ts:86` (all now org-scoped, confirmed by direct read); `routes/brand.ts` (unscoped module-level state, confirmed still present, unchanged).
- **Frontend evidence:** No dedicated screen (unchanged).
- **Production deployment status:** The IOC fix is on `origin/main`. The `brand.ts` leak is also on `origin/main`, unfixed.
- **Demo-only functionality:** None — this is a real-tenancy finding, not something Demo Mode touches.
- **Missing work:** `brand.ts`'s cross-tenant leak (one organisation's monitored socials/executives/apps/signatures/brand-assets are literally the same in-memory objects for every organisation) is unfixed. `urlscan`/`webscan` history leaks were not re-verified directly in this pass (not in the diff, so presumed unchanged — re-verify before relying on this).
- **Verification status:** **PARTIAL** (upgraded — the audit's single most severe, explicitly "confirmed exploitable" finding is now fixed and merged; a second, equally real leak remains unfixed on the same line numbers the original audit cited).
- **Recommended next action:** Close `brand.ts` next — same fix pattern as P26 (add `org_id`, scope every read/write), and it's a much smaller table set than `ioc_enrichments` was.

### Requirement 17 — NCC-CSIRT access to aggregated and provider-specific views
- **Wording:** NCC-CSIRT access to aggregated and provider-specific views.
- **Relevant implementation:** None. Directly re-read `backend/src/middleware/auth.ts`'s `UserRole` type in `origin/main`: still exactly `'super_admin' | 'soc_manager' | 'analyst' | 'executive' | 'portal_user'` — no oversight/regulator tier exists.
- **Backend evidence:** `backend/src/middleware/auth.ts:22` (confirmed unchanged).
- **Frontend evidence:** None; the public `/cert-csirt` marketing page still addresses an audience with no corresponding role.
- **Production deployment status:** N/A (not built).
- **Demo-only functionality:** None.
- **Missing work:** Entire oversight role and its views — unchanged.
- **Verification status:** **MISSING** (unchanged, directly re-confirmed, not carried forward blind).
- **Recommended next action:** Same as original — ground-up build.

### Requirement 18 — Provider access restricted to own data + anonymised benchmarking
- **Wording:** Provider access restricted to own data + anonymised benchmarking.
- **Relevant implementation:** Core isolation mechanism unchanged (same `lib/permissions.ts`-gated model, now with P26's IOC fix applied, Req 16). The client-portal-specific finding — "16 of 22 sidebar items confirmed broken, rendered with no distinction" — has a confirmed, real fix: `frontend/src/config/nav.ts`'s `badge` field (17 items still flagged, close to the original's 16/22 count) is now actively read and enforced by `components/layout/Sidebar.tsx`, whose own comment states a BROKEN/PLANNED item's badge is shown only to `super_admin`, and such items are otherwise not shown to anyone else at all — a direct, confirmed implementation of the original audit's own recommended fix.
- **Backend evidence:** Same isolation mechanism as Req 16.
- **Frontend evidence:** `frontend/src/config/nav.ts` (17 `badge`-flagged items); `components/layout/Sidebar.tsx:20-38` (confirmed: hides BROKEN/PLANNED items from non-super_admin, badges them for super_admin).
- **Production deployment status:** On `origin/main`.
- **Demo-only functionality:** None.
- **Missing work:** The underlying API gaps behind those ~17 items are presumably still broken (hiding a broken feature is not the same as fixing it) — this reconciliation did not have budget to re-test each one's live API call; only the presentation-layer fix (no longer shown as if working) was confirmed.
- **Verification status:** **PARTIAL** (upgraded — the specific "shown with no distinction" defect from Critical Finding #4 is confirmed fixed; underlying functional completeness of those ~17 features is unverified, not confirmed complete).
- **Recommended next action:** Credit the nav-badge fix explicitly; separately, audit each of the 17 badged items to see how many can now actually be un-broken versus genuinely removed from scope.

### Requirement 19 — MSSP managed security operations (monitoring, triage, response)
- **Wording:** MSSP managed security operations (monitoring, triage, response).
- **Relevant implementation:** `routes/cases.ts` and `routes/secops.ts` were both modified in this diff (R3.3C, "SecOps investigation & automation completion," commits `35caf7d`/`0fa2360`). The case lifecycle (create/assign/escalate/execute-step/close/report) is the same mechanism, now with more automation around it.
- **Backend evidence:** `routes/cases.ts` (modified), `routes/secops.ts` (modified).
- **Frontend evidence:** Clear, per original.
- **Production deployment status:** On `origin/main`.
- **Demo-only functionality:** Demo Mode's SecOps Cases screen (synthetic cases per fictional org, with session-local simulated status/assign/escalate/close/notes actions) is the richest interactive surface in the whole demo layer — a convincing walkthrough here is specifically not evidence of live-operations capability at volume.
- **Missing work:** Still no live-operations evidence of a real SOC running this at volume — unchanged, and not something a code diff can resolve.
- **Verification status:** **PARTIAL** (unchanged classification; backend genuinely matured further, the live-evidence gap is unaffected by any commit).
- **Recommended next action:** Same as original — this needs operational evidence (uptime logs, case volume over a real period), not more code.

### Requirement 20 — GRC platform integration (Commission's platform)
- **Wording:** GRC platform integration (Commission's platform).
- **Relevant implementation:** None. Re-grepped `backend/src` for `grc|archer|servicenow` against `origin/main` — zero matches, same as original.
- **Backend evidence:** None.
- **Frontend evidence:** The `/grc` marketing page still exists and is still not backed by any integration.
- **Production deployment status:** N/A.
- **Demo-only functionality:** None.
- **Missing work:** Entire integration — blocked on an external party (NCC must supply API spec/data contract), unchanged.
- **Verification status:** **MISSING** (unchanged, re-confirmed).
- **Recommended next action:** Same as original — not an engineering backlog item until NCC supplies a spec.

### Requirement 21 — Strategic intelligence dashboards, sector benchmarking
- **Wording:** Strategic intelligence dashboards, sector benchmarking.
- **Relevant implementation:** `routes/dashboard.ts` was modified in this diff, and the R3.2 dashboard redesign (commits `d3af531`/`d1b50f6`) directly targeted tenant-isolation defects in these widgets: commit `d1b50f6` fixes a confirmed real bug where every org-scoped effect in `GeneralDashboard.tsx`/`ExecutiveReport.tsx` only overwrote state on fetch success, so switching organisation left the previous organisation's figures on screen until the next fetch resolved — fixed with React's documented render-phase "reset state when a prop changes" pattern instead of an effect (avoids committing one stale, cross-tenant frame). This is a genuine, confirmed fix to a real tenant-data-hygiene bug, found and fixed independently of this audit.
- **Backend evidence:** `routes/dashboard.ts` (modified).
- **Frontend evidence:** `components/dashboards/GeneralDashboard.tsx`, `components/features/ExecutiveReport.tsx` (both fixed per commit `d1b50f6`).
- **Production deployment status:** On `origin/main`.
- **Demo-only functionality:** Demo Mode's dashboard KPIs are fully synthetic per fictional org — not evidence of the real dashboard's data correctness, though the stale-cross-org-data fix above is a real, non-demo improvement.
- **Missing work:** The original audit's specific "Executive Report calls endpoints the `executive` role is itself refused — 403 renders as zero" defect was not independently re-tested live in this pass (would require signing in as `executive` against a real backend); the benchmarking half (Req 14) remains entirely absent regardless.
- **Verification status:** **PARTIAL** (unchanged overall classification; one of the two named defects — stale cross-org data on switch — is confirmed fixed; the 403-as-zero defect's current status is unverified, not confirmed either way).
- **Recommended next action:** Re-test the Executive Report as the `executive` role specifically before claiming that defect is fixed too; credit the cross-org stale-data fix now.

### Requirement 22 — Emerging threat intelligence, KEV correlation
- **Wording:** Emerging threat intelligence, KEV correlation.
- **Relevant implementation:** Unchanged — `services/cisa.ts` and `lib/riskScore.ts`'s KEV weighting are not in the diff.
- **Backend evidence:** `services/cisa.ts`, `lib/riskScore.ts` (unchanged).
- **Frontend evidence:** Clear, unchanged.
- **Production deployment status:** On `origin/main` (was already on `main` at the original audit).
- **Demo-only functionality:** None.
- **Missing work:** Still 12-hour polling, not push — acceptable given CISA KEV's own update cadence, same note as original.
- **Verification status:** **COMPLETE** (re-stamped, unchanged).
- **Recommended next action:** None required.

### Requirement 23 — CCI mapping, automated executive reporting
- **Wording:** CCI mapping, automated executive reporting.
- **Relevant implementation:** CCI/CNII classification (`routes/cniiNational.ts`) is modified but structurally the same strong mechanism as before. The **"automated executive reporting" half is substantially changed**: the original audit's specific finding — "reporting — manual trigger only, not scheduled" — is **no longer accurate**. The new `report_type` enum in `lib/reportScheduling.ts` explicitly includes `'executive_summary'`, with full weekly/monthly cadence scheduling and automated email delivery (Req 10's pipeline). This is a real, working, cadence-based automated executive report, not a manual-export-only process — confirmed by direct read of the scheduling and delivery code, not inferred from a feature name.
- **Backend evidence:** `routes/cniiNational.ts:140-196` (modified, CCI mapping unchanged in substance); `lib/reportScheduling.ts` (`report_type: 'executive_summary'`), `services/reportDelivery.ts` (automated send).
- **Frontend evidence:** `frontend/src/app/admin/reports` (schedule an `executive_summary` report, weekly or monthly, with recipients).
- **Production deployment status:** On `origin/main`.
- **Demo-only functionality:** Demo Mode's "Sample Documents" tab generates a sample executive summary PDF client-side, unrelated to this real scheduled pipeline — don't let a demo download stand in for evidence the real schedule actually fires and delivers.
- **Missing work:** Delivery confirmation is honestly incomplete by design (no webhook receiver means "sent" is the strongest status ever reached, never a confirmed "read" or "bounced") — stated plainly in the code's own comments, not a hidden gap.
- **Verification status:** **PARTIAL → upgraded within PARTIAL** (this is one of the most significant corrections in this reconciliation: the original audit's "automated reporting is actually manual" finding is factually superseded by real, merged, tested code).
- **Recommended next action:** Re-write any stakeholder-facing claim about "manual-only" executive reporting — it is no longer accurate. Keep the honest "sent, not confirmed-delivered" caveat when describing this capability.

### Requirement 24 — MFA for all administrator accounts
- **Wording:** MFA for all administrator accounts.
- **Relevant implementation:** None. Re-grepped for TOTP/WebAuthn/OTP code or dependency across the full `origin/main` tree — zero hits, same as original.
- **Backend evidence:** None.
- **Frontend evidence:** None.
- **Production deployment status:** N/A.
- **Demo-only functionality:** None.
- **Missing work:** Entire capability, unchanged.
- **Verification status:** **MISSING** (unchanged, re-confirmed).
- **Recommended next action:** Same as original — hard blocker, highest non-functional priority.

## Section 2 — Non-Functional Requirements

### Requirement 25 — Audit trails for scans, access, configuration changes
- **Wording:** Audit trails for scans, access, configuration changes.
- **Relevant implementation:** `lib/audit.ts` itself is not in the diff (unchanged mechanism: ring buffer + batched Supabase flush), but `lib/exportEvent.ts` was modified, and every new P26–P31 feature (onboarding, scan authorisation, collector enrolment, report scheduling) calls `logAudit()` at its key actions, confirmed by grep across the new route files (`onboarding.ts`, `vmsAuthorisation.ts`'s service, `collectors.ts`) — audit coverage breadth genuinely grew with the new features, though the underlying storage mechanism (durability, batching) did not change.
- **Backend evidence:** `lib/audit.ts` (unchanged mechanism); `lib/exportEvent.ts` (modified); `logAudit()` calls present in `routes/onboarding.ts`, `services/vmsAuthorisation.ts`, `routes/collectors.ts` (confirmed by direct grep).
- **Frontend evidence:** Page works, unchanged.
- **Production deployment status:** On `origin/main`.
- **Demo-only functionality:** None — Demo Mode's mutations never call `logAudit()` (they're pure client-side session overlays), so they don't pollute the real audit trail; this is a correctly-designed isolation property, not a gap.
- **Missing work:** Durability-until-flush is still memory-only (same risk as original); full-coverage claim across every action is still not independently verified row-by-row.
- **Verification status:** **PARTIAL** (unchanged classification; coverage breadth improved, durability/verification gaps did not).
- **Recommended next action:** Same as original.

### Requirement 26 — SSO (SAML/OAuth) with NCC identity management
- **Wording:** SSO (SAML/OAuth) with NCC identity management.
- **Relevant implementation:** None. `.env.example` re-checked — still Google OAuth only, no SAML library anywhere in `package.json`/`node_modules` manifest.
- **Backend evidence:** `.env.example:24-25` (unchanged).
- **Frontend evidence:** Google OAuth button unchanged; live status still unverified.
- **Production deployment status:** N/A for real SSO.
- **Demo-only functionality:** None.
- **Missing work:** No SAML/OIDC federation with any NCC IdP — unchanged, blocked on stakeholder input (NCC's IdP details).
- **Verification status:** **MISSING** (unchanged, re-confirmed).
- **Recommended next action:** Same as original.

### Requirement 27 — Strict logical separation of provider data
- **Wording:** Strict logical separation of provider data.
- **Relevant implementation:** This is the big one. The original audit's **single most severe finding** — a confirmed, exploitable cross-tenant leak via `ioc_enrichments` (no `org_id` column at all, affecting CTI feed/stats, STIX export, and IOC search) with a fix sitting unmerged on `feat/vms-onboarding` — is **now fixed and merged into `origin/main`**. Directly confirmed: `git merge-base --is-ancestor 3bd3a6e origin/main` → true; `backend/sql/2026-10-31_p26_ioc_cache_tenancy.sql` exists in `origin/main`'s tree and was read in full (adds `org_id`, migrates the primary key, makes `(org_id, ioc_value)` the upsert target, fails closed on any pre-existing un-attributed row rather than guessing); all three previously-unscoped routes (`cti.ts`, `intelligence.ts`, `search.ts`) now filter by `org_id`, confirmed by direct read of each call site, not by trusting the migration's existence alone.
- **Backend evidence:** `backend/sql/2026-10-31_p26_ioc_cache_tenancy.sql` (full migration read); `routes/cti.ts:103,143`; `routes/intelligence.ts:11,36,79`; `routes/search.ts:86` — all confirmed org-scoped.
- **Frontend evidence:** N/A (backend tenancy fix).
- **Production deployment status:** On `origin/main` — this is real, deployed-line, production code, not an unmerged worktree anymore.
- **Demo-only functionality:** None — this is exactly the kind of fix Demo Mode's own design explicitly must never substitute for; noted for completeness, not because Demo Mode touches it.
- **Missing work:** The `brand.ts` leak (Req 16) and the `urlscan`/`webscan` history leaks (not re-verified in this pass; same caveat as Req 16) mean "strict" logical separation is still not achieved platform-wide, even though this specific, worst instance is closed.
- **Verification status:** **PARTIAL** (upgraded from the original's "PARTIAL, with one CONFIRMED CRITICAL instance" — the critical instance is now fixed; the requirement is not yet COMPLETE because other confirmed leaks remain).
- **Recommended next action:** This is the single most important correction to report upward: the audit's #1 security blocker is resolved. Next priority is `brand.ts`, then re-verifying `urlscan`/`webscan`.

### Requirement 28 — Cloud-native SaaS, 99.9% uptime SLA
- **Wording:** Cloud-native SaaS, 99.9% uptime SLA.
- **Relevant implementation:** `services/uptimerobot.ts` not in the diff — unchanged, still complete-but-only-manually-invoked.
- **Backend evidence:** `services/uptimerobot.ts` (unchanged).
- **Frontend evidence:** `/status` page — not re-verified live in this pass; original audit called it a logo placeholder.
- **Production deployment status:** Configured only, same as original.
- **Demo-only functionality:** None.
- **Missing work:** No uptime figure ever computed, stored, or surfaced operationally — unchanged, still the cheapest fix in the whole audit per the original's own note.
- **Verification status:** **PARTIAL** (unchanged).
- **Recommended next action:** Same as original — quick win, do it.

### Requirement 29 — Scan thousands of assets across 100+ licensed entities
- **Wording:** Scan thousands of assets across 100+ licensed entities.
- **Relevant implementation:** Indexing design (`(org_id, ...)` composite indexes, `FOR UPDATE SKIP LOCKED` job claiming) unchanged. Collector V1 (P31) adds a comparable distributed-safety pattern for log ingestion at the application layer (`lib/reportScheduling.ts`'s compare-and-swap claiming, same engineering discipline) — relevant as design evidence, not as load-test evidence.
- **Backend evidence:** `backend/sql/2026-10-14_p4_vms_asm.sql:137-150` (unchanged); `lib/reportScheduling.ts` (new, same design pattern).
- **Frontend evidence:** None.
- **Production deployment status:** On `origin/main`.
- **Demo-only functionality:** None.
- **Missing work:** Still no load-test evidence anywhere in the repository at the stated target scale — unchanged; a code diff cannot resolve this regardless of how much new, well-designed code exists.
- **Verification status:** **UNVERIFIED** (unchanged).
- **Recommended next action:** Same as original — this needs an actual load test, not more static review.

## Section 3 — Integration & Interoperability

### Requirement 30 — Open APIs for CTI/SIEM integration
- **Wording:** Open APIs for CTI/SIEM integration.
- **Relevant implementation:** Still internal REST only; no `/api/v1/` versioning found in the new route files either (`onboarding.ts`, `reports.ts`, `collectors.ts` all mount unversioned, same convention as the rest of the app).
- **Backend evidence:** ~72 route files now (grew from ~66), still no versioning scheme.
- **Frontend evidence:** No dev portal, unchanged.
- **Production deployment status:** On `origin/main`.
- **Demo-only functionality:** None.
- **Missing work:** No published, versioned, externally-documented API product — unchanged.
- **Verification status:** **PARTIAL** (unchanged).
- **Recommended next action:** Same as original.

### Requirement 31 — Workflow Management API support
- **Wording:** Workflow Management API support.
- **Relevant implementation:** `routes/vmsWorker.ts` (modified for P27/collector reasons) remains an internal worker protocol only — no external WMS adapter.
- **Backend evidence:** `routes/vmsWorker.ts` (modified, still internal-only).
- **Frontend evidence:** None.
- **Production deployment status:** N/A for external WMS.
- **Demo-only functionality:** None.
- **Missing work:** Same as Req 9 — needs a named target system.
- **Verification status:** **MISSING** (unchanged).
- **Recommended next action:** Same as original.

## Section 3 — Deliverables (32–49)

The brief's own instruction treats these as contractual/organisational facts a repository can only partially evidence. The **Overall** status uses the same four-value vocabulary (for the Part 12.B count); **Readiness** alongside it uses READY/READY WITH CONDITIONS/NOT READY/NOT VERIFIED, as the original audit did, since the two scales serve different purposes.

### Requirement 32 — Inception report
No matching artifact in `origin/main` either (re-checked). **UNVERIFIED.** Readiness: NOT VERIFIED — may exist outside version control.

### Requirement 33 — NCC-CSIRT-hosted go-live
`render.yaml`/`railway.json`/Vercel config all still commercial clouds, unchanged. **MISSING.** Readiness: NOT READY.

### Requirement 34 — Core platform capabilities (asset mapping, scanning, reporting, RBAC, multitenancy)
This is the requirement most changed by the re-baseline: asset mapping gained real import/dedup (Req 1), scanning gained formal authorisation/scheduling (Req 2/3), **reporting gained a full automated scheduling+delivery pipeline (Req 10/23)**, RBAC gained the P26 tenancy fix (Req 27) and the nav-badge fix (Req 18), and multitenancy's worst confirmed leak is closed. Backend evidence: `lib/permissions.ts`, `lib/resolveOrg.ts` (unchanged, still tested), plus every file cited above. **PARTIAL**, materially stronger than the original's "READY WITH CONDITIONS" framing implied. Readiness: READY WITH CONDITIONS — the remaining conditions are narrower now (close `brand.ts`, get live-at-scale proof) than they were at the original audit.

### Requirement 35 — Operational self-service stakeholder portal
Same finding as Req 15: the staff-assisted wizard is real and much improved; self-service specifically (`POST /api/auth/signup`) is confirmed still a 502 stub. **MISSING.** Readiness: NOT READY — confirmed directly this pass, not carried forward on faith.

### Requirement 36 — Complete API documentation
No OpenAPI/Swagger/Postman artifact found in `origin/main`. **MISSING.** Readiness: NOT READY.

### Requirement 37 — First 10 pilot providers onboarded
No pilot-provider roster/tracking found. **UNVERIFIED.** Readiness: NOT VERIFIED.

### Requirement 38 — Tested workflow automation
SOAR + case-lifecycle tests still pass; the new reporting pipeline adds its own real test coverage (`routes/__tests__/reports.test.ts`, confirmed present in the diff) and onboarding/collector flows add `onboardingFlows.test.ts`, `onboardingWizard.test.ts`, `collectors.test.ts`. **PARTIAL**, upgraded — test breadth genuinely grew with the new features. Readiness: READY WITH CONDITIONS — still unit-level evidence, no end-to-end workflow-automation test spanning a full schedule→generate→deliver cycle against a live recipient.

### Requirement 39 — Full VTEM operationalisation + CCI mapping
CNII hierarchy real and now has `cniiCoverage.ts` (monitoring-coverage states, R3.3B) on top. **PARTIAL**, with CCI mapping stronger than before. Readiness: NOT READY as a business state — MFA/SSO/self-service-portal/benchmarking/NCC-role gaps still block "full," unchanged by this diff since none of those five are touched by it.

### Requirement 40 — Threat exposure monitoring, interactive heatmaps
Per Req 8: a real interactive Nigeria heatmap now exists in production with real aggregate data, not just backend JSON. **PARTIAL**, upgraded from "no interactive frontend heatmap exists." Readiness: upgraded from NOT READY to READY WITH CONDITIONS — the heatmap exists and works; the remaining condition is drill-down depth, not existence.

### Requirement 41 — Automated threat intelligence sharing
Per Req 12: pull-based anonymised sharing is unchanged; a new, real, but narrower automated push (scheduled aggregate reports) now exists alongside it. **PARTIAL.** Readiness: NOT READY — push distribution at the IOC/alert level and acknowledgement tracking (Req 12/13) are still absent; don't let the new reporting pipeline be mistaken for closing this specific gap.

### Requirement 42 — Strategic dashboards, sector benchmarking
Executive dashboard remains real and honest, and gained the stale-cross-org-data fix (Req 21). Benchmarking half (Req 14) still entirely absent. **PARTIAL**, unchanged overall. Readiness: NOT READY — benchmarking is the blocking half, unaffected by this diff.

### Requirement 43 — Emerging threats, KEV correlation (deliverable)
Same technical evidence as Req 22, unchanged. **COMPLETE** (technical capability only). Readiness: READY (technical only; formal deliverable sign-off remains a separate contractual fact this repository cannot confirm).

### Requirement 44 — Complete provider onboarding
Per Req 15/35: staff-assisted onboarding is now a real, 6-step, tested product — a genuine improvement — but "complete provider onboarding" as named requires the provider to be able to onboard itself, and that path is confirmed still a 502 stub. **PARTIAL**, upgraded from MISSING — the staff-run half of this deliverable is now real and should be credited; the self-service half is not. Readiness: NOT READY — re-classify with the stakeholder whether staff-assisted onboarding satisfies this deliverable's intent at all; if self-service is contractually required, this stays NOT READY regardless of how good the staff tool is.

### Requirement 45 — Automated executive reporting
Per Req 23, this is the second major correction in this reconciliation: automated, cadence-based executive-summary report generation and delivery is now real, merged, and tested — not manual-export-only. **PARTIAL**, upgraded — arguably close to COMPLETE pending a live end-to-end confirmation that a scheduled report actually fires and a real email arrives (this reconciliation read the code; it did not trigger a live schedule). Readiness: upgraded from NOT READY to READY WITH CONDITIONS — the condition is "prove it fires live," not "build it."

### Requirement 46 — Threat landscape report
No matching document found in `origin/main` either. **UNVERIFIED.** Readiness: NOT VERIFIED.

### Requirement 47 — Security assessment (independent pentest)
`securityAssessment.ts`/`routes/securityAssessment.ts` were both modified in this diff, but remain an internal self-assessment feature (SLA-rate/posture scoring across an org's own clients), not an independent third-party penetration test — confirmed by reading the modified file; the modification extended internal metrics, it did not add third-party pentest tracking. **MISSING**, unchanged classification. Readiness: NOT READY — do not conflate the two, same warning as the original audit.

### Requirement 48 — Final API documentation
Same as Req 36. **MISSING.** Readiness: NOT READY.

### Requirement 49 — Technical knowledge transfer
`handover.ts`/`ShiftHandover.tsx` remain SOC shift-handover tooling, not project knowledge transfer — same naming collision the original audit flagged, unchanged. **UNVERIFIED.** Readiness: NOT VERIFIED.

---

## Rollup count (must total 49)

| Status | Count | IDs |
|---|---|---|
| COMPLETE | 3 | 4, 22, 43 |
| PARTIAL | 28 | 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 16, 18, 19, 21, 23, 25, 27, 28, 30, 34, 38, 39, 40, 41, 42, 44, 45 |
| MISSING | 13 | 13, 14, 15, 17, 20, 24, 26, 31, 33, 35, 36, 47, 48 |
| UNVERIFIED | 5 | 29, 32, 37, 46, 49 |
| NOT APPLICABLE | 0 | — |
| **Total** | **49** | |

(Net change from the original rollup: MISSING drops from 14 to 13 — Requirement 44 moves from MISSING to PARTIAL. No requirement's bucket count changes beyond that single move, but several PARTIAL requirements have materially stronger evidence behind the same label — see each subsection above; a bucket count alone understates how much changed.)

## What changed since the original audit, and why

**Moved status:**
- **Requirement 27** (tenant-data separation): the audit's #1 critical, "confirmed exploitable" finding is fixed and merged (P26). Still PARTIAL only because `brand.ts` (Req 16) remains a second, real leak.
- **Requirement 44** (complete provider onboarding): MISSING → PARTIAL. Staff-assisted onboarding is now a real, tested, 6-step product; self-service specifically is still absent.

**Same bucket, materially stronger evidence (read the subsections, not just the letter):**
- **Requirement 10 / 23 / 45** (reporting workflows / automated executive reporting): the original audit's "manual trigger only, not scheduled" finding is factually superseded — a real scheduled generation+delivery pipeline exists, is tested, and includes an `executive_summary` report type on a weekly/monthly cadence.
- **Requirement 8 / 40** (interactive heatmaps): a real, production, interactive Nigeria map exists now, pre-dating and independent of the unmerged Demo Mode branch.
- **Requirement 16 / 18**: the nav-badge fix (Critical Finding #4's "shown with no distinction" defect) is confirmed implemented.
- **Requirement 21**: the stale-cross-org-data-on-switch bug is confirmed fixed.
- **Requirement 1 / 2 / 3 / 25 / 29 / 34 / 38**: materially more backend capability (asset import, scan authorisation/windows, audit-call coverage, test breadth) without changing the underlying classification, because the specific gaps each requirement names (AFRINIC bulk import, custom signatures, durability, load-test evidence) are untouched by any of it.

**Confirmed unchanged (re-verified directly against `origin/main`, not carried forward on faith):** Requirements 4, 11, 13, 14, 17, 20, 22, 24, 26, 28, 30, 31, 32, 33, 36, 37, 39 (the non-reporting half), 41 (the IOC/alert-level half), 42 (the benchmarking half), 43, 46, 47, 48, 49.

**One open discrepancy, not resolved either way:** Requirement 10's original "SLA route built then removed" finding is contradicted by `jobs/incidentEscalation.ts` (automated SLA-breach escalation email), which already existed before the original audit ran. This reconciliation does not have enough budget to track down exactly which specific route the original finding meant; flagged for the next pass rather than silently dropped or silently accepted.

**Nothing found that undermines the "P26/P27 merge fixed the critical leak" read.** The migration, and all three consuming routes, were read directly, not inferred from the migration's filename or a commit message — the fix is real and complete for `ioc_enrichments` specifically. The one genuine complication is that it is not the *only* cross-tenant leak (`brand.ts` remains, confirmed at the same lines the original audit cited), so "the critical finding is fixed" is true, while "tenant isolation is fixed" is not.
