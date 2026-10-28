# VTEM Gap Analysis and Implementation Roadmap

Synthesized from all five audit documents. Tasks are grouped into the brief's four packages. Complexity: S/M/L/XL. Priority: P0 (blocking/critical) / P1 / P2 / P3. "Depends on" references other task IDs. Quick wins are marked explicitly — they are called out separately from major engineering work per the brief's instruction, and none of them require new infrastructure or paid services; every proposed solution extends existing architecture.

---

## Package A — Core VMS and TEM

### A1 — Merge the P26 IOC-cache-tenancy fix [P0, Complexity S]
**Requirement(s):** 16, 18, 27. **Current state:** confirmed, exploitable cross-tenant IOC-enrichment leak on the primary line (`ioc_enrichments` has no `org_id`; `cti.ts`, `intelligence.ts`, `search.ts` read it unscoped). **Missing capability:** the org-scoping migration and route fixes. **Proposed solution:** the fix already exists, is tested, and is sitting on the unmerged `feat/vms-onboarding` worktree (`novr-vms/backend/sql/2026-10-31_p26_ioc_cache_tenancy.sql` + 4 route diffs + `iocCacheTenancy.test.ts`) — cherry-pick or merge it onto the primary line; do not rewrite it. **Backend files:** `backend/src/routes/cti.ts`, `intelligence.ts`, `search.ts`, `secops.ts`. **DB changes:** the P26 migration (surrogate PK, `(org_id, ioc_value)` unique, fail-closed legacy-row attribution). **Integration dependencies:** none. **Security implications:** closes the single most severe confirmed finding in this audit. **Test requirements:** the P26 test suite already covers this — re-run after merge. **Acceptance criteria:** AT-16/AT-27 pass; a second organisation cannot read or overwrite another's IOC cache row. **Dependencies:** none — do this first.

### A2 — Enable RLS on `organisations` [P1, Complexity S]
**Requirement(s):** 27. **Current state:** every reference-cache table has RLS + explicit anon/authenticated revoke except `organisations`, which holds direct PII. **Missing capability:** a one-line RLS policy matching the existing pattern. **Proposed solution:** `ALTER TABLE public.organisations ENABLE ROW LEVEL SECURITY;` + a service-role-bypass policy, identical to the 8 tables in `rls-policies.sql`. **DB changes:** one migration. **Security implications:** closes a gap whose exploitability depends on whether a Supabase anon key has ever been issued (not established from this repo — flag for live confirmation). **Dependencies:** none.

### A3 — Reconcile the unmerged backend/frontend lines [P0, Complexity M–L]
**Requirement(s):** cross-cutting (1, 9, 10, 15, 27 directly). **Current state:** 17 git worktrees exist; the UI/marketing line (main → `marketing-pages-merge`) and the VMS/integration line (P24→P26→P27, `feat/vms-onboarding`) diverged at commit `9429743` and have never been reconciled — the richer frontend has an older backend, and the newer backend has almost no frontend. **Proposed solution:** this is a product/engineering decision, not a pure technical one — pick a reconciliation strategy (rebase the backend line onto the frontend line, or vice versa, or a dedicated merge branch) and execute it before any further feature work compounds the divergence. **Acceptance criteria:** one branch contains both the full admin/client/marketing frontend and P26/P27. **Dependencies:** should happen before A1 is finalized in a durable way (A1 can be cherry-picked ahead of the full reconciliation as an interim step, which this plan recommends given its severity).

### A4 — Restore the removed SLA route and build breach alerting [P1, Complexity M]
**Requirement(s):** 10. **Current state:** an SLA route existed and was removed (confirmed regression, not a never-built gap); `due_at` exists on findings with no breach alerting. **Proposed solution:** restore a dedicated SLA endpoint/dashboard; add a scheduled job (alongside existing `jobs/vmsMaintenance.ts` pattern) that flags/notifies on `due_at` breach. **Backend files:** new `routes/sla.ts` (or equivalent), a job in `backend/src/jobs/`. **Frontend files:** replace the decorative Settings-page SLA fields with real config wired to the new route. **Test requirements:** breach-detection unit test + the AT-10 acceptance case. **Dependencies:** none.

### A5 — Build a named-target external Workflow Management System adapter [P2, Complexity L]
**Requirement(s):** 9, 31. **Current state:** internal approval-gated remediation is solid; no external WMS integration exists. **Missing capability:** an adapter to an actual external system. **Proposed solution:** do not build this speculatively — first get a product decision on which external WMS (ServiceNow, Jira Service Management, or a generic webhook bridge) is actually required, then build a thin adapter on top of the existing `responseApprovals`/`cases` REST surface. **Dependencies:** a named target system (business decision, not engineering).

### A6 — CVSS v4 support and score versioning [P1, Complexity M]
**Requirement(s):** 6. **Current state:** CVSS v3/v2 only; risk-scoring weights are unversioned module constants. **Proposed solution:** add CVSS v4 vector parsing to `services/nvd.ts`/`cveIntel.ts`; version the weight constants in `lib/riskScore.ts` (e.g., a `risk_policy_version` column stamped onto `vms_findings` at score time) so a score is reconstructable after a weight change. **DB changes:** add `risk_policy_version` to `vms_findings`. **Dependencies:** none.

### A7 — Clarify and build CRF-NCS compliance mapping [P1, Complexity M, pending product decision]
**Requirement(s):** 5. **Current state:** no framework literally named "CRF-NCS" exists in the backend; NDPA/NDPR naming is inconsistent. **Proposed solution:** get a product/legal decision on the Commission's actual framework name and whether "CRF-NCS" is a renaming of the existing "CBN Risk-Based Cybersecurity Framework" mapping or a genuinely separate framework to add; standardize NDPA vs. NDPR naming across `complianceMapping.ts`, `routes/compliance.ts`, `lib/cnii-sectors.ts`. **Dependencies:** a naming/scope decision before engineering proceeds.

### A8 — Custom Nuclei template authoring [P2, Complexity M]
**Requirement(s):** 3. **Current state:** built-in template selection exists; no CRUD/authorization path for analyst-authored templates. **Proposed solution:** add a template-submission + approval route (reusing the existing approval-gate pattern from `responseApprovals.ts`) before a custom template can run. **Dependencies:** none.

---

## Package B — Sector and Provider Intelligence

### B1 — Build the self-service stakeholder portal [P0, Complexity L]
**Requirement(s):** 15, 35, 44. **Current state:** the only onboarding UI is a staff-only wizard whose created accounts cannot sign in (no invite/welcome email — a literal TODO in `organisations.ts`); no provider self-registration exists on either line. **Proposed solution:** build a real registration→invitation→approval→org-provisioning flow with actual credential issuance and a working sign-in path for the accounts it creates; this is the single most consequential MISSING item for contractual deliverables 15/35/37/44. **Backend files:** `routes/organisations.ts` (fix the TODO), new invite/email-send path. **Frontend files:** new public registration flow (today `/cert-csirt`/`/regulators` are dead-end copy pages for exactly this audience). **Dependencies:** none technically, but should follow A3 (branch reconciliation) so it lands once, not twice.

### B2 — Build anonymised provider benchmarking [P1, Complexity L]
**Requirement(s):** 14, 21, 42. **Current state:** zero database representation — no table, no aggregation, nothing. **Proposed solution:** new schema (`org_id`-anonymised cohort metrics: patch cadence, exposure density), a minimum-cohort-size (k-anonymity) enforcement rule before any metric is shown, and a new dashboard. This is ground-up work, not a scoping fix. **DB changes:** new benchmarking tables/materialized views. **Frontend files:** new Sector Oversight dashboard (see redesign blueprint §3). **Dependencies:** B3 (the oversight role) should land first or alongside, since this is the primary audience.

### B3 — Build the NCC-CSIRT / sector-oversight role [P0, Complexity M]
**Requirement(s):** 17. **Current state:** no oversight tier exists in the role model at all; `super_admin` and `soc_manager` are identical. **Proposed solution:** a new role (e.g. `sector_overseer`), read-only, scoped to aggregated sector/CNII views with explicitly-authorised, logged provider-level drill-down — never reuse `super_admin`. **Backend files:** `middleware/auth.ts` (role union), `lib/permissions.ts` (new permission scopes), `routes/cniiNational.ts` (grant read access). **Frontend files:** new nav section + a visible "you are viewing as sector oversight; this access is logged" banner on every drill-down (per the redesign blueprint). **Dependencies:** should precede B2 since benchmarking's primary consumer is this role.

### B4 — Build intelligence-distribution + acknowledgement tracking [P1, Complexity M]
**Requirement(s):** 12, 13. **Current state:** only a pull-based `/api/org-cti/shared` endpoint exists; no push, no delivery record, no ack/escalation. **Proposed solution:** a durable `distribution_log` table (stakeholder, item, sent-at, acknowledged-at, escalated-at), a send path (reusing existing email infrastructure — Brevo/Resend/SMTP, already configured), and a reminder/escalation job. **DB changes:** new table. **Backend files:** new `routes/distribution.ts`, a job alongside `jobs/incidentEscalation.ts`'s pattern. **Dependencies:** none, but natural to sequence after B3 since stakeholders need a recipient list.

### B5 — Promote the manual IOC store to durable storage [P2, Complexity M]
**Requirement(s):** 13, 29 (durability under horizontal scaling). **Current state:** `orgCtiStore.ts`'s manual IOC store is an in-memory `Map`, lost on restart, inconsistent across instances. **Proposed solution:** promote to a real table using the already-correct `OrgIOC` interface as the schema. **Dependencies:** none.

### B6 — CNII subsector drill-down [P2, Complexity M]
**Requirement(s):** 8. **Current state:** backend has only a flat `subfield` string; no subsector hierarchy. **Proposed solution:** per V2's own existing design (already specified, not re-derived here) — add a subsector table/hierarchy and the corresponding drill-down view. **Dependencies:** none.

### B7 — Interactive geographic heatmap for CNII/sector exposure [P1, Complexity M]
**Requirement(s):** 8, 40. **Current state:** backend aggregation is real; no frontend renders it as an actual geographic/interactive heatmap. **Proposed solution:** extract the existing `NigeriaStateMap` component (currently embedded in `TiMap.tsx`) into a standalone, reusable component and wire it to `cniiNational.ts`'s sector/provider data, per the redesign blueprint's component plan. **Dependencies:** none; can run parallel to B2.

---

## Package C — SOC, XDR, Workflow and GRC

### C1 — Fix confirmed cross-tenant leaks on `/api/brand/*` and `/api/urlscan|webscan/history` [P0, Complexity S]
**Requirement(s):** 16, 18, 27. **Current state:** any staff/executive token from any org can read (and on brand routes, write) another org's data — confirmed, not theoretical. **Proposed solution:** add `requirePermission` with org filtering to every listed route (`routes/brand.ts:93,190,394,536,663`, `domainSuite.ts:90-111`, `urlscan.ts:165-176`, `webscan.ts:208-219`); add the regression test the prior V2 audit already recommends (`tenantGuard.test.ts`, auto-fails any `requireAuth`-only route not on an explicit allow-list) so this class of bug cannot silently recur. **Dependencies:** none — do this alongside A1, both are P0 and both are Complexity S.

### C2 — Gate `/api/dashboard/nigeria-threats/collect` [P1, Complexity S]
**Requirement(s):** 16. **Current state:** any authenticated non-portal role can trigger external-intel collection and MISP writes with no `intel:manage` check. **Proposed solution:** add `requirePermission('intel:manage')`. **Dependencies:** none.

### C3 — Build MFA [P0, Complexity M]
**Requirement(s):** 24. **Current state:** zero MFA code anywhere, including `super_admin`. **Proposed solution:** TOTP (e.g. `otplib`) at minimum for `super_admin`/`soc_manager`; consider WebAuthn specifically for the break-glass dev-admin account. **Backend files:** `routes/auth.ts`, new MFA enrollment/verification routes. **Frontend files:** new MFA enrollment screen, login-flow second-factor step. **Dependencies:** none — this is the single highest-severity MISSING non-functional requirement and should be scheduled early regardless of package sequencing.

### C4 — Build SSO (SAML/OIDC) [P0 pending NCC input, Complexity L]
**Requirement(s):** 26. **Current state:** only Google OAuth exists, not SAML, and its live status is unverified; no NCC IdP integration of any kind. **Proposed solution:** get the real target IdP's details from NCC (ADFS/Okta/Azure AD/other) before building — this cannot be engineered against an unspecified identity provider. Once known, implement via `saml2-js`/`node-saml` or a hosted IdP broker, with role mapping from IdP claims. **Dependencies:** external input (NCC IdP spec) required before implementation starts.

### C5 — Verify and fix MISP's live credential [P1, Complexity S, operational not engineering]
**Requirement(s):** 11, 22. **Current state:** the integration is well-engineered (TLS pinning, auth-failure vs. unreachable distinction, write kill-switch), but the configured API key was last recorded as rejected (403) by the live MISP instance. **Proposed solution:** rotate/obtain a working, API-access-enabled MISP key; separately fix the MISP server's own `MISP.baseurl` (set to `localhost`, causing broken browse links) via one `cake Admin setSetting` command, documented in `misp.ts`'s own header comment. **Dependencies:** access to the MISP server's admin console (operational, not a code change).

### C6 — SSRF review of outbound-fetch-on-user-input paths [P1, Complexity M]
**Requirement(s):** general security hygiene supporting 16/27. **Current state:** not reviewed by this audit — `lib/scan.ts` and every `services/*scan*`/`*webscan*` outbound fetch triggered by user/org-supplied URLs needs a dedicated pass to confirm private-IP/metadata-endpoint blocking. **Dependencies:** none; schedule as a standalone security task.

### C7 — GRC platform integration [Blocked, Complexity L once unblocked]
**Requirement(s):** 20. **Current state:** zero code, zero config, zero docs. **Proposed solution:** cannot be engineered until NCC supplies the GRC platform's API specification and data contract — this is a pure external dependency, not a backlog item. Flag to stakeholders as a blocking input needed before any sequencing commitment can be made. **Dependencies:** external (NCC-supplied API spec).

### C8 — Wire up the existing UptimeRobot client [P1, Complexity S — quick win]
**Requirement(s):** 28. **Current state:** `services/uptimerobot.ts` is a complete, real client, but it is called only from a manual CLI diagnostic script — no uptime figure is ever computed, stored, or surfaced operationally. **Proposed solution:** call it from a scheduled job (same pattern as existing jobs) and surface the result on a real `/status` page (today a logo placeholder) and in the Platform Health settings screen. This is the cheapest fix in the entire audit relative to its requirement's visibility. **Dependencies:** none.

---

## Package D — Enterprise Readiness

### D1 — Hide `BROKEN`-flagged client nav items [P0, Complexity S — quick win]
**Requirement(s):** 18. **Current state:** `config/nav.ts` already carries an unused `BROKEN` status flag on 18 client-portal items; `Sidebar.tsx`'s filter does not consult it, so a provider sees 16 of 22 items as if live when they are dead. **Proposed solution:** a one-line filter change — consult the existing `status` field. This alone turns the client portal from "majority broken" to "small and honest" with no backend work. **Dependencies:** none — ship this before any other client-portal work.

### D2 — Promote VMS into the main admin sidebar [P1, Complexity S — quick win]
**Requirement(s):** 1, 2, 3, 6 (discoverability). **Current state:** the platform's most complete 23-page module is reachable only by already knowing the `/admin/vms` URL. **Proposed solution:** add the existing VMS shell as a first-class sidebar section. **Dependencies:** none.

### D3 — Fix the four confirmed 403-renders-as-zero dashboard widgets + the Executive Report [P0, Complexity S — quick win]
**Requirement(s):** 7, 21, 23. **Current state:** at least 4 dashboard widgets and the Executive Report render `0`/empty on an authorization failure instead of "unavailable to your role" — making the Executive Report unusable by one of its two named audiences. **Proposed solution:** build the "Unavailable to your role" state once as a reusable component and apply it to all 5 confirmed sites. **Dependencies:** none; this is the single highest-trust-impact, lowest-cost fix in the frontend findings.

### D4 — Replace static "Telemetry Online"/"Cloud Node" indicators with real health signals [P1, Complexity S — quick win]
**Requirement(s):** supports 28. **Current state:** these header indicators are hardcoded `true` on every admin page, never reflecting actual Wazuh/indexer/backend health. **Proposed solution:** wire to the existing `/api/platform/health` endpoint. **Dependencies:** pairs naturally with C8.

### D5 — Fix the mock-data organisation "Setup" path [P1, Complexity S]
**Requirement(s):** 34. **Current state:** `/admin/settings/organisations` lists `MOCK_ORGS`, and its "Setup" wizard writes `org_setup` rows keyed to non-existent mock ids — an admin trying to configure a real organisation through the obvious path silently creates orphaned data. **Proposed solution:** point the listing and the wizard at the real `organisations` table. **Dependencies:** none.

### D6 — Write and publish OpenAPI documentation [P2, Complexity M]
**Requirement(s):** 30, 36, 48. **Current state:** no OpenAPI/Swagger/Postman artifact exists anywhere; ~66 internal route files have no versioning scheme. **Proposed solution:** generate an OpenAPI spec from the existing Zod schemas already used for request validation (`vmsWorker.ts` and others already define Zod objects — these can largely drive spec generation rather than hand-writing one) and publish it; introduce `/api/v1/` versioning going forward. **Dependencies:** none, but should follow A3 so documentation describes the reconciled API surface, not a soon-to-change one.

### D7 — Load-test at target scale [P2, Complexity M, needs a non-production environment]
**Requirement(s):** 29. **Current state:** index design looks correct; zero load-test evidence exists. **Proposed solution:** run a synthetic load test (thousands of assets, 100+ organisations) in a staging environment and record actual latency/throughput numbers — do not claim scale readiness without this. **Dependencies:** a staging environment with production-like data volume (infrastructure the audit was not authorized to provision or test against live).

### D8 — Retire the legacy UI layer; promote the VMS/TI/CNII kit platform-wide [P2, Complexity L]
**Requirement(s):** general usability supporting all frontend-visible requirements. **Current state:** two competing design systems coexist; the dashboard/header/legacy `components/shared/*` layer is visibly a generation behind the VMS/TI/CNII kit. **Proposed solution:** per the redesign blueprint, promote `features/vms/{kit,ui,table,charts}` to a platform-wide `components/ds/*` and rebuild the dashboard/header onto it; remove `RightRail` (nothing depends on it) and the legacy Nigeria map components once the dashboard is rebuilt on the TI map component. **Dependencies:** should follow D3/D4 (fix honesty defects before a visual refresh makes a still-dishonest surface *more* convincing, per the redesign blueprint's own sequencing note).

### D9 — Global, platform-wide organisation-context switcher [P1, Complexity M]
**Requirement(s):** supports 16, 18, 27 visibility. **Current state:** an org switcher exists only inside the VMS shell (`lib/vmsOrg.ts`, sessionStorage). **Proposed solution:** promote to a platform-wide header chip ("Viewing: \<org\>") shown on every page when staff are viewing a client's data — already fully designed in the prior V2 audit (§4.4), adopted unchanged here. **Dependencies:** none.

---

## Quick wins (no migration, no new infrastructure, days not weeks)

1. **D1** — hide `BROKEN` nav items (one-line filter change).
2. **D3** — "Unavailable to your role" state on 5 confirmed sites.
3. **D2** — promote VMS into the main sidebar.
4. **D4** — wire header status pills to real health data.
5. **C8** — call the already-built UptimeRobot client from a job instead of a CLI script.
6. **C2** — add one permission check to the intel-collection route.
7. **D5** — point the organisation "Setup" wizard at real data instead of `MOCK_ORGS`.

## Critical path before any further feature work

**A1 / C1** (merge the P26 fix; close the brand/urlscan/webscan leaks) are both P0, both Complexity S, and both are confirmed, exploitable cross-tenant data leaks — these should ship before anything else in this plan, including the quick wins above, since they are security fixes, not usability improvements.
