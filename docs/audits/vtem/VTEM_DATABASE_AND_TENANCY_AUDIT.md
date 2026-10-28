# VTEM Audit — Part 6: Database and Multitenancy

**Scope of this document:** Requirement 16 (Logical Separation/RBAC — database-scoping half only; application-layer RBAC is covered in `VTEM_SECURITY_AND_INTEGRATIONS_AUDIT.md`), Requirement 27 (Strict Data Separation — schema and query-isolation evidence), and a narrow contribution to Requirement 29 (Large-Scale Asset Monitoring — indexing/query-efficiency evidence only; worker concurrency and job-queue scaling are covered elsewhere).

**Branch convention used throughout this document** (see the audit's own repository-verification rule — do not assume HEAD):
- **Primary line** = `C:\Users\USER\NovrSOC`, branch `marketing-pages-merge` (= `main` + 5 website commits). Migrations present through `backend/sql/2026-10-30_p25_ti_v1.sql`. This is what is deployed today unless a maintainer confirms otherwise — **unverified from the repo alone**.
- **Unmerged line** = `C:\Users\USER\novr-vms`, branch `feat/vms-onboarding`, tip `3bd3a6e`. Contains two migrations **not present on the primary line**: `backend/sql/2026-10-31_p26_ioc_cache_tenancy.sql` and `backend/sql/2026-11-01_p27_vms_onboarding.sql`. `git merge-base` between these two lines is `9429743`; every commit after that point diverged and was never reconciled. **Nothing from this line should be credited to the primary line's security posture.**

All statuses use the audit's vocabulary: COMPLETE / PARTIAL / MISSING / UNVERIFIED / NOT APPLICABLE. All claims cite file paths and line numbers. This is a read-only review — no migration was applied, no live database was queried.

---

## 1. How isolation actually works here (read this before the risk register)

There is **no multi-tenant Row-Level Security** in this schema. `backend/src/db/rls-policies.sql:1-19` states this explicitly: the only tables with RLS policies are 8 reference/cache tables (`ip_enrichment_cache`, `nigerian_asns`, `nigeria_state_threats`, `ioc_enrichments`, `host_packages`, `vulnerability_matches`, `url_scans`, `website_scans`), each given exactly one policy — `service_role_all` — which is not a tenant filter, it is a bypass for the backend's own service-role connection. The file's own comment: *"this backend has no org_id / per-user auth model for this data yet... Writing org_isolation policies against tables/columns that don't exist wouldn't just be inert — enabling RLS in the same pass with no matching policy for a table locks every client out of it."*

**Practical consequence:** every tenant-data table in this schema (`vms_*`, `cases`, `alerts`, `cnii_*`, `ti_*`, `ioc_enrichments`, etc.) enables RLS with the *same* single `service_role_all` policy pattern (verified across every migration below) and relies **entirely on application code** — `lib/orgScope.ts`, `lib/resolveOrg.ts`, `lib/permissions.ts`, and each route handler's own `.eq('org_id', ...)` — to keep one organisation's data from another's. The database provides zero defense-in-depth: a single missing `.eq('org_id', ...)` in a route is a complete, silent cross-tenant leak, because the connection itself (service-role key) can read any row in any table. This is the lens for every finding below — the question is never "does RLS protect this table" (it structurally cannot, by design), it is "does every single read path filter by org."

---

## 2. Table inventory

Grouped by domain. "Tenant column" = how the table is attributed to an organisation. "RLS" = enabled/not, and whether the policy is a real tenant filter or a service-role bypass (per §1, it is a bypass on every table below unless stated otherwise).

### 2.1 Identity, organisations, RBAC

| Table | Tenant column | RLS | Key indexes | Notes |
|---|---|---|---|---|
| `organisations` | `id` (UUID) / `slug` (TEXT) — **slug is the `org_id` string used everywhere else** | **NOT ENABLED** — grep across every file in `backend/sql/*.sql` for `organisations.*ENABLE ROW LEVEL` returns no matches | `organisations_slug_key` (unique, `sql/2026-09-organisations-onboarding.sql:20`) | Holds `contact_name`, `contact_email`, `contact_phone`, `ciso_name`, `ciso_email`, `address` — PII. See Risk R-2. |
| `platform_users` | `org_id` (references `organisations.id`) | Enabled, service-role bypass (`sql/2026-09-organisations-onboarding.sql:32-35`) | `platform_users_email_lower_key` (unique, `sql/2026-10-14_p2_identity_audit.sql:15`) | Role is a free-text column (`super_admin`/`soc_manager`/`analyst`/`portal_user`/`executive`), not a normalised `roles` table — RBAC is enum-in-code (`backend/src/lib/permissions.ts`), not DB-governed. Not a defect per se, but means role definitions cannot be audited from the schema alone. |
| `auth_links` | via `user_id` → `platform_users` | Enabled, bypass (`p2_identity_audit.sql:53-58`) | `auth_links_user_idx` | One-time invite/reset tokens, SHA-256 hashed at rest (`p2_identity_audit.sql:18-19`). |
| `staff_org_assignments` | `org_slug` (FK → `organisations.slug`, `ON DELETE CASCADE`) | Enabled, bypass (`p21_staff_org_assignments.sql:24-29`) | `staff_org_assignments_org_idx`; unique `(user_id, org_slug)` | **P21.** This is the analyst cross-org access-control table consumed by `lib/resolveOrg.ts:66-73,88-98` — fails closed (no table/lookup error ⇒ deny) per `resolveOrg.ts:71-72`. Correctly designed. |
| `org_access_audit` | `home_org` / `target_org` | Not explicitly re-stated in its own migration, but written via `lib/resolveOrg.ts:38-60` | — (not inspected for an index; low write volume) | Logs every staff cross-org access. `resolveOrg.ts:56-59` warns-and-continues if the insert fails (audit entry still lands in the in-process log) — availability over strict audit durability; acceptable trade-off for a UX page, weaker for a compliance-grade audit trail (Requirement 25 territory, not scored here). |

### 2.2 VMS — scope, assets, jobs, findings, remediation

All from `sql/2026-10-14_p4_vms_asm.sql` and `sql/2026-10-14_p5_vms_findings.sql` unless noted. Every table in this group has `org_id TEXT NOT NULL`, RLS enabled, one service-role policy, and at least one `(org_id, ...)` composite index — this group is the most consistently well-built part of the schema.

| Table | Tenant scoping evidence | Indexes |
|---|---|---|
| `vms_scopes` | `org_id NOT NULL` (`p4:12`); unique active key is `(org_id, kind, lower(value))` (`p4:28`) — **two different orgs can hold the identical scope value** (e.g. a shared vendor domain) without collision, which is correct | `vms_scopes_org_idx (org_id, status)` |
| `vms_scan_jobs` | `org_id NOT NULL` (`p4:33`) | `vms_scan_jobs_org_idx (org_id, requested_at DESC)`; global `vms_scan_jobs_queue_idx (status, requested_at)` for the worker claim query |
| `vms_assets` | `org_id NOT NULL` (`p4:62`); unique `(org_id, asset_type, value)` (`p4:80`) — **the same hostname in two organisations is two distinct rows**, correct for a shared-infrastructure/reseller scenario | `vms_assets_org_seen_idx (org_id, last_seen DESC)` |
| `vms_services`, `vms_technologies` | `org_id NOT NULL`, but keyed off `asset_id` (which is already org-scoped) — no direct `(org_id,...)` index on either | unique `(asset_id, port, protocol)` / `(asset_id, name, version)` |
| `vms_asset_events` | `org_id NOT NULL` (`p4:116`) | `vms_asset_events_org_idx (org_id, at DESC)` |
| `vms_findings` | `org_id NOT NULL`; unique dedupe key is `(org_id, dedupe_key)` (`p5:68`) — correct, prevents one org's dedupe from swallowing another's identical finding | `vms_findings_org_status_idx (org_id, status, priority)`, `vms_findings_cves_idx` GIN on `cve_ids` |
| `vms_finding_evidence`, `vms_finding_events` | `org_id NOT NULL`, keyed off `finding_id` | indexed by `(finding_id, ...)` only — fine, access is always finding-first |
| `vms_remediation_tasks` | `org_id NOT NULL` (`p5:101`) | `vms_remediation_tasks_org_idx (org_id, status, due_at)` |
| `vms_wazuh_sync` | `org_id` is the primary key itself (one row per org) | — |
| `cve_intel` | **No `org_id` — intentionally global/shared.** Comment at `p5:4`: *"shared, not per organisation: public data."* Correct — CVE/CWE/CVSS/EPSS/KEV data is reference data, not tenant data. | `cve_intel_kev_idx` (partial, `WHERE kev`) |
| `vms_scope_approvals` (P27, **unmerged line only**) | `org_id NOT NULL`, immutable via an `UPDATE/DELETE`-blocking trigger (`p27:87-91`) | `vms_scope_approvals_org_idx (org_id, decided_at DESC)` |

**Assessment: COMPLETE** for tenant-column presence and indexing discipline in the VMS core. No cross-org leak found in this group's schema design. (This says nothing about whether every *route* that reads these tables filters correctly — that is checked per-route below and is Fork B's deeper territory for the rest of the API surface.)

### 2.3 CNII Watch

From `sql/2026-10-cnii-assets.sql`, `p9_cnii.sql`, `2026-10-23_p17_cnii_intake.sql`, `2026-10-24_p18_cnii_authorisation.sql`.

| Table | Tenant scoping | Notes |
|---|---|---|
| `cnii_org_profiles` | `org_id TEXT PRIMARY KEY` — one profile per org | Sector classification (`sector_id`, `designation`). |
| `cnii_profile_events` | `org_id NOT NULL` | History of classification changes. |
| `cnii_submissions` | **`org_id` is nullable** (`p17:27`: *"organisations.slug, once linked"*) and `value` has a **global** `UNIQUE` constraint (`p17:22`), not per-org. This is deliberate, not a bug: a submission is an open question ("who owns this domain?") that by definition starts unattributed, and a value can only ever resolve to one real owner — see `p17:6-13`. Flagged here only so it is not mistaken for a missed `org_id` requirement elsewhere in this report. | `cnii_submissions_org_idx`, `cnii_submissions_status_idx` |
| `vms_observations` | `org_id NOT NULL` (`p9:77`) | Passive-intel sightings; unique `(asset_id, source, kind, key)`. |
| `cnii_assets` (legacy, pre-P9) | **No `org_id` in its original definition** (`2026-10-cnii-assets.sql`, not re-inspected line-by-line here); P9 adds `imported_org_id`/`imported_asset_id` columns (`p9:127-132`) as a one-way migration path into the org-scoped `vms_assets` model — i.e., the legacy table is explicitly being retired in favour of the scoped one, not fixed in place. | — |

**Assessment: COMPLETE** for the current (P9+) CNII model; the pre-P9 `cnii_assets` legacy table is a known, explicitly-labelled transitional artifact, not an active risk, provided nothing still writes to it outside the import path (not independently verified — flag as **UNVERIFIED** whether any route still reads/writes `cnii_assets` directly).

### 2.4 Threat Intelligence

From `sql/2026-10-15_p6_threat_info.sql`, `2026-10-30_p25_ti_v1.sql`, and the global `nigeria_advisories` / `threat_pulses` tables (`sql/2026-09-threat-intel.sql`).

| Table | Tenant scoping | Notes |
|---|---|---|
| `ti_indicators`, `ti_indicator_sources`, `ti_indicator_geo` | No `org_id` visible in the Appendix-C reference count context — these are **shared indicator data** (MISP/feed-sourced IOCs before per-org attribution), consistent with `ti_matches(org_id)` being the actual tenant-attribution point (per `NOVRSOC_REDESIGN_TECHNICAL_AUDIT_V2.md` Appendix C key-relationships note: *"`ti_indicators` ← ... `ti_matches(org_id)`"*). **Not independently re-verified from the raw SQL in this pass — UNVERIFIED**, carried forward from the primer audit rather than re-derived; Fork A/B should confirm `ti_matches` is the only read path client-facing code uses. |
| `ti_feeds`, `ti_feed_runs` | Global — feed configuration and sync run history are platform-wide, not per-tenant (correct: there is one MISP/OpenCTI/OTX integration, shared across tenants). |
| `ti_reports` | Not re-inspected directly; per Appendix C used by `tiReports.ts`/`tiMap.ts`. **UNVERIFIED** org-scoping — flag for Fork A. |
| `nigeria_advisories`, `threat_pulses` | Global, intentionally — national/public advisories, no tenant attribution needed. `routes/search.ts:48-50` reads `nigeria_advisories` with no org filter, which `NOVRSOC_REDESIGN_TECHNICAL_AUDIT_V2.md` F-18 already flags as correct *only as long as it stays global data* — if TLP-marked P25 TI reports are ever added to this same search path, they would need explicit TLP filtering first. Treat this as a standing constraint on future work, not a current defect. |

### 2.5 IOCs, enrichment cache — **the flagship finding (R-1)**

See §3.1 below — this gets its own section because it is the clearest, most concretely evidenced cross-tenant disclosure in the codebase, with a complete fix that exists but is not merged.

### 2.6 SecOps — alerts, cases, response

From `sql/2026-10-09_alerts_pipeline.sql`, `2026-09-cases-soar.sql`, `2026-10-14_p3_secops_ai.sql`, `2026-10-29_p24_wazuh_sources.sql`.

| Table | Tenant scoping | Notes |
|---|---|---|
| `alerts` | `org_id` (per Appendix C; 32 references) | `alerts_org_assigned_idx (org_id, assigned_to) WHERE assigned_to IS NOT NULL` (`p3:11`); `alerts_case_idx`. |
| `alert_events` | `org_id NOT NULL`, FK `alert_id → alerts(id) ON DELETE CASCADE` (`p3:17-18`) | |
| `cases`, `case_tasks`, `case_notes`, `case_timeline`, `case_iocs` | `org_id` (per Appendix C); `cases` has a unique-per-org constraint added later (`sql/2026-10-08_cases_unique_per_org.sql`, not re-read in this pass) | |
| `response_approvals` | `org_id NOT NULL` (`p3:37`); **at most one open request per `(org_id, action, target)`** via a partial unique index (`p3:57`) — correct, prevents duplicate concurrent approval requests for the same consequential action. | `response_approvals_org_status_idx` |
| `wazuh_group_org_map`, `wazuh_source_org_map` | `org_id` — this is the ownership source-of-truth consumed by `lib/orgScope.ts:140-166`. **Fail-closed design, verified in code:** an agent whose groups map to more than one organisation belongs to **none** of them (`orgScope.ts:141-145,154-157` — `orgs.length === 1` is required); an unmapped syslog sender is owned by nobody (`orgScope.ts:13`); when the maps or agent list cannot be loaded at all, `orgScope()` throws `ScopeError(503)` rather than returning an unfiltered scope (`orgScope.ts:104,110,116,125`). This is the strongest-designed isolation boundary in the codebase — no fallback-to-everything path exists anywhere in it. | `wazuh_group_org_map`/`wazuh_source_org_map` (not line-inspected for index names) |
| `ai_requests`, `ai_artifacts` | `org_id` (nullable on `ai_requests`, `NOT NULL` on `ai_artifacts`) | `ai_artifacts_subject_idx (org_id, subject_type, subject_id, created_at DESC)`. |

**Assessment: COMPLETE** for schema-level tenant scoping and indexing in this group. The Wazuh ownership-resolution design (`orgScope.ts`) is worth calling out as an exemplar other integrations should follow.

### 2.7 No table exists for: benchmarking, structured notification/acknowledgement tracking

- **Benchmarking (Requirement 14):** `grep -i benchmark` across the entire `backend/` tree returns **zero files**. There is no `benchmark*` table, no aggregation view, nothing. **Requirement 14 is MISSING at the database layer, full stop** — there is no schema to even partially support anonymised provider benchmarking (patch cadence, exposure density, cohort sizing). This is a schema-design task from scratch, not a scoping fix.
- **Intelligence-distribution acknowledgement tracking (Requirement 13):** no table in Appendix C or in the migrations read for this pass is named anything like `distribution_log`, `notification_log`, or `acknowledgement`. `ai_artifacts`/`audit_log`/`org_access_audit` are the closest adjacent structures but none of them model "stakeholder X was sent intelligence Y, acknowledged at time Z, escalated after no response." **Likely MISSING at the database layer** — flagged for Fork A to confirm there is no persistence for this anywhere in `services/`, since a purely in-memory or fire-and-forget email implementation (no DB row at all) would be consistent with the `orgCtiStore.ts` precedent in §3.2 below.

---

## 3. Isolation risk register (ranked by severity)

### R-1 — CRITICAL — Confirmed cross-tenant IOC-enrichment disclosure on the primary line; fix exists but is unmerged

**What leaks:** On the primary line (`NovrSOC`, `marketing-pages-merge`), the `ioc_enrichments` table has a single global primary key on `ioc_value` alone (`backend/novrsoc_supabase_schema.sql:95`: `ioc_value text primary key`) — there is **no `org_id` column on this table at all** on the primary line. Every authenticated user of every organisation reads and writes the same global row set:

- `GET /api/cti/feed` — `backend/src/routes/cti.ts:92-97` — `supabase.from('ioc_enrichments').select('*')...` — **no `.eq('org_id', ...)`**.
- `GET /api/cti/stats` — `cti.ts:134` — `supabase.from('ioc_enrichments').select('risk_score')` — **no org filter**.
- `GET /api/intelligence/stix` and `/stix/summary` — `backend/src/routes/intelligence.ts:32-37,74-77` — builds a STIX export described in the route's own comment as *"the org's accumulated intelligence in one file"* (`intelligence.ts:2`), but the query has **no org filter** — it is every organisation's accumulated intelligence, downloadable by any signed-in user via `GET /api/intelligence/stix?download=true`.
- `GET /api/search` (IOC branch) — `backend/src/routes/search.ts:52-53` — `supabase.from('ioc_enrichments').select(...).ilike('ioc_value', like)` — **no org filter**, three lines below a `cases` query on the same route that *is* correctly scoped (`search.ts:41-44`: `.eq('org_id', orgId)`), and in direct tension with the route's own header comment at `search.ts:25-26`: *"the org scope must not be something the search box can widen."*

This is not a theoretical risk — it is a live, exploitable read path for every analyst/executive account against every other organisation's IOC lookup history (which values an org has investigated, their risk scores, the escalation notes a peer org attached via `routes/secops.ts`).

**The fix exists, is complete, and is tested — but only on the unmerged `feat/vms-onboarding` line:**
- `novr-vms/backend/sql/2026-10-31_p26_ioc_cache_tenancy.sql` — adds `org_id`, replaces the `ioc_value`-only primary key with a surrogate `id` + unique `(org_id, ioc_value)`, and explicitly attributes legacy rows with no `org_id` to **nobody** (fail-closed: migration comment at lines 13-15: *"Rows without one... are attributed to nobody, so no organisation sees them."*).
- `novr-vms/backend/src/routes/cti.ts:103,143`, `intelligence.ts:12,38,81` (`router.use(requireOrg)` plus `.eq('org_id', requestOrg(req))` on every query), `search.ts:53`, `secops.ts:107-118` all add the org filter.
- `novr-vms/backend/src/routes/__tests__/iocCacheTenancy.test.ts` — a dedicated P26 test suite proving: each org's lookup writes only its own row; a second org escalating the same IOC value does not take over or overwrite the first org's row; legacy unattributed rows are shown to nobody.

**Verdict:** CONFIRMED on the primary/deployed line (Requirement 27: MISSING). CONFIRMED FIXED on the unmerged line (if and when merged, this specific leak becomes COMPLETE). **Do not credit the primary line with this fix under any circumstance** — the audit's own instruction not to assume P26 resolves tenant isolation is directly borne out here: P26 resolves *this one* leak, nothing else, and only once merged.

**Remediation:** cherry-pick or merge `feat/integration-sprint`/`feat/vms-onboarding`'s P26 commit (`5857078`/`8c6e65b` lineage) onto the primary line, or reapply the migration and the four route diffs directly. Complexity: **S** (the fix is already written and tested) — the only work is the merge/reconciliation itself, which given the 5-commit divergence and unrelated marketing changes on the primary line should be a straightforward cherry-pick, not a rewrite.

### R-2 — HIGH (likelihood currently low-to-unverified) — `organisations` table has no RLS and no explicit REVOKE

`organisations` is the one table in this schema that every other table's `org_id`/`org_slug` ultimately resolves against, and it holds direct PII: `contact_name`, `contact_email`, `contact_phone`, `ciso_name`, `ciso_email`, `address` (per `sql/2026-09-organisations-onboarding.sql:6-9`'s description of existing columns). A targeted search of every file in `backend/sql/` for `ENABLE ROW LEVEL SECURITY` applied to `organisations` returns **no matches** — unlike the 8 reference-cache tables (`rls-policies.sql:23-65`), which get both RLS *and* an explicit `REVOKE ALL ... FROM anon, authenticated`, `organisations` gets neither.

In a default Supabase project, PostgREST exposes every table in the `public` schema through the REST API, and the `anon`/`authenticated` roles typically hold default grants on the `public` schema unless explicitly revoked. With no RLS and no revoke, a client holding the project's anon/publishable key could, in principle, `SELECT * FROM organisations` directly through Supabase's auto-generated REST endpoint, bypassing this backend's application-layer checks entirely.

**Likelihood check performed:** grepped `frontend/src` for `NEXT_PUBLIC_SUPABASE`, `createClient(...supabase...)`, and `SUPABASE_ANON` — **zero matches**. The frontend does not appear to hold or use a Supabase client-side key anywhere in this repo, and `backend/.env.example` has no `ANON_KEY`/`anon_key` entry either. So the most common way this kind of gap becomes exploitable (an anon key shipped in a client bundle) is **not present in this codebase as far as it can be checked**. **Status: UNVERIFIED** whether the live Supabase project's actual role grants/API settings close this gap independently (e.g., the project's PostgREST exposure could be restricted outside of what's visible in this repo) — this cannot be settled by static analysis alone.

**Remediation:** enable RLS on `organisations` with a service-role-bypass policy, matching every other table's pattern (this is a one-line, zero-risk addition — `ALTER TABLE public.organisations ENABLE ROW LEVEL SECURITY; CREATE POLICY ... USING (auth.role() = 'service_role');`), and add it to the same migration-pattern checklist used everywhere else. Complexity: **S**. Also confirm live, out of band, whether the Supabase project has ever issued or exposed an anon/publishable key — if one exists anywhere (support tooling, a script, a forgotten `.env`), this table is reachable today.

### R-3 — MEDIUM — Manual/shared IOC store is in-memory only, not backed by any table

`backend/src/lib/orgCtiStore.ts:193-227` — the entire "manual/analyst-added IOC" store (`manualIOCStore`) is a module-level `Map<string, OrgIOC[]>`, explicitly documented as a stopgap (`orgCtiStore.ts:6-7`: *"Replace with Supabase once a real schema exists... mirrors routes/threatManagement.ts's existing 'module-level mutable cache, live until process restart' pattern"*). The org-keying itself is implemented correctly (every accessor takes `orgId` and the Map is keyed by it), so this is **not a tenant-isolation bug** — but it means:
- Every manually-added/escalated IOC and every "shared" flag (`allSharedManualIOCs()`, `orgCtiStore.ts:221-223`) is lost on process restart.
- In a horizontally-scaled deployment (more than one backend instance), different instances hold different, inconsistent copies of this data — a correctness problem for Requirement 29 (scaling to 100+ licensed entities implies more than one instance eventually) and for Requirement 13 (acknowledgement/escalation state that must be durable and auditable).

This is the same underlying gap noted in §2.7 for distribution/acknowledgement tracking generally — there is a recurring pattern in this codebase of using in-memory accumulators (see also `wazuhAccumulator` in the same file, `orgCtiStore.ts:65-76`, which is correctly org-scoped on read but also not persisted) where a durable, auditable table is what Requirement 10/12/13/25 actually need.

**Remediation:** promote `manualIOCStore` to a real table (`org_id`, `value`, `type`, `verdict`, `shared`, etc. — the `OrgIOC` interface at `orgCtiStore.ts:18-35` is already a usable schema). Complexity: **M** (schema + migration + rewiring every accessor to async Supabase calls instead of synchronous Map operations, plus whatever call sites assume synchronous behaviour).

### R-4 — LOW / architectural note — RBAC roles are an enum in code, not a database table

No `roles` or `permissions` table exists; `platform_users.role` is a free-text column constrained only by application code in `backend/src/lib/permissions.ts` (not fully re-read in this pass — ownership of deep RBAC analysis belongs to the security/integrations fork). This is a common, defensible pattern, but it means role definitions, their permission sets, and any change to them are not independently auditable from the schema or from SQL migrations — a GRC reviewer (Requirement 20) working only from the database would not be able to answer "what can a `soc_manager` do" without reading TypeScript. Not scored as a defect; noted because Requirement 16 explicitly asks for role-based access to be verifiable, and right now that verification can only happen by reading application code, not by inspecting the database.

### R-5 — INFORMATIONAL — carried forward from the existing V2 technical audit, not re-derived here

`NOVRSOC_REDESIGN_TECHNICAL_AUDIT_V2.md` §3 already documents several **application-layer** (not database-layer) cross-tenant exposures consistent with the "no DB backstop" pattern in §1 above: F-01 (`/api/brand/*` — one shared list for all tenants, confirmed), F-02 (`urlscan`/`webscan` history unfiltered, confirmed), F-03 (`portal/scan` history takes an unverified JWT org claim), F-12 (any non-portal role can trigger an external collector write). These are out of this document's scope (they are route/service-layer findings, not database-schema findings) but are flagged here so the 49-requirement matrix does not double-count or contradict them — they should be cited from the V2 audit's own line numbers, not re-verified in this pass.

---

## 4. Requirement 29 contribution — indexing and query-efficiency evidence only

Every tenant-scoped table inspected in §2.2, §2.3, §2.6 carries at least one composite index with `org_id` as the leading column (typically `(org_id, status)`, `(org_id, last_seen DESC)`, or `(org_id, status, priority)`), which is the correct shape for the dominant query pattern (list this organisation's open items, ordered by recency or priority). The `vms_findings_cves_idx` GIN index on `cve_ids` (`p5:71`) is appropriate for cross-asset CVE correlation. The worker job queue (`vms_scan_jobs_queue_idx (status, requested_at)`, `p4:54`) is a global (not per-org) index deliberately, since the worker claims across all organisations' queued jobs — correct for that access pattern, and the `vms_claim_job` function (`p4:137-150`) uses `FOR UPDATE SKIP LOCKED`, the correct Postgres idiom for concurrent multi-worker job claiming without contention.

**What this does *not* establish:** there is no load-test evidence, no query-plan (`EXPLAIN ANALYZE`) output, and no measurement of behaviour at the stated target scale (thousands of assets across 100+ licensed entities) anywhere in the repository. Index *design* is sound; index *sufficiency at scale* is **UNVERIFIED** — this requires either a live staging-environment load test or production telemetry, neither of which is available from static repository inspection. Per the audit's own rule, this is explicitly not claimed as COMPLETE.

---

## 5. Summary table for the 49-requirement matrix

| Requirement | DB-layer status | Evidence | Primary gap |
|---|---|---|---|
| 16 — Logical Separation/RBAC (DB half) | **PARTIAL** | §2 (tenant columns + indexes present on every tenant table except the R-1 exception); §1 (no RLS tenant filter anywhere, by design) | No DB-level backstop anywhere; R-1 is a live hole in the one place the backstop would have mattered most |
| 27 — Strict Data Separation | **PARTIAL**, with one **MISSING** sub-case (R-1, primary line) and that same sub-case **COMPLETE** on the unmerged line | §3.1 | Merge P26; fix R-2; promote R-3 to durable storage |
| 29 — Large-Scale Monitoring (indexing contribution only) | **PARTIAL** (design COMPLETE, scale **UNVERIFIED**) | §4 | No load-test evidence exists in-repo |
| 14 — Anonymised Provider Benchmarking (DB existence) | **MISSING** | §2.7 | No table, no aggregation, nothing — ground-up schema work |
| 13 — Distribution acknowledgement tracking (DB existence) | **MISSING** or **UNVERIFIED** (pending Fork A confirmation of service-layer persistence) | §2.7 | No table found; may be fire-and-forget with no durable record |

---

## 6. Evidence index (file:line, for `VTEM_AUDIT_EVIDENCE_INDEX.md`)

- `backend/src/db/rls-policies.sql:1-19,23-65` — RLS scope and rationale; the only 8 tables with real anon/authenticated denial.
- `backend/novrsoc_supabase_schema.sql:90-111` — pre-P26 `ioc_enrichments` definition, global PK on `ioc_value`.
- `backend/src/routes/cti.ts:92-97,134` — unscoped `ioc_enrichments` reads (primary line).
- `backend/src/routes/intelligence.ts:2,32-37,74-77` — unscoped STIX export (primary line).
- `backend/src/routes/search.ts:25-27,41-44,52-53` — scoped `cases` query beside unscoped `ioc_enrichments` query in the same handler.
- `novr-vms/backend/sql/2026-10-31_p26_ioc_cache_tenancy.sql:1-60` — the fix, unmerged.
- `novr-vms/backend/src/routes/cti.ts:56-58,101-103,143`; `intelligence.ts:12,38,81`; `search.ts:53`; `secops.ts:107-118` — the fix applied, unmerged.
- `novr-vms/backend/src/routes/__tests__/iocCacheTenancy.test.ts:1-102` — the fix, tested, unmerged.
- `backend/sql/2026-09-organisations-onboarding.sql:6-9,20,32-35` — `organisations` columns and the RLS gap (platform_users gets RLS in the same file; organisations does not).
- `backend/src/lib/orgScope.ts:104,110,116,125,141-145,154-166` — fail-closed Wazuh ownership resolution, no fallback-to-everything path.
- `backend/src/lib/resolveOrg.ts:62-73,75-102` — fail-closed analyst cross-org resolution, full audit trail.
- `backend/src/lib/orgCtiStore.ts:6-7,18-35,193-227` — in-memory, non-durable manual IOC store.
- `backend/sql/2026-10-14_p4_vms_asm.sql`, `2026-10-14_p5_vms_findings.sql`, `2026-10-17_p9_cnii.sql`, `2026-10-23_p17_cnii_intake.sql`, `2026-10-24_p18_cnii_authorisation.sql`, `2026-10-27_p21_staff_org_assignments.sql`, `2026-10-14_p2_identity_audit.sql`, `2026-10-14_p3_secops_ai.sql` — full schema evidence for §2.
- `novr-vms/backend/sql/2026-11-01_p27_vms_onboarding.sql:1-103` — unmerged scope-approval workflow and its immutability trigger.
- `NOVRSOC_REDESIGN_TECHNICAL_AUDIT_V2.md:141-168` (§3) and `:1671-1778` (Appendix C) — primer material, cross-referenced not re-derived, per R-5.
- `PRODUCTION_NOTES.md:55-57` (item 6) — independent, live-verified confirmation that multitenancy is partial and several routes are unscoped, consistent with every finding above.
