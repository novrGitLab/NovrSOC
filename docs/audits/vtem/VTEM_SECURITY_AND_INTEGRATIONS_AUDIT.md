# VTEM Security & Integrations Audit

Scope: VTEM Requirements 11 (Open XDR), 15-18 (Portal/RBAC/NCC-CSIRT/Provider isolation), 20 (GRC), 24-27 (MFA/Audit/SSO/Data separation), 30-31 (Open APIs/Workflow APIs); Part 7 (Security & Reliability) and Part 8 (Integration Audit) of the VTEM audit spec.

**Audit target.** `C:\Users\USER\NovrSOC`, branch `marketing-pages-merge` (= `main` + 5 marketing commits). Backend history runs through **P25** (Threat Intelligence V1). A separate, **unmerged** worktree `C:\Users\USER\novr-vms` (branch `feat/vms-onboarding`) carries **P26** (per-organisation IOC lookup cache, incremental read-only MISP sync hardening) and **P27** (VMS onboarding) — two SQL migrations (`2026-10-31_p26_ioc_cache_tenancy.sql`, `2026-11-01_p27_vms_onboarding.sql`) that do not exist in this branch's `backend/sql/`. Every finding below is against `NovrSOC` unless explicitly marked "on `novr-vms` only." Confidence in `novr-vms` findings is lower — they were not independently re-verified here beyond confirming the two migration files exist on disk there.

Status vocabulary follows the audit spec: COMPLETE / PARTIAL / MISSING / UNVERIFIED / NOT APPLICABLE for backend/security/integration; six-point classification for each integration (Implemented and live-verified / Implemented but not live-verified / Partially implemented / Configured only / Planned / Missing).

---

## Part 7 — Security and Reliability Audit

### 7.1 Authentication and session handling

**Evidence:** `backend/src/routes/auth.ts:12-43`, `backend/src/middleware/auth.ts:28-58`.

- Staff sign-in is password-based: `platform_users.password_hash` (bcrypt), set via a one-time link a `super_admin` issues (`routes/users.ts`, not independently re-read this pass). 5 failed attempts lock the account 15 minutes (`MAX_FAILED_LOGINS=5`, `LOCK_MINUTES=15`, `auth.ts:26-27`). A timing-equalising dummy hash (`auth.ts:30`) prevents email-enumeration by response latency — a correct, non-obvious control.
- **Break-glass bypass**: `DEV_ADMIN_EMAIL`/`DEV_ADMIN_PASSWORD` issue a token with no password check, auditable, disablable via `DEV_ADMIN_LOGIN_ENABLED=false` (`auth.ts:14-20`). `PRODUCTION_NOTES.md` confirms this was, as of 2026-09-02, **the only working admin login path live** — Google OAuth and the real password path both depended on an unreachable legacy host (`APP_API_BASE_URL`, 502). That dependency has since been removed from `auth.ts`'s sign-in path per the comment at line 23 ("The old proxy to APP_API_BASE_URL is gone from sign-in"), but this was not re-verified against a live deployment in this pass — **UNVERIFIED** whether the real password path is live-reachable today.
- Tokens are HS256, hand-rolled HMAC (`auth.ts:36-43`), not a JWT library's `sign()` — functionally equivalent but worth noting as a maintenance risk (no library-level claim validation, e.g. no `exp` enforcement visible in `issueToken`; expiry enforcement must be checked at `requireAuth`'s `jwt.verify` call, which does use the `jsonwebtoken` library and so does honor `exp` if present in the payload — confirm `exp` is actually set wherever `issueToken` is called, not verified in this pass for every call site).
- `requireAuth` (`middleware/auth.ts:28-58`) fails closed on missing/invalid token (401) and on missing signing secret (500, not a silent bypass). `portal_user` tokens are confined server-side to `/api/client/*` regardless of a route's own logic (`auth.ts:51-53`) — a sound fail-closed design.

**Status: PARTIAL.** Core auth is sound and tested (101/101 route-gating/tenancy tests passed locally, §7.9), but there is no session revocation mechanism visible (no token blocklist/refresh-rotation), and the "real" password sign-in path's current live reachability is unverified.

### 7.2 MFA (Requirement 24)

**Searched:** `backend/src/**` for `mfa|totp|2fa|two-factor` (case-insensitive) — zero relevant matches (the only hits were unrelated: `tiGeo.ts`, `mitre.ts` etc. match "sso" as a substring of other words, not actual SSO code). No TOTP/WebAuthn/OTP library in `backend/package.json`.

**Status: MISSING.** There is no multi-factor authentication anywhere in the codebase, for any role, including `super_admin`. The spec requires MFA "for all administrator accounts" — this is not partially done; it does not exist. **This is a hard blocker for Requirement 24 and for any production go-live claim involving administrator accounts.**

### 7.3 SSO (Requirement 26)

**Evidence:** `backend/.env.example:24-25` (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`), `AUTH_EXEMPT_PATHS` includes `/api/auth/google` (`middleware/auth.ts:82`).

- The only SSO-adjacent capability is Google OAuth sign-in, not SAML and not generic OAuth/OIDC against an arbitrary identity provider. There is no SAML library in `package.json`, no OIDC discovery/metadata handling, and no visible mechanism for NCC's own identity provider to federate in.
- Per `PRODUCTION_NOTES.md` item 1, Google OAuth sign-in was **broken in production** (502, dependent on the since-presumably-removed legacy proxy) as of the last live check (2026-09-02). Not re-verified live in this pass.
- Role mapping on SSO sign-in (which role a Google-authenticated user receives) was not located in this pass — would need `routes/auth.ts`'s `/google` handler read in full (out of this fork's time budget; flagged for follow-up).

**Status: MISSING** against the literal requirement ("SAML/OAuth with NCC identity management"). Google OAuth existing is not SAML, and there is no NCC IdP integration of any kind. Even the Google path's live status is unverified.

### 7.4 RBAC and object-level authorization

**Evidence:** `backend/src/lib/permissions.ts` (full file read).

- Five roles (`super_admin, soc_manager, analyst, executive, portal_user`), a flat permission list (`PERMISSIONS`, 17 scopes spanning alerts/cases/response/VMS/intel/CNII/client), and a static `ROLE_PERMISSIONS` map (lines 55-65). `super_admin` and `soc_manager` are **identical** in permission scope today — there is no separation between "platform owner" and "SOC delivery manager," which matters for Requirement 17 (an oversight role needs to be distinct from an operational one, and isn't).
- There is **no "sector oversight" / "NCC-CSIRT" role** in `UserRole` (`middleware/auth.ts:22`: `'super_admin' | 'soc_manager' | 'analyst' | 'executive' | 'portal_user'`) or in `PERMISSIONS`. Confirmed by grep: zero matches for `ncc.?csirt|oversight` anywhere in `backend/src` except an unrelated hit in `services/serper.ts` (a Google-search wrapper, not a role).
- `requirePermission()` composes `requireAuth` + a permission check + mandatory organisation resolution (`permissions.ts:91-102`) — a token with a permission but no `org_id` is refused (403), not defaulted to a global view. This is the correct fail-closed shape and is enforced centrally, not per-route, which reduces the chance of a route forgetting the check.
- **However**, per `NOVRSOC_REDESIGN_TECHNICAL_AUDIT_V2.md` §3 (read in full this pass) and `PRODUCTION_NOTES.md` item 5, a documented set of routes are mounted with `requireAuth` only (no `requirePermission`), by design, because client-portal tokens can't yet be dual-verified against them: `wazuh`, `threats`, `threat`, `brand`, `dns`, `urlscan`, `webscan`, `org-cti`, `recovery`, `alerts` (narrowed from a longer list — `incidents`, `vendor-assessments`, `sla`, `weblogic`, `advisories` were since removed per the 2026-10-07 update note). Confirmed cross-tenant read/write exposure on `/api/brand/*` (F-01) and `/api/urlscan|webscan/history` (F-02) — **any staff or executive token, from any organisation, can read and in some cases write another organisation's data** on these routes. `/api/dashboard/nigeria-threats/collect` (F-12) lets any authenticated non-portal role trigger external-intel collection and MISP writes with no `intel:manage` check.

**Status: PARTIAL.** The RBAC *mechanism* (permission map, fail-closed org resolution) is well-built and tested. Its *coverage* is incomplete: a known, self-documented set of routes bypass it entirely, with at least two (F-01, F-02) confirmed to leak cross-tenant data to any staff/executive token. No oversight-tier role exists at all.

### 7.5 Tenant isolation (cross-reference only — Fork C owns the database-level audit)

Confirmed at the route layer by both static evidence (V2 §3) and local test execution (§7.9 below): `cases`, `soar`, `handover`, `search`, `communications`, `secops`/Wazuh routes, `security assessment`, and `ioc_enrichments` all correctly scope by `org_id` and were exercised by passing tests. The **known exceptions** are the routes named in §7.4 (F-01, F-02, F-12, F-16, F-17, F-18 per V2's numbering) — not a database schema defect, but an **authorization-layer** one: the tables themselves may be fine, but the routes reading/writing them don't filter.

### 7.6 Input validation, secrets, SSRF, exports

- **Input validation / sanitization middleware exists**: `backend/src/middleware/sanitize.ts`, `validate.ts` (not read line-by-line this pass; presence confirmed, depth UNVERIFIED).
- **TLS**: `lib/tlsGuard.ts` strips `NODE_TLS_REJECT_UNAUTHORIZED=0` at startup (per `misp.ts:9` comment and `.env.example:63-65`) rather than allowing it — a real, deliberate hardening decision, not a default. `lib/pinnedTls.ts` implements certificate pinning for self-signed internal services (MISP, confirmed in `misp.ts:96-101`; presumably Ollama per `.env.example:74-80`'s `OLLAMA_CA_CERT`).
- **Secrets**: `.env.example` is tracked, `.env` is git-ignored (confirmed, `.env.example:2`). `lib/redact.ts` exists (purpose: strip secrets from logs/exports — not read in depth). `lib/envGuard.ts` / `lib/runtimeEnv.ts` **refuse to start outside production unless `SUPABASE_URL` points at a database explicitly declared development/test** (`.env.example:4-7`) — a strong, unusual safeguard against accidentally running dev code against the production database. This is a genuine strength worth preserving in any redesign.
- **SSRF**: Not specifically audited this pass (would require reading `lib/scan.ts`, `services/urlscanio.ts`, `services/webscan`-adjacent fetch call sites for unrestricted outbound URL fetches triggered by user input). **UNVERIFIED** — flagged as a gap in this audit, not in the product; needs a dedicated pass given the platform fetches many user/organization-supplied URLs and domains (URL scan, webscan, brand monitoring, DNS lookups).
- **Webhook authentication**: `EMAIL_PROXY_TOKEN` (shared secret for the mail gateway, `.env.example:48`), `MAILGUN_WEBHOOK_SIGNING_KEY` (`.env.example:49`) — both present, suggesting webhook sources are authenticated, not re-verified line-by-line.

### 7.7 Audit trails (Requirement 25)

**Evidence:** `backend/src/lib/audit.ts` (full file read).

- `logAudit()` writes synchronously to a 1,000-entry in-memory ring buffer and asynchronously flushes to a Supabase `audit_log` table (`sql/2026-10-14_p2_identity_audit.sql`) in batches of 200, with retry (up to 5 tries) and backoff (`audit.ts:43-71`). Entries carry actor, action, resource, resource_id, org_id, ip, result, severity, details, and a timestamp (`audit.ts:11-28`).
- **Honest degradation**: if the table doesn't exist, it says so once in the server log and keeps entries in memory only rather than crashing or silently losing them permanently within the process lifetime (`audit.ts:53-57`) — but a restart with no table still loses everything that was only in memory. There's no durability guarantee until the migration is confirmed applied.
- `readAuditLog()` prefers the database, falls back to memory, and **reports which source answered** (`audit.ts:92-108`) — this is exactly the kind of honest-provenance behavior the VTEM spec asks the frontend to surface; confirm the Audit Log *page* actually displays `source` (frontend fork's territory, flagging here as a cross-cutting ask).
- Calls to `logAudit` were seen in `services/responseApprovals.ts:73` (approval requests) and are presumably scattered across sign-in, admin actions, exports etc. — **not exhaustively enumerated in this pass**; the spec's own caution ("do not equate a function existing with coverage") applies: whether *every* scan, access and configuration change is actually audited was not confirmed row-by-row. Based on the V2 audit's independent review (§16, not fully re-read here) and the breadth of `logAudit(...)` call sites implied by the severity/resource vocabulary, coverage looks broad but is **UNVERIFIED as exhaustive**.

**Status: PARTIAL.** The audit mechanism is real, tested in spirit (used by response-approval tests, §7.9), and has sensible failure behavior. Full-coverage claims ("all scans, access and configuration changes") are not independently confirmed, and durability before the P2 migration is applied is memory-only.

### 7.8 Dependency, retry, duplicate-processing and recovery behavior

- **Alert forwarder** (`infra/soar/README.md:69-79`): cursor-based (`search_after` on timestamp+id, not timestamp alone — the README documents a real incident where a timestamp-only cursor stalled for six days under burst load, and the fix is in place), retried on 429/5xx with exponential backoff (2/4/8/16/32s), re-sends a trailing overlap window periodically to catch stragglers, and the backend de-duplicates. This is genuine operational maturity with a documented incident-driven fix, not a theoretical design.
- **SOAR engine** (`infra/soar/README.md:59-67`): tiered response (enrich → auto-close / block+email / block+isolate+CISO-email) with explicit SKIPPED (config missing) vs FAILED (remote system rejected) vs SUCCESS (remote system confirmed) states, and isolation is logged as "REQUESTED" rather than "done," because the manager accepting a command doesn't confirm the endpoint executed it — an honest distinction, not oversold.
- **Response approvals** (`services/responseApprovals.ts`): consequential actions (`block_ip`, `isolate_agent`) require a second person's approval; self-approval is blocked unless explicitly configured for a one-person team (`responseApprovals.ts` + `.env.example:157-160`); re-checks organisation ownership of the target **at execution time**, not just at request time (`responseApprovals.ts:22-28`) — closes a TOCTOU gap where an agent's org could change between request and approval.
- **Duplicate processing**: the SOAR test alert path explicitly logs "already has case" on a repeat alert id rather than creating a duplicate (`infra/soar/README.md:57`).

**Status: PARTIAL→COMPLETE for the specific workflows inspected** (alert ingestion, SOAR response, approvals) — unusually well-engineered with incident-driven hardening. Not assessed: VMS worker job-claim idempotency (Fork A/C territory) and general HTTP-client retry policy across the ~70 integration service files.

### 7.9 Existing security/tenancy tests — executed this pass

Command (from `backend/`, local, non-destructive, no production access):

```
node --import tsx --test src/routes/__tests__/routeGating.test.ts src/routes/__tests__/wazuhTenancy.test.ts \
  src/routes/__tests__/secopsAccess.test.ts src/routes/__tests__/secopsP3.test.ts \
  src/lib/__tests__/permissions.test.ts src/lib/__tests__/resolveOrg.test.ts
```

**Result: 101 tests, 101 pass, 0 fail, 0 skipped.** ~30s wall time. Ran against the project's test harness (in-process Express app + mocked/stubbed Supabase and Wazuh clients — confirmed by console output like `[notifications] Wazuh alert fetch failed: ... WAZUH_INDEXER_HOST environment variable is not set` and `[VirusTotal] API key not configured — skipping`, i.e., no live external services were reached). Representative assertions actually exercised: 401 with no token on 7 route groups; 403 for `executive`/`portal_user` on staff-only routes; 403 for a token with no `org_id`; cross-org isolation for cases/notes/tasks/reports, SOAR stats, handover logs, search results, communications, IOC enrichment escalation, Wazuh agents/alerts/groups, threat hunting, org switching (an analyst cannot switch to an unassigned org; a manager can and then sees only that org), and NovrAI telemetry gating.

**Caveat per the audit's own methodology**: this proves the *routes and their mocked dependencies* enforce isolation correctly under the test harness. It does **not** prove production Supabase RLS policies, production Wazuh indexer queries, or the live MISP/third-party integrations behave identically — those require either reading the RLS policy SQL directly (Fork C) or live-environment verification (out of scope, non-destructive constraint).

### 7.10 Security findings — prioritized

| # | Finding | Impact | Likelihood | Evidence | Remediation |
|---|---|---|---|---|---|
| S-1 | **No MFA anywhere**, including `super_admin` | Critical — single-factor compromise of one admin credential (phishing, credential stuffing, break-glass password leak) yields full platform control | High (no MFA is a well-known, commonly-exploited gap) | Grep: zero hits in `backend/src`; no TOTP/WebAuthn dependency in `package.json` | Implement TOTP (e.g., `otplib`) at minimum for `super_admin`/`soc_manager`; consider WebAuthn for the break-glass account specifically |
| S-2 | **No SAML/OIDC federation with an NCC identity provider**; only Google OAuth (and its live status unverified) | High — Requirement 26 cannot be satisfied without this; blocks a named national-oversight integration | Certain (not built) | `.env.example:24-25`; no SAML library in `package.json` | Decide the real IdP target (NCC's own ADFS/Okta/Azure AD or similar) before building; likely `saml2-js`/`node-saml` or a hosted IdP broker |
| S-3 | **Confirmed cross-tenant read/write** on `/api/brand/*` and read on `/api/urlscan\|webscan/history` for any staff/executive token | High — any client executive can read/write another client's brand-protection data (including breach results with masked emails) | Confirmed (not theoretical) — F-01/F-02 in V2 audit, with file:line citations | `backend/src/routes/brand.ts:93,190,394,536,663`; `routes/domainSuite.ts:90-111`; `routes/urlscan.ts:165-176`; `routes/webscan.ts:208-219` | Add `requirePermission` (new scope e.g. `brand:read`/`brand:manage`) with org filtering to every listed route; add the regression test V2 recommends (`routes/__tests__/tenantGuard.test.ts`, auto-fails any `requireAuth`-only route not on an explicit allow-list) |
| S-4 | **No distinct oversight/regulator role** — `super_admin` and `soc_manager` share identical permissions; no `ncc_csirt`-type role exists | High for Requirement 17 — there is literally nothing to grant a national oversight stakeholder that is narrower than full platform admin | Confirmed by code (role union, permission map) | `middleware/auth.ts:22`; `lib/permissions.ts:55-65` | Design a new role (e.g. `sector_oversight`) scoped to read-only, cross-organisation, aggregated/anonymised views only — do not reuse `super_admin` |
| S-5 | **Any authenticated non-portal role can trigger external-intel collection and MISP writes** (`/api/dashboard/nigeria-threats/collect`) with no `intel:manage` check | Medium — quota exhaustion on paid/rate-limited APIs (GreyNoise, FOFA etc.), unwanted MISP writes by a client executive | Confirmed (F-12) | `routes/dashboard.ts:277-289`; `index.ts:383` | Gate with `requirePermission('intel:manage')` |
| S-6 | **No SSRF review performed** on the many user/org-supplied-URL fetch paths (URL scan, webscan, brand domain checks) | Unknown — could range from none to server-side request forgery against internal infrastructure | UNVERIFIED (not reviewed this pass) | — | Dedicated SSRF review of `lib/scan.ts` and every `services/*scan*.ts`/`*webscan*` outbound fetch; confirm private-IP/metadata-endpoint blocking |
| S-7 | Google OAuth and the "real" password sign-in path's **live production reachability is unverified** post the `APP_API_BASE_URL` removal | Medium — if still broken, break-glass remains the only working admin login, which is itself audited at warning level but is a weaker control long-term | UNVERIFIED | `PRODUCTION_NOTES.md` items 1; `auth.ts:23` comment claims the dependency was removed | Live-verify `POST /api/auth/signin` (real account) and `/api/auth/google` against the current deployment |
| S-8 | **Audit log durability depends on a migration being applied**; pre-migration or mid-outage entries live only in a 1,000-row in-memory ring buffer that is lost on restart | Medium — a restart during an incident could lose the last events before/during it | Confirmed by design (not a bug, a known limitation) | `lib/audit.ts:30-35,53-57` | Confirm `sql/2026-10-14_p2_identity_audit.sql` is applied in every environment claiming audit-trail compliance; consider a local durable fallback (append-only file) before the DB write, not just memory |

---

## Part 8 — Integration Audit

For each integration: Purpose · Implementation location · Config requirements · Auth method · Data exchanged · R/W permissions · Error handling · Retry behavior · Health checks · Existing tests · Frontend visibility · Live operational evidence · Security risks · Missing functionality · Recommended next steps · **Classification**.

### 8.1 Wazuh (SIEM / EDR manager + indexer)

1. **Purpose**: endpoint/host telemetry, alert ingestion, MITRE mapping, agent inventory, trend/aggregation queries that back most of the SOC dashboard.
2. **Location**: `backend/src/services/wazuh.ts`, `wazuhCheck.ts`, `wazuhVulnSync.ts`; `backend/src/lib/wazuh.ts`, `wazuh-indexer.ts`, `wazuh-group.ts`; `routes/wazuh.ts` (status, agents, MITRE stats, trend — V2 §5 table rows 1, 12, 19).
3. **Config**: `WAZUH_HOST/PORT/USER/PASSWORD`, `WAZUH_INDEXER_HOST/PORT/USER/PASSWORD` (`.env.example:84-91`).
4. **Auth**: manager REST + indexer credentials (basic auth presumed, not re-confirmed this pass).
5. **Data exchanged**: agent status, alerts (via indexer query), MITRE tactic/technique aggregations, trend histograms — read-only from NovrSOC's side for these routes.
6. **R/W**: read-only for dashboard/status/MITRE/trend; the SOAR path (§8.9) is where NovrSOC-initiated *writes* happen (via the manager's integratord calling out, not NovrSOC calling in).
7. **Error handling**: `orgScope` resolution fails closed when agent-to-org group mapping is unclear (`notifications` test output: `"Cannot work out which Wazuh agents this organisation owns"` when indexer host is unset — i.e., it refuses to guess rather than showing all agents).
8. **Retry**: not independently reviewed this pass for the manager-REST/indexer query paths.
9. **Health checks**: `/api/platform/health` probes multiple services including (presumably) Wazuh (V2 row 7, F-06) — not line-confirmed this pass.
10. **Tests**: `routes/__tests__/wazuhTenancy.test.ts` — **executed, 101/101 passing overall batch including this file** (§7.9); specifically covers org-scoped agent/alert/group queries and manager exclusion from "agent" results.
11. **Frontend visibility**: dashboard KPIs (Agents, MITRE ATT&CK, trend chart), `/admin/secops/*` per V2 §5.
12. **Live operational evidence**: `PRODUCTION_NOTES.md` item 2 — **confirmed live as of 2026-09-02**: `GET /api/wazuh/status` returned real agent data (3 registered, 2 active) against `WAZUH_HOST=169.58.242.174`. Not re-verified in this pass (would require live network access, outside the non-destructive/no-production-access constraint for this audit fork).
13. **Security risks**: per §7.4, `wazuh` routes are in the `requireAuth`-only (no `requirePermission`) list — tested isolation exists at the *data* level (org scoping inside the handler, confirmed by passing tests) even though the *permission* gate is weaker than other routers; this is a narrower risk than F-01/F-02 since the handlers themselves scope correctly.
14. **Missing**: MITRE dashboard widget shows only 8 of 14 Enterprise tactics (V2 row 12) — a display gap, not an integration gap.
15. **Next steps**: add `requirePermission` to Wazuh routes for defense-in-depth even though handler-level scoping already passes tests; live-reverify agent counts against current production.

**Classification: Implemented and live-verified** (as of the last documented check; **not re-verified in this pass** — treat as "last known good," not current).

### 8.2 Greenbone / OpenVAS

1. **Purpose**: authenticated/credentialed vulnerability scanning engine for VMS.
2. **Location**: `backend/src/lib/openvasPolicy.ts` (full file read); worker-side execution in `infra/vms-worker/` (`audit-greenbone.sh`, `test_greenbone.py`, `test_openvas_report.py`); ingestion in `routes/vmsWorker.ts`, `routes/vms.ts` (queueScan).
3. **Config**: `VMS_OPENVAS_ENABLED` (must be exactly `"true"`), `VMS_OPENVAS_SCOPE_IDS` (comma-separated UUID allow-list) — **both default to off/empty, i.e., fail-closed by design** (`openvasPolicy.ts:1-16`).
4. **Auth**: worker-side, against the Greenbone instance; not reviewed (worker code is Python, outside this fork's remit — Fork A/C territory for VMS internals).
5. **Data exchanged**: scan jobs out, vulnerability findings/evidence in.
6. **R/W**: read findings, trigger scans (write, intrusive) — explicitly gated by scope authorization, checked **twice**: at queue time and again when a worker claims the job (`openvasPolicy.ts:9-11`) — closes a race where policy changes after queuing but before claiming.
7. **Error handling / 8. Retry**: not reviewed (worker-side, Python).
9. **Health checks**: `test_openvas_report.py`, `audit-greenbone.sh`, `verify-tools.sh` exist in `infra/vms-worker` — presence confirmed, not executed (would require a live Greenbone host, non-destructive constraint).
10. **Tests**: `backend/src/routes/__tests__/openvasIngest.test.ts`, `fixtures/openvas-observations.json` — present; not run in this pass (in scope for Fork A/E's VMS-focused test run, to avoid duplicate execution).
11. **Frontend visibility**: VMS pages (Fork D's territory).
12. **Live operational evidence**: **none found this pass.** `openvasPolicy.ts`'s own comment frames this as "switched on only once the scanner host and the target are authorised" — i.e., this reads as **deliberately disabled by default pending an authorization decision that may not yet have been made for any real target.**
13. **Security risks**: the double-check design (queue-time + claim-time) is a genuine strength — correctly treats "intrusive scanning" as something that needs explicit, scope-specific authorization, not a global on/off switch.
14. **Missing**: **Nmap and Nuclei integrations do not exist anywhere in this codebase.** Exhaustive grep (`nmap|nuclei`, case-insensitive, whole repo) returned only matches for Wazuh's agent/alert term "**nap**ped"-type false positives and genuinely unrelated files (video-production scripts, runbook docs about *deploying* OpenVAS that happen to mention scan types) — **zero actual Nmap or Nuclei integration code, scripts, or worker logic.**
15. **Next steps**: confirm with the VMS worker owner whether Nmap/Nuclei were ever planned as separate engines or whether Greenbone/OpenVAS was always intended to be the sole scanner (affects Requirement 2's "scanning for network infrastructure... APIs... containers" breadth, since OpenVAS alone doesn't natively cover container-image or API-contract scanning).

**Classification: Partially implemented, configured only, not live-verified.** The *policy and plumbing* are real and well-designed; there is no evidence any real target has ever actually been scanned with it live.

### 8.3 Nmap / Nuclei

**Finding: MISSING entirely.** No files, no service wrappers, no CLI invocation, no fixtures, no tests, no documentation beyond the VTEM spec itself naming them. This directly affects Requirement 2 and Requirement 3 ("custom Nuclei templates or equivalent") — there is no "or equivalent" either; OpenVAS/Greenbone does not provide Nuclei-style custom-template scanning.

**Classification: Missing.**

### 8.4 MISP

1. **Purpose**: central CTI source — IOC enrichment (read) and Nigerian-collector IOC publishing (write, opt-in).
2. **Location**: `backend/src/services/misp.ts` (full file read, ~120 of its lines).
3. **Config**: `MISP_URL`, `MISP_API_KEY`, `MISP_CA_CERT` (pinned cert for the self-signed instance), `MISP_WRITE_ENABLED` (must be exactly `"true"` to allow writes — fail-closed), `MISP_BROWSE_URL` (override for human-facing links) (`.env.example:66-71`; `misp.ts:62-65`).
4. **Auth**: API-key header (`misp.ts:103-109`).
5. **Data exchanged**: events/attributes (read) for enrichment; IOC push (write, gated).
6. **R/W**: read by default; write only when `MISP_WRITE_ENABLED=true`, used specifically by the Nigerian intel collector.
7. **Error handling**: **excellent, documented degradation** — every call funnels through `mispFetch`, returns `null` rather than throwing on any failure, and a dedicated function (`isMISPConfigured`) lets callers show "not connected" honestly (`misp.ts:35-37,111-120`).
8. **Retry**: not visible in the excerpt read (8-second default timeout per call, `misp.ts:113`); no backoff/retry loop seen in this function — single attempt per call.
9. **Health checks**: `checkMISPBrowseRedirect()` specifically detects and explains a real server misconfiguration (MISP's `baseurl` set to `localhost`, so browser links from NovrSOC would land on the analyst's own machine) with the exact server-side fix command (`misp.ts:62-94`) — this is unusually thorough self-diagnosis, not just a boolean up/down check.
10. **Tests**: not located by name in this pass (no `misp.test.ts` seen in the test-file glob run); **UNVERIFIED** whether MISP-specific logic has dedicated tests (it may be covered indirectly via `ioc_enrichments` tests, which did pass, §7.9, but those test tenancy of the *cache*, not MISP connectivity itself, which is mocked/absent in that harness).
11. **Frontend visibility**: Threat Intelligence pages / Sources page (per the comment "the Sources page warns if the key can write," `.env.example:70`) — Fork D's territory to confirm.
12. **Live operational evidence**: **Confirmed broken**, not merely unverified. `misp.ts:13-20`'s own comment states the configured MISP_API_KEY was **live-tested on 2026-09-07 and rejected (403 "Authentication failed")** across every endpoint tried (`/servers/getVersion`, `/servers/getPyMISPVersion`, `/events/index`, `/attributes/restSearch`). The key is "the right shape" (40 chars) — so this is a wrong/expired key or a user without API access enabled, not a code defect. **As of the last documented check, MISP integration is implemented correctly but non-functional in production for lack of a working credential.** The TLS/redirect issues (self-signed cert now pinned; `baseurl=localhost` redirect bug identified) were separately diagnosed and are either fixed (pinning) or server-side (baseurl, not fixable from this repo).
13. **Security risks**: none beyond the credential problem; the pinning and write-gating are actual security improvements over the prior `NODE_TLS_REJECT_UNAUTHORIZED=0` approach.
14. **Missing**: a working, API-enabled MISP key. Also: the unmerged `novr-vms`/P26 work (per this fork's branch convention note) reportedly adds "incremental read-only MISP sync" hardening and "private-intel boundaries in enrichment" (per commit message `5857078` in that line's history) — **not independently verified in this pass**, flagged for Fork A/C or a follow-up audit pass specifically against the `novr-vms` worktree.
15. **Next steps**: obtain/rotate a working, API-access-enabled MISP key and re-run the live probe; fix `MISP.baseurl` on the MISP server itself (one `cake Admin setSetting` command, documented); merge or re-verify the P26 MISP hardening work.

**Classification: Implemented but not live-verified as working — specifically, last live-verified as BROKEN (auth failure), not simply "not yet checked."**

### 8.5 CISA KEV / NVD / CTI feeds (non-MISP)

**Evidence**: `.env.example:174-178` — "CVE intelligence: CISA KEV and FIRST EPSS need no key. NVD works without one (5 requests/30s); a free NVD API key raises that to 50." `backend/src/services/cveIntel.ts`, `jobs/vmsIntelJob.ts`, `jobs/globalIntelJob.ts`, `jobs/threatInfoJob.ts` exist. `VMS_INTEL_ENABLED` flag controls "the hourly Wazuh vulnerability sync and the 6-hourly CVE refresh" (`.env.example:177-178`) — i.e., there's a scheduled job, not just an on-demand lookup.

**Classification: Implemented, scheduled, not independently live-verified this pass** (would require confirming the job actually ran recently and populated `cve_intel` with current KEV flags — Fork A/E territory for the full workflow trace and job-execution evidence).

### 8.6 NVIDIA AI

1. **Purpose**: backs every AI feature (NovrAI chat, AI panels, investigation summaries).
2. **Location**: `backend/src/services/nvidia.ts` (full file read), `services/ai.ts`, `routes/novr-ai.ts`.
3. **Config**: `NVIDIA_API_KEY`, optional `AI_MODEL` (default `nvidia/nemotron-3-super-120b-a12b`), `AI_FALLBACK_MODEL`, `AI_TIMEOUT_MS` (default 120000) (`.env.example:149-156`).
4. **Auth**: bearer API key, server-side only, via the OpenAI SDK pointed at NVIDIA's OpenAI-compatible base URL (`nvidia.ts:12-14,40-47`).
5. **Data exchanged**: chat/completion requests; the platform's own telemetry/context is sent as prompt content (what exactly is sent is a data-classification question for Fork C/security, not re-traced in this pass).
6. **R/W**: effectively read (generation), no write-back to NVIDIA.
7. **Error handling**: graceful fallback to Gemini if NVIDIA unset/fails, else `503 {"configured": false}` with a clear "unavailable" UI state rather than a crash (`PRODUCTION_NOTES.md` item 7).
8. **Retry**: `maxRetries: 2` on the client (`nvidia.ts:43`).
9. **Health checks**: `probeNvidia()` — deliberately clever: NVIDIA's `/v1/models` returns 200 even for a bad key, so the probe sends an empty chat request instead, which checks the key first (401/403) before validating the (empty) payload (400/422) — confirms genuine key-validity testing, not just reachability (`nvidia.ts:54-60`).
10. **Tests**: `smoke:nvidia` script exists in `backend/package.json` (`tsx src/scripts/smokeNvidia.ts`) — a live-hitting smoke test, not run in this pass (would consume real API quota against a possibly-unconfigured key; left to the user/CI with real credentials, consistent with the non-destructive audit constraint).
11. **Frontend visibility**: NovrAI chat, AI panels across SecOps/VMS/CNII/TI (per `services/aiPurposes*.ts` file names: `aiPurposesVms.ts`, `aiPurposesCnii.ts`, `aiPurposesTi.ts`).
12. **Live operational evidence**: needs `NVIDIA_API_KEY` set in the Railway/Render environment; **not independently confirmed live in this pass.** `ANTHROPIC_API_KEY` is explicitly noted as no longer read (`PRODUCTION_NOTES.md` item 7) — i.e., a prior provider was fully decommissioned, not left as dead config.
13. **Security risks**: key is server-side only, never returned/logged per the file's own header comment (not independently verified by searching every AI-related route for accidental key leakage — reasonable to trust given the pattern but not exhaustively checked).
14. **Missing**: nothing structurally; depends entirely on whether a valid key is actually set in the deployed environment (unknown from this repo).
15. **Next steps**: confirm `NVIDIA_API_KEY` is set and valid in whichever environment is claimed as "current production"; run `smoke:nvidia` there.

**Classification: Implemented, not live-verified** (graceful-degradation design is real and tested conceptually; actual live key validity is unknown).

### 8.7 Supabase (database/platform)

Primary datastore for essentially everything (`getSupabase()` used across dozens of files). `runtimeEnv.ts`/`envGuard.ts` enforce dev/test-only `SUPABASE_URL` outside production (§7.6) — a strong safety control. Live reachability not re-tested this pass (would require credentials this audit does not have/use). **Classification: Implemented and live-verified** per `PRODUCTION_NOTES.md`'s "What's actually verified working" section (backend deploy health-checked against a Supabase-backed `/health`), **not re-verified in this pass.**

### 8.8 Render / Vercel / Railway (deployment)

`render.yaml` exists at the repo root (current primary target, per its presence and recency — `Oct 24` per `ls -la` timestamp). `PRODUCTION_NOTES.md` (dated "September 2026") verifies a **Railway** backend and **Vercel** frontend — i.e., the production notes predate what looks like a Render migration. **This is a material unknown**: it is not established from this repo which platform is the current live deployment target. **Status: UNVERIFIED — flagged explicitly as a "remaining unknown" for the executive summary.**

### 8.9 SOAR engine (Wazuh-triggered response automation)

Covered in depth at §7.8. **Classification: Implemented and live-demonstrable via a documented manual test procedure** (`infra/soar/README.md` §4 gives an exact curl-equivalent command to create a test case) — **not independently re-run in this pass** (would require a live Wazuh manager with the integration installed; outside this fork's non-destructive remit).

### 8.10 Email / notifications (Brevo, Resend, SMTP/Zoho, SendGrid, Mailgun)

Four email-sending paths configured (`BREVO_API_KEY`, `RESEND_API_KEY`, `SMTP_*`, plus `services/sendgrid.ts` present in the services list though not in `.env.example` — possibly legacy/unused, **UNVERIFIED which is actually wired up to current notification code**). `PRODUCTION_NOTES.md` item 9: SMTP via Zoho configured for `info@cybernovr.com`, "not independently re-verified this pass (would require actually sending mail)" — same caveat applies here; not re-tested. **Classification: Configured only / not live-verified**, and the presence of 4 different email-provider service files with only some referenced in `.env.example` suggests **provider sprawl worth consolidating**, not a functional gap per se.

### 8.11 GRC platform integration (Requirement 20)

**Searched**: `grc|archer|servicenow|workflow.?management` (case-insensitive) across `backend/src` — **zero matches.**

**Finding: no external GRC platform integration exists in any form** — no adapter, no credential placeholder in `.env.example`, no route, no service file, no mention in any runbook found this pass. `services/complianceMapping.ts` exists (confirmed in the services glob) and the frontend has a `/admin/compliance` area (per `frontend/src/app/admin` top-level listing seen during initial recon) — but per the spec's own explicit instruction ("do not equate general compliance features with GRC platform integration"), **internal compliance-mapping UI is not the same as integrating with "the Commission's GRC platform."** No external API spec, credential contract, or organizational dependency for this exists anywhere in the repo — meaning this requirement cannot proceed without NCC/the Commission first supplying their GRC platform's API documentation and a data contract. This is a **pure external dependency**, not an engineering backlog item, until that information exists.

**Classification: Missing** (and blocked on an external stakeholder, not on engineering effort).

### 8.12 Open APIs for CTI/SIEM interoperability (Requirement 30) and Workflow Management APIs (Requirement 31)

- NovrSOC exposes ~66 route files (per the primer recon) constituting its own REST API, but these are **internal, consumer-facing APIs for its own frontend**, not a published, versioned, externally-documented API product for third-party CTI/SIEM platforms to integrate against. No API versioning scheme (`/api/v1/`, `/api/v2/`) was observed in any route path seen this pass (all routes appear to be flat `/api/<resource>`). No OpenAPI/Swagger spec file was found in this pass's searches (not exhaustively confirmed — a dedicated search for `swagger|openapi.yaml|openapi.json` was not run by this fork; flagged for the test/acceptance fork or a follow-up grep).
- `routes/vmsWorker.ts` is the closest thing to a genuine external-system API contract: a token-authenticated (`VMS_WORKER_TOKEN`) interface for the Python scanner worker to claim jobs and submit evidence — but this is an internal worker protocol, not a general "workflow management system" integration surface per Requirement 9's "Workflow Management System API."
- **No external workflow-management-system adapter** (e.g., ServiceNow, Jira Service Management, a generic webhook-based ticketing bridge) was found. The closest analog is the SOAR engine's own internal case/approval workflow (§7.8, §8.9), which is NovrSOC's *own* workflow engine, not an integration *with* an external one.

**Classification: Requirement 30 — Partially implemented** (a de facto internal REST API exists and is consumed by the platform's own frontend and worker, but nothing resembling a documented, versioned, third-party-facing API product). **Requirement 31 — Missing** (no external workflow-management-system integration; only an internal equivalent).

---

## Requirement findings table

| Req | Security/Integration status | Evidence | Gap | Priority |
|---|---|---|---|---|
| 11 (Open XDR) | PARTIAL | Wazuh SIEM (§8.1) + SOAR response automation (§8.9, §7.8) are real and tenant-isolated; MISP enrichment exists but is currently credential-broken (§8.4); no NDR/network-detection product integration found | Cross-source correlation beyond Wazuh+MISP+internal alerts not evidenced; "genuinely integrated XDR" vs. "SOC features" distinction (spec's own caution) leans toward the latter today | P1 |
| 15 (Stakeholder portal/onboarding) | UNVERIFIED by this fork (Fork A/D territory for the onboarding flow itself); auth/RBAC substrate it depends on is sound (§7.1, §7.4) | — | Defer to Fork A/D | — |
| 16 (RBAC / logical separation) | PARTIAL | Strong mechanism (§7.4), tested (§7.9), but confirmed exceptions (S-3, S-5) | Fix the `requireAuth`-only route list; add the regression test V2 recommends | P0 |
| 17 (NCC-CSIRT oversight) | MISSING | No oversight role exists in code (S-4) | Entire role/permission tier needs designing and building | P0 (if contractually near-term) |
| 18 (Provider-restricted access) | PARTIAL | Core routes tested and isolated (§7.9); known leaks (S-3) undercut the guarantee | Same fix as 16/S-3 | P0 |
| 20 (GRC integration) | MISSING | Zero code, zero config, zero docs (§8.11) | Blocked on external stakeholder (NCC GRC API spec) | Blocked — not engineering-sequenceable yet |
| 24 (MFA) | MISSING | Zero MFA code anywhere (S-1) | Full feature build | P0 |
| 25 (Audit trails) | PARTIAL | Real, tested-in-spirit mechanism with honest degradation (§7.7); exhaustiveness of coverage and pre-migration durability unconfirmed (S-8) | Confirm migration applied everywhere; verify coverage breadth | P1 |
| 26 (SSO) | MISSING | Only Google OAuth, not SAML/NCC IdP; live status unverified (S-2, S-7) | Full feature build once NCC's IdP details are known | P0 (pending NCC input) |
| 27 (Strict data separation) | PARTIAL | Same evidence as 16/18 | Same as S-3 | P0 |
| 30 (Open APIs) | PARTIAL | Internal REST API exists; no external-facing documented/versioned product (§8.12) | API documentation, versioning, third-party auth model | P2 |
| 31 (Workflow Management APIs) | MISSING | No external workflow-system integration; only internal SOAR/approvals equivalent (§8.12) | Needs a named target system before building an adapter | P2 (needs target system named first) |

---

## Unresolved items for the executive summary / other forks

- Deployment platform of record (Railway vs. Render vs. Vercel) is **not established from this repo** — `PRODUCTION_NOTES.md` (Sept 2026) says Railway+Vercel; `render.yaml`'s presence and Oct 24 modification date suggest a possible migration to Render that postdates those notes. Needs a direct answer from whoever manages deployment, or a fresh live check.
- P26/P27 (`novr-vms` worktree) MISP-hardening and IOC-cache-tenancy claims were not independently verified in this pass — only the SQL files' existence on disk was confirmed. A follow-up pass against that worktree specifically would close this gap.
- SSRF review of outbound-fetch-on-user-input paths (URL scan, webscan, brand domain checks) was not performed — recommend as a dedicated, narrowly-scoped follow-up given the breadth of integration service files that take arbitrary external input.
- OpenAPI/Swagger spec existence was not exhaustively searched for — a quick follow-up grep (`swagger|openapi`) would close this before the Requirement 30/36/48 "API documentation" findings are finalized elsewhere in this audit.
