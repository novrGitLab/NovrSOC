# VTEM Backend Architecture Audit (Fork A)

**Scope:** Part 4 (backend architecture map + 12 workflow traces) and Requirements 1–10, 23.
**Primary audit target:** `C:\Users\USER\NovrSOC` (branch `marketing-pages-merge` = `main` + 5 marketing commits). Backend code on this branch is current through phase **P25** (Threat Intelligence V1).
**Branch divergence (read before anything below):** a separate, **unmerged** worktree `C:\Users\USER\novr-vms` (branch `feat/vms-onboarding`, commit `3bd3a6e`) contains phases **P26** (IOC lookup cache tenancy, MISP incremental sync fixes, worker 1.8.2 evidence-target fixes) and **P27** (VMS onboarding / scope authorisation) that do **not exist** in `NovrSOC`. The git merge-base of `NovrSOC` HEAD and the P26 release commit (`8c6e65b`) is `9429743` ("unified release manifest") — both lines fork there and were never reconciled. Any capability that depends on P26/P27 is marked below with the worktree it was verified in; it is **not** counted as COMPLETE for the primary line. This is Critical Finding #1 for the executive summary.

Evidence convention: `path:line` is relative to the repo root unless prefixed with a different worktree name.

---

## Part 4A — Backend architecture map

### Entry point and middleware (evidence: `backend/src/index.ts`)

- Express app, single process (`backend/src/index.ts:91`). `app.listen` at `index.ts:412`.
- Order-sensitive middleware chain (documented in-line, each decision has a dated comment explaining a real production incident it fixed):
  1. `/health`, `/` — registered before all middleware, unauthenticated, used for Railway/Render health probes (`index.ts:119-126`).
  2. CORS (`index.ts:194-195`) — deliberately before helmet/HTTPS-redirect so preflight `OPTIONS` isn't 301'd.
  3. `helmet` CSP (inert for this JSON-only API but kept as defense-in-depth) (`index.ts:202-224`).
  4. Production-only HTTP→HTTPS redirect, explicitly skipping `OPTIONS` (`index.ts:234-251`).
  5. Three unauthenticated, self-rate-limited mounts registered **before** the global JSON body parser: `/api/ingest` (machine alert ingest), `/api/export/v1` (vendor export), `/api/vms/worker` (scanner worker, own `VMS_WORKER_TOKEN`), and `/taxii2` (TAXII 2.1 read-only exchange) (`index.ts:253-263`).
  6. Global `express.json()` (`index.ts:265`), then a tight `authLimiter` (10/15min on auth paths) and a general `apiLimiter` (100/min) (`index.ts:271-292`).
  7. ~45 feature routers mounted individually, each with its own `requireAuth`/`requireRole`/`requirePermission` gate chosen per route family (`index.ts:300-404`) — there is no single blanket auth middleware; gating is reviewed and enforced per mount, and a dedicated test (`routes/__tests__/routeGating.test.ts`, referenced at `index.ts:135`) fails CI if a new mount is added ungated.
  8. A single catch-all error handler (`index.ts:407-410`) returns a generic 500, never a stack trace.
- Background jobs start at the bottom of the file (`index.ts:440-469`), gated by `announceJobPolicy()` (`lib/runtimeEnv.ts`) so mutating jobs never run against an undeclared database (e.g., a laptop accidentally pointed at production).

### Router inventory (66 files under `backend/src/routes/`)

Grouped by domain (file list from `ls backend/src/routes`, 66 files, Oct 2026):
- **Auth/org/admin:** `auth.ts`, `portal.ts`, `organisations.ts`, `users.ts`, `team.ts`, `orgAccess.ts`, `platform.ts`.
- **VMS (8 routers, additive by phase):** `vms.ts` (P4, scope/scan core), `vmsFindings.ts` (P5), `vmsContinuous.ts` (P7, schedules/trends/reports), `vmsAssessments.ts` (P13, Full Assessment), `vmsAdmin.ts` (P14, policy/worker/integration admin), `vmsOperations.ts` (P19, profiles/eligibility), `vmsInsights.ts` (P20, read-only dashboards), `vmsClient.ts` (P21, client-portal read-only), `vmsWorker.ts` (P4/P10, scanner-worker machine API).
- **CNII:** `cnii.ts`, `cniiNational.ts` (P23).
- **Threat intel / SOC:** `threat.ts`, `threatInfo.ts` (P6), `threatManagement.ts`, `cti.ts`, `orgCTI.ts`, `taxii.ts` (P25), `intelligence.ts` (STIX export), `mitre.ts`, `secops.ts`, `clientSecops.ts`, `wazuh.ts`, `wazuhGroupMap.ts`.
- **Cases/response:** `cases.ts`, `soar.ts`, `playbooks.ts`, `responseApprovals.ts`, `search.ts`, `handover.ts`, `communications.ts`.
- **Email/brand/web:** `email.ts`, `emailProxy.ts`, `emailSecurity.ts`, `brand.ts`, `domainSuite.ts`, `urlscan.ts`, `webscan.ts`, `dns.ts`, `geo.ts`.
- **Compliance/customers/assessment:** `compliance.ts`, `customers.ts`, `securityAssessment.ts`.
- **Export/ops:** `exportApi.ts`, `exportClients.ts`, `pushStatus.ts`, `dataRecovery.ts`, `notifications.ts`, `insights.ts` (P8), `dashboard.ts`, `assets.ts`.
- **Misc/public:** `public.ts` (unauthenticated marketing scanner), `contact.ts`, `ai.ts`, `novr-ai.ts`, `test.ts`, `ingest.ts`, `alertStore.ts`, `alerts.ts`.

### Services (73 files under `backend/src/services/`) — selected by VTEM relevance

`cveIntel.ts` (KEV+EPSS+NVD+OSV orchestration), `nvd.ts`, `cisa.ts`, `complianceMapping.ts`, `riskScore` (in `lib/`), `vmsFindings.ts`, `vmsIngest.ts`, `vmsAssessments.ts`, `vmsPolicies.ts`, `vmsCorrelation.ts`, `vmsWorkers.ts` (presence), `vmsEligibility.ts`, `vmsProfiles.ts`, `misp.ts`, `iocEnrichment.ts`, `tiPolicy.ts`, `tiGeo.ts`, `tiMap.ts`, `tiReports.ts`, `tiExchange.ts`, `tiStix.ts`, `stix.ts`, `responseActions.ts`, `responseApprovals.ts`, `cases.ts`, `weeklyInsights.ts`, `pipelineHealth.ts`, `cniiIntake.ts`, `cniiPassive.ts`, `rdap.ts`, `ripeStat.ts`, `geoEnrichment.ts`.

### Jobs (12 files under `backend/src/jobs/`)

`ctiWatcher.ts` (always on, read-only, every 5 min — `index.ts:428-434`), `incidentEscalation.ts`, `nigerianIntelJob.ts`, `globalIntelJob.ts`, `emailSecurityJob.ts`, `stellarPush.ts` (off by default), `autoCase.ts` (off unless `AUTO_CASE_ENABLED`), `vmsMaintenance.ts`, `vmsIntelJob.ts` (CVE intel + Wazuh vuln sync), `threatInfoJob.ts`, `vmsContinuousJob.ts` (schedules/snapshots/notify/policies, see Workflow Trace #1 below), `cniiPassiveJob.ts` (off unless `CNII_PASSIVE_ENABLED`).

### Worker / infra

- `infra/vms-worker/worker.py` — Python scanner worker; authenticates with `VMS_WORKER_TOKEN` against `backend/src/routes/vmsWorker.ts`. Contract documented at `vmsWorker.ts:1-11`: `heartbeat` → `claim` → per-job `heartbeat`/`results`/`complete`/`evidence`/`release`. Job lifecycle `queued → running (claim) → succeeded|failed|cancelled (complete)`, idempotent `/complete` (`vmsWorker.ts:18-22`).
- `infra/soar/soar.py` — the SOAR engine; writes `soar_log`, creates/closes tier-1 cases, calls the same response actions as the backend's manual "Execute" path (`services/responseActions.ts:1-9`).

### Service dependency map (text form)

```
Frontend (Next.js, admin + client)
   │  Bearer JWT / X-Org-Id
   ▼
Express API (backend/src/index.ts)
   │                                │                           │
   ▼                                ▼                           ▼
VMS routers (8)              SOC/TI routers              Admin/org routers
   │                                │                           │
   ▼                                ▼                           ▼
vmsFindings/vmsIngest/        misp.ts, iocEnrichment.ts,   organisations.ts, users.ts
vmsAssessments/vmsPolicies    threatInfo services,         (Supabase/Postgres via
   │                          cveIntel.ts (KEV/EPSS/NVD)    getSupabase() in every service)
   ▼                                │
Supabase/Postgres (vms_*     ti_matches, cve_intel,
tables, RLS — see Fork C)    threat_indicators
   │                                │
   ▼                                ▼
infra/vms-worker (Python,    External TI: MISP (pinned TLS),
VMS_WORKER_TOKEN)            AbuseIPDB, URLhaus, ThreatFox,
   │                          VirusTotal, GreyNoise, LeakIX,
Nmap / Nuclei / Greenbone     CISA KEV, FIRST EPSS, NVD, OSV
(OpenVAS, policy-gated)
                              External SOC: Wazuh (REST+Indexer),
                              OPNsense (firewall block, gated by
                              response_approvals)
```

Background jobs (`jobs/*.ts`) sit beside the routers and call the same services; they are the only mutating code paths that run without an HTTP request (see `lib/runtimeEnv.ts` gate at `index.ts:441`).

---

## Part 4B — 12 workflow traces

### 1. Asset discovery

- **Entry point:** `POST /api/vms/scopes` (request) → organisation approval → `POST /api/vms/assets/discover` or a scheduled `discovery` job queued by `services/vmsContinuous.ts: runDueSchedules` (invoked every 5 min, `jobs/vmsContinuousJob.ts:50`).
- **Execution path:** scope check (`lib/vmsScope.ts: coveringScope`) → job queued → `infra/vms-worker/worker.py` claims via `POST /api/vms/worker/claim` → runs `subfinder → dnsx → httpx` (per V2 audit §7.3, in-scope only) → posts observations to `POST /api/vms/worker/jobs/:id/results` → `services/vmsIngest.ts: ingestObservations` re-checks scope server-side (never trusts the worker's own check) and upserts into `vms_assets` keyed `(org_id, asset_type, value)` (`backend/sql/2026-10-14_p4_vms_asm.sql:60-80`).
- **AFRINIC/ownership:** ASN/IP registry data comes from `services/ripeStat.ts` (RIPE Stat's `whois` call reports the authoritative RIR, including `afrinic`; verified live against 6 real Nigerian ISP ASNs per the file's own header comment, `ripeStat.ts:1-11`) and `services/geoEnrichment.ts: fetchFromAFRINIC` (direct RDAP call to `rdap.afrinic.net`, `geoEnrichment.ts:59-76`, used as a fallback for African netblocks, `geoEnrichment.ts:115-117`). There is no separate AFRINIC-specific allocation database import — this is live lookup, not a bulk AFRINIC allocation feed.
- **Security checks:** every discovered asset's scope membership is re-verified server-side before it is marked `scan_eligibility`-active; imports "never widen scope" (`services/vmsImport.ts:1-15`, confirmed by V2 audit §6.1).
- **Persistence:** `vms_assets`, provenance in `discovery_sources`, `confidence` columns.
- **Failure states:** a target outside scope → `not_attempted` with a stated reason (`services/vmsAssessments.ts: planStep`, `vmsAssessments.ts:47-63`); a private IP with no worker route → `not_attempted` (`vmsAssessments.ts:60-62`).
- **User-visible result:** VMS Assets inventory page (frontend — Fork D's scope for the UI itself).
- **Status: PARTIAL.** Discovery pipeline and ownership/RIR verification are real and well-evidenced; CIDR/domain discovery works through documented tools. AFRINIC is answered honestly via RIPE Stat/RDAP, not a dedicated allocation-registry import — adequate for "is this AFRINIC-registered" but not for a bulk "all AFRINIC allocations for Nigeria" dataset, which is not implemented.

### 2. Vulnerability scan

- **Entry point:** `POST /api/vms/scan` or `POST /api/vms/assessments` (Full Assessment, P13) → `services/vmsAssessments.ts: planStep` per profile step (`discovery`, `ports`, `vuln_nuclei`, `vuln_openvas`).
- **Execution path:** scope + worker-capability check (`planStep`, `vmsAssessments.ts:47-63`) → `queueScan` (`routes/vms.ts`) → worker claims job of the right `kind` → runs Nmap (`ports`), Nuclei (`vuln_nuclei`), or Greenbone/OpenVAS (`vuln_openvas`, gated — see Requirement 2 table below) → results posted back.
- **Security checks:** `VMS_KINDS = ['discovery','ports','vuln_nuclei','vuln_openvas']` (`routes/vmsWorker.ts:47`); OpenVAS additionally needs `VMS_OPENVAS_ENABLED=true` plus a scope-id allowlist (`lib/openvasPolicy.ts`, per V2 audit §7.3); worker `WORKER_FEATURES = ['exclusions','pinned_addresses']` — a worker that doesn't declare `exclusions` support is refused a job on a scope that has exclusions (`vmsAssessments.ts:58-59`).
- **Persistence:** `vms_scan_jobs` (status machine `queued→running→succeeded|failed|cancelled`), `vms_finding_evidence` for raw tool output (redacted, 30-day retention per `vmsWorker.ts:11`).
- **Failure states:** `unsupported` (no connected worker runs this kind/tool), `not_attempted` (scope forbids it or private-IP with no route), `inconclusive` (ran but too little evidence) — these are three distinct states, not collapsed into "failed" (`vmsAssessments.ts: stepStatus`, lines 69-86). This directly satisfies the audit brief's warning that a file's existence is not proof of a working scanner — the code itself refuses to claim "completed" unless a job both ran and produced an assessable outcome.
- **Status: COMPLETE for Nmap/Nuclei** (worker runs them, evidence retained, outcomes distinguished). **PARTIAL for OpenVAS/Greenbone** — integration exists (task creation, report parsing, health check per V2 audit §7.3) but is **administratively disabled** (`VMS_OPENVAS_ENABLED` policy gate) — a governance decision, not a missing capability, per the existing worker-1.8.2 runbook. **No evidence of web-application-specific (DAST/API fuzzing), cloud-configuration, or container-image scanning** beyond what Nuclei templates cover generically — these categories are **MISSING** as distinct engines.

### 3. Vulnerability ingestion

- **Entry point:** `POST /api/vms/worker/jobs/:id/results` (worker → backend) and the parallel Wazuh path `services/wazuhVulnSync.ts`.
- **Execution path:** `services/vmsIngest.ts: ingestObservations` deduplicates via `dedupe_key` (per asset+port+issue), re-checks scope, and calls `ingestFindings` (`services/vmsFindings.ts`, invoked from `routes/vmsWorker.ts`) which upserts `vms_findings`, preserving `risk_accepted`/`false_positive` status across re-sightings (V2 audit §7.3 "Finding dedup").
- **CVE enrichment:** `services/cveIntel.ts: ensureCves` creates a `cve_intel` row per CVE on a finding; `refreshCveIntel` (run from `jobs/vmsIntelJob.ts`) backfills KEV flags, EPSS scores and NVD CVSS/CWE/description data in three independent passes, each failure isolated so one source's outage doesn't block the others (`cveIntel.ts:170-224`).
- **Persistence:** `vms_findings`, `vms_finding_evidence`, `cve_intel`.
- **Failure states:** a failed NVD/EPSS/KEV fetch is recorded per-CVE in `errors[]` and retried next run (`cveIntel.ts:218`); OSV lookups stop cleanly on HTTP 429 and resume next run (`cveIntel.ts:151`).
- **Status: COMPLETE.** This is one of the most rigorously evidenced pipelines in the codebase.

### 4. Risk prioritisation

Already fully traced and verified in the primer (`NOVRSOC_REDESIGN_TECHNICAL_AUDIT_V2.md` §7.1, `backend/src/lib/riskScore.ts:1-72`, `services/vmsFindings.ts:87-128`). Re-verified present on `NovrSOC` HEAD. Formula: `score = round(0.45·technical + 0.30·exploitation + 0.15·exposure + 0.10·criticality)`; `priority` from fixed thresholds with a KEV+internet override to P1. **Known defect (confirmed, not re-derived):** weights are module constants, not versioned or auditable per-change (`vmsFindings.ts:112-128` overwrites `risk_score`/`priority` silently except when priority itself changes). **Status: COMPLETE but not auditable/versioned** — matches V2's own finding; this audit does not relitigate it, only confirms it is still true on this branch.

### 5. Remediation

- **Entry point:** `POST /api/vms/findings/:id/tasks` (`routes/vmsFindings.ts:225`) creates a `vms_remediation_tasks` row (owner, due date, optional AI-artifact reference).
- **Execution path:** analyst marks a finding `fixed_pending_verification` (`PATCH /findings/:id`, `vmsFindings.ts:145`) → triggers verification (see Trace #6). Tasks are also surfaced read-only in CNII per-organisation views (`routes/cniiNational.ts:259`, `tally(tasks.data)`).
- **Consequential actions (network containment) use a separate, stronger gate:** `services/responseApprovals.ts` — a request (`block_ip`/`isolate_agent`) is recorded `pending`; a **different** user holding `response:approve` must decide (self-approval blocked unless `RESPONSE_ALLOW_SELF_APPROVAL=true`, `responseApprovals.ts:99-101`); the decision claim is atomic (`eq('status','pending')` on the update, `responseApprovals.ts:104-107`, preventing a double-approval race); execution calls the same `services/responseActions.ts` functions the SOAR engine uses automatically, so a manual approval and an automated one produce identical logged outcomes (`responseActions.ts:1-9`).
- **Security checks:** `isolationRefusal` re-verifies the target agent still belongs to the approving organisation **at execution time**, not at request time (`responseApprovals.ts:18-28`) — closes a TOCTOU gap that would otherwise let a stale approval isolate an agent that moved orgs.
- **Status: COMPLETE for the approval-gated containment workflow** (block IP / isolate agent) — genuinely good engineering with a human-approval gate, audit logging (`logAudit`, `responseApprovals.ts:73,109`), and race-safe decision claiming. **PARTIAL for general remediation task tracking** — task CRUD exists but there is no SLA-breach alerting tied to `due_at` beyond the `due_at` field itself (see Requirement 10).

### 6. Verification rescan

- **Entry point:** `POST /api/vms/findings/:id/verify` (`vmsFindings.ts:181`), permission `vms:scan`.
- **Execution path:** only callable once a finding is `fixed_pending_verification` (`vmsFindings.ts:187`, 409 otherwise) → queues the **same check** (`vmsFindings.ts:195`, reusing the original rule/template and port) → stores `verification_job_id` on the finding (`vmsFindings.ts:198`) → emits a `verification_queued` event (`vmsFindings.ts:199`) → worker result ingestion calls `concludeVerification` (imported at `routes/vmsWorker.ts:34`) to close the loop.
- **Status: COMPLETE.** This is a deliberately narrow, well-guarded re-check (same rule, same port, same tool) rather than a generic rescan — an honest design choice, not a shortcut.

### 7. MISP ingestion

- **Entry point:** `jobs/nigerianIntelJob.ts` (hourly Nigerian threat-intel collection, `index.ts:445-448`) and read-path calls from `services/iocEnrichment.ts: enrichIOC` (`misp` source, `iocEnrichment.ts:36-42,79`).
- **Execution path:** all MISP traffic funnels through `services/misp.ts: mispFetch`/`mispStrict`, pinned-TLS (`lib/pinnedTls.ts`) because the configured instance has a self-signed certificate (`misp.ts:9-12`); reads use `/attributes/restSearch`, `/events/restSearch`; writes (`addToMISP`, `addAttributeToEvent`) are gated behind `MISP_WRITE_ENABLED=true` and are off by default (`misp.ts:186-188`) — the integration starts **read-only by design**.
- **Live-verified status (as documented in the code itself, dated 2026-09-07/09, not re-verified live by this audit):** the configured MISP host is reachable over HTTPS only (HTTP 301s, which silently turns POSTs into no-op GETs — handled by `normalizeBase()` upgrading to https, `misp.ts:24-29`), but **the configured `MISP_API_KEY` is rejected (403) on every endpoint tried** (`misp.ts:13-20`). `getMISPStats()` therefore reports `auth_failed` distinctly from `unreachable` so Platform Health shows the real cause (`misp.ts:256-267`). Additionally the MISP server's own `MISP.baseurl` is set to `https://localhost`, so any analyst clicking a generated MISP link lands on their own machine — detected and surfaced by `checkMISPBrowseRedirect()` (`misp.ts:78-94`), with the exact server-side fix documented in the file's own header comment (`misp.ts:52-57`).
- **Status: PARTIAL / UNVERIFIED-LIVE.** The integration code is correct and defensively engineered (TLS pinning, auth-failure vs unreachable distinction, write kill-switch), but the **last-recorded live state is a rejected API key** — meaning MISP read enrichment and the Nigerian-intel collector's MISP writes were **not functioning** as of the date in the code comment. Whether this has since been fixed requires a fresh live check against the current `MISP_API_KEY` — this audit cannot confirm current state from static code alone. **P26 (unmerged, `novr-vms` worktree) is reported to add "incremental read-only MISP sync" fixes** — these are not present on the primary line audited here.

### 8. IOC enrichment

- **Entry point:** `services/iocEnrichment.ts: enrichIOC(value, type)`, called from `routes/threat.ts`, CTI Platform, Threat Management, and URL Scan Suite (file header, `iocEnrichment.ts:1-2`).
- **Execution path:** fans out in parallel to AbuseIPDB, URLhaus, ThreatFox, VirusTotal, GreyNoise, LeakIX and MISP (`iocEnrichment.ts:4-10`), each independently null-safe if unconfigured (`configuredSources`, `iocEnrichment.ts:70-81`); composes a single `risk_score`/`verdict` (`verdictFromScore`, `lib/severity.ts`) plus per-source raw detail so the UI can show provenance, not just a number.
- **Explainability:** the `EnrichedIOC.sources.misp` field distinguishes "this exact value is in the org's own curated MISP" (strongest signal) from third-party feed hits (`iocEnrichment.ts:36-42`) — a genuine design decision toward explainability, matching Part 5.3's audit requirement.
- **Status: COMPLETE as an orchestration layer.** Individual source health (e.g., MISP's auth failure above) degrades gracefully to "no answer from this source" rather than a false clean verdict — correctly engineered, but the **honesty of the composite verdict is only as good as the currently-working subset of sources**, which per Trace #7 currently excludes MISP.

### 9. Threat intelligence correlation

- **Entry point:** `jobs/threatInfoJob.ts` (threat feeds: abuse.ch, CISA KEV, expiry, correlation — `index.ts:463-464`) and `jobs/globalIntelJob.ts` (CIRCL pulse + Wazuh-derived MITRE technique sync, `index.ts:449-450`).
- **Execution path:** correlates stored `threat_indicators`/`ti_matches` against an organisation's own Wazuh alert stream and VMS findings; `correlationOrgs()` (imported into `vmsContinuousJob.ts:10`) scopes the correlation per organisation, not globally.
- **Status: COMPLETE for the correlation mechanics** (periodic batch, not event-driven real-time — see Requirement 7 below for the real-time-vs-periodic distinction).

### 10. Incident investigation

- **Entry point:** case creation from an alert (`jobs/autoCase.ts`, off unless `AUTO_CASE_ENABLED=true`) or manually (`routes/cases.ts`).
- **Execution path:** case lives in Supabase (`backend/sql/2026-09-cases-soar.sql`); SOAR engine (`infra/soar/soar.py`) and `services/responseActions.ts` both write to `soar_log` and the case `timeline` with matching wording so manual and automated actions are indistinguishable in the audit trail (`responseActions.ts:1-9`); escalation for unresolved HIGH/CRITICAL cases is a separate job (`jobs/incidentEscalation.ts`).
- **Status: COMPLETE for case lifecycle and action logging.** TheHive and Shuffle were deliberately removed (confirmed in `PRODUCTION_NOTES.md` items 3–4) in favor of this in-house SOAR — a design consolidation, not a regression, per the same production notes.

### 11. Client onboarding

- **Entry point:** `routes/organisations.ts` (create org, role: super_admin) and `routes/vms.ts` scope request/approval flow (P27 authorisation — see Requirement 15/35 cross-reference).
- **Execution path (primary line, `NovrSOC`):** organisation created → VMS scope requested (`vms:scope`) → approved by the organisation's executive or recorded offline by a super_admin, with a typed declaration (`vms-scan-authority-v1`), SHA-256 of the declaration, and an immutable `vms_scope_approvals` row (per V2 audit §7.2, re-confirmed present at `backend/sql/2026-11-01_p27_vms_onboarding.sql` — **this SQL file does not exist on `NovrSOC` HEAD** (`git show HEAD:backend/sql/2026-11-01_p27_vms_onboarding.sql` → "does not exist in HEAD"); it exists only in the `novr-vms` / `feat/vms-onboarding` worktree). **This means the P27 authorisation workflow described in V2 is not present on the branch this audit otherwise treats as primary.**
- **Status: PARTIAL, with a line-dependent split.** Organisation creation and basic VMS scope request/approval (pre-P27, "legacy"/"cnii" approval methods per V2 §7.2) exist on `NovrSOC`. The full P27 declaration-based authorisation workflow exists only on the unmerged `novr-vms` worktree. A self-service stakeholder portal (Requirement 15) for providers to onboard themselves was **not found** on either line inspected by this fork — see Fork D for the frontend-side confirmation.

### 12. Sector reporting

- **Entry point:** `GET /api/cnii/national` and `/sectors/:sector` (`routes/cniiNational.ts:140,196`).
- **Execution path:** aggregates `vms_assets`/`vms_findings` across every organisation with a `cnii_org_profiles` row, grouped by the 13 fixed CNII sectors (`lib/cnii-sectors.ts:11-25`), computing per-sector severity/priority counts, mean contextual risk, and KEV-open counts (`cniiNational.ts:149-161`). Drill-down is overview → sector → organisation → asset, exactly as Part 1.2's known history claims (`cniiNational.ts:1-7`).
- **Visibility/tenant control:** `visibility()` restricts non-super_admin/soc_manager callers to `staff_org_assignments` (`cniiNational.ts:43-49`); viewing another org's detail is explicitly audited (`cniiNational.ts:228`).
- **Explainability:** every KPI ships a plain-English `DEFINITIONS` block returned in the same response (`cniiNational.ts:132-137`) — a genuinely good practice that directly satisfies Part 5.3's "explain how sector-level statistics are calculated."
- **Status: COMPLETE for the data/aggregation layer.** This is backend only — whether the frontend renders this as an actual geographic/interactive heatmap (Requirement 8's literal ask) is outside this fork's scope; see Fork D.

---

## Requirements 1–10, 23 — findings table

| Req | Backend status | Evidence | Gap | Notes |
|---|---|---|---|---|
| **1. Asset discovery/inventory, AFRINIC** | PARTIAL | `backend/src/services/ripeStat.ts:1-96`, `geoEnrichment.ts:58-76`, `backend/sql/2026-10-14_p4_vms_asm.sql:60-80`, `services/vmsImport.ts:1-15` | No bulk AFRINIC allocation-registry import; AFRINIC status answered via live RIPE Stat/RDAP lookup only, which is honest but not a dataset. Asset dedup/ownership verification is solid (unique `(org_id, asset_type, value)`). | Ownership verification before scanning = scope approval (Trace #1); genuinely enforced. |
| **2. Vulnerability scanning coverage** | PARTIAL | `routes/vmsWorker.ts:47` (`VMS_KINDS`), `lib/openvasPolicy.ts`, V2 audit §7.3 | Nmap/Nuclei: COMPLETE and wired. OpenVAS/Greenbone: implemented but administratively disabled (governance gate, not missing code). Web-app (DAST), cloud-config, and container scanning: no dedicated engine found — MISSING as distinct categories. | Do not count OpenVAS as COMPLETE while `VMS_OPENVAS_ENABLED` is off in production — verify live. |
| **3. Scan scheduling / custom signatures** | PARTIAL | `jobs/vmsContinuousJob.ts:1-54` (schedules every 5 min), `backend/sql/2026-10-16_p7_vms_continuous.sql:15` (`interval_hours` 24–2160) | On-demand + scheduled scans: COMPLETE. Custom Nuclei templates: no dedicated CRUD/authorization UI/API found in this fork's scope for *custom* (org-authored) templates — only built-in template selection via `templates:` option (`vmsFindings.ts:195`). Missed-schedule catch-up: explicitly absent per V2 §7.3. | Verify whether analysts can actually author/upload a Nuclei YAML template anywhere in the API — not found in routes inspected. |
| **4. CVE, NVD, CWE** | COMPLETE | `services/cveIntel.ts:1-224`, `services/nvd.ts`, `services/cisa.ts` | CWE comes through NVD's `weaknesses` field only (`cveIntel.ts:69-70`) — no independent CWE taxonomy/classification beyond what NVD reports per-CVE. | Rate-limiting and partial-failure handling are genuinely good (per-source isolated try/catch, `cveIntel.ts:183-222`). |
| **5. Misconfiguration / compliance detection (NIST, CIS, NDPA, CRF-NCS)** | PARTIAL | `services/complianceMapping.ts:1-143`, `routes/compliance.ts:45` | `complianceMapping.ts` maps **vulnerability severity → framework clause**, explicitly documented as "not an assessment" (`complianceMapping.ts:3-6`) — it is not configuration-benchmark scanning (no CIS Benchmark or NIST 800-53 control-by-control check engine found). **"CRF-NCS" by that exact name was not found anywhere in the backend** (`grep -ri "CRF-NCS"` → no matches); the closest analogues are "CBN Risk-Based Cybersecurity Framework" (`complianceMapping.ts:14,82`) and "NCC Framework" (`lib/cnii-sectors.ts:14`), which are different frameworks belonging to different regulators (Central Bank of Nigeria vs. NCC). NDPA is referenced as both "NDPA 2023 s.39" (`complianceMapping.ts:13,73`) and "NDPR" elsewhere (`routes/compliance.ts:25`, `lib/cnii-sectors.ts:12-24`) — Nigeria's NDPR (2019 regulation) was superseded by the NDPA (2023 act); the codebase is inconsistent about which it means. | This is a naming/scope gap that needs a product decision: either CRF-NCS does not yet exist as a mapped framework and must be added, or the platform's compliance mapping needs relabeling against the Commission's actual framework name. |
| **6. Risk prioritisation (CVSS v3/v4, KEV, exploit, criticality, business context)** | COMPLETE (mechanics); PARTIAL (governance) | `backend/src/lib/riskScore.ts:1-72`, `services/vmsFindings.ts:87-128` (verified via V2 audit §7.1, re-confirmed present) | **CVSS v4 is not used** — only v3.1/v3.0/v2 fields are parsed (`services/cveIntel.ts:62`, `services/nvd.ts` has no v4 metric key). Exploit evidence beyond KEV/EPSS (Metasploit/ExploitDB/PoC) is not used. Business impact (distinct from asset criticality) is not used. Scoring weights are global constants, not versioned/auditable — a score cannot be reconstructed after a weight change. | This is the platform's most mature subsystem; the only real gaps are CVSS v4 and score auditability/versioning, both previously identified in V2 and unchanged here. |
| **7. Continuous exposure monitoring, real-time KEV correlation** | PARTIAL | `jobs/vmsContinuousJob.ts:1-54`, `jobs/vmsIntelJob.ts`, `jobs/threatInfoJob.ts` | This is **periodic polling**, not event-driven real time: schedules checked every 5 min, risk snapshots hourly, KEV/EPSS refresh on a job cycle (not pushed). That is a reasonable architecture for this domain but it is not literally "real-time" — the audit brief explicitly asks to distinguish the two, and this is polling. | Change-digest notifications exist but are off by default (`VMS_NOTIFY_ENABLED`, `vmsContinuousJob.ts:52-53`). |
| **8. Sector heatmaps with provider drill-down** | COMPLETE (backend data layer only) | `routes/cniiNational.ts:1-309`, `lib/cnii-sectors.ts:11-27` | Backend provides full overview→sector→org→asset drill-down with explainable KPIs. Whether this renders as an actual interactive geographic heatmap is a frontend question (Fork D) — the backend returns tabular/aggregate JSON, not geo-coordinates per sector. | Tenant-restricted via `staff_org_assignments`; access to another org's detail is audited. |
| **9. Automated remediation via Workflow Management System API** | PARTIAL/MISSING (split) | `services/responseApprovals.ts:1-120`, `services/responseActions.ts:1-120`, `routes/vmsFindings.ts:225-253` | Internal approval-gated remediation (block IP, isolate agent) is COMPLETE and well-engineered. Finding-level remediation task tracking (create/assign/due date) is COMPLETE as CRUD. **An external "Workflow Management System API" integration (e.g., ServiceNow, Jira, a ticketing system) was searched for and not found** (`grep -i "ServiceNow\|Jira\|workflow management\|external workflow"` in `backend/src` → no matches). The platform's own case/approval system functions as its workflow engine, but there is no API to an *external* WMS as the requirement's wording implies. | If "Workflow Management System API" means the platform exposing its own API for an external WMS to call (rather than consuming one), note that `routes/responseApprovals.ts`, `routes/soar.ts`, and `routes/cases.ts` already expose read/write REST endpoints that could serve that role — but no documentation or client positions them that way (see Fork E for API-docs status). |
| **10. Approval, SLA, status sync, audit trails, reporting workflows** | PARTIAL | `services/responseApprovals.ts` (approval: COMPLETE), `PRODUCTION_NOTES.md` item 51 (SLA route removed) | Approval workflow: COMPLETE, race-safe, audited. **A dedicated SLA route/dashboard was removed** per `PRODUCTION_NOTES.md`'s 2026-10-07 update ("`sla` ... have since been removed"). SLA now exists only implicitly as `due_at` on findings (`lib/riskScore.ts` due-date table) with no breach-alerting or SLA-compliance reporting surface found in the routes inspected. Status sync for approvals is real (`decideApproval`, atomic claim). Reporting: `services/weeklyInsights.ts` (see below) covers operational reporting; no dedicated SLA-compliance report. | This is a confirmed regression, not a gap that was never built — the route existed and was removed. |
| **23. CCI mapping, automated executive reporting** | PARTIAL | `routes/cniiNational.ts` (CCI/CNII mapping: COMPLETE), `services/weeklyInsights.ts:1-107`, `services/tiReports.ts` (125 lines, not fully read in this fork — flagged UNVERIFIED) | CCI/CNII classification and sector/org/asset mapping is COMPLETE (see Trace #12). `weeklyInsights.ts` produces a structured weekly facts object (alerts, cases, vulnerabilities, TI matches, pipeline health, explicit `limitations[]` when a data source is missing/degraded — a genuinely good explainability pattern, `weeklyInsights.ts:15-25,86-87`) surfaced at `GET /api/insights/weekly` (`routes/insights.ts`, 22 lines). **Whether this is scheduled/delivered automatically (vs. pulled on demand) and whether a formal "executive report" (PDF/branded document) is generated was not fully verified in this fork** — `tiReports.ts` (125 lines) was not read in depth; flag UNVERIFIED pending a dedicated read, likely owned by Fork B/E given overlap with reporting UI. | `weeklyInsights.ts` is also fed to the AI model as a "purpose" input (`weekly_insights`) with the explicit rule that the model adds interpretation but never its own numbers (`weeklyInsights.ts:5-6`) — a strong AI-explainability/trust pattern worth highlighting positively in the executive summary. |

---

## Summary for synthesis (coordinator use)

- **Strongest subsystems (backend):** risk scoring (6), vulnerability ingestion/CVE enrichment (3/4), approval-gated remediation (9 partial/10 partial), CNII sector aggregation (8/23 partial), verification rescan (6 in trace numbering).
- **Weakest/most consequential gaps:** (a) branch divergence means P26/P27 are not on the line this audit treats as primary — MISP sync fixes and formal scope-authorisation onboarding are unmerged; (b) MISP read/write integration's last recorded live state is an auth failure, not merely "unverified"; (c) no framework literally named "CRF-NCS" exists in the compliance mapping, and NDPR/NDPA naming is inconsistent; (d) SLA reporting route was built then removed; (e) no external Workflow Management System API integration exists; (f) OpenVAS/Greenbone is code-complete but governance-disabled; (g) CVSS v4 is not supported anywhere in the pipeline.
