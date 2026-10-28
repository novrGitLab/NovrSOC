# VTEM Audit Evidence Index

Consolidated, traceable index of evidence cited across all nine other audit documents. Organized by source document, then by file. Paths are relative to `C:\Users\USER\NovrSOC` unless prefixed with a different worktree name (`novr-vms`, etc.).

For the full narrative evidence (file:line plus explanation), see the originating document named in each row. This index exists so a specific claim can be traced back to its exact source without re-reading an entire 30-45KB document.

---

## Repository / git evidence (coordinator, this turn)

| Claim | Command / evidence |
|---|---|
| 17 git worktrees exist on this machine | `git worktree list` |
| Primary line (`marketing-pages-merge`) = `main` + 5 commits | `git log --oneline main..HEAD \| wc -l` → 5; `git log --oneline HEAD..main \| wc -l` → 0 |
| `main` = `e306092`, matches `feat/r3.3e-client-reporting` and `feat/novrsoc-enterprise-website` tips | `git worktree list` output |
| P26 commit (`8c6e65b`) is NOT an ancestor of HEAD | `git merge-base --is-ancestor 8c6e65bbfd6a04ca3f546a24f84ed5947cfdac95 HEAD` → false |
| Merge-base of HEAD and `8c6e65b` is `9429743` | `git merge-base HEAD 8c6e65bbfd6a04ca3f546a24f84ed5947cfdac95` |
| P26/P27 SQL files absent from primary line's HEAD tree | `git show HEAD:backend/sql/2026-10-31_p26_ioc_cache_tenancy.sql` → "does not exist in 'HEAD'"; same for `2026-11-01_p27_vms_onboarding.sql` |
| `novr-vms` worktree is on branch `feat/vms-onboarding`, commit `3bd3a6e` | `git worktree list`; `cd novr-vms && git log --oneline -5` |
| Nmap/Nuclei integration is real (correction of a fork contradiction) | Direct grep + read: `infra/vms-worker/worker.py:1757-1829` (real `nmap`/`nuclei` subprocess invocation, XML/JSONL parsing); `backend/src/routes/vmsWorker.ts:49,78,237` (`VMS_KINDS`, `TOOL_NAMES`, tool enum) |

---

## VTEM_BACKEND_ARCHITECTURE_AUDIT.md (Fork A)

| File | Lines | Claim |
|---|---|---|
| `backend/src/index.ts` | 91, 119-126, 194-224, 234-292, 300-404, 407-410, 428-469 | Middleware chain, health probes, CORS/helmet/HTTPS-redirect order, rate limiters, 45 feature routers, error handler, job start order |
| `backend/src/routes/vmsWorker.ts` | 1-11, 18-22, 47 | Worker job-lifecycle contract; `VMS_KINDS` |
| `backend/src/lib/riskScore.ts` | 1-72 | Risk formula: `0.45·technical + 0.30·exploitation + 0.15·exposure + 0.10·criticality` |
| `backend/src/services/vmsFindings.ts` | 87-128 | Risk score applied/overwritten on findings; not versioned |
| `backend/src/services/ripeStat.ts` | 1-96 | AFRINIC/RIR lookup via RIPE Stat `whois` |
| `backend/src/services/geoEnrichment.ts` | 58-76, 115-117 | Direct AFRINIC RDAP fallback for African netblocks |
| `backend/sql/2026-10-14_p4_vms_asm.sql` | 60-80 | Asset upsert key `(org_id, asset_type, value)` |
| `backend/src/services/vmsAssessments.ts` | 47-63, 69-86 | `planStep`; `unsupported`/`not_attempted`/`inconclusive` distinct outcome states |
| `backend/src/services/cveIntel.ts` | 1-224 | CVE/NVD/KEV/EPSS/OSV orchestration, per-source isolated failure handling |
| `backend/src/services/misp.ts` | 9-20, 24-29, 62-94, 186-188 | TLS pinning rationale; **live API key rejected 403 as of 2026-09-07**; `baseurl=localhost` redirect bug; write kill-switch |
| `backend/src/services/responseApprovals.ts` | 18-28, 73, 99-107, 109 | TOCTOU-safe org re-check at execution time; self-approval block; atomic decision claim; audit logging |
| `backend/src/routes/vmsFindings.ts` | 145, 181-199, 225-253 | Remediation task creation; verification-rescan trigger and narrow re-check scope |
| `backend/src/routes/cniiNational.ts` | 43-49, 132-161, 171, 196, 228, 259 | Visibility scoping, DEFINITIONS block, drill-down, cross-org-view audit |
| `PRODUCTION_NOTES.md` | item 5, item 3-4 | SLA route removed 2026-10-07; TheHive/Shuffle removed in favor of in-house SOAR |
| grep: `CRF-NCS` | repo-wide | Zero matches |

## VTEM_DATABASE_AND_TENANCY_AUDIT.md (Fork C)

| File | Lines | Claim |
|---|---|---|
| `backend/src/db/rls-policies.sql` | 1-19, 23-65 | Only 8 tables have real RLS (anon/authenticated revoke); every other table's RLS is a service-role bypass only |
| `backend/novrsoc_supabase_schema.sql` | 90-111, 95 | **Pre-P26 `ioc_enrichments`: global PK on `ioc_value`, no `org_id` column** |
| `backend/src/routes/cti.ts` | 92-97, 134 | Unscoped `ioc_enrichments` reads |
| `backend/src/routes/intelligence.ts` | 2, 32-37, 74-77 | Unscoped STIX export — "every organisation's accumulated intelligence" downloadable by any signed-in user |
| `backend/src/routes/search.ts` | 25-27, 41-44, 52-53 | Scoped `cases` query beside unscoped `ioc_enrichments` query in the same handler |
| `novr-vms/backend/sql/2026-10-31_p26_ioc_cache_tenancy.sql` | 1-60, 13-15 | **[unmerged]** the fix: surrogate PK, `(org_id, ioc_value)` unique, fail-closed legacy-row attribution |
| `novr-vms/backend/src/routes/__tests__/iocCacheTenancy.test.ts` | 1-102 | **[unmerged]** dedicated test suite proving the fix |
| `backend/sql/2026-09-organisations-onboarding.sql` | 6-9, 20, 32-35 | `organisations` PII columns; RLS applied to `platform_users` in the same file but not to `organisations` |
| `backend/src/lib/orgScope.ts` | 104, 110, 116, 125, 141-145, 154-166 | Fail-closed Wazuh ownership resolution — no fallback-to-everything path anywhere |
| `backend/src/lib/resolveOrg.ts` | 62-73, 75-102 | Fail-closed analyst cross-org resolution with full audit trail |
| `backend/src/lib/orgCtiStore.ts` | 6-7, 18-35, 65-76, 193-227 | In-memory, non-durable manual IOC store and Wazuh accumulator |
| `backend/sql/2026-10-14_p4_vms_asm.sql` | 28, 54, 62, 80, 116, 137-150 | Scope/asset unique keys; worker queue index; `FOR UPDATE SKIP LOCKED` job claim |
| `backend/sql/2026-10-14_p5_vms_findings.sql` | 4, 68, 71, 101 | `cve_intel` intentionally global ("shared, not per organisation: public data"); findings dedupe key; GIN CVE index |
| `backend/sql/2026-10-23_p17_cnii_intake.sql` | 6-13, 22, 27 | `cnii_submissions` deliberately nullable `org_id` and global-unique value (by design, not a bug) |
| grep: `benchmark` | `backend/` tree-wide | Zero hits — Requirement 14 has no database representation at all |

## VTEM_SECURITY_AND_INTEGRATIONS_AUDIT.md (Fork B)

| File | Lines | Claim |
|---|---|---|
| `backend/src/routes/auth.ts` | 12-43, 14-20, 23, 26-27, 30, 36-43, 51-53 | Password sign-in, lockout, dev-admin break-glass bypass, timing-equalising dummy hash, hand-rolled HMAC tokens |
| `backend/src/middleware/auth.ts` | 22, 28-58, 82 | Role union (no oversight tier); fail-closed `requireAuth`; `/api/auth/google` exempt path |
| `backend/src/lib/permissions.ts` | 55-65, 91-102 | `super_admin`/`soc_manager` identical permissions; fail-closed `requirePermission` with mandatory org resolution |
| `backend/src/routes/brand.ts` | 93, 190, 394, 536, 663 | **Confirmed cross-tenant read/write leak** |
| `backend/src/routes/domainSuite.ts` | 90-111 | Same leak class |
| `backend/src/routes/urlscan.ts` | 165-176 | **Confirmed cross-tenant read leak** |
| `backend/src/routes/webscan.ts` | 208-219 | **Confirmed cross-tenant read leak** |
| `backend/src/routes/dashboard.ts` | 277-289 | Any authenticated non-portal role can trigger external-intel collection / MISP writes with no `intel:manage` check |
| `backend/src/lib/audit.ts` | 11-28, 43-71, 53-57, 92-108 | Audit log entry shape, batched flush with retry, honest degradation, source-provenance on read |
| `backend/src/lib/tlsGuard.ts`, `pinnedTls.ts` | — | TLS hardening is a deliberate decision, not a default |
| `backend/src/lib/runtimeEnv.ts`, `envGuard.ts` | — | Refuses to start outside production against an undeclared database |
| `infra/soar/README.md` | 57, 59-67, 69-79 | Cursor-based forwarder (fixes a documented 6-day stall incident); tiered SOAR response with SKIPPED/FAILED/SUCCESS states; duplicate-alert handling |
| `backend/src/lib/openvasPolicy.ts` | 1-16 | Double-check (queue-time + claim-time) scope authorization |
| `infra/vms-worker/worker.py` | 1757-1829, 938, 961, 988-989 | Real Nmap/Nuclei subprocess integration (confirms/corrects Fork B's own earlier grep miss) |
| `backend/src/services/nvidia.ts` | 12-14, 40-47, 43, 54-60 | Bearer-key auth, graceful fallback, `maxRetries:2`, key-validity probe design |
| `.env.example` | 24-25, 48-49, 63-80, 84-91, 149-178 | Google OAuth config, webhook signing keys, TLS/MISP/CVE/NVIDIA config surface |
| grep: `mfa\|totp\|2fa\|two-factor` | `backend/src/**` | Zero relevant matches — **MFA MISSING entirely** |
| grep: `saml` | `backend/package.json` | No SAML library |
| grep: `ncc.?csirt\|oversight` | `backend/src` | Zero matches (one unrelated false positive in `serper.ts`) |
| grep: `grc\|archer\|servicenow\|workflow.?management` | `backend/src` | Zero matches |
| Local test run | `node --import tsx --test` on 6 route-gating/tenancy files | **101/101 pass** |

## VTEM_FRONTEND_VISIBILITY_AUDIT.md + VTEM_FRONTEND_REDESIGN_BLUEPRINT.md (Fork D)

| File | Lines | Claim |
|---|---|---|
| `frontend/src/app/page.tsx` | 32 | Homepage claims "ngCERT, NCC-CSIRT and CBN advisory integration" |
| `frontend/src/app/platform/page.tsx` | 29 | Same claim repeated |
| `frontend/src/app/cert-csirt/page.tsx`, `regulators/page.tsx`, `grc/page.tsx` | full files | Static marketing copy, no form/sign-up/request-access anywhere |
| `docs/audit/ONBOARDING_GENERAL.md` | §1.3, §1.6, §2.1, §2.2, §3 | OnboardingWizard creates unsignable accounts (literal TODO in `organisations.ts`); Settings Save button has no handler; mock-org Setup wizard writes orphaned data |
| `frontend/src/config/nav.ts` | — | 18 client items carry an unused `BROKEN` status field |
| `frontend/src/components/layout/Sidebar.tsx` | — | Filters only on `adminOnly`/`managerOnly`/`roles` — does not consult `status` |
| `NOVRSOC_REDESIGN_TECHNICAL_AUDIT_V2.md` | §3 (F-01 through F-23), §4-9, §15-17, Appendix A (137 routes), Appendix B (389 routes), Appendix C | Primer source for nearly every numbered finding (F-04 fabricated heatmap, F-06 executive-role 403s, F-08 risk formula, F-13 static status pills, F-14 403-as-zero, F-19 ungoverned legacy AI chat, F-23 free-text case assignment) |
| `docs/audit/NAV_DUMP.md` | §2 | Exact client-sidebar structure, 22 of 25 pages in nav |

## VTEM_TEST_AND_ACCEPTANCE_PLAN.md (Fork E)

| File / command | Result |
|---|---|
| `cd backend && npm test` | **640 tests, 637 pass, 0 fail, 3 skipped, ~157s** |
| `cd frontend && npm test` | **15/15 pass**, 4 test files only |
| grep: `misp` under `backend/src/**/__tests__` | Zero files — MISP has no dedicated test coverage |
| `backend/src/services/uptimerobot.ts` + grep for its call sites | Only referenced from `scripts/testNewKeys.ts` (manual CLI) — never from a route or scheduled job |
| `backend/src/services/cisa.ts` + `backend/src/lib/riskScore.ts` | Live CISA KEV fetch genuinely wired into the 30%-weight exploitation factor and P1 override |
| `backend/src/routes/cases.ts` | Full RBAC-gated lifecycle: create/assign/escalate/execute-step/close/report |
| `backend/src/routes/handover.ts`, `frontend ShiftHandover.tsx` | Naming collision flagged — SOC shift handover, not project knowledge transfer (Req 49) |
| `backend/src/routes/securityAssessment.ts` | Naming collision flagged — internal self-assessment, not independent pentest (Req 47) |
| No `.github/workflows` or other CI config found | No CI exists anywhere in the repository |

---

## Known unresolved cross-fork items (not independently re-verified by the coordinator)

1. Deployment platform of record: `PRODUCTION_NOTES.md` (dated September 2026) documents Railway + Vercel; `render.yaml`'s presence and later modification date suggest a possible Render migration. Not established from this repo which is current.
2. MISP's live credential status is current only as of the date embedded in `misp.ts`'s own code comment (2026-09-07/09) — not re-tested live by this audit (would require live network access, outside the non-destructive constraint).
3. Whether a Supabase anon/publishable key has ever been issued for this project (relevant to R-2, the `organisations` RLS gap) — not establishable from static repository inspection.
4. OpenAPI/Swagger existence was checked by targeted grep, not an exhaustive repository-wide search for every possible spec-file naming convention.
