# VTEM Test and Acceptance Plan

Scope: Part 9 (Testing and Acceptance Audit) in full, plus primary evidence for Requirements 12, 13, 14, 19, 21, 22, 28, 29 (performance angle), and 32–49. Repository audited: `C:\Users\USER\NovrSOC`, branch `marketing-pages-merge` (= `main` + 5 marketing commits). A separate, unmerged worktree `C:\Users\USER\novr-vms` (`feat/vms-onboarding`) carries additional P26/P27 work not present on this branch; where relevant this is called out explicitly and was **read, not executed**, to avoid mixing test results across divergent trees.

No CI configuration exists anywhere in the repository (no `.github/workflows`, no other pipeline definition found). All test execution below is manual, local, and was run once for this audit.

---

## 1. Actual test execution results

### 1.1 Backend

- **Command:** `cd backend && node --import tsx --test "src/**/*.test.ts"` (the `npm test` script, run directly)
- **Environment:** local Windows checkout, Node ≥22 (per `engines`), no live Supabase/Wazuh/MISP/OpenVAS credentials — tests exercise mocked/fixture paths and pure logic, not live external services.
- **Result:**
  ```
  tests 640
  pass 637
  fail 0
  cancelled 0
  skipped 3
  todo 0
  duration_ms 157228 (~157s)
  exit code 0
  ```
- 61 test files under `backend/src/{lib,routes,jobs,services}/__tests__/**`. The default Node test reporter did not print distinguishable per-test skip labels in the captured log (only the aggregate `skipped 3` line was emitted) — the 3 skipped tests could not be individually identified from this run's output; re-running with `--test-reporter=tap` would surface them individually if needed.
- No failures. Representative coverage actually observed in the output (not inferred): DMARC/DKIM/SPF parsing and XXE/zip-bomb defenses, Microsoft 365 / Google Workspace OAuth state/nonce/tenant validation, cross-tenant isolation checks (Email Security), typosquatting/homoglyph detection, SSRF guards (private/loopback/CGNAT/mapped-address refusal), RBAC matrices (analyst/manager/executive/non-staff), and KEV/CVSS severity banding.

### 1.2 Frontend

- **Command:** `cd frontend && node --test "scripts/**/*.test.mjs"` (the `npm test` script)
- **Result:** `tests 15, pass 15, fail 0, skipped 0, duration_ms 4509`. Only 4 test files exist (`cnii-intake.test.mjs`, `severity.test.mjs`, `ti.test.mjs`, `vms-format.test.mjs`), covering CNII intake formatting, severity/CVSS banding parity with the backend, a 37-state Nigeria map outline count, CSV injection-safe export, and VMS section-to-route mapping. This is a thin slice of the ~137-route frontend (see Fork D's route inventory) — no component rendering tests, no route-level integration tests, no accessibility tests.

### 1.3 What was not run (and why)

- Worker (`infra/vms-worker/worker.py`) test scripts (`test_worker.py`, `test_greenbone.py`, `test_openvas_report.py`) were **not executed** by this fork — Python test execution and worker job-lifecycle verification is Fork A's (backend architecture) remit; this fork only confirms their existence (present under `infra/vms-worker/`).
- SOAR (`infra/soar/test_forwarder.py`) likewise not executed here — same reasoning.
- No test was run against any live external integration (Wazuh, MISP, OpenVAS/Greenbone, Nmap, Nuclei, NVD, NVIDIA) — doing so would violate the audit's non-destructive/no-live-scan rule and in most cases there is no reachable instance from this environment regardless.
- `npm run security:audit` / `security:check` (npm audit) were not run as part of this fork's scope — recommend Fork B or a dedicated dependency-audit pass cover this explicitly (not duplicated here to avoid conflicting findings).

---

## 2. Test coverage vs. the Part 9 checklist

| Area | Status | Evidence |
|---|---|---|
| API routes (auth/authz happy+unhappy path) | PARTIAL | `routeGating.test.ts`, `secopsAccess.test.ts`, `playbooksAuth.test.ts`, `cniiAuthorisation.test.ts` cover permission gating for several route groups; only a minority of the 66 route files have a matching `__tests__` file (see list in §1.1) — most VMS/CNII/TI routes do, most legacy/simple routes (e.g. `brand.ts`, `dns.ts`, `urlscan.ts`) do not. |
| Authentication | PARTIAL | `authSignin.test.ts` exists; OAuth/OIDC state-nonce-tenant validation is tested thoroughly but only for the Email Security M365/Google onboarding flow, not for the primary admin/client sign-in path's own OAuth (if any — see Fork B for whether admin Google OAuth has equivalent tests). |
| Tenant isolation | PARTIAL | Explicit isolation tests exist and pass for Email Security (`integration.test.ts`: "tenant isolation: another org's ids are 404, and org_id from the client is ignored") and for `resolveOrg.test.ts`/`cnii.test.ts`/`cniiScope.test.ts`. No equivalent isolation test was found for `org-cti` (shared IOC endpoint), `wazuh` routes, or `threats` — consistent with `PRODUCTION_NOTES.md` item 6 ("wazuh, incidents, threats, org-cti are not yet scoped"). Full cross-surface isolation audit is Fork C's remit; this is a test-coverage observation only. |
| Scanner contracts (Nmap/Nuclei/OpenVAS) | PARTIAL | `openvasIngest.test.ts` tests the OpenVAS evidence-ingestion contract. No equivalent test file found for Nmap or Nuclei ingestion specifically — Fork A/B should confirm whether those scanners post through the same generic ingestion path (and are therefore covered indirectly) or have no contract test at all. |
| Worker job lifecycle | UNVERIFIED (by this fork) | `vmsJobLifecycle.test.ts` and `vmsWorkerPresence.test.ts` exist and were not individually read in depth here; Python-side `test_worker.py` exists but was not executed (see §1.3). Treat as PARTIAL pending Fork A's confirmation of what these actually assert. |
| Evidence ingestion | PARTIAL | `openvasIngest.test.ts`, `vmsOutcomes.test.ts` (outcomes/evidence). |
| Vulnerability normalization | PARTIAL | `vmsFindings.test.ts` exists; severity/CVSS banding is tested in both backend (`severity.test.ts`) and frontend (`severity.test.mjs`) with cross-checked boundary parity — this specific pairing is genuinely solid evidence, not just file presence. |
| Remediation / verification | PARTIAL | `vmsOutcomes.test.ts`, `vmsAssessments.test.ts` present; no dedicated "verification rescan" test was identified by name — Fork A should confirm whether rescan-triggers-reassessment logic has any test coverage at all. |
| MISP ingestion | MISSING (in this test run) | No `misp*.test.ts` file found anywhere under `backend/src/**/__tests__`. `services/misp.ts` exists (per Fork B) but appears to have zero automated test coverage in this branch's tree. |
| IOC correlation | PARTIAL | `iocEnrichment.test.ts` exists under `services/__tests__`. |
| AI context isolation | PARTIAL | `ai.test.ts`, `aiCnii.test.ts` exist; whether they specifically assert tenant-boundary isolation of AI context (as opposed to just functional correctness) was not verified line-by-line by this fork — flag for Fork B/C. |
| Sector aggregation | PARTIAL | `cniiNational.test.ts` covers national/sector-level CNII endpoints. |
| Reporting | PARTIAL | `exportApi.test.ts`, `exportClientsAdmin.test.ts`. |
| Onboarding | UNVERIFIED | No test file named for client/provider onboarding was found (`accounts.test.ts` and `clientPortal.test.ts` are the closest matches; neither name implies full onboarding-wizard coverage) — the onboarding SQL migration (`2026-09-organisations-onboarding.sql`) exists but test coverage for the onboarding *flow* specifically is not established here. |
| Integrations (general) | PARTIAL | Strong, specific coverage exists for Email Security's three external integrations (M365, Google Workspace, Mailgun inbound) — this is the best-tested integration surface in the repo by a wide margin. Wazuh, OpenVAS, MISP, Nmap, Nuclei, NVIDIA have thinner or no direct test coverage (see rows above). |

**Overall testing posture:** the backend has genuine, substantial, passing unit/integration-style test coverage (640 tests, all passing) — this is real engineering discipline, not theater. But coverage is uneven: Email Security and VMS/CNII core logic are well tested; MISP ingestion, onboarding flows, and several scanner/worker contracts have little or no dedicated coverage. No test in this run touches a live external system, so **none of this test suite is evidence that production integrations (live Wazuh, live MISP, live OpenVAS) actually work** — it only proves the code's internal logic behaves correctly against its own fixtures and mocks.

---

## 3. Acceptance test cases — all 49 requirements

Format: **AT-NN** | Requirement | Preconditions | Steps | Expected result | Evidence to capture | Responsible role | Pass/fail criteria.

### Section 1 — Functional

| ID | Req | Preconditions | Steps | Expected result | Evidence to capture | Role | Pass/Fail |
|---|---|---|---|---|---|---|---|
| AT-01 | 1. Asset discovery | Tenant with at least one authorised domain/CIDR scope | Trigger discovery scan; wait for completion | New assets appear, tagged with owning org, internet-facing/internal classification, and AFRINIC allocation data if African IP range | Discovery job log, asset list diff, AFRINIC lookup response | VMS analyst | Fail if any discovered asset lacks an org_id or ownership verification flag |
| AT-02 | 2. Scan coverage | Target with known services (web, API, network) | Run each scanner category individually (Nmap, Nuclei, OpenVAS) | Each scanner returns normalized findings tagged with its source engine; unsupported categories (cloud config, container) return an explicit "not supported" state, not silence | Per-scanner raw output + normalized finding record | VMS analyst | Fail if a category silently returns zero findings indistinguishable from "not supported" |
| AT-03 | 3. Scheduling/custom sigs | Scheduler configured, one custom Nuclei template submitted | Schedule a recurring scan; submit a custom signature; attempt cancel/retry | Scan runs on schedule; custom signature requires authorisation before use; cancel/retry both functional | Schedule record, signature approval audit entry, job status transitions | Platform admin | Fail if a custom signature runs without an approval record |
| AT-04 | 4. CVE/NVD/CWE | Finding with a known CVE | Inspect finding detail | CVE ID, CVSS, CWE class, and NVD metadata all present and traceable to source | Finding detail payload, `services/nvd.ts` / `cveIntel.ts` call log | VMS analyst | Fail if CVE shown without CVSS/CWE provenance |
| AT-05 | 5. Misconfig/compliance | Compliance framework assigned to org | Run a control assessment | Result maps to a named framework (NIST/CIS/NDPA/CRF-NCS) with versioned control ID, not a generic "misconfiguration found" | Assessment record with framework + control reference | GRC analyst | Fail if framework mapping is absent or framework version unspecified |
| AT-06 | 6. Risk prioritisation | Finding with known CVE, asset with criticality set | Inspect risk score breakdown | Score shows weighted components (exploitation/KEV/EPSS, asset criticality, business context) individually, each with its basis stated | Risk score explain payload (`lib/riskScore.ts` output) | VMS analyst | Fail if score given without itemised, traceable basis |
| AT-07 | 7. Continuous exposure | KEV catalog updated externally | Wait one refresh cycle (12h) or force refresh | Newly-KEV-listed CVE on an existing finding is reflected and surfaced, with a timestamp showing when the correlation last ran | KEV cache timestamp, finding re-score event | VMS analyst | Fail if "continuous" claim cannot show an actual refresh timestamp distinct from scan time |
| AT-08 | 8. Sector heatmaps | Multiple orgs across ≥2 sectors with findings | Open sector heatmap view | Interactive map renders with drill-down to provider-level detail, honest empty state for sectors with no data | Screenshot/DOM snapshot, underlying aggregation API response | Sector oversight user | Fail if heatmap is static marketing copy / not backed by a real aggregation endpoint |
| AT-09 | 9. Automated remediation / Workflow API | A finding requiring remediation | Trigger remediation workflow via API | Task created, assignable, status syncs back, consequential actions require human approval | Workflow API request/response, approval gate log | VMS analyst / approver | Fail if any "automated" remediation executes without an approval record for a consequential action |
| AT-10 | 10. Approval/SLA/reporting workflows | Remediation task with an SLA | Let SLA elapse without action | Escalation/notification fires at SLA breach; audit trail records breach; reporting dashboard reflects breach | SLA timer config, breach notification log, dashboard screenshot | SOC manager | Fail if SLA breach is silent |
| AT-11 | 11. Open XDR | Alert from SIEM (Wazuh) correlated with a TI IOC | Trigger a Wazuh alert matching a known IOC | Case auto-created with cross-source correlation (SIEM + TI) visible in one investigation view, with a response playbook offered, not just two separate data points | Case record showing both source types, playbook suggestion | SOC analyst | Fail if "XDR" is two disconnected dashboards rather than one correlated case |
| AT-12 | 12. Automated intel distribution | IOC/advisory marked for distribution | Publish an IOC | Designated stakeholders receive it through a tracked channel (not a pull-only shared endpoint) with a delivery record | Delivery/send log, recipient list, classification tag | TI analyst | Fail if "distribution" is only a GET endpoint stakeholders must poll |
| AT-13 | 13. Distribution workflow automation | Distributed advisory | Stakeholder does not acknowledge within SLA | Reminder/escalation fires automatically; non-ack is visible to sender | Ack/escalation audit trail | TI analyst | Fail if no ack-tracking record exists at all |
| AT-14 | 14. Anonymised benchmarking | ≥2 providers with comparable metrics | Open benchmarking dashboard | Patch cadence / exposure density shown per cohort with a defined minimum cohort size (k-anonymity) preventing re-identification | Benchmarking API response, cohort-size enforcement logic | Sector oversight user | Fail if a cohort of 1 can be viewed, or metric defs are undocumented |
| AT-15 | 15. Self-service portal | Prospective provider, no account | Complete registration → invitation → approval → org creation flow unattended | Org provisioned with scoped API credentials, onboarding progress visible | Onboarding state machine transitions, issued credential scope | Platform admin / provider | Fail if any step requires manual backend intervention not represented in the UI |
| AT-16 | 16. RBAC / logical separation | Two tenants, each with data | Attempt cross-tenant read via API, export, search, and cache paths | All denied/scoped correctly, including exports and cached enrichment | Per-surface 403/empty-result evidence | Security reviewer | Fail if any single surface leaks cross-tenant data |
| AT-17 | 17. NCC-CSIRT oversight | Oversight role exists | Oversight user requests aggregated view, then a specific provider's identifiable data | Aggregated view open; identifiable drill-down requires explicit authorisation and is logged | Role definition, access-authorisation record, audit log entry | NCC-CSIRT reviewer | Fail if oversight role has unrestricted silent access to identifiable data |
| AT-18 | 18. Provider-restricted access | Provider user | Attempt to view another provider's data via UI, search, analytics export | All denied or anonymised | Negative-test evidence across all listed surfaces | Provider user | Fail on any leak |
| AT-19 | 19. MSSP operations | Alert ingested | Full lifecycle: triage → assign → investigate → response approval → close → report | Each stage recorded with actor, timestamp, and RBAC-gated action | Case audit trail (`cases.ts` lifecycle), report output | SOC analyst/manager | Fail if any stage is missing an actor/timestamp |
| AT-20 | 20. GRC platform integration | GRC platform endpoint/contract | Attempt a live data exchange per the Commission's GRC API spec | Bi-directional data exchange succeeds per contract | API call/response against the actual GRC system | GRC specialist | Fail (automatically, pending) — no external GRC integration contract exists in this repo; mark NOT READY until the Commission's API spec is obtained |
| AT-21 | 21. Strategic dashboards | Org with compliance/case/Wazuh data | Open executive dashboard | Real KPIs render with honest "not yet assessed" states, no fabricated trend | Dashboard screenshot, underlying 4 API calls' responses | Executive/manager | Fail if any number shown has no backing API call |
| AT-22 | 22. Emerging threats + KEV | New CVE added to CISA KEV | Re-score an affected finding | Finding's risk score and priority reflect KEV status within one refresh cycle | Before/after risk score, KEV cache state | VMS analyst | Fail if KEV status never reaches the finding's score |
| AT-23 | 23. CCI mapping + executive reporting | CNII asset classified | Generate executive report including CCI section | Report includes CCI-classified assets, provider relationships, and is schedulable/deliverable, not only on-demand | Generated report file, delivery schedule config | Executive | Fail if "automated" reporting has no scheduling mechanism |

### Section 2 — Non-functional

| ID | Req | Preconditions | Steps | Expected result | Evidence | Role | Pass/Fail |
|---|---|---|---|---|---|---|---|
| AT-24 | 24. MFA | Admin account | Attempt admin login without second factor | Login blocked pending second factor, for every admin account, not just one configured example | Auth flow trace, account-level MFA enforcement flag | Security reviewer | Fail if any admin account can bypass MFA |
| AT-25 | 25. Audit trails | Any scan/access/config change | Perform one of each | Each produces an immutable, actor-attributed, timestamped audit record with retention and access control | Audit table rows, access-control check on the audit log itself | Security reviewer | Fail if any listed action type leaves no audit record |
| AT-26 | 26. SSO | NCC identity provider | Attempt SAML/OAuth login via that IdP | Successful login with correct role mapping from IdP claims | IdP metadata config, successful SSO session, role-mapping log | Platform admin | Fail (pending) — no NCC IdP integration found in this repo; mark NOT READY |
| AT-27 | 27. Strict data separation | Two tenants | Re-run AT-16 plus P21/P25/P26-specific regression cases | No leakage across any surface including those added by P21 (staff org assignment), P25 (TI), P26 (IOC cache) | Regression test results | Security reviewer | Fail on any leak; note P26/P27 are on an unmerged branch — re-run there separately |
| AT-28 | 28. Cloud-native SaaS, 99.9% uptime | Production deployment reachable | Query actual uptime measurement source for a rolling 30/90-day window | A real measured uptime percentage is produced, backed by a monitoring tool, not asserted | UptimeRobot (or equivalent) dashboard export | Platform admin | Fail (currently) — `services/uptimerobot.ts` exists but is called only from a manual CLI diagnostic script (`scripts/testNewKeys.ts`), never from any API route or scheduled job; no uptime figure is ever computed, stored, or surfaced today |
| AT-29 | 29. Scale (1000s of assets, 100+ orgs) | Load-test environment (non-production) | Run a synthetic load test simulating target scale | System meets defined latency/throughput targets without starving smaller tenants | Load test report with concrete numbers | DevOps/Performance engineer | Fail (currently) — no load-test evidence of any kind exists in this repository; mark NOT VERIFIED, not PASS or FAIL, until a test is actually run in a non-production environment |

### Section 3 — Open APIs / Workflow APIs

| ID | Req | Preconditions | Steps | Expected result | Evidence | Role | Pass/Fail |
|---|---|---|---|---|---|---|---|
| AT-30 | 30. Open APIs for CTI/SIEM | External CTI/SIEM client | Authenticate and call a documented endpoint per published API docs | Call succeeds per the documented contract; versioning and error format are stable | Published API documentation (none found — see AT-36/AT-48), successful external call | Integration partner | Fail — no published API documentation exists in this repository (no OpenAPI/Swagger file found under any non-`node_modules` path); third-party interoperability cannot be exercised against a spec that does not exist |
| AT-31 | 31. Workflow management API | External workflow system | Call the remediation workflow API from outside the platform | External system can create/update/close a remediation task | External call trace | Integration engineer | PARTIAL — `cases.ts` and VMS remediation routes exist as internal-facing APIs; no evidence of a published contract or external-system integration test |

### Section 3 — Deliverables (32–49)

These are, by the audit's own rule, **contractual/organisational facts** that a repository can only partially evidence. Each row states what the repo *can* show and what it explicitly *cannot*.

| ID | Req | What the repo can show | What it cannot show | Status |
|---|---|---|---|---|
| AT-32 | 32. Inception report | Nothing — no document matching "inception report" exists anywhere in the repo or `docs/` tree | Whether one was delivered to the Commission outside this repo | NOT VERIFIED |
| AT-33 | 33. NCC-CSIRT-hosted go-live | `render.yaml`, `railway.json`, Vercel config show deployment to **Render/Railway/Vercel**, general-purpose commercial clouds | Any NCC-CSIRT-hosted environment, any evidence of a handover to NCC-CSIRT-controlled infrastructure | NOT READY — the audit brief explicitly warns not to substitute commercial-cloud deployment for this; that substitution is exactly what the repo would tempt one to do |
| AT-34 | 34. Core platform capabilities | Asset mapping (VMS), scanning, basic reporting (`exportApi.ts`), RBAC (`permissions.ts`), multitenancy (`resolveOrg.ts`, `orgScope.ts`) — all present in code with passing unit tests | Live operational proof at the target scale | READY WITH CONDITIONS |
| AT-35 | 35. Stakeholder portal | `clientPortal.test.ts`, `app/client/*` routes, onboarding SQL migration | Whether the portal is reachable/functional in the production environment right now — `PRODUCTION_NOTES.md` (2026-09-02) records the portal's auth path returning `502` from an unreachable upstream host at that time | NOT READY per the repo's own operational notes (dated evidence); may have changed since — unverified now |
| AT-36 | 36. API documentation | None — no OpenAPI/Swagger/Postman collection found | — | MISSING |
| AT-37 | 37. First 10 pilot providers | No pilot-provider tracking, roster, or onboarding-completion record found anywhere in code or docs (`pilot` only appears in unrelated marketing copy and AI script names) | Real-world onboarding status entirely | NOT VERIFIED / likely MISSING |
| AT-38 | 38. Workflow automation testing | SOAR (`infra/soar/soar.py`, `test_forwarder.py`) and case-lifecycle backend tests exist | End-to-end tested evidence of the *workflow automation* specifically (vs. unit tests of pipeline mechanics) | PARTIAL |
| AT-39 | 39. Full VTEM operationalisation + CCI mapping | CNII hierarchy (overview→sector→org→asset, per commit `e79f382`) is real and implemented | "Full operationalisation" as a business state | PARTIAL (backend) / NOT VERIFIED (business) |
| AT-40 | 40. Exposure monitoring + heatmaps | KEV-correlated risk scoring is real; sector heatmap is marketing copy only (see AT-08) | — | PARTIAL, heatmap specifically MISSING |
| AT-41 | 41. Automated intelligence sharing | See AT-12/13 — pull-based anonymised IOC sharing exists; push distribution with ack-tracking does not | — | PARTIAL/MISSING |
| AT-42 | 42. Strategic dashboards | See AT-21 — real, honest executive dashboard exists | Sector benchmarking half of this requirement (see AT-14) | PARTIAL |
| AT-43 | 43. Emerging threats + KEV | See AT-22 — real and wired into scoring | — | COMPLETE (backend) |
| AT-44 | 44. Complete provider onboarding | Onboarding SQL/UI scaffolding exists | "Complete" as a rollout state | NOT VERIFIED |
| AT-45 | 45. Automated executive reporting | `ExecutiveReport.tsx` exists and is genuinely honest about data provenance; PDF export is manual (click-to-export), not scheduled | Any scheduled/automated delivery mechanism (cron job, email send) for this report | PARTIAL — "automated" specifically is not evidenced; it is manually triggered |
| AT-46 | 46. Threat landscape report | No document matching this found | — | MISSING / NOT VERIFIED |
| AT-47 | 47. Security assessment (pentest) | `routes/securityAssessment.ts` and `services/securityAssessment.ts` exist — these appear to be an internal self-assessment feature, not evidence of an independent third-party penetration test | A real external pentest report | NOT READY — do not conflate the internal `securityAssessment` module with Requirement 47's independent pentest |
| AT-48 | 48. Final API documentation | Same as AT-36 | — | MISSING |
| AT-49 | 49. Knowledge transfer | `routes/handover.ts` / `ShiftHandover.tsx` exist but are a SOC **shift-handover** feature (analyst-to-analyst operational handoff), unrelated to a project knowledge-transfer deliverable — do not conflate these | Any project-level technical knowledge-transfer artifact | MISSING / NOT VERIFIED — flagging this naming collision explicitly so it is not mistaken for evidence |

---

## 4. Findings table — Requirements 12, 13, 14, 19, 21, 22, 28, 29 (perf), 32–49

For folding into the master 49-requirement matrix.

| ID | Requirement | Backend | Integration | Status | Evidence | Gap |
|---|---|---|---|---|---|---|
| 12 | Automated intelligence distribution | PARTIAL | PARTIAL | PARTIAL | `routes/orgCTI.ts` GET `/shared` — pull-based, anonymised, no ack | No push distribution, no delivery record, no stakeholder targeting |
| 13 | Distribution workflow automation | MISSING | MISSING | MISSING | `routes/notifications.ts` only covers internal staff notify (`handover:write` gated), not external stakeholder ack workflows | No acknowledgement tracking, no escalation/reminder logic found anywhere |
| 14 | Anonymised provider benchmarking | MISSING | MISSING | MISSING | Only match for "benchmark" is unrelated (`stix.ts` anonymization-type tagging); no patch-cadence/exposure-density cohort dashboard found | Entire capability absent; `/api/org-cti/shared` is IOC sharing, not benchmarking |
| 19 | MSSP managed security operations | PARTIAL/COMPLETE (backend) | UNVERIFIED (live) | PARTIAL | `routes/cases.ts` full lifecycle: create/assign/close/notes/tasks/escalate/execute-step/report, all `requirePermission`-gated | Backend lifecycle is genuinely solid; no live-operations evidence (actual SOC running it at volume) |
| 21 | Strategic intelligence dashboards | PARTIAL | COMPLETE (internal data) | PARTIAL | `components/features/ExecutiveReport.tsx` — real, honest, composed from 5 live endpoints | Sector-benchmarking half (Req 14) absent; no drill-down into per-sector comparison |
| 22 | Emerging threat intel + KEV correlation | COMPLETE | COMPLETE | COMPLETE | `services/cisa.ts` (live CISA KEV fetch, 12h cache) wired into `lib/riskScore.ts` (30% exploitation weight, P1 priority logic) | Refresh is 12h-polling, not push/real-time — acceptable given CISA KEV itself updates infrequently, but don't call it "real-time" |
| 28 | Cloud-native SaaS / 99.9% uptime SLA | PARTIAL | CONFIGURED ONLY | PARTIAL | `services/uptimerobot.ts` is a real, complete UptimeRobot client | **Never called from any route or job** — only referenced from a manual CLI script (`scripts/testNewKeys.ts`); no uptime figure is ever computed/stored/shown; no SLA measurement exists operationally |
| 29 | Scale (perf angle) | UNVERIFIED | UNVERIFIED | UNVERIFIED | `express-rate-limit` used broadly (41 files) for per-request throttling; no job-queue library (BullMQ etc.) found — concurrency appears to rely on the Python worker's own polling/claim model | No load-test evidence anywhere in the repo; no documented concurrency ceiling or tenant-fairness mechanism |
| 32–49 | Contractual deliverables | N/A | N/A | See §3 table (AT-32…AT-49) | — | Most require evidence outside this repository; several (API docs, inception report, threat landscape report, independent pentest, knowledge transfer) have **no matching artifact at all** in the repo, and two (handover, security-assessment) have naming collisions that must not be mistaken for the deliverable they sound like |

---

## 5. Honest limits of this fork's audit

- Test results above are accurate and reproducible (command + counts given verbatim).
- Acceptance test cases are design-time specifications, not run results — none of AT-01…AT-49 was actually executed against a live system by this fork; running them requires the stakeholder/role access and live infrastructure the audit brief explicitly says to defer.
- Requirements 32–49 are, by nature, facts about contracts, sign-offs, and physical hosting that no code inspection can establish. Where this report says MISSING for a document (e.g., inception report, threat landscape report, API documentation), that means **no such artifact exists in this repository** — it does not mean one was never produced; it may exist outside version control (e.g., sent directly to the Commission as a PDF/email) and this repo simply cannot confirm or deny that.
