# Remaining Implementation Roadmap

Prioritized by operational and regulatory importance, drawn from the Priority column of the
re-baselined `VTEM_49_REQUIREMENT_MATRIX.md` and the per-requirement detail in
`VTEM_49_REQUIREMENT_RECONCILIATION.md`. Four tiers: fix now, high-value but scoping/stakeholder
-dependent, maturity/scale validation, and facts to confirm rather than build.

## Tier 0 — Security/regulatory-critical, start immediately

| Requirement | Gap | Why it's Tier 0 | Effort signal |
|---|---|---|---|
| 16 — Logical separation of provider data | `routes/brand.ts` still leaks across tenants via unscoped module-level state, at the same lines the original audit cited | This is the *same class* of bug as the audit's #1 critical finding (Req 27), which is now fixed — the fix pattern (`org_id`-scoped storage, confirmed effective) applies directly here | Low — a known pattern, already proven once |
| 24 — MFA for all administrator accounts | No TOTP/WebAuthn/OTP exists for any role, including super_admin | A single compromised admin credential is a total breach with no second factor anywhere in the system | Medium — new auth flow, but well-understood (TOTP is standard) |
| 17 — NCC-CSIRT oversight role | No oversight role tier exists in the role model at all | The public `/cert-csirt` page already addresses this audience; there is currently no way to honor that promise in the product | Medium — new role tier, read-only aggregated + per-provider views |
| 15 / 35 / 44 — Self-service onboarding | `POST /api/auth/signup` is a literal always-fails stub; only a staff-run wizard exists | This is one of the deliverables explicitly named in the contract ("self-service"); a staff-assisted alternative, however good, does not satisfy that wording | Medium-High — needs a real registration flow, email verification, and a decision on what self-service should and shouldn't allow a provider to do unsupervised |

## Tier 1 — High-value, blocked or scoping-dependent

| Requirement | Gap | Dependency | Notes |
|---|---|---|---|
| 26 — SSO/SAML with NCC identity management | No SAML/OIDC federation exists | **Blocked on NCC** supplying IdP details | Flag this explicitly as a stakeholder dependency in any schedule, not an engineering slip |
| 20 — GRC platform integration | No integration with the Commission's platform exists | **Blocked on NCC** supplying an API spec/data contract | Same category as above — don't schedule engineering time against an unknown target |
| 28 — 99.9% uptime SLA | The UptimeRobot client is fully built and never invoked operationally | None — this is the cheapest fix in the entire audit | Wire the existing client into a scheduled job and surface the number on `/status`, which is currently a logo placeholder |
| 14 / 42 — Anonymised provider benchmarking | Zero schema, aggregation, or UI exists | None (ground-up) | Needs its own design pass — this is new product work, not a bug fix |
| 12 / 13 / 41 — Push-based intelligence distribution + acknowledgement tracking | Current sharing is pull-only; no ack-tracking/escalation to external stakeholders exists | None | Natural extension of the now-real scheduled-reporting pipeline (P30) — reuse its delivery/ack infrastructure rather than building a second one |
| 6 — Risk prioritisation completeness | No CVSS v4, no exploit evidence beyond KEV/EPSS, scoring weights are unversioned constants | None | Make the weights an auditable, versioned config before adding v4 — regulators will ask how a score was derived |
| 25 — Audit trail durability | Ring-buffer + batched flush exists; full-coverage and durability-under-restart not independently confirmed | None | A verification task, not necessarily new code — confirm the P2 migration is applied everywhere and walk every mutation path |
| 9 / 31 — External Workflow Management System integration | The platform's own approval/case engine is solid but not positioned as, or connected to, an external WMS | **Needs a named target system** (ServiceNow/Jira/other) before scoping | Don't build a generic adapter speculatively — get the target from the stakeholder first |

## Tier 2 — Maturity and scale validation (the capability exists; prove it)

| Requirement | What to prove | How |
|---|---|---|
| 10 / 23 / 45 — Automated executive reporting | The real P30 scheduled generate-and-deliver pipeline fires end-to-end and an email actually arrives | Run one real schedule through a full cycle against a real recipient in a non-production org; also resolve the open discrepancy between "SLA route removed" (original audit) and the pre-existing `jobs/incidentEscalation.ts` SLA-breach email — don't let that ambiguity stand |
| 21 — Executive dashboard correctness | The stale-cross-org-data bug is confirmed fixed; the separate 403-renders-as-zero defect for the `executive` role specifically was **not** re-tested live this pass | Sign in as `executive`, hit every KPI card, confirm none render a false zero on a permission refusal |
| 18 — Client portal functional completeness | The misleading-presentation bug (broken items shown as if working) is confirmed fixed; the ~17 underlying broken API calls behind those badged items were not individually re-tested | Walk the client portal as a `portal_user`, exercise every badge-flagged nav item, and either fix or formally re-scope each one |
| 29 — Scale (thousands of assets, 100+ entities) | Indexing design looks correct; no load-test evidence exists anywhere | Run an actual load test against realistic asset/org counts before claiming this in any readiness conversation |
| 2 / 3 — Scan coverage/scheduling scope | OpenVAS is governance-disabled; no web/cloud/container scanning engine; no custom-signature authoring UI | Get a scope decision from the stakeholder on whether these are in scope for go-live at all — this is a product decision, not an open engineering task |
| 5 — Compliance framework naming | No framework literally named "CRF-NCS" exists anywhere; NDPA/NDPR naming is inconsistent | Get the exact framework name/scope from the stakeholder before doing any further engineering here |

## Tier 3 — Confirm, don't build

These are facts a repository audit cannot establish either way. Each needs a yes/no answer from
whoever holds the artifact or record, not engineering time:

- **32** — Does an inception report exist outside version control?
- **37** — Is there a pilot-provider roster, and have the first 10 actually onboarded?
- **46** — Does a threat landscape report deliverable exist?
- **47** — Has an independent third-party penetration test occurred? (The existing
  `securityAssessment.ts` is an internal self-assessment feature and must not be presented as
  satisfying this.)
- **49** — Has technical knowledge transfer happened as a project deliverable? (`ShiftHandover.tsx`
  is SOC shift-handover between analysts, not project knowledge transfer — a naming collision,
  not evidence either way.)
- **33** — Is NCC-CSIRT-hosted go-live still the plan, given the platform is currently deployed on
  commercial cloud infrastructure (Render/Railway/Vercel)? This is a hosting-strategy decision,
  not something engineering can resolve unilaterally.

## Sequencing recommendation

Start Tier 0 now — none of it is blocked, and the brand.ts leak fix in particular should take
days, not weeks, given the proven P26 pattern. Get the NCC dependencies (Tier 1's SSO/GRC rows)
moving in parallel so they stop sitting on the critical path invisibly. Tier 2's verification
tasks are cheap relative to their value — several of them could turn "PARTIAL" into "COMPLETE"
with a day of live testing rather than new engineering. Tier 3 just needs someone to ask.
