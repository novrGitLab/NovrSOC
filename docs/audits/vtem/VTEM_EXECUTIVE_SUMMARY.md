# VTEM Platform Audit — Executive Summary

**Audited:** `C:\Users\USER\NovrSOC`, branch `marketing-pages-merge` (commit `bab6ff0`, = `main` + 5 marketing/website commits). **Audit date:** 2026-10-28. **Method:** evidence-first, read-only, five-dimension review (backend, frontend, integration, security/tenancy, testing) against 49 numbered VTEM requirements, executed via five parallel specialist review passes plus coordinator synthesis and spot-verification. Full detail is in the nine companion documents in this folder; this summary is the condensed, decision-grade view.

---

## Overall readiness assessment

**NovrSOC is a substantially real, substantially engineered platform with genuine operational depth in its core domains (VMS, CNII, SecOps case management, risk scoring, CVE/KEV intelligence) — and it is not ready for a VTEM go-live as specified, for reasons that are fixable but currently blocking.** Of 49 requirements: **3 COMPLETE, 27 PARTIAL, 14 MISSING, 5 UNVERIFIED, 0 NOT APPLICABLE** (full breakdown in `VTEM_49_REQUIREMENT_MATRIX.md`). The platform's strongest subsystems — CVE/CWE enrichment, KEV-driven risk scoring, CNII sector mapping, case/response lifecycle management — are evidenced in depth, tested, and genuinely good engineering. Its weakest areas are not "unbuilt features" in the usual sense but **structural**: an unreconciled fork between two major development lines, a confirmed and currently-exploitable cross-tenant data leak with an unmerged fix already sitting in the repository, zero MFA, no real SSO, no oversight role for the platform's own named national-stakeholder audience, and a client portal that is majority non-functional while still presenting itself as working.

---

## Critical Finding #1: two unreconciled development lines

This repository has **17 active git worktrees**. The branch audited as primary (`marketing-pages-merge` = `main` + 5 commits) has the full admin app, the full client app, and a public marketing site — but its backend stops at phase P25. A separate, unmerged worktree (`feat/vms-onboarding`, path `novr-vms`) has phases P26 (per-organisation IOC cache tenancy, MISP sync hardening) and P27 (formal VMS onboarding/scope-authorisation) — but almost no frontend at all. Both lines share a common ancestor at commit `9429743` ("unified release manifest") and have never been merged back together since. **Every finding in this audit that touches P26/P27 is marked accordingly** and is not credited to the line treated as current. This is not a minor bookkeeping issue: it means the fix for this audit's single most severe security finding (see below) already exists, is tested, and is simply not deployed anywhere.

## Critical Finding #2: a confirmed, exploitable cross-tenant data leak, with the fix already written

On the primary line, `ioc_enrichments` — the table backing IOC lookup history, CTI feed/stats, and STIX export — has **no `org_id` column at all**. Four route paths (`cti.ts` feed/stats, `intelligence.ts` STIX export, `search.ts` IOC search) read it with zero organization filtering. **Any authenticated user from any organisation can read every other organisation's IOC enrichment history and download it as a STIX export.** The fix — a schema migration, four route diffs, and a dedicated passing test suite — exists, complete and tested, on the unmerged `novr-vms` worktree (P26). It has simply never been merged. **This should be the first thing fixed, before any other work in this plan**, and the engineering cost of doing so is small (the fix is already written).

## Critical Finding #3: non-functional requirements are the platform's weakest area, not its functional ones

MFA does not exist anywhere, for any role, including the platform's own super-admin. Real SSO does not exist (only non-NCC Google OAuth, itself reported broken as of the last documented live check). No role exists for the NCC-CSIRT/sector-oversight audience the platform's own marketing site explicitly addresses. Two additional confirmed cross-tenant leaks exist on `/api/brand/*` and `/api/urlscan|webscan/history`. These are the kind of gap that blocks a production go-live regardless of how mature the functional modules are.

## Critical Finding #4: the client portal and public marketing site overstate what exists

16 of 22 client-portal sidebar items are confirmed broken — every API call they make is refused — and are rendered with no visual distinction from the 6 that work; a `BROKEN` status field already exists in the navigation config and is simply never checked. Separately, the public marketing site makes two checkable-and-false claims: live ngCERT/NCC-CSIRT/CBN advisory integration (the platform's own internal evidence shows this is mock data / a 403'd feed) and a live, accurate state-level threat heatmap (confirmed fabricated — hardcoded ASN→state fallback with uncapped cumulative counters). A regulator or CERT reading the public site today would reasonably expect capabilities that do not exist.

---

## Major strengths (verified, not assumed)

- **Risk scoring and CVE/KEV intelligence** (Requirements 4, 6, 22): a genuinely mature, deterministic, well-tested pipeline — live CISA KEV correlation is actually wired into the scoring formula, not a stub.
- **CNII sector/provider drill-down** (Requirement 8, backend half): real aggregation with overview→sector→organisation→asset traversal, tenant-restricted, and ships plain-English KPI definitions with every response — a genuinely good explainability pattern.
- **Approval-gated remediation** (Requirement 9/10, the internal half): race-safe, audited, closes a TOCTOU gap, and produces identical logged outcomes whether a human or the automated SOAR engine acted.
- **VMS worker engineering**: real Nmap and Nuclei subprocess integrations with safety-conscious exclusion tags and honest three-way outcome classification (`unsupported`/`not_attempted`/`inconclusive`), never collapsing "no answer" into a false "clean" result.
- **Backend test discipline**: 640 backend tests, 637 passing, 0 failing, run live for this audit — substantial, real engineering practice, not aspirational.
- **Fail-closed design patterns throughout**: Wazuh agent-ownership resolution, cross-org staff access, and MISP's auth-failure-vs-unreachable distinction all refuse to guess rather than defaulting to an unsafe "show everything" state.

## Critical deficiencies

- No MFA, no real SSO, no NCC-CSIRT oversight role — three non-functional/access-control requirements with zero implementation.
- A confirmed, exploitable cross-tenant leak on the primary line with its own fix sitting unmerged.
- Two further confirmed cross-tenant leaks (`brand`, `urlscan`/`webscan`).
- Anonymised provider benchmarking (Requirement 14) has zero backend representation of any kind.
- No self-service stakeholder portal; the one onboarding UI that exists creates accounts that cannot sign in.
- No external GRC platform integration, and this is blocked on an external party (NCC must supply the API spec) rather than being an engineering backlog item.

## Security blockers (must resolve before any go-live claim)

1. Merge the P26 IOC-cache fix (or reapply it) — Critical Finding #2.
2. Close the `brand`/`urlscan`/`webscan` cross-tenant leaks.
3. Build MFA for administrator accounts.
4. Resolve SSO against an actual NCC-supplied identity-provider spec.

## Deployment blockers

- The platform is deployed to commercial clouds (Render/Railway/Vercel per visible config), not an NCC-CSIRT-hosted environment — Requirement 33 is not met and the audit brief explicitly warns against substituting one for the other.
- Deployment platform of record is itself ambiguous from the repo (`PRODUCTION_NOTES.md`, dated September 2026, documents Railway+Vercel; a more recent `render.yaml` suggests a possible migration not reflected in those notes).
- No load-test evidence exists for the stated target scale (thousands of assets, 100+ licensed entities).

## Frontend usability concerns

- The platform's most complete module (VMS, 23 pages) is absent from the main admin sidebar and reachable only by already knowing the URL.
- A recurring "403 renders as 0/0%" pattern affects at least 4 dashboard widgets and the Executive Report — making the latter unusable by one of its two named audiences (`executive`).
- Two competing design systems coexist; the VMS/TI/CNII kit is the clear target language, the dashboard/header/legacy layer is a generation behind it.
- Static "Telemetry Online"/"Cloud Node" header indicators are hardcoded true on every page, never reflecting real system health.

## Recommended next steps

1. Fix Critical Findings #1 and #2 first — merge or reapply the P26 fix, then reconcile the two development lines before any further feature work compounds the divergence.
2. Close the remaining confirmed cross-tenant leaks (`brand`, `urlscan`/`webscan`) alongside the P26 merge — same priority, same low cost.
3. Ship the quick wins in `VTEM_GAP_IMPLEMENTATION_PLAN.md` (hide broken nav items, fix the 403-as-zero pattern, promote VMS into the sidebar, wire up the existing UptimeRobot client) — all are small, backend-complete, and materially improve both trust and demonstrability within days.
4. Scope and begin MFA and SSO in parallel with the above — these are the two most consequential non-functional gaps and do not depend on any other package.
5. Get explicit stakeholder input on three items this repository cannot resolve alone: the NCC GRC platform's API spec (blocks Requirement 20 entirely), the NCC identity provider's details (blocks Requirement 26), and which external Workflow Management System (if any) Requirement 9/31 actually targets.
6. Treat Requirements 14 (benchmarking), 15 (self-service portal), and 17 (NCC-CSIRT role) as ground-up builds, not refinements — each has zero existing implementation and each is explicitly named in the VTEM checklist as a flagship capability.

---

## What is verified fact vs. assumption in this summary

**Verified directly, this audit:** the git worktree topology and branch divergence; the `ioc_enrichments` schema and its four unscoped route reads; the `brand`/`urlscan`/`webscan` route-level leaks; the absence of MFA/SAML/GRC-integration code (exhaustive grep); the real Nmap/Nuclei worker code (independently re-verified by the coordinator after a cross-fork contradiction); the 640/637 backend and 15/15 frontend test results (run live for this audit); the `BROKEN`-nav-flag-not-consulted bug; the two overstated public-marketing claims (cross-checked against the repo's own internal evidence).

**Carried forward from the existing `NOVRSOC_REDESIGN_TECHNICAL_AUDIT_V2.md` (dated 2026-10-25) and re-confirmed where re-checked, not independently re-derived everywhere:** the 137-route frontend inventory, the 389-route backend inventory, the exact risk-scoring formula, the fabricated-heatmap and 403-as-zero findings, the dual-design-system finding.

**Explicitly unverified by this audit (requires live access, stakeholder input, or a non-production environment this audit was not authorized to use):** current live status of MISP's API credential; which commercial cloud (Render vs. Railway) is the actual current deployment target; whether a Supabase anon key has ever been issued for this project; actual production uptime; actual load-test behavior at target scale; whether an inception report, threat-landscape report, independent pentest, or knowledge-transfer session exists outside this repository (a repository cannot prove a negative about documents delivered elsewhere).
