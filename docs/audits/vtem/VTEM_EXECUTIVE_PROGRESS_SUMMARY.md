# NovrSOC — Executive Progress Summary (Re-baselined)

**Date:** 2026-10-28. **Baseline:** real `origin/main` @ `48747ba` (see
`VTEM_49_REQUIREMENT_RECONCILIATION.md` for full per-requirement evidence; this page is the
condensed, decision-grade view for management).

## The one-sentence version

Of the 49 contracted VTEM/NCC requirements, **3 are fully complete, 28 are partially built with
real evidence behind them, 13 are genuinely missing, and 5 cannot be confirmed from the
repository alone** — and the platform is materially stronger than an audit run three weeks ago
would have shown, because that audit's "current" baseline had quietly gone stale.

## What changed since the last formal audit

The original VTEM audit (also dated 2026-10-28, run earlier the same day) was performed against
a local `main` reference that had not been re-fetched in weeks. The *real* `origin/main` was 45
commits ahead, containing entire feature releases the original audit never saw: a 6-step client
onboarding wizard, a dashboard redesign, VMS executive/technical reporting and compliance
mapping, CNII monitoring-coverage completion, SecOps investigation/automation, Threat
Intelligence relevance/reporting, a full scheduled client-reporting pipeline, and Collector V1
(client-site log collection). We re-fetched, re-verified every requirement plausibly touched by
that gap against the real current code, and updated the matrix accordingly.

**The single most important correction:** the original audit's #1 critical security finding — a
confirmed, exploitable cross-tenant data leak in the threat-intelligence indicator cache — had a
fix that existed only in an unmerged branch at the time of that audit. **That fix is now merged
into `origin/main` and we independently confirmed it closes the leak** by reading the migration
and every route that touches that data. This is fixed, not just scheduled to be fixed.

## Net movement

| | Original audit | Re-baselined | Change |
|---|---|---|---|
| COMPLETE | 3 | 3 | — |
| PARTIAL | 27 | 28 | +1 bucket move, several upgraded within PARTIAL |
| MISSING | 14 | 13 | −1 |
| UNVERIFIED | 5 | 5 | — |

Only Requirement 44 (complete provider onboarding) formally changed bucket, from MISSING to
PARTIAL — a real, tested staff-run onboarding product now exists, even though true self-service
registration still doesn't. But several requirements that stayed "PARTIAL" on paper now carry
substantially stronger evidence:

- **Tenant isolation (Req 16/27)** — the confirmed-exploitable leak is fixed and merged. A
  second, separate, still-unfixed leak in the brand-monitoring feature remains and is now the
  single highest-priority security item.
- **Automated executive reporting (Req 10/23/45)** — "manual export only" is no longer accurate.
  A real scheduled generate-and-deliver pipeline exists, with weekly/monthly cadence and a
  dedicated executive-summary report type. What's left is proving it fires end-to-end live, not
  building it.
- **Interactive threat heatmap (Req 8/40)** — a real, production, click-to-drill-down Nigeria map
  now exists on the live dashboard — built and merged independently of, and before, the demo
  presentation layer described below. Don't credit the demo for this; it was already real.
- **Two UI-trust bugs** the original audit flagged by name are confirmed fixed: broken/planned
  sidebar items are now hidden from non-admin roles instead of shown indistinguishably from
  working ones, and the executive dashboard no longer shows a previous organisation's stale
  figures after switching tenants.

## What is still genuinely missing — unchanged by any of the above

- **No MFA** on any account, including the super-admin role.
- **No SSO/SAML** federation with any NCC identity system (blocked on NCC supplying IdP
  details — this is a stakeholder dependency, not an engineering gap).
- **No NCC-CSIRT oversight role** exists in the system at all, despite a public page explicitly
  addressing that audience.
- **No true self-service** provider registration — the one endpoint for it is a literal stub
  that always fails.
- **No GRC platform integration** (blocked on NCC supplying an API spec — same category as SSO).
- **No anonymised cross-provider benchmarking** — ground-up work, not a scoping fix.
- **No independent third-party penetration test** has occurred — an internal self-assessment
  feature exists and must not be confused with one.

## About the management demonstration running alongside this audit

A separate, staff-only "Demo Mode" has been built this sprint for executive walkthroughs. It is
**not merged into `origin/main` and does not count toward any requirement's status above.** It
reuses the real product UI with three fictional organisations and fully synthetic data so a
presenter can show the platform's actual screens without touching any real client's information.
Several of the screens it covers correspond to requirements still rated PARTIAL or MISSING above
(behavioral-analysis anomaly scoring, collector health monitoring, CNII compliance scoring) — a
convincing demo of those screens is not evidence those requirements are met for a real tenant.
See `VTEM_DEMO_VS_LIVE_COMPARISON.md` for the full screen-by-screen breakdown.

## Recommended immediate focus

See `VTEM_ROADMAP.md` for the prioritized plan. In one line: fix the second tenant-isolation leak
(cheap — the same pattern as the first fix), decide and resource MFA, get NCC's IdP/GRC
integration details so that dependency stops blocking planning, and define what "self-service
onboarding" needs to mean contractually before building more staff-assisted tooling on top of it.
