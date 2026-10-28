# VTEM Frontend Redesign Blueprint

**This is a blueprint, not an implementation.** It proposes information architecture, navigation, role-specific dashboards, feature-explanation patterns, missing views, and reusable UI components so that every capability documented across the VTEM audit — found or missing — becomes visible, understandable, and demonstrable. It draws heavily on `NOVRSOC_REDESIGN_TECHNICAL_AUDIT_V2.md` §§4, 5, 15–17 (an existing, code-grounded redesign plan from 2026-10-25) and reframes it specifically against the 49 VTEM requirements, rather than re-deriving a design from scratch. Companion document: `VTEM_FRONTEND_VISIBILITY_AUDIT.md` (the findings this blueprint responds to).

**Principle carried over from V2 and endorsed here:** the VMS/TI/CNII design kit (`components/features/vms/{kit,ui,table,charts,data}`) is already the platform's best UI — token-based, dark-mode-correct, accessible, reused across three modules. The redesign target is to extend *that* language everywhere, not invent a new one, and to retire the legacy `components/shared/*` layer that the dashboard, header, and older modules still use.

---

## 1. Information architecture

### 1.1 The core problem this fixes
Today's IA has three faults, evidenced in the visibility audit: (a) the most complete module (VMS, 23 pages) is entirely absent from the main sidebar and only reachable by already knowing it exists; (b) dead pages (16 of 22 client items, 2 of 5 compliance frameworks, 6 orphaned admin pages) are shown with no distinction from live ones; (c) there is no role or surface for the sector-oversight stakeholder (NCC-CSIRT) that the public marketing site explicitly targets.

### 1.2 Proposed top-level structure (admin shell)

Replace the current flat 13-section sidebar with role-aware, capability-grouped sections, each directly traceable to VTEM requirement numbers:

| Section | Requirement(s) | Replaces / absorbs |
|---|---|---|
| **Overview** | 7, 21, 23 | Dashboard, Executive Report — rebuilt per §3 below |
| **Vulnerability & Exposure Management** | 1, 2, 3, 4, 6, 7 | Promotes the existing VMS shell into the main sidebar as a first-class section instead of a side-door. Absorbs "Infrastructure & Assets," "Network" (dedup per V2 §6.3's unified-inventory view) |
| **Remediation & Workflow** | 9, 10 | VMS remediation + Response Approvals + Playbooks, merged into one "Response" workflow per V2 F-07, with an explicit "Workflow API" tab showing outbound integration status (today: MISSING, shown honestly) |
| **Threat Intelligence** | 4, 12, 13, 22 | Existing TI module, unchanged IA (already sound) |
| **Security Operations** | 11, 19 | Cases, Alerts, Threats, SOAR, MITRE — unchanged IA, add an explicit "this is not full XDR" scope note (see §4) |
| **CNII Watch** | 8, 23 | Existing, extended with the subsector level V2 §8.2 proposes |
| **Compliance & GRC** | 5, 20 | Relabelled "Internal Compliance Mapping (not an external GRC integration)" until/unless Requirement 20 is actually built — honesty over ambition |
| **Sector Oversight** *(new)* | 8, 14, 17, 21 | A new section, visible only to a new oversight role — see §2 |
| **Reporting** | 21, 23, 45, 46 | Consolidated report centre per V2 §13.2's shared engine design |
| **Administration** | 15, 16, 24–27 | Customers/onboarding, Settings, Audit, Team — fix the mock-data "Setup" path first |
| **Platform Health** | 28, 29 | `/admin/settings/health`, promoted out of Settings into its own top-level item with real uptime/SLA data once backend exists |

### 1.3 Client portal IA
Hide every `BROKEN`-flagged item (the `status` field in `config/nav.ts` already exists and is simply not consulted — this is a one-line fix, not a redesign, and should ship before any visual redesign work: see Gap Plan Task referencing F-10). Until the backend for a client capability exists, do not render a sidebar entry for it at all; a capability a provider cannot use is not navigation, it is noise. Reduce the current 22-item client sidebar to the ~6 items that work (VMS × 5, Dashboard) plus explicit "Coming soon" entries only for capabilities with a committed backend date.

### 1.4 Public marketing site
Keep the existing marketing pages' structure and copy style, but: (a) correct the two overstated integration claims identified in the visibility audit (ngCERT/NCC-CSIRT/CBN advisory integration, live state-level heatmap) to describe what is actually live versus planned; (b) add a real, functioning entry point for self-service stakeholder registration if Requirement 15 is to be delivered — today `/cert-csirt` and `/regulators` are dead-end copy pages for exactly the audience that would need one.

---

## 2. Navigation and role model changes needed

The frontend's role model today is fixed at five roles (`super_admin`, `soc_manager`, `analyst`, `executive`, `portal_user`). Two VTEM-required audiences have no role at all:

1. **NCC-CSIRT / sector oversight stakeholder (Requirement 17).** Needs a new role, e.g. `sector_overseer`, scoped read-only to aggregated sector/CNII views plus explicitly-authorised provider drill-down, with every drill-down access logged (the backend audit (`VTEM_SECURITY_AND_INTEGRATIONS_AUDIT.md`) covers what logging exists; this blueprint only specifies that the *frontend* must show, on every drill-down screen, a visible "you are viewing \<provider\> as sector oversight; this access is logged" banner — oversight access should never look identical to normal staff access).
2. **Level-1 analyst** — V2 §11 already identifies this gap on the backend side (no `analyst_l1` role or tier exists); the frontend should add a reduced Cases/Alerts-only nav profile once the backend role exists, rather than giving L1 the full analyst nav and relying on 403s to hide things.

**Global organisation switcher** (V2 F-05): promote the VMS-only switcher (`lib/vmsOrg.ts`, sessionStorage) to a platform-wide `orgContext` mounted in the header, so staff viewing a client's data see a persistent "Viewing: \<org\>" chip on *every* page, not only inside the VMS shell. This single change does more for "is this real or demo data, and whose" clarity than any other item in this blueprint, and V2 already designs it in full (§4.4) — this blueprint adopts that design unchanged.

---

## 3. Role-specific dashboards

Each dashboard below replaces the current single `GeneralDashboard.tsx`, which today mixes real and fabricated data behind one undifferentiated view for every role (V2 §5's 19-widget trace).

| Dashboard | Audience | Must show | Must NOT do (confirmed anti-patterns to remove) |
|---|---|---|---|
| **SOC dashboard** | analyst, soc_manager | Real alert/case KPIs, MITRE (all 14 tactics, not 8), SOAR status, AI entry point (replacing the "Automation" widget per V2 §5.2) | Render 403s as `0`/`0%` (F-14); show the fabricated Nigeria attack map (F-04) |
| **Vulnerability & Exposure dashboard** *(new, does not exist today)* | analyst, soc_manager | Open findings by priority, KEV-matched count, overdue remediation, scope/authorisation status, risk-policy version in use | Hide the risk formula — show it, with a "why this score" link on every finding |
| **Executive dashboard** | executive, soc_manager, super_admin | Only endpoints the `executive` role can actually read; strategic trend, coverage, critical/overdue counts, no raw evidence | Call endpoints the viewer's own role is refused by (F-06) — this is the single highest-priority dashboard fix, since it is currently unusable by one of its two named audiences |
| **Sector Oversight dashboard** *(new)* | the new `sector_overseer` role | Aggregated sector risk, anonymised benchmarking (once built), authorised provider drill-down with access logging visible on-screen | Ever show identifiable provider data without an explicit, logged authorisation step |
| **Client/provider dashboard** | portal_user | Only the ~6 working client capabilities; explicit onboarding checklist (groups mapped / alerts flowing / scope approved / first scan done — V2 §13.3 already specifies this exact checklist from existing backend records) | Show 16 broken sidebar items as if available |

---

## 4. Feature-explanation patterns (apply platform-wide)

These are reusable UI patterns, not one-off fixes, meant to close the explainability gaps found in §5.3 of the visibility audit:

1. **"Why this score" drawer** on every risk/priority number: factor breakdown (technical/exploitation/exposure/criticality), policy version, and a link to the policy definition. Backend already stores `risk_factors`; today nothing renders them (V2 F-08).
2. **"Unavailable to your role" state**, distinct from "no data," for every KPI/widget that depends on a permission the viewer lacks. Replaces every confirmed `0`/empty-on-403 pattern (F-06, F-14) — this single component, built once and reused, closes four separate confirmed defects.
3. **Data-freshness and scope badges**: every map, feed, or aggregate shows its source, last-updated time, and precision level (reuse the existing TI precision model — `state`/`country`/`unknown` — everywhere geography is shown, instead of the dashboard's separate, fabricated ASN→state fallback; V2 §8.4, §9).
4. **"Not an assessment" / "advisory only" banners**: on Compliance pages (deterministic mapping ≠ control assessment) and on the legacy AI chat surface (ungoverned ≠ the grounded, logged AI path) — both are confirmed-real distinctions that are invisible to a user today.
5. **Mean vs. concentration callouts**: anywhere a statistic is an average (CNII `infrastructure_risk`), show the max and the P1/P2 count beside it, per V2 §8.1's own recommendation.
6. **Integration honesty badges** on both the admin UI and the public marketing site: "Live," "Configured, not verified," "Planned" — replacing the static green "Telemetry Online"/"Cloud Node" indicators (F-13) and the marketing site's unqualified "ngCERT, NCC-CSIRT and CBN advisory integration" claim (§5.0 of the visibility audit).

---

## 5. Missing views this blueprint specifies (net-new, no backend assumed built)

| View | Requirement | Depends on backend work (see Gap Plan) |
|---|---|---|
| Self-service stakeholder registration/onboarding (provider-facing, not staff-facing) | 15 | Yes — no such API exists today |
| API documentation / developer portal page | 30, 36, 48 | Partially — routes exist; no schema/doc generation found |
| Anonymised benchmarking dashboard | 14 | Yes — no backend metric exists |
| Intelligence/IOC/incident distribution + acknowledgement tracking UI | 12, 13 | Yes |
| External Workflow Management API status/config screen | 9, 31 | Yes |
| GRC external-platform integration status screen | 20 | Yes — clarify first whether this is in scope at all (see Gap Plan) |
| Real platform status/uptime page (today `/status` is a placeholder) | 28 | Yes — needs actual monitoring data |
| MFA enrollment/management screen | 24 | Yes |
| SSO/NCC identity configuration screen | 26 | Yes |
| CNII subsector drill-down level | 8 | Partially — backend has only a flat `subfield` string (V2 §8.1/§8.2 already designs the fix) |
| Container/cloud scanning results view | 2 | Yes — no backend scanner for these categories exists |

---

## 6. Reusable UI component inventory (verified, carried from V2 §15)

| Component | Path | Action |
|---|---|---|
| PageHeader, KpiCard, SeverityBadge, PriorityBadge, RiskScore, Tag, EmptyState, ErrorState, Notice, Segmented, Toggle, Select, SearchBox, Drawer, ConfirmDialog, Timeline, ExportCsvButton, EvidenceViewer | `components/features/vms/kit.tsx` | **Keep, promote to `components/ds/*`** as the platform-wide design system |
| Card, SectionTitle, Skeleton, Unavailable, StatusPill, CountUp, SegmentBar, Tip | `features/vms/ui.tsx` | Keep → ds |
| Data table | `features/vms/table.tsx` | Keep → ds |
| Charts | `features/vms/charts.tsx` | Keep → ds |
| `useVmsData`, `useVmsOrg`, `useVmsCan` | `features/vms/data.ts` | Keep, generalise to `useApi`, `useOrgContext`, `useCan` |
| NigeriaStateMap (extract from `TiMap.tsx`) | `features/ti/TiMap.tsx` + `nigeriaPaths.ts` | Extract as a standalone, reusable component — needed by both the SOC dashboard replacement and the Sector Oversight dashboard |
| TlpBadge, Limitations | `features/ti/common.tsx` | Keep |
| KpiCard, EmptyState, PageHeader, ChartWrapper (legacy) | `components/shared/*` | **Retire**, replace call sites with `ds/*` equivalents |
| RightRail | `components/dashboard/RightRail.tsx` | **Remove** — nothing else depends on it (V2 §4.1 confirms by import-graph check) |
| Header | `components/layout/Header.tsx` | **Rework**: real status indicators, org switcher, breadcrumbs (V2 §4.2 gives the exact target structure) |
| NigeriaThreatMap, NigeriaMap2, GlobalThreatMap | `components/geo/*` | **Remove** once the dashboard is rebuilt on the TI map component (F-04) |

---

## 7. Sequencing

This blueprint assumes the engineering sequencing already defined in `NOVRSOC_REDESIGN_TECHNICAL_AUDIT_V2.md` §17 (sprints S0–S9) remains the correct order for anything that touches shared infrastructure (org context, search, the design system promotion) — **redesign visuals should not start before S0–S2 land**, because a visual refresh of pages that are still cross-tenant-unsafe (F-01/F-02/F-03) or still rendering fabricated data (F-04) would make the dishonesty *more* convincing, not less. The VTEM-specific net-new views in §5 above should be sequenced into the Gap Implementation Plan's Packages A–D (see `VTEM_GAP_IMPLEMENTATION_PLAN.md`) rather than scheduled independently, since most of them have no backend yet to visualise.

**First three redesign moves, in order, regardless of which VTEM package ships first:**
1. Ship the "Unavailable to your role" pattern and fix the four confirmed 403-renders-as-zero widgets (F-06, F-14) — small, high-trust-impact, no migration.
2. Hide `BROKEN`-flagged nav items using the `status` field that already exists in `config/nav.ts` (one-line sidebar filter change) — immediately turns the client portal from "majority broken" to "small and honest."
3. Promote the VMS module into the main admin sidebar — the platform's most complete capability should not be the hardest one to find.
