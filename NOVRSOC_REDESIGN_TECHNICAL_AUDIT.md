# NOVRSOC Redesign Technical Audit

## 1. Executive summary

This repository is not a single thin app; it is a multi-domain security platform that already contains substantial implementation work in the backend, frontend, and SQL migrations. The strongest evidence of production intent is in the platform layer: the backend enforces tenant-bound access centrally, records cross-org access, and routes major product domains through a single Express entrypoint. The main redesign risk is not lack of ambition; it is that the system combines many modules with different maturity levels and operational assumptions into one broad product surface.

The codebase clearly distinguishes between:

- Working, domain-specific logic that is already implemented and tied to real tables and permissions
- Partially implemented or future-facing modules that are backed by SQL and navigation but not yet full runtime-ready
- Product-layer shell work that improves the UX and navigation but does not necessarily indicate a finalised service model

The strongest production-ready foundations are the multi-tenant org resolution model, the VMS risk model and findings lifecycle, the threat-intel ingestion pipeline, and the CNII watch logic. The main risk is architectural sprawl: the product has broad coverage across SecOps, VMS, TI, CNII, email security, AI, client portal, and compliance, but many sections are clearly in different completion states and some are only partially linked from the UI or SQL migrations.

## 2. Scope and method

This assessment is based on direct source review rather than README claims alone. Key evidence reviewed includes:

- [backend/src/index.ts](backend/src/index.ts)
- [backend/src/lib/resolveOrg.ts](backend/src/lib/resolveOrg.ts)
- [backend/src/routes/search.ts](backend/src/routes/search.ts)
- [backend/src/services/vmsFindings.ts](backend/src/services/vmsFindings.ts)
- [backend/src/routes/cnii.ts](backend/src/routes/cnii.ts)
- [frontend/src/app/admin/layout.tsx](frontend/src/app/admin/layout.tsx)
- [frontend/src/components/layout/Header.tsx](frontend/src/components/layout/Header.tsx)
- [frontend/src/components/layout/GlobalSearch.tsx](frontend/src/components/layout/GlobalSearch.tsx)
- [frontend/src/components/dashboard/RightRail.tsx](frontend/src/components/dashboard/RightRail.tsx)
- [frontend/src/config/nav.ts](frontend/src/config/nav.ts)

The objective was to establish what is implemented, what is partially wired, and what should be protected or redesigned before re-platforming or product consolidation.

## 3. Architecture evidence and delivery posture

### 3.1 Backend architecture is broad and modular
The backend entrypoint mounts many domain routers into a single API surface, including security operations, VMS, TI, dashboard, CNII, and AI-related routes. This is a strong sign that the system was designed as a consolidated SOC platform, not a single feature prototype. Evidence is in [backend/src/index.ts](backend/src/index.ts).

### 3.2 Multi-tenant access control is central and deliberately enforced
The most important security result is the org resolution model in [backend/src/lib/resolveOrg.ts](backend/src/lib/resolveOrg.ts). It enforces:

- client roles always use the token org
- staff roles may act on another org only when X-Org-Id is provided and the org exists
- analysts are restricted by staff_org_assignments and fail closed when the mapping is missing or unreadable
- all cross-org access is logged and recorded in org_access_audit when available

This is a production-oriented access model and a meaningful design foundation for a redesign.

### 3.3 Platform feature status is already annotated in navigation metadata
The frontend nav explicitly carries statuses like WORKING, PARTIAL, BROKEN, and PLANNED. This is important because it shows the product already understands maturity differences rather than pretending everything is equally ready. The status metadata is in [frontend/src/config/nav.ts](frontend/src/config/nav.ts).

This makes the redesign less about “start from zero” and more about sequencing a controlled consolidation. The codebase is already telling us which domains are mature and which are exploratory or impaired.

## 4. Feature inventory and implementation posture

### 4.1 SecOps and platform dashboard
The platform has working administration shells and global search, with the search endpoint restricted to analyst-authenticated flows. The backend route is in [backend/src/routes/search.ts](backend/src/routes/search.ts), and the frontend search UI is in [frontend/src/components/layout/GlobalSearch.tsx](frontend/src/components/layout/GlobalSearch.tsx). The header disables the search box for client routes and only shows it in admin flows, which is a deliberate security and UX constraint.

### 4.2 VMS is a major core module
The VMS system is broad and already structured around a legitimate findings lifecycle. In [backend/src/services/vmsFindings.ts](backend/src/services/vmsFindings.ts), findings are normalized, deduplicated, scored by scanner severity plus CVSS, KEV, EPSS, asset exposure, and criticality, and then processed through statuses like open, acknowledged, in progress, fixed pending verification, and reopened.

This is a serious platform capability, not just a form layer. The risk model is intentionally tied to evidence and to asset context.

### 4.3 CNII Watch is a sectorised intelligence layer over VMS and TI
The CNII route in [backend/src/routes/cnii.ts](backend/src/routes/cnii.ts) makes it explicit that CNII is not a separate data store; it is a sector classification layered across organisation assets and threat-intel data. It uses cnii_org_profiles and then aggregates VMS findings, active scopes, and TI matches by organisation.

This is a sound architectural pattern for a regulated-sector view, and it should be preserved in any redesign.

### 4.4 Threat Intel and Wazuh integration are implemented as operational pipelines
Threat intelligence is broad and includes Nigeria Targeting, feed ingestion, advisory processing, and indicator matching. The architecture and telemetry references are clearly present in the backend modules and startup job registration in [backend/src/index.ts](backend/src/index.ts). This supports the idea that TI and Wazuh are treated as real operational data sources, not just dashboards.

### 4.5 Email security and client portal exist as separate product surfaces
The frontend nav exposes admin email security and a client portal route set in [frontend/src/config/nav.ts](frontend/src/config/nav.ts). This indicates a multi-tenant product model with both analyst/admin and customer org views. The current code is clearly structured to separate the two exposure modes.

### 4.6 Compliance and AI are present but clearly uneven
The same nav file shows compliance sections as PARTIAL or BROKEN, while the AI section is clearly PARTIAL. This tells us the roadmap includes more than the MSSP core and that compliance and AI still need careful implementation sequencing rather than being “just another page.”

## 5. UI redesign assessment: admin shell, right rail, and search

### 5.1 Admin shell is already a serious product UI, not a prototype
The admin layout in [frontend/src/app/admin/layout.tsx](frontend/src/app/admin/layout.tsx) includes a sidebar, a sticky header, a fixed right rail, and a help assistant. The shell is built around a desktop-first SaaS pattern and it is intentionally designed to support high-density operational work.

### 5.2 The right rail is explicitly a design element, not an accident
The right rail component in [frontend/src/components/dashboard/RightRail.tsx](frontend/src/components/dashboard/RightRail.tsx) contains account overview, settings shortcuts, and quick actions. The admin shell persists its collapsed/expanded state via localStorage through the RAIL_STORAGE_KEY in [frontend/src/app/admin/layout.tsx](frontend/src/app/admin/layout.tsx).

This is an important design fact: the current admin shell already has a dense enterprise UI pattern with extra side infrastructure and action shortcuts. If the redesign goal is a cleaner or more “operational” experience, this rail is a legitimate candidate for trimming or re-scoping.

### 5.3 Header search is intentionally admin-only
The header in [frontend/src/components/layout/Header.tsx](frontend/src/components/layout/Header.tsx) disables the search box for client routes and only renders the global search for admin flows. The comment directly states that the `/api/search` endpoint is for analyst-authenticated case reads. The search results are also intentionally limited in size and query-safe. This is a strong sign that the product already understands route/role separation in the UI.

### 5.4 Search is featureably mature but should stay scoped to analyst/admin use
The backend search route in [backend/src/routes/search.ts](backend/src/routes/search.ts) searches cases, advisories, IOC values, and recent Wazuh alerts with per-source failure isolation. The query is sanitized before building PostgREST filters, with explicit comment protection against query injection patterns. This is a positive finding: the search is a bounded operational capability, not an open-ended broad indexing surface.

## 6. Dashboard flow and operational UX audit

### 6.1 The platform already has operational dashboard patterns and dashboard-specific backend routes
The backend includes a dashboard router and threat map logic. The route mounts are present in [backend/src/index.ts](backend/src/index.ts), and the current admin layout is built with a consistent header/search/layout rhythm. This suggests a coherent dashboard operating model exists, even if the data is not equally mature everywhere.

### 6.2 The UI is a product shell around multiple underlying domains
The navigation metadata in [frontend/src/config/nav.ts](frontend/src/config/nav.ts) clearly shows that the product shell is a multi-domain control plane rather than a single workflow. The issue is not lack of structure; it is that the shell is hosting several operational domains with different levels of maturity.

### 6.3 A redesign should preserve working flows and consolidate only the shared shell
The right rail, global search, and layout shell are sensible top-layer patterns. The redesign should not destroy the working interfaces; it should simplify the shell and make the underlying domains more legible.

## 7. Infrastructure and deployment posture

The repository includes a backend Dockerfile, Railway/render deployment config, SQL migration files, and environment-dependent services. The app is clearly designed around external services and infrastructure dependencies rather than a purely local monolith. This is typical for an MSSP platform with Wazuh, AI, TI, and database integrations.

The most relevant infra signals are in:

- [backend/Dockerfile](backend/Dockerfile)
- [render.yaml](render.yaml)
- [backend/package.json](backend/package.json)
- [backend/src/index.ts](backend/src/index.ts)

The architecture reads as “connected platform service with operational integrations,” not a simple SaaS app. This is a real strength, but it also increases deployment and configuration risk.

## 8. VMS findings and model integrity

The VMS system is the strongest evidence that the platform already contains serious SOC workflow logic. Several concrete characteristics stand out in [backend/src/services/vmsFindings.ts](backend/src/services/vmsFindings.ts):

- findings are normalized to a single model across Nuclei, OpenVAS, and Wazuh
- a finding is deduplicated by asset, port, and issue
- risk is recalculated when intelligence or exposure changes
- evidence is kept per detection and stored as a separate evidence trail
- manual and automated lifecycle transitions are represented explicitly

This is the kind of data model a redesign should protect, because it is the underlying operational intelligence layer of the platform.

## 9. CNII Watch: the most regulated domain and a good preserve candidate

The CNII route is one of the clearest evidence-backed examples of a domain-specific regulatory model with strict role and scope constraints. In [backend/src/routes/cnii.ts](backend/src/routes/cnii.ts), CNII is defined as a sector view over VMS and TI records, not a proprietary data store. The route also explicitly documents that staff can act on another organisation only under controlled conditions and that the system keeps CNII authorisation details separate from the core scanner data model.

This is a strong candidate to preserve during redesign because:

- it has explicit role boundaries
- it reuses existing VMS/TI assets instead of inventing a parallel model
- it is built around sector classification, scope, and authorisation records rather than ad hoc UI pages

## 10. Threat Intel and monitoring domain

The TI domain is broad and includes Nigeria-specific threat map logic, source ingestion, threat indicators, and advisory information. The project includes data and map-specific modules as well as role-based access rules. This makes the TI domain a real strategic capability, not just a visual add-on.

The strongest evidence is the combination of the TI routes and the nav status metadata in [frontend/src/config/nav.ts](frontend/src/config/nav.ts). This area is more complete than some of the compliance or brand-protection domains, which is why it should be treated as a core operating domain in redesign sequencing.

## 11. SecOps and AI role boundaries

The system clearly separates staff and client roles, and the permissions model is enforced at the route level and through org resolution. This is one of the most important architectural facts in the repo.

The AI features are present but still framed as purpose-specific and permission-gated. This implies the AI stack is a support layer for analyst workflows rather than a standalone application. That is a sensible pattern for a redesign: keep AI as a capabilities layer attached to operating domains rather than as a separate product surface.

## 12. Compliance, email security, and client portal status

The nav metadata shows that email security is WORKING and that the client portal is structured but not consistently mature across features. The same file points out that some client features are BROKEN, while others are PARTIAL or WORKING. That is a strong example of a product that has broad feature goals but uneven implementation quality.

Compliance is also clearly mixed: some frameworks are PARTIAL and some are BROKEN. This should be treated as domain-level technical debt rather than a single app-wide issue.

## 13. Public website boundaries and product scope

The repo includes public-facing marketing and login surfaces in [frontend/src/app/page.tsx](frontend/src/app/page.tsx) and other app-level pages, but the actual core operational product is clearly not a public website only. The existence of multi-role admin/auth flows, client portal flows, and internal operational modules means the app has a proper B2B security platform boundary rather than a simple public marketing site.

This makes redesign sequencing more important: public-facing messaging and internal/admin functionality should not be conflated.

## 14. Key risks

1. Product sprawl: Too many domains exist in one app shell, and they do not all have the same operational maturity.
2. Partial implementation drift: Some modules are clearly WORKING while others are PARTIAL or BROKEN, which increases rollout and maintenance risk.
3. Risk of UI/UX over-productization: The admin shell is rich and dense, but some sections may be carrying far more surface area than the underlying service maturity supports.
4. Non-uniform operational readiness: The platform has strong internal patterns but not uniform runtime completeness across all product domains.
5. Integration complexity: Wazuh, TI feeds, CNII, compliance, AI, and email security all rely on external integration assumptions and environment configuration.

## 15. Technical debt and redesign implications

The codebase’s main technical debt is not “bad code”; it is architectural heterogeneity. The platform appears to have been built in phases with different domain modules and different SQL milestones. This is a normal pattern for a serious platform, but it makes redesign and consolidation much more sensitive to scope boundaries.

The key redesign lesson is: preserve proven domain foundations, trim or merge shared shell/chassis elements, and treat the product as a set of mature operational domains rather than a single flat app.

## 16. Architecture changes recommended before a broad redesign

1. Reduce the shell to a stable shared control plane.
2. Preserve the org resolution and permission model as non-negotiable.
3. Keep the VMS findings lifecycle and risk model as the canonical operational domain.
4. Preserve CNII as a sector-aware overlay over VMS/TI rather than creating a standalone parallel system.
5. Separate AI into a capabilities layer attached to the relevant domains rather than as a new top-level system.
6. Decide which dashboard elements are real operational telemetry and which are product polish.
7. Consolidate duplicated or transitional routes in the client/admin boundaries.
8. Treat compliance and client-brand portals as separate product tracks with their own readiness gates.

## 17. Recommended phased roadmap

### Phase 1 — Stabilize foundations
- confirm org resolution model and role boundaries
- align route permissions and secure cross-org access logging
- remove or hide clearly broken client/admin paths
- standardize status definitions across modules

### Phase 2 — Preserve working domains
- keep VMS findings and risk engine in place
- preserve CNII classification and authorisation model
- keep TI/Wazuh ingestion and search logic intact
- stabilize dashboard services behind a single query contract

### Phase 3 — Consolidate shell and navigation
- reduce duplicated right-rail and navigation patterns
- simplify admin shell into a framework that supports consistent domain surfaces
- separate admin vs client portal responsibilities more explicitly

### Phase 4 — Sequence domain completion
- address compliance frameworks with explicit readiness gating
- re-evaluate email security and portal route maturity
- decide what AI capabilities are truly needed in the core product and what should remain additive

### Phase 5 — Redesign execution
- move to a more explicit product domain architecture
- standardize common UX primitives and API contracts
- treat each matured domain as a deployable unit with its own contract and lifecycle

## 18. Final assessment

This repository is not an unready prototype; it is a broad, partially matured security platform. It already contains several strong operational foundations, especially in org resolution, VMS risk processing, TI ingestion, and CNII sector analysis. The redesign should therefore be framed as consolidation and sequencing, not replacement.

The most important strategic choice is to preserve the working trust boundary and the real operational models, while reducing the shell and product sprawl that have accumulated around them.

## Appendix A — high-value evidence files

- [backend/src/index.ts](backend/src/index.ts) — central router and service mounting
- [backend/src/lib/resolveOrg.ts](backend/src/lib/resolveOrg.ts) — tenant resolution and analyst assignment enforcement
- [backend/src/routes/search.ts](backend/src/routes/search.ts) — admin search with scoped query sanitization
- [backend/src/services/vmsFindings.ts](backend/src/services/vmsFindings.ts) — VMS finding lifecycle and risk model
- [backend/src/routes/cnii.ts](backend/src/routes/cnii.ts) — CNII overlay model and sector analytics
- [frontend/src/app/admin/layout.tsx](frontend/src/app/admin/layout.tsx) — admin shell and side rail
- [frontend/src/components/layout/Header.tsx](frontend/src/components/layout/Header.tsx) — header behavior and search gating
- [frontend/src/components/layout/GlobalSearch.tsx](frontend/src/components/layout/GlobalSearch.tsx) — search UX and result model
- [frontend/src/components/dashboard/RightRail.tsx](frontend/src/components/dashboard/RightRail.tsx) — account/settings quick actions
- [frontend/src/config/nav.ts](frontend/src/config/nav.ts) — implementation status model for the whole app

## Appendix B — product-area inventory

- Overview / dashboard
- Security operations
- VMS and asset management
- Threat intelligence and TI map
- CNII watch
- Email security
- Compliance
- AI analyst
- Client portal
- Branding / external intelligence surfaces

## Appendix C — implementation sequencing recommendation

1. Multi-tenant foundation
2. VMS risk model and findings
3. TI and Wazuh pipeline integrity
4. CNII preserved as regulated overlay
5. Shell simplification and route hygiene
6. Client/admin portal separation
7. Compliance and AI readiness gating

## Appendix D — unknowns and follow-up questions

- Which domains are expected to be customer-facing versus internal-only in the next product phase?
- Which modules are still intentionally partial and should be hidden rather than promoted?
- What is the deployment reality of the Wazuh and TI integrations in production?
- Which compliance libraries or frameworks are actually required in the target operating model?

This audit is intentionally read-only and evidence-based. It preserves the robust working design patterns while flagging the broad platform complexity that would make a careless redesign higher-risk than necessary.
