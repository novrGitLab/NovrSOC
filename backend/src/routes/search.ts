import { Router } from 'express';
import { requireAuth, type AuthRequest } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';
import { searchStrict as search } from '../lib/wazuh-indexer';
import { orgScope, alertScopeFilter } from '../lib/orgScope';
import { severityFromLevel } from '../lib/severity';
import { requireOrg, requestOrg, hasPermission, type Permission } from '../lib/permissions';
import { isStaffRole } from '../lib/resolveOrg';
import { TLP_ORDER, isTlp, type Tlp } from '../services/tiPolicy';
import { NIGERIAN_ACTORS, GLOBAL_ACTORS } from '../services/threatActors';
import { dbErrorMessage } from '../services/cases';

// GET /api/search?q= — the header's global search (2026 redesign, Stage 3).
//
// A provider per entity, each independently gated on its own permission and run in parallel
// (Promise.allSettled): a role that lacks a permission never attempts that source at all; a
// source a role CAN use that then fails (indexer down, table missing) is reported in `sources`
// with its error, so the UI can tell "nothing found" apart from "could not check" rather than
// folding every outcome into zero results. Every source is scoped to the caller's own
// organisation (requestOrg — staff may view another, exactly as the rest of the app) except
// reference data that is not tenant-owned (CVEs, threat actors). Threat Intelligence results
// respect each record's own TLP marking against the viewer's ceiling (services/tiPolicy.ts) —
// client roles never see AMBER+STRICT or RED, same rule as /api/ti itself.
//
// Organisation and application-navigation results are deliberately not provided here:
// organisation search is `/api/organisations`-backed and staff-only (added once a lighter list
// endpoint exists for soc_manager/analyst — see NOVRSOC_REDESIGN_TECHNICAL_AUDIT_V2.md, F-15);
// navigation search is client-side only (frontend/src/components/layout/GlobalSearch.tsx), over
// config/nav.ts, and never touches the network.

const router = Router();
// index.ts mounts this router with no requireAuth wrapper (the old code's single
// requirePermission('alerts:read') supplied it); every provider below needs its own
// permission check instead of one shared gate, so auth and org resolution are both done here.
router.use(requireAuth, requireOrg);

type ResultType = 'case' | 'advisory' | 'ioc' | 'alert' | 'vms_asset' | 'vms_finding' | 'cve' | 'ti_indicator' | 'threat_actor' | 'cnii_org';
interface SearchResult { type: ResultType; title: string; subtitle: string; badge?: string; url: string }
interface SourceStatus { entity: ResultType; ok: boolean; error?: string }

// The term is spliced into PostgREST `or=(...)` filters, where `,` `(` `)` are syntax and `%` `_`
// `*` are wildcards. Stripping them stops a query like "x,org_id.neq.cybernovr" from rewriting
// the filter — the org scope must not be something the search box can widen.
const pgSafe = (q: string) => q.replace(/[,()%_*\\"'`]/g, ' ').replace(/\s+/g, ' ').trim();

const viewerCeiling = (req: AuthRequest): Tlp => (isStaffRole(req.user?.role) ? 'red' : 'amber');
const mayView = (tlp: unknown, ceiling: Tlp) => TLP_ORDER.indexOf(isTlp(tlp) ? tlp : 'amber') <= TLP_ORDER.indexOf(ceiling);

interface Ctx { req: AuthRequest; q: string; raw: string; like: string; org: string; ceiling: Tlp }
interface Provider { entity: ResultType; permission: Permission | null; run: (ctx: Ctx) => Promise<SearchResult[]> }

const PROVIDERS: Provider[] = [
    {
        entity: 'case', permission: 'cases:read',
        run: async ({ org, like }) => {
            const supabase = getSupabase();
            if (!supabase) return [];
            const { data, error } = await supabase.from('cases').select('id, case_number, title, severity, status')
                .eq('org_id', org).or(`title.ilike.${like},case_number.ilike.${like},source_ip.ilike.${like},agent_name.ilike.${like}`)
                .order('created_at', { ascending: false }).limit(5);
            if (error) throw error;
            return (data ?? []).map((c) => ({ type: 'case' as const, title: `${c.case_number} — ${c.title}`, subtitle: c.status, badge: c.severity, url: `/admin/secops/cases?id=${c.id}` }));
        },
    },
    {
        // Stored alerts (the table the Alerts page itself reads), not the Wazuh indexer — a
        // separate alert provider below still covers alerts the store has not ingested yet.
        entity: 'alert', permission: 'alerts:read',
        run: async ({ org, like }) => {
            const supabase = getSupabase();
            if (!supabase) return [];
            const { data, error } = await supabase.from('alerts').select('id, rule_description, agent_name, severity, event_time')
                .eq('org_id', org).ilike('rule_description', like).order('event_time', { ascending: false }).limit(5);
            if (error) throw error;
            return (data ?? []).map((a) => ({
                type: 'alert' as const, title: a.rule_description || 'Alert', subtitle: `${a.agent_name ?? 'Unknown agent'} · ${new Date(a.event_time).toLocaleString('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })} WAT`,
                badge: a.severity, url: `/admin/secops/alerts?id=${a.id}`,
            }));
        },
    },
    {
        entity: 'ioc', permission: 'intel:read',
        run: async ({ org, like }) => {
            const supabase = getSupabase();
            if (!supabase) return [];
            const { data, error } = await supabase.from('ioc_enrichments').select('ioc_value, ioc_type, risk_score').eq('org_id', org).ilike('ioc_value', like).limit(3);
            if (error) throw error;
            return (data ?? []).map((i) => ({ type: 'ioc' as const, title: i.ioc_value, subtitle: `${i.ioc_type} · risk ${i.risk_score ?? 0}`, url: `/admin/threat/cti?q=${encodeURIComponent(i.ioc_value)}` }));
        },
    },
    {
        entity: 'advisory', permission: 'intel:read',
        run: async ({ like, ceiling }) => {
            const supabase = getSupabase();
            if (!supabase) return [];
            const [legacy, reports] = await Promise.all([
                supabase.from('nigeria_advisories').select('id, title, severity, source').or(`title.ilike.${like},description.ilike.${like}`).order('published_at', { ascending: false }).limit(3),
                supabase.from('ti_reports').select('id, title, threat_level, tlp, feed_id').ilike('title', like).order('published_at', { ascending: false }).limit(3),
            ]);
            if (legacy.error && reports.error) throw legacy.error;
            const out: SearchResult[] = [];
            for (const a of legacy.data ?? []) out.push({ type: 'advisory', title: a.title, subtitle: a.source, badge: a.severity, url: '/admin/ti/vulnerabilities' });
            for (const r of reports.data ?? []) if (mayView(r.tlp, ceiling)) out.push({ type: 'advisory', title: r.title, subtitle: `${r.feed_id}${r.threat_level ? ` · ${r.threat_level}` : ''}`, url: '/admin/ti/vulnerabilities' });
            return out;
        },
    },
    {
        entity: 'vms_asset', permission: 'vms:read',
        run: async ({ org, like }) => {
            const supabase = getSupabase();
            if (!supabase) return [];
            const { data, error } = await supabase.from('vms_assets').select('id, value, asset_type, criticality').eq('org_id', org).ilike('value', like).limit(5);
            if (error) throw error;
            return (data ?? []).map((a) => ({ type: 'vms_asset' as const, title: a.value, subtitle: `${a.asset_type} · ${a.criticality}`, url: `/admin/vms/assets/${a.id}` }));
        },
    },
    {
        entity: 'vms_finding', permission: 'vms:read',
        run: async ({ org, q, like }) => {
            const supabase = getSupabase();
            if (!supabase) return [];
            const cveMatch = /^CVE-\d{4}-\d+$/i.test(q) ? q.toUpperCase() : null;
            let query = supabase.from('vms_findings').select('id, title, priority, status, asset_value').eq('org_id', org).limit(5);
            query = cveMatch ? query.contains('cve_ids', [cveMatch]) : query.or(`title.ilike.${like},rule_id.ilike.${like}`);
            const { data, error } = await query;
            if (error) throw error;
            return (data ?? []).map((f) => ({ type: 'vms_finding' as const, title: f.title, subtitle: `${f.asset_value} · ${f.status}`, badge: f.priority ?? undefined, url: `/admin/vms/findings?id=${f.id}` }));
        },
    },
    {
        // Global reference data (not org-owned) — any staff/client role with vms:read.
        entity: 'cve', permission: 'vms:read',
        run: async ({ q }) => {
            if (!/^CVE-?\d{0,4}-?\d*$/i.test(q) && !/^\d{4}-\d+$/.test(q)) return [];
            const supabase = getSupabase();
            if (!supabase) return [];
            const { data, error } = await supabase.from('cve_intel').select('cve_id, cvss_score, kev, epss_score').ilike('cve_id', `%${q.replace(/^cve-?/i, '')}%`).order('cve_id', { ascending: false }).limit(5);
            if (error) throw error;
            return (data ?? []).map((c) => ({ type: 'cve' as const, title: c.cve_id, subtitle: `CVSS ${c.cvss_score ?? '—'}${c.kev ? ' · CISA KEV' : ''}`, badge: c.kev ? 'critical' : undefined, url: `/admin/ti/vulnerabilities?cve=${c.cve_id}` }));
        },
    },
    {
        entity: 'ti_indicator', permission: 'intel:read',
        run: async ({ q, ceiling }) => {
            if (q.length < 3) return [];
            const supabase = getSupabase();
            if (!supabase) return [];
            const { data, error } = await supabase.from('ti_indicators').select('id, type, value, status').ilike('value', `%${q}%`).limit(8);
            if (error) throw error;
            const rows = data ?? [];
            if (!rows.length) return [];
            const { data: sources } = await supabase.from('ti_indicator_sources').select('indicator_id, tlp').in('indicator_id', rows.map((r) => r.id));
            // Conservative, same rule as routes/threatInfo.ts hideRestrictedLabels: any source over
            // the viewer's ceiling takes the whole indicator out of these results, not just a label.
            const restricted = new Set((sources ?? []).filter((s) => !mayView(s.tlp, ceiling)).map((s) => s.indicator_id as string));
            return rows.filter((r) => !restricted.has(r.id)).slice(0, 5).map((r) => ({
                type: 'ti_indicator' as const, title: r.value, subtitle: `${r.type}${r.status === 'expired' ? ' · expired' : ''}`, url: `/admin/ti/indicators?q=${encodeURIComponent(r.value)}`,
            }));
        },
    },
    {
        // A curated reference library (public reporting), not this platform's own telemetry —
        // the same source /api/ti/actors reads. Matched in process; no database involved.
        entity: 'threat_actor', permission: 'intel:read',
        run: async ({ q }) => {
            const needle = q.toLowerCase();
            return [...NIGERIAN_ACTORS, ...GLOBAL_ACTORS]
                .filter((a) => a.name.toLowerCase().includes(needle) || a.aliases.some((al) => al.toLowerCase().includes(needle)))
                .slice(0, 5)
                .map((a) => ({ type: 'threat_actor' as const, title: a.name, subtitle: `${a.origin} · ${a.motivation}`, url: '/admin/ti/actors' }));
        },
    },
    {
        // Cross-organisation by design (cnii:sector) — an organisation's own CNII profile is read
        // from its own portal, not searched for here.
        entity: 'cnii_org', permission: 'cnii:sector',
        run: async ({ like }) => {
            const supabase = getSupabase();
            if (!supabase) return [];
            const { data: orgs, error } = await supabase.from('organisations').select('slug, name').ilike('name', like).limit(10);
            if (error) throw error;
            if (!orgs?.length) return [];
            const { data: profiles } = await supabase.from('cnii_org_profiles').select('org_id, sector_id, designation').in('org_id', orgs.map((o) => o.slug));
            const bySlug = new Map((profiles ?? []).map((p) => [p.org_id, p]));
            // sector_id only, not a label: the backend validates it (lib/cnii-sectors.ts) but has
            // no display label for it — the frontend's own copy of the list does that lookup, the
            // same as every other CNII page already leaves to the client.
            return orgs.filter((o) => bySlug.has(o.slug)).slice(0, 5).map((o) => {
                const p = bySlug.get(o.slug)!;
                return { type: 'cnii_org' as const, title: o.name, subtitle: `${p.sector_id} · ${p.designation}`, url: `/admin/cnii/org/${o.slug}` };
            });
        },
    },
    {
        // The organisation's own Wazuh-sighted alerts not yet in the stored table, from the
        // indexer directly (kept from the original implementation) — org-scoped (lib/orgScope.ts).
        entity: 'alert', permission: 'alerts:read',
        run: async ({ org, raw }) => {
            const scope = await orgScope(org);
            interface AlertHit { _source?: { rule?: { description?: string; level?: number }; agent?: { name?: string }; timestamp?: string } }
            const result = await search<{ hits?: { hits?: AlertHit[] } }>('wazuh-alerts-4.x-*', {
                size: 3,
                sort: [{ timestamp: { order: 'desc' } }],
                query: { bool: { must: [{ multi_match: { query: raw, fields: ['rule.description', 'agent.name', 'data.srcip'], lenient: true } }, { range: { timestamp: { gte: 'now-7d' } } }], filter: [alertScopeFilter(scope)] } },
                _source: ['rule.description', 'rule.level', 'agent.name', 'timestamp'],
            });
            return (result?.hits?.hits ?? []).map((hit) => {
                const s = hit._source ?? {};
                return {
                    type: 'alert' as const, title: s.rule?.description || 'Wazuh alert',
                    subtitle: `${s.agent?.name ?? 'Unknown agent'} · ${s.timestamp ? new Date(s.timestamp).toLocaleString('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }) + ' WAT' : ''}`,
                    badge: severityFromLevel(s.rule?.level ?? 0), url: '/admin/secops/alerts',
                };
            });
        },
    },
];

router.get('/', async (req: AuthRequest, res) => {
    const raw = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 100) : '';
    const q = pgSafe(raw);
    if (q.length < 2) { res.json({ results: [], query: raw, total: 0, sources: [] }); return; }

    const ctx: Ctx = { req, q, raw, like: `%${q}%`, org: requestOrg(req), ceiling: viewerCeiling(req) };
    const role = req.user?.role;
    const runnable = PROVIDERS.filter((p) => !p.permission || hasPermission(role, p.permission));
    const settled = await Promise.allSettled(runnable.map((p) => p.run(ctx)));

    const results: SearchResult[] = [];
    const sources: SourceStatus[] = [];
    settled.forEach((outcome, i) => {
        const entity = runnable[i].entity;
        if (outcome.status === 'fulfilled') {
            results.push(...outcome.value);
            sources.push({ entity, ok: true });
        } else {
            sources.push({ entity, ok: false, error: dbErrorMessage(outcome.reason) });
        }
    });

    // At least one attempt for a role that has no permission for anything searchable (shouldn't
    // happen for an authenticated caller, but keeps the response shape honest either way).
    if (!runnable.length) { res.json({ results: [], query: raw, total: 0, sources: [] }); return; }
    res.json({ results, query: raw, total: results.length, sources });
});

export default router;
