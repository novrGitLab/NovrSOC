import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { requireAuth } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';
import { search } from '../lib/wazuh-indexer';
import { DEFAULT_ORG_ID } from '../services/cases';

// GET /api/search?q= — the header's global search. Analyst-only (it reads cases).
//
// Searches cases, advisories, cached IOC lookups and the last 7 days of Wazuh alerts. Each source
// is independent: one failing (indexer down, table missing) drops only its own results.

const router = Router();

interface SearchResult {
    type: 'case' | 'advisory' | 'ioc' | 'alert';
    title: string;
    subtitle: string;
    badge?: string;
    url: string;
}

// The term is spliced into PostgREST `or=(...)` filters, where `,` `(` `)` are syntax and `%` `_`
// `*` are wildcards. Stripping them stops a query like "x,org_id.neq.cybernovr" from rewriting
// the filter — the org scope must not be something the search box can widen.
const pgSafe = (q: string) => q.replace(/[,()%_*\\"'`]/g, ' ').replace(/\s+/g, ' ').trim();

const levelBadge = (level: number) => (level >= 13 ? 'critical' : level >= 10 ? 'high' : level >= 7 ? 'medium' : 'low');

interface AlertHit { _source?: { rule?: { description?: string; level?: number }; agent?: { name?: string }; timestamp?: string; data?: { srcip?: string } } }

router.get('/', requireAuth, async (req: AuthRequest, res) => {
    const raw = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 100) : '';
    const q = pgSafe(raw);
    if (q.length < 2) { res.json({ results: [], query: raw, total: 0 }); return; }

    const orgId = req.user?.org_id || DEFAULT_ORG_ID;
    const supabase = getSupabase();
    const like = `%${q}%`;

    const casesP = supabase
        ? supabase.from('cases').select('id, case_number, title, severity, status')
            .eq('org_id', orgId)
            .or(`title.ilike.${like},case_number.ilike.${like},source_ip.ilike.${like},agent_name.ilike.${like}`)
            .order('created_at', { ascending: false }).limit(5)
        : null;
    const advisoriesP = supabase
        ? supabase.from('nigeria_advisories').select('id, title, severity, source')
            .or(`title.ilike.${like},description.ilike.${like}`)
            .order('published_at', { ascending: false }).limit(3)
        : null;
    const iocsP = supabase
        ? supabase.from('ioc_enrichments').select('ioc_value, ioc_type, risk_score').ilike('ioc_value', like).limit(3)
        : null;
    const alertsP = search<{ hits?: { hits?: AlertHit[] } }>('wazuh-alerts-4.x-*', {
        size: 3,
        sort: [{ timestamp: { order: 'desc' } }],
        query: {
            bool: {
                must: [
                    // lenient: data.srcip is an IP-typed field; without this a non-IP term makes
                    // the whole query fail instead of just not matching that field.
                    { multi_match: { query: raw, fields: ['rule.description', 'agent.name', 'data.srcip'], lenient: true } },
                    { range: { timestamp: { gte: 'now-7d' } } },
                ],
            },
        },
        _source: ['rule.description', 'rule.level', 'agent.name', 'timestamp'],
    });

    const [casesR, advR, iocR, alertR] = await Promise.allSettled([casesP, advisoriesP, iocsP, alertsP]);
    const results: SearchResult[] = [];

    if (casesR.status === 'fulfilled' && casesR.value?.data) {
        for (const c of casesR.value.data) {
            results.push({ type: 'case', title: `${c.case_number} — ${c.title}`, subtitle: c.status, badge: c.severity, url: `/admin/secops/cases?id=${c.id}` });
        }
    }
    if (advR.status === 'fulfilled' && advR.value?.data) {
        for (const a of advR.value.data) {
            results.push({ type: 'advisory', title: a.title, subtitle: a.source, badge: a.severity, url: '/admin/threat/nigeria' });
        }
    }
    if (iocR.status === 'fulfilled' && iocR.value?.data) {
        for (const i of iocR.value.data) {
            results.push({ type: 'ioc', title: i.ioc_value, subtitle: `${i.ioc_type} · risk ${i.risk_score ?? 0}`, url: `/admin/threat/cti?q=${encodeURIComponent(i.ioc_value)}` });
        }
    }
    if (alertR.status === 'fulfilled') {
        for (const hit of alertR.value?.hits?.hits ?? []) {
            const s = hit._source ?? {};
            const level = s.rule?.level ?? 0;
            results.push({
                type: 'alert',
                title: s.rule?.description || 'Wazuh alert',
                subtitle: `${s.agent?.name ?? 'Unknown agent'} · ${s.timestamp ? new Date(s.timestamp).toLocaleString('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }) + ' WAT' : ''}`,
                badge: levelBadge(level),
                url: '/admin/secops/alerts',
            });
        }
    }

    res.json({ results, query: raw, total: results.length });
});

export default router;
