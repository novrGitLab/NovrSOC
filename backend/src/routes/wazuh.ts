import { Router } from 'express';
import { requireAuth } from '../middleware/auth';
import { searchStrict as search, search as rawSearch } from '../lib/wazuh-indexer';
import { isConfigured as wazuhConfigured, getAgentInventory } from '../services/wazuh';
import { orgScope, requireScope, alertScopeFilter, agentStateFilter, scoped, ownsAgent, padAgentId, ScopeError, type OrgScope } from '../lib/orgScope';
import { requestOrg } from '../lib/resolveOrg';
import { alertNetwork } from '../lib/alertNetwork';
import { getComplianceImpact } from '../services/complianceMapping';
import { isDemoMode, DEMO_AGENTS } from '../lib/demoMode';
import { severityFromLevel, SEVERITY_MIN_LEVEL } from '../lib/severity';
import { requirePermission } from '../lib/permissions';
import { unusableReply } from '../services/wazuhVulnSync';

const router = Router();

// Every route here reads Wazuh telemetry for the whole SOC, so all of them need a SecOps token
// with alerts:read (and an org on the token); POST /hunt additionally needs cases:write, since
// a hunt is the start of an investigation. Executive and portal_user tokens get 403. The client
// portal's dashboard used to read /agents, /incidents, /threats-blocked and /network-connections
// here anonymously; portal tokens can't be verified by this backend, so that path is closed
// until portal auth exists (see index.ts).
//
// /enrollment is not left public: Wazuh agents enroll against the manager itself (ports
// 1515/1514), never against this API. Its only caller is the admin Setup Guide page.
router.use(requirePermission('alerts:read'));

// Multi-tenancy (P22): every route reads only what the request's organisation owns —
// lib/orgScope.ts: agents whose Wazuh groups map to it (wazuh_group_org_map) and syslog senders
// mapped to it (wazuh_source_org_map). Staff choose the organisation with X-Org-Id (audited;
// analysts only for organisations they are assigned to). ?group= only narrows to one of the
// organisation's own groups; another organisation's group is a 403. Per-agent routes answer 404
// for an agent the organisation doesn't own, exactly as for one that doesn't exist.

const groupParam = (req: import('express').Request) =>
    typeof req.query.group === 'string' && req.query.group.trim() ? req.query.group.trim() : null;

/** The scope for this request, honouring ?group=. Null once the reason has been sent. */
const scopeOf = (req: import('express').Request, res: import('express').Response) => requireScope(req, res, groupParam(req));

const errMsg = (err: unknown) => (err instanceof Error ? err.message : String(err));

// GET /api/wazuh/status — whether the organisation's agent inventory can be read, and its agents
// by state. connected:false carries the reason; counts are then null, never a false zero.
router.get('/status', async (req, res) => {
    if (isDemoMode()) {
        res.json({ connected: true, agent_count: DEMO_AGENTS.length, active_agents: DEMO_AGENTS.filter((a) => a.status === 'active').length, source: 'demo' });
        return;
    }
    try {
        const s = await orgScope(requestOrg(req));
        const count = (...states: string[]) => s.agents.filter((a) => states.includes(a.status)).length;
        // Registered = active + disconnected + never_connected/pending, so the dashboard can
        // show all three without inferring one from the others.
        res.json({
            connected: true,
            agent_count: s.agents.length,
            active_agents: count('active'),
            disconnected_agents: count('disconnected'),
            never_connected_agents: count('never_connected', 'pending'),
            agent_source: s.agentSource,
            groups: s.groups,
            syslog_sources: s.locations.length,
        });
    } catch (err) {
        res.json({ connected: false, agent_count: null, active_agents: null, disconnected_agents: null, never_connected_agents: null, error: errMsg(err) });
    }
});

// GET /api/wazuh/enrollment — the manager address the setup guides (OPNsense, Sysmon, osquery)
// tell agents to enrol against. WAZUH_AGENT_MANAGER overrides WAZUH_HOST for when agents reach
// the manager on a different address than the backend does (e.g. over the VPN). Analyst-only.
router.get('/enrollment', requireAuth, (_req, res) => {
    const manager = (process.env.WAZUH_AGENT_MANAGER || process.env.WAZUH_HOST || '').trim();
    res.json({ manager: manager || null, enrollment_port: 1515, events_port: 1514 });
});

// GET /api/wazuh/alerts — was previously its own hand-rolled https.request call with a
// hardcoded fallback password (value removed from this comment; rotate it) duplicated from
// lib/wazuh-indexer.ts's already-correct, auth-required search() helper (the one every other
// route in this file uses) — a real credential sitting in source, and exactly the kind of
// duplicated indexer client search()'s own header comment says it was written to eliminate.
// Consolidated onto search(): same https + Basic-auth request, no fallback credential, and it
// now fails loudly (WAZUH_INDEXER_HOST/PASS unset -> a rejected promise) instead of silently
// falling back to a stale default host/password.
interface AlertHit {
    _id?: string;
    _source?: {
        id?: string;
        timestamp?: string;
        rule?: { id?: string; level?: number; description?: string; groups?: string[]; mitre?: { id?: string[]; tactic?: string[]; technique?: string[] } };
        agent?: { id?: string; name?: string };
        location?: string;
    } & Record<string, unknown>;
}
interface AlertsSearchResponse { hits?: { hits?: AlertHit[] } }

router.get('/alerts', async (req, res) => {
    const scope = await scopeOf(req, res);
    if (!scope) return;
    try {
        const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 500);
        const result = await search<AlertsSearchResponse>('wazuh-alerts-4.x-*', {
            size: limit,
            sort: [{ timestamp: { order: 'desc' } }],
            query: scoped(undefined, alertScopeFilter(scope)),
        });

        const hits = result?.hits?.hits ?? [];
        const alerts = hits.map((h) => {
            const src = h._source ?? {};
            const rule = src.rule ?? {};
            const agent = src.agent ?? {};

            return {
                id: String(h._id || src.id || ''),
                wazuh_alert_id: src.id ?? null,
                timestamp: src.timestamp ?? null,
                rule_id: rule.id != null ? String(rule.id) : null,
                rule_level: Number(rule.level || 0),
                rule_description: rule.description ?? null,
                rule_groups: Array.isArray(rule.groups) ? rule.groups : [],
                mitre_id: rule.mitre?.id?.[0] ?? null,
                mitre_tactic: rule.mitre?.tactic?.[0] ?? null,
                mitre_technique: rule.mitre?.technique?.[0] ?? null,
                agent_id: agent.id ?? null,
                agent_name: agent.name ?? null,
                location: src.location ?? null,
                ...alertNetwork(src),
            };
        });

        res.status(200).json(alerts);
    } catch (err) {
        console.error('[routes/wazuh/alerts] Indexer request failed:', err instanceof Error ? err.message : err);
        res.status(502).json({ error: 'Indexer connection failed', message: err instanceof Error ? err.message : String(err) });
    }
});

// GET /api/wazuh/agents
router.get('/agents', async (req, res) => {
    if (isDemoMode()) {
        const active = DEMO_AGENTS.filter((a) => a.status === 'active').length;
        res.json({ active, total: DEMO_AGENTS.length, agents: DEMO_AGENTS, data: { connection: { active, total: DEMO_AGENTS.length } }, source: 'demo' });
        return;
    }
    // The organisation's agents (lib/orgScope.ts): from the Manager API, or the indexer's
    // wazuh-monitoring snapshot when the API can't be reached (agent_source says which). A failure
    // answers 503 with the reason — it used to be swallowed, and the Manager and the indexer have
    // been seen failing independently on this deployment.
    const scope = await scopeOf(req, res);
    if (!scope) return;
    const agents = scope.agents;
    const active = agents.filter((a) => a.status === 'active').length;
    const total = agents.length;
    const agentDetails = agents.map((a) => ({
        id: a.id,
        name: a.name,
        ip: a.ip,
        status: a.status,
        lastSeen: a.lastKeepAlive,
        os: a.os,
        version: a.version,
        group: a.group.join(', '),
    }));
    res.json({ active, total, agents: agentDetails, data: { connection: { active, total } }, agent_source: scope.agentSource, groups: scope.groups });
});

// GET /api/wazuh/mitre-stats — tactic counts over the last 24h, for the dashboard's MITRE
// ATT&CK widget. rule.mitre.tactic is a real Wazuh 4.x field (populated when a matching rule
// has MITRE mapping enabled) — not every alert has one, so this is a genuine subset, not "all
// alerts categorized." Demo mode bypasses this entirely (no MITRE data attached to the fixed
// demo agents), so it returns the same honest empty state as a real Wazuh outage would.
router.get('/mitre-stats', async (req, res) => {
    interface TacticBucket { key: string; doc_count: number }
    interface SearchResponse { aggregations?: { mitre_tactics?: { buckets?: TacticBucket[] } } }

    if (isDemoMode()) {
        res.json({ tactics: {}, source: 'demo' });
        return;
    }
    const scope = await scopeOf(req, res);
    if (!scope) return;

    try {
        const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        const result = await search<SearchResponse>('wazuh-alerts-4.x-*', {
            size: 0,
            query: scoped({ range: { timestamp: { gte: since } } }, alertScopeFilter(scope)),
            aggs: { mitre_tactics: { terms: { field: 'rule.mitre.tactic', size: 20 } } },
        });

        const buckets = result?.aggregations?.mitre_tactics?.buckets ?? [];
        const tactics: Record<string, number> = {};
        for (const b of buckets) tactics[b.key] = b.doc_count;

        // 'empty' = the indexer answered and nothing in the window carried a MITRE mapping.
        res.json({ tactics, source: buckets.length > 0 ? 'wazuh' : 'empty' });
    } catch (err) {
        res.status(502).json({ tactics: {}, source: 'unavailable', error: errMsg(err) });
    }
});

// GET /api/wazuh/notifications
router.get('/notifications', async (req, res) => {
    interface WazuhHit { _id: string; _source: { timestamp?: string; rule?: { description?: string; level?: number }; agent?: { name?: string } } }
    interface SearchResponse { hits?: { hits?: WazuhHit[] } }

    const timeAgo = (iso?: string): string => {
        if (!iso) return '—';
        const mins = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 60000));
        if (mins < 1) return 'Just now';
        if (mins < 60) return `${mins} min ago`;
        const hrs = Math.floor(mins / 60);
        return `${hrs} hr${hrs === 1 ? '' : 's'} ago`;
    };
    const truncate = (s: string, max: number): string => (s.length > max ? s.slice(0, max - 3) + '...' : s);

    const scope = await scopeOf(req, res);
    if (!scope) return;

    try {
        const result = await search<SearchResponse>('wazuh-alerts-4.x-*', {
            size: 6,
            sort: [{ 'rule.level': { order: 'desc' } }, { timestamp: { order: 'desc' } }],
            query: scoped({ range: { 'rule.level': { gte: SEVERITY_MIN_LEVEL.medium } } }, alertScopeFilter(scope)),
            _source: ['timestamp', 'rule.description', 'rule.level', 'agent.name'],
        });

        const hits = result?.hits?.hits ?? [];
        const notifications = hits.map((h) => {
            const level = h._source.rule?.level ?? 0;
            const description = h._source.rule?.description ?? 'Wazuh alert';
            return {
                id: h._id,
                // Notification styling derived from the shared severity (critical / medium+ / low).
                type: severityFromLevel(level) === 'critical' ? 'critical' : severityFromLevel(level) === 'low' ? 'info' : 'warning',
                title: truncate(description, 60),
                description: 'Detected on ' + (h._source.agent?.name ?? 'unknown agent'),
                time: timeAgo(h._source.timestamp),
                read: false,
            };
        });

        res.json(notifications);
    } catch (err) {
        res.status(502).json({ error: errMsg(err) });
    }
});

// RFC 1918, loopback and link-local prefixes, as string prefixes of a keyword IP field.
const PRIVATE_PREFIXES = [
    '10.', '127.', '192.168.', '169.254.',
    ...Array.from({ length: 16 }, (_, i) => `172.${16 + i}.`),
];

// GET /api/wazuh/network-connections — the organisation's busiest addresses over 24 h, split into
// external (public) and internal (private) by source and destination. Fails as a whole with the
// reason rather than showing a partial picture as if it were complete.
router.get('/network-connections', async (req, res) => {
    interface AggBucket { key: string; doc_count: number }
    interface RawHit { _source: { data?: { srcip?: string; dstip?: string; dstport?: string; srcport?: string } } }
    interface SearchResponse { hits?: { hits?: RawHit[] }; aggregations?: { top_ips?: { buckets?: AggBucket[] } } }
    const networkLabel = (ip: string): string => {
        if (ip.startsWith('10.')) return '10.x Corporate';
        if (ip.startsWith('192.168.')) {
            const parts = ip.split('.');
            return `192.168.${parts[2] ?? '0'}.x LAN`;
        }
        if (ip.startsWith('172.')) return '172.16/12 LAN';
        return 'Private Network';
    };

    const scope = await scopeOf(req, res);
    if (!scope) return;
    const filter = alertScopeFilter(scope);

    const ipAggQuery = (field: 'data.srcip' | 'data.dstip', kind: 'external' | 'internal') => {
        const must: unknown[] = [{ exists: { field } }, { range: { timestamp: { gte: 'now-24h' } } }];
        const query =
            kind === 'external'
                ? { bool: { must, must_not: PRIVATE_PREFIXES.map((p) => ({ prefix: { [field]: p } })), filter: [filter] } }
                : { bool: { must, should: PRIVATE_PREFIXES.map((p) => ({ prefix: { [field]: p } })), minimum_should_match: 1, filter: [filter] } };
        return search<SearchResponse>('wazuh-alerts-4.x-*', { size: 0, query, aggs: { top_ips: { terms: { field, size: 10 } } } });
    };

    try {
        const [extSrcRes, extDstRes, intSrcRes, intDstRes, rawRes] = await Promise.all([
            ipAggQuery('data.srcip', 'external'),
            ipAggQuery('data.dstip', 'external'),
            ipAggQuery('data.srcip', 'internal'),
            ipAggQuery('data.dstip', 'internal'),
            search<SearchResponse>('wazuh-alerts-4.x-*', {
                size: 40,
                query: scoped({
                    bool: {
                        must: [
                            { bool: { should: [{ exists: { field: 'data.srcip' } }, { exists: { field: 'data.dstip' } }] } },
                            { range: { timestamp: { gte: 'now-24h' } } },
                        ],
                    },
                }, filter),
                _source: ['data.srcip', 'data.dstip', 'data.dstport', 'data.srcport'],
            }),
        ]);

        const bucketsOf = (r: SearchResponse | null) => r?.aggregations?.top_ips?.buckets ?? [];
        const rawHits = rawRes?.hits?.hits ?? [];

        // The port seen with this address in the sampled hits; null when the sample has none.
        const portForIp = (ip: string, field: 'srcip' | 'dstip', portField: 'dstport' | 'srcport') => {
            const hit = rawHits.find((h) => h._source.data?.[field] === ip);
            return hit?._source.data?.[portField] ?? null;
        };

        // No reputation lookup runs here, so external verdicts are 'Unknown' and country is null:
        // not checked, rather than an invented value.
        const externalInbound = bucketsOf(extSrcRes).map((b) => ({ ip: b.key, count: b.doc_count, verdict: 'Unknown' as const, country: null, port: portForIp(b.key, 'srcip', 'dstport') }));
        const externalOutbound = bucketsOf(extDstRes).map((b) => ({ ip: b.key, count: b.doc_count, verdict: 'Unknown' as const, country: null, port: portForIp(b.key, 'dstip', 'srcport') }));
        const internalInbound = bucketsOf(intSrcRes).map((b) => ({ ip: b.key, count: b.doc_count, verdict: 'Internal' as const, network: networkLabel(b.key), port: portForIp(b.key, 'srcip', 'dstport') }));
        const internalOutbound = bucketsOf(intDstRes).map((b) => ({ ip: b.key, count: b.doc_count, verdict: 'Internal' as const, network: networkLabel(b.key), port: portForIp(b.key, 'dstip', 'srcport') }));

        res.json({
            external: { inbound: externalInbound, outbound: externalOutbound },
            internal: { inbound: internalInbound, outbound: internalOutbound },
            summary: {
                total_external_inbound: externalInbound.reduce((s, c) => s + c.count, 0),
                total_external_outbound: externalOutbound.reduce((s, c) => s + c.count, 0),
                total_internal: internalInbound.reduce((s, c) => s + c.count, 0) + internalOutbound.reduce((s, c) => s + c.count, 0),
                malicious_detected: null,
            },
        });
    } catch (err) {
        res.status(502).json({ error: errMsg(err) });
    }
});

// GET /api/wazuh/vulnerabilities
router.get('/vulnerabilities', async (req, res) => {
    interface VulnHit {
        _source?: {
            vulnerability?: { id?: string; description?: string; severity?: string; under_evaluation?: boolean; score?: { base?: number } };
            package?: { name?: string; version?: string };
            agent?: { name?: string };
        };
    }
    interface SearchResponse { hits?: { hits?: VulnHit[] }; aggregations?: { by_severity?: { buckets?: { key: string; doc_count: number }[] } } }

    // This page distinguishes "none found" from "couldn't read" (index_available): an ownership
    // failure is the second, in the same shape — except another organisation's group, a 403.
    let scope: OrgScope;
    try {
        scope = await orgScope(requestOrg(req), { group: groupParam(req) });
    } catch (err) {
        const status = err instanceof ScopeError && err.status === 403 ? 403 : 502;
        res.status(status).json({ vulnerabilities: [], summary: null, index_available: false, problem: errMsg(err) });
        return;
    }
    try {
        const severity = typeof req.query.severity === 'string' ? req.query.severity : null;

        // The organisation's agents only (narrowed by ?group= to one of its groups).
        const groupFilters: Record<string, unknown>[] = [agentStateFilter(scope)];
        // ?agent=<name> narrows to one endpoint (the page's agent selector, fed by /agents).
        const agentName = typeof req.query.agent === 'string' && req.query.agent.trim() ? req.query.agent.trim() : null;
        if (agentName) groupFilters.push({ term: { 'agent.name': agentName } });

        const aggsQuery = { bool: { filter: groupFilters } };

        const hitsFilters = [...groupFilters];
        if (severity) hitsFilters.push({ term: { 'vulnerability.severity': severity } });
        const hitsQuery = { bool: { filter: hitsFilters } };

        // The lenient search(): unusableReply() below reads the indexer's own error body.
        const [hitsRes, aggsRes] = await Promise.allSettled([
            rawSearch<SearchResponse>('wazuh-states-vulnerabilities-*', {
                size: 50,
                sort: [{ 'vulnerability.score.base': { order: 'desc' } }],
                _source: [
                    'vulnerability.id', 'vulnerability.description', 'vulnerability.severity',
                    'vulnerability.score.base', 'vulnerability.under_evaluation',
                    'package.name', 'package.version', 'agent.name',
                ],
                query: hitsQuery,
            }),
            rawSearch<SearchResponse>('wazuh-states-vulnerabilities-*', {
                size: 0,
                query: aggsQuery,
                aggs: { by_severity: { terms: { field: 'vulnerability.severity' } } },
            }),
        ]).then((results) => results.map((r) => (r.status === 'fulfilled' ? r.value : null)));

        const vulnerabilities = (hitsRes?.hits?.hits ?? []).map((h) => {
            const v = h._source?.vulnerability;
            return {
                cve: v?.id ?? '',
                title: v?.description ?? '',
                severity: v?.severity ?? '',
                cvss_score: v?.score?.base ?? null,
                package: h._source?.package?.name ?? '',
                version: h._source?.package?.version ?? '',
                agent: h._source?.agent?.name ?? '',
                status: v?.under_evaluation ? 'Under Evaluation' : 'Confirmed',
            };
        });

        const buckets = aggsRes?.aggregations?.by_severity?.buckets ?? [];
        const countFor = (label: string) => buckets.find((b) => b.key?.toLowerCase() === label)?.doc_count ?? 0;

        const summary = {
            critical: countFor('critical'),
            high: countFor('high'),
            medium: countFor('medium'),
            low: countFor('low'),
            total: buckets.reduce((sum, b) => sum + (b.doc_count ?? 0), 0),
        };

        // index_available separates "no vulnerabilities found" from "couldn't read the index" —
        // both would otherwise render as an empty list. The indexer answers errors (bad
        // credentials, no permission) and a wildcard matching no index with parsed JSON too, so a
        // non-null reply is not enough (P16): the reason is returned instead of zeros.
        const problem = unusableReply(aggsRes as never) ?? unusableReply(hitsRes as never);
        if (problem) { res.status(502).json({ vulnerabilities: [], summary: null, index_available: false, problem }); return; }
        res.json({ vulnerabilities, summary, index_available: true });
    } catch (err) {
        res.status(502).json({ vulnerabilities: [], summary: null, index_available: false, problem: errMsg(err) });
    }
});

// GET /api/wazuh/alerts-indexer
router.get('/alerts-indexer', async (req, res) => {
    interface SearchResponse { hits?: { total?: { value?: number }; hits?: { _source?: unknown }[] } }

    const RANGE_MAP: Record<string, string> = { '1h': 'now-1h', '24h': 'now-24h', '7d': 'now-7d' };

    const scope = await scopeOf(req, res);
    if (!scope) return;
    const filter = alertScopeFilter(scope);

    const countByLevel = (minLevel: number) => search<SearchResponse>('wazuh-alerts-4.x-*', {
        size: 0, track_total_hits: true,
        query: { bool: { must: [{ range: { 'rule.level': { gte: minLevel } } }, { range: { timestamp: { gte: 'now-24h' } } }], filter: [filter] } },
    });

    try {
        const minLevelParam = typeof req.query.minLevel === 'string' ? Number(req.query.minLevel) : NaN;
        const minLevel = Number.isInteger(minLevelParam) && minLevelParam >= 0 && minLevelParam <= 16 ? minLevelParam : SEVERITY_MIN_LEVEL.medium;
        const rangeParam = typeof req.query.range === 'string' ? req.query.range : null;
        const since = RANGE_MAP[rangeParam ?? '24h'] ?? RANGE_MAP['24h'];

        const [alertsRes, criticalRes, openRes] = await Promise.all([
            search<SearchResponse>('wazuh-alerts-4.x-*', {
                size: 10,
                sort: [{ timestamp: { order: 'desc' } }],
                query: { bool: { must: [{ range: { 'rule.level': { gte: minLevel } } }, { range: { timestamp: { gte: since } } }], filter: [filter] } },
                _source: ['timestamp', 'rule.description', 'rule.level', 'agent.name', 'agent.ip', 'location'],
            }),
            countByLevel(SEVERITY_MIN_LEVEL.critical),
            countByLevel(SEVERITY_MIN_LEVEL.medium),
        ]);

        const hits = (alertsRes?.hits?.hits ?? []).map((h) => h._source).filter(Boolean);
        res.json({ hits, criticalCount: criticalRes?.hits?.total?.value ?? null, openIncidentsCount: openRes?.hits?.total?.value ?? null });
    } catch (err) {
        res.status(502).json({ hits: [], criticalCount: null, openIncidentsCount: null, error: errMsg(err) });
    }
});

// GET /api/wazuh/trend
router.get('/trend', async (req, res) => {
    interface Bucket { key_as_string?: string; doc_count?: number; high_severity?: { doc_count?: number }; critical?: { doc_count?: number } }
    interface SearchResponse { aggregations?: { alerts_over_time?: { buckets?: Bucket[] } } }

    const RANGE_CONFIG: Record<string, { interval: 'hour' | 'day'; min: string; count: number }> = {
        '24h': { interval: 'hour', min: 'now-24h', count: 24 },
        '7d': { interval: 'day', min: 'now-7d', count: 7 },
        '30d': { interval: 'day', min: 'now-30d', count: 30 },
    };

    const scope = await scopeOf(req, res);
    if (!scope) return;

    try {
        const rangeParam = typeof req.query.range === 'string' ? req.query.range : null;
        const config = RANGE_CONFIG[rangeParam ?? '7d'] ?? RANGE_CONFIG['7d'];

        const result = await search<SearchResponse>('wazuh-alerts-4.x-*', {
            size: 0,
            query: scoped({ range: { timestamp: { gte: config.min } } }, alertScopeFilter(scope)),
            aggs: {
                alerts_over_time: {
                    date_histogram: {
                        field: 'timestamp',
                        calendar_interval: config.interval,
                        min_doc_count: 0,
                        extended_bounds: { min: config.min, max: 'now' },
                    },
                    aggs: {
                        high_severity: { filter: { range: { 'rule.level': { gte: SEVERITY_MIN_LEVEL.medium } } } },
                        critical: { filter: { range: { 'rule.level': { gte: SEVERITY_MIN_LEVEL.critical } } } },
                    },
                },
            },
        });

        const buckets = result?.aggregations?.alerts_over_time?.buckets ?? [];
        const trend = buckets.slice(-config.count).map((b) => {
            const date = b.key_as_string ? new Date(b.key_as_string) : null;
            const label = date
                ? config.interval === 'hour'
                    ? date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false })
                    : date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
                : '—';
            return { label, alerts: b.doc_count ?? 0, incidents: b.high_severity?.doc_count ?? 0, critical: b.critical?.doc_count ?? 0 };
        });

        res.json(trend);
    } catch (err) {
        res.status(502).json({ error: errMsg(err) });
    }
});

// GET /api/wazuh/attack-origins
router.get('/attack-origins', async (req, res) => {
    interface Bucket { key: string; doc_count: number; top_groups?: { buckets?: { key: string }[] } }
    interface SearchResponse { aggregations?: { top_countries?: { buckets?: Bucket[] } } }

    const NAME_TO_ISO: Record<string, string> = {
        'United States': 'US', 'United Kingdom': 'GB', 'China': 'CN', 'Russia': 'RU',
        'Germany': 'DE', 'Netherlands': 'NL', 'France': 'FR', 'Brazil': 'BR', 'India': 'IN',
        'Ukraine': 'UA', 'South Korea': 'KR', 'Indonesia': 'ID', 'Japan': 'JP', 'Vietnam': 'VN',
        'Poland': 'PL', 'Romania': 'RO', 'Turkey': 'TR', 'Iran': 'IR', 'Singapore': 'SG',
        'Hong Kong': 'HK', 'Taiwan': 'TW', 'Mexico': 'MX', 'Italy': 'IT', 'Spain': 'ES',
        'Sweden': 'SE', 'Switzerland': 'CH', 'Australia': 'AU', 'South Africa': 'ZA',
        'Nigeria': 'NG', 'Egypt': 'EG', 'Israel': 'IL', 'Thailand': 'TH', 'Malaysia': 'MY',
        'Philippines': 'PH', 'Pakistan': 'PK', 'Bangladesh': 'BD', 'Argentina': 'AR',
        'Colombia': 'CO', 'Chile': 'CL', 'Belgium': 'BE', 'Austria': 'AT', 'Czechia': 'CZ',
        'Czech Republic': 'CZ', 'Portugal': 'PT', 'Ireland': 'IE', 'Norway': 'NO', 'Denmark': 'DK',
        'Finland': 'FI', 'Greece': 'GR', 'Hungary': 'HU', 'Bulgaria': 'BG', 'Moldova': 'MD',
        'Belarus': 'BY', 'Kazakhstan': 'KZ', 'Uzbekistan': 'UZ', 'Iraq': 'IQ', 'Saudi Arabia': 'SA',
        'United Arab Emirates': 'AE', 'Morocco': 'MA', 'Algeria': 'DZ', 'Kenya': 'KE',
        'Venezuela': 'VE', 'Peru': 'PE', 'Ecuador': 'EC', 'Panama': 'PA', 'Costa Rica': 'CR',
        'Cuba': 'CU', 'Lithuania': 'LT', 'Latvia': 'LV', 'Estonia': 'EE', 'Slovakia': 'SK',
        'Slovenia': 'SI', 'Croatia': 'HR', 'Serbia': 'RS', 'Canada': 'CA', 'New Zealand': 'NZ',
    };

    const isoCode = (countryName: string): string => NAME_TO_ISO[countryName] ?? countryName.slice(0, 2).toUpperCase();

    // Classifies the dominant attack pattern for a country's alerts from the
    // rule.groups Wazuh itself assigned, rather than guessing from the description text.
    const classify = (groups: string[]): string => {
        const set = new Set(groups);
        if (set.has('sshd') || set.has('authentication_failed') || set.has('invalid_login')) return 'Brute Force';
        if (set.has('web') || set.has('attack') || set.has('sqlinjection') || set.has('xss')) return 'Web Attack';
        if (set.has('recon') || set.has('nmap') || set.has('portscan') || set.has('scan')) return 'Scanning';
        if (set.has('malware') || set.has('virus') || set.has('rootkit')) return 'Malware';
        if (set.has('firewall') || set.has('ids') || set.has('firewall_drop')) return 'Intrusion Attempt';
        return 'Suspicious Activity';
    };

    const scope = await scopeOf(req, res);
    if (!scope) return;

    try {
        // Excludes RFC1918 / loopback / link-local so internal agent-to-agent traffic
        // never shows up disguised as an "attack".
        const result = await search<SearchResponse>('wazuh-alerts-4.x-*', {
            size: 0,
            query: {
                bool: {
                    must: [{ exists: { field: 'data.srcip' } }, { range: { timestamp: { gte: 'now-24h' } } }],
                    must_not: PRIVATE_PREFIXES.map((p) => ({ prefix: { 'data.srcip': p } })),
                    filter: [alertScopeFilter(scope)],
                },
            },
            aggs: {
                top_countries: {
                    terms: { field: 'GeoLocation.country_name', size: 5 },
                    aggs: { top_groups: { terms: { field: 'rule.groups', size: 6 } } },
                },
            },
        });

        const buckets = result?.aggregations?.top_countries?.buckets ?? [];
        const origins = buckets.map((b) => ({
            country: isoCode(b.key),
            name: b.key,
            count: b.doc_count,
            label: classify((b.top_groups?.buckets ?? []).map((g) => g.key)),
        }));

        res.json(origins);
    } catch (err) {
        res.status(502).json({ error: errMsg(err) });
    }
});

// GET /api/wazuh/incidents — the organisation's level 3+ alerts over 7 days, highest first, and
// counts by severity. Raw Wazuh alerts carry no triage state: status, assignee and SLA belong to
// stored alerts and cases, so none is made up here.
router.get('/incidents', async (req, res) => {
    interface WazuhHit {
        _id: string;
        _source: { timestamp?: string; rule?: { description?: string; level?: number; mitre?: { id?: string[]; technique?: string[] } }; agent?: { id?: string; name?: string }; location?: string };
    }
    interface SearchResponse { hits?: { hits?: WazuhHit[]; total?: { value?: number } } }

    // Capitalised labels are this route's existing response format.
    const SEVERITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' } as const;
    const severityFor = (level: number) => SEVERITY_LABEL[severityFromLevel(level)];

    const scope = await scopeOf(req, res);
    if (!scope) return;
    const filter = alertScopeFilter(scope);

    const countInRange = (minLevel: number, maxLevelExclusive: number | undefined) => {
        const levelRange: { gte: number; lt?: number } = { gte: minLevel };
        if (maxLevelExclusive !== undefined) levelRange.lt = maxLevelExclusive;
        return search<SearchResponse>('wazuh-alerts-4.x-*', {
            size: 0, track_total_hits: true,
            query: { bool: { must: [{ range: { 'rule.level': levelRange } }, { range: { timestamp: { gte: 'now-7d' } } }], filter: [filter] } },
        });
    };

    try {
        const [alertsRes, criticalRes, highRes, mediumRes, lowRes] = await Promise.all([
            search<SearchResponse>('wazuh-alerts-4.x-*', {
                size: 20,
                sort: [{ 'rule.level': { order: 'desc' } }, { timestamp: { order: 'desc' } }],
                query: { bool: { must: [{ range: { 'rule.level': { gte: 3 } } }, { range: { timestamp: { gte: 'now-7d' } } }], filter: [filter] } },
                _source: ['timestamp', 'rule.description', 'rule.level', 'rule.groups', 'agent.id', 'agent.name', 'agent.ip', 'location', 'data.srcip', 'rule.mitre.id', 'rule.mitre.technique'],
            }),
            countInRange(SEVERITY_MIN_LEVEL.critical, undefined),
            countInRange(SEVERITY_MIN_LEVEL.high, SEVERITY_MIN_LEVEL.critical),
            countInRange(SEVERITY_MIN_LEVEL.medium, SEVERITY_MIN_LEVEL.high),
            countInRange(3, SEVERITY_MIN_LEVEL.medium),
        ]);

        const incidents = (alertsRes?.hits?.hits ?? []).map((h) => {
            const level = h._source.rule?.level ?? 0;
            return {
                id: h._id,
                severity: severityFor(level),
                name: h._source.rule?.description ?? `Wazuh alert (level ${level})`,
                // The agent, or for syslog the sender's address.
                asset: h._source.agent?.id === '000' ? h._source.location ?? null : h._source.agent?.name ?? null,
                // null when the rule carries no MITRE mapping (this used to default to T1059).
                mitre: h._source.rule?.mitre?.id?.[0] ?? null,
                mitre_technique: h._source.rule?.mitre?.technique?.[0] ?? null,
                timestamp: h._source.timestamp ?? null,
                level,
            };
        });

        const critical = criticalRes?.hits?.total?.value ?? 0;
        const high = highRes?.hits?.total?.value ?? 0;
        const medium = mediumRes?.hits?.total?.value ?? 0;
        const low = lowRes?.hits?.total?.value ?? 0;

        res.json({ incidents, kpis: { total: critical + high + medium + low, critical, high, medium, low } });
    } catch (err) {
        res.status(502).json({ incidents: [], kpis: null, error: errMsg(err) });
    }
});

// POST /api/wazuh/hunt — Threat Hunting page's query builder. A POST (not GET) because the
// query builder produces a list of conditions, not one field/operator/value triple — trying to
// serialize an array of objects into GET querystring params is exactly the kind of thing that
// looks fine for the single-condition case and breaks the moment someone adds a second row.
interface HuntCondition {
    field: string; // one of HUNT_FIELDS
    op: 'equals' | 'contains' | 'greater_than' | 'less_than' | 'exists';
    value: string;
}
const HUNT_TIME_RANGE_MS: Record<string, number> = {
    '1h': 60 * 60 * 1000, '6h': 6 * 60 * 60 * 1000, '24h': 24 * 60 * 60 * 1000, '7d': 7 * 24 * 60 * 60 * 1000,
};

interface HuntQueryClause {
    term?: Record<string, string>;
    wildcard?: Record<string, string>;
    range?: Record<string, { gte?: string | number; lte?: string | number }>;
    exists?: { field: string };
}

// The fields the query builder offers — checked at runtime, not only by the type above.
const HUNT_FIELDS = new Set<string>(['agent.name', 'rule.level', 'rule.groups', 'data.srcip', 'data.dstip', 'rule.description', 'data.action', 'data.protocol', 'data.dstport', 'location']);

router.post('/hunt', requirePermission('cases:write'), async (req, res) => {
    const { conditions, time_range = '24h', limit = 100 }: { conditions?: HuntCondition[]; time_range?: string; limit?: number } = req.body ?? {};
    const rangeMs = HUNT_TIME_RANGE_MS[time_range] ?? HUNT_TIME_RANGE_MS['24h'];
    if (conditions !== undefined && !Array.isArray(conditions)) { res.status(400).json({ error: 'conditions must be a list', results: [], total: 0 }); return; }
    for (const cond of conditions ?? []) {
        if (!cond || typeof cond.field !== 'string' || !HUNT_FIELDS.has(cond.field)) {
            res.status(400).json({ error: `Unsupported hunt field: ${String(cond?.field).slice(0, 64)}`, results: [], total: 0 });
            return;
        }
        if (cond.value !== undefined && (typeof cond.value !== 'string' || cond.value.length > 200)) {
            res.status(400).json({ error: 'Each condition value must be text of up to 200 characters', results: [], total: 0 });
            return;
        }
    }

    const scope = await requireScope(req, res);
    if (!scope) return;

    // ISO string, matching every other route's timestamp range query in this file/dashboard.ts
    // — not epoch millis, which would still work (OpenSearch accepts both for a date field)
    // but be the one inconsistent convention in this codebase for no reason.
    const must: HuntQueryClause[] = [{ range: { timestamp: { gte: new Date(Date.now() - rangeMs).toISOString() } } }];
    for (const cond of conditions ?? []) {
        if (!cond.op) continue;
        if (cond.op === 'exists') {
            must.push({ exists: { field: cond.field } });
        } else if (cond.op === 'contains') {
            if (!cond.value) continue;
            must.push({ wildcard: { [cond.field]: `*${cond.value}*` } });
        } else if (cond.op === 'equals') {
            if (!cond.value) continue;
            must.push({ term: { [cond.field]: cond.value } });
        } else if (cond.op === 'greater_than' || cond.op === 'less_than') {
            const n = Number(cond.value);
            if (!cond.value || Number.isNaN(n)) continue;
            must.push({ range: { [cond.field]: cond.op === 'greater_than' ? { gte: n } : { lte: n } } });
        }
    }

    try {
        const result = await search<{ hits?: { hits?: Array<{ _id?: string; _source: Record<string, unknown> }>; total?: { value?: number } } }>('wazuh-alerts-4.x-*', {
            size: Math.min(Math.max(Number(limit) || 100, 1), 500),
            sort: [{ timestamp: { order: 'desc' } }],
            query: { bool: { must, filter: [alertScopeFilter(scope)] } },
            _source: [
                'id', 'timestamp', 'agent.id', 'agent.name', 'agent.ip', 'location', 'decoder.name', 'predecoder.hostname',
                'rule.id', 'rule.level', 'rule.description', 'rule.groups',
                'data.srcip', 'data.dstip', 'data.srcport', 'data.dstport', 'data.protocol', 'data.proto', 'data.action',
                'data.direction', 'data.dir', 'data.interface', 'data.iface',
                'GeoLocation.country_name', 'GeoLocation.region_name',
            ],
        });

        const hits = result?.hits?.hits ?? [];
        res.json({
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            results: hits.map((h) => {
                const src = h._source as any;
                return {
                    id: h._id ?? null,
                    timestamp: src?.timestamp,
                    agent: src?.agent?.name,
                    rule_id: src?.rule?.id,
                    rule_level: src?.rule?.level,
                    rule_description: src?.rule?.description,
                    source_ip: src?.data?.srcip,
                    dest_ip: src?.data?.dstip,
                    country: src?.GeoLocation?.country_name,
                    location: src?.location ?? null,
                    ...alertNetwork(src),
                    raw: src,
                };
            }),
            total: result?.hits?.total?.value ?? 0,
            source: 'wazuh',
        });
    } catch (err) {
        res.status(502).json({ error: errMsg(err), results: [], total: 0 });
    }
});

// ── Per-agent detail (Digital Assets → asset detail page) ────────────────────────────
//
// Registered after GET /agents so the literal path still wins: Express matches in definition
// order, and a '/agents/:id' declared earlier would swallow '/agents' itself.
//
// Each answers 404 for an agent the organisation does not own — the same answer as for an agent
// that does not exist, so another organisation's agent ids can't be probed.

/** The request's scope and the padded agent id when the organisation owns it; else null (answered). */
async function ownedAgent(req: import('express').Request, res: import('express').Response): Promise<{ scope: OrgScope; agentId: string } | null> {
    const scope = await requireScope(req, res);
    if (!scope) return null;
    const agentId = padAgentId(String(req.params.id ?? '').trim());
    if (!/^\d{3,}$/.test(agentId) || !ownsAgent(scope, agentId)) {
        res.status(404).json({ error: 'Agent not found' });
        return null;
    }
    return { scope, agentId };
}

// GET /api/wazuh/agents/:id — one agent's record, from the same inventory the list uses so the
// detail page can never disagree with the row the analyst clicked.
router.get('/agents/:id', async (req, res) => {
    const { id } = req.params;

    if (isDemoMode()) {
        const agent = DEMO_AGENTS.find((a) => String(a.id) === id);
        if (!agent) { res.status(404).json({ error: 'Agent not found' }); return; }
        res.json({ agent, source: 'demo' });
        return;
    }

    const owned = await ownedAgent(req, res);
    if (!owned) return;
    const a = owned.scope.agents.find((x) => x.id === owned.agentId)!;
    res.json({
        agent: { id: a.id, name: a.name, ip: a.ip, os: a.os, status: a.status, last_keepalive: a.lastKeepAlive, version: a.version, group: a.group },
        agent_source: owned.scope.agentSource,
    });
});

// GET /api/wazuh/agents/:id/vulnerabilities
//
// Queries the indexer's wazuh-states-vulnerabilities-* index, NOT wazuh-alerts-4.x-* with
// data.vulnerability.* fields. Wazuh 4.8 moved vulnerability state into its own index with a
// flattened schema (vulnerability.id / vulnerability.severity / vulnerability.score.base /
// package.name); querying the alerts index for data.vulnerability.* returns zero hits here.
// Same index and field names the existing GET /vulnerabilities route already uses.
//
// The compliance impact of these findings is returned alongside them so the asset page's
// Compliance tab and its Vulnerabilities tab can never disagree about the same asset.
router.get('/agents/:id/vulnerabilities', async (req, res) => {
    interface VulnHit {
        _source?: {
            vulnerability?: { id?: string; description?: string; severity?: string; under_evaluation?: boolean; score?: { base?: number } };
            package?: { name?: string; version?: string; condition?: string };
            agent?: { id?: string; name?: string };
        };
    }
    interface VulnSearch { hits?: { hits?: VulnHit[] } }

    const owned = await ownedAgent(req, res);
    if (!owned) return;

    try {
        const result = await search<VulnSearch>('wazuh-states-vulnerabilities-*', {
            size: 100,
            sort: [{ 'vulnerability.score.base': { order: 'desc' } }],
            _source: [
                'vulnerability.id', 'vulnerability.description', 'vulnerability.severity',
                'vulnerability.score.base', 'vulnerability.under_evaluation',
                'package.name', 'package.version', 'package.condition', 'agent.id', 'agent.name',
            ],
            query: { bool: { filter: [{ term: { 'agent.id': owned.agentId } }] } },
        });

        const vulnerabilities = (result?.hits?.hits ?? []).map((h) => {
            const v = h._source?.vulnerability;
            return {
                cve: v?.id ?? '',
                title: v?.description ?? '',
                severity: v?.severity ?? 'Unknown',
                cvss_score: v?.score?.base ?? null,
                package: h._source?.package?.name ?? '',
                version: h._source?.package?.version ?? '',
                fix: h._source?.package?.condition ?? '',
                status: v?.under_evaluation ? 'Under Evaluation' : 'Confirmed',
            };
        });

        const compliance = getComplianceImpact(
            vulnerabilities.map((v) => ({ severity: v.severity, package: v.package, cvss: v.cvss_score ?? undefined })),
        );

        res.json({ vulnerabilities, agent_id: owned.agentId, compliance });
    } catch (err) {
        console.error('[wazuh/agents/:id/vulnerabilities] failed:', errMsg(err));
        // 200 with an explicit `error`, not 502: the asset page renders five other tabs and must
        // not lose all of them because the vulnerability index is unreachable.
        res.json({
            vulnerabilities: [], agent_id: owned.agentId, error: `Vulnerability index unavailable: ${errMsg(err)}`,
            compliance: getComplianceImpact([]),
        });
    }
});

// GET /api/wazuh/agents/:id/packages — installed software inventory.
//
// Two sources, tried in order, because which one holds the data depends on the Wazuh version:
//   1. wazuh-states-inventory-packages-* on the indexer. Wazuh 4.8+ ships syscollector state
//      here, and it is the faster path (one query, no Manager auth round trip).
//   2. GET /syscollector/{id}/packages on the Manager REST API — where it lives pre-4.8, and
//      still populated on some deployments where the indexer template was never created.
//
// Confirmed live on 2026-09-17: the Manager path returned 0 packages for every agent on this
// deployment, which is what prompted adding the indexer path. If BOTH return nothing, the
// response says syscollector is not reporting rather than implying the host has no software —
// the agent's syscollector wodle has to be enabled with <packages>yes</packages>.
router.get('/agents/:id/packages', async (req, res) => {
    interface PkgHit {
        _source?: {
            package?: { name?: string; version?: string; architecture?: string; vendor?: string; install_time?: string };
        };
    }
    interface PkgSearch { hits?: { hits?: PkgHit[] } }

    const owned = await ownedAgent(req, res);
    if (!owned) return;
    const { agentId } = owned;

    let indexerError: string | null = null;
    try {
        const result = await search<PkgSearch>('wazuh-states-inventory-packages-*', {
            size: 500,
            query: { bool: { filter: [{ term: { 'agent.id': agentId } }] } },
            _source: ['package.name', 'package.version', 'package.architecture', 'package.vendor', 'package.install_time'],
        });

        const hits = result?.hits?.hits ?? [];
        if (hits.length > 0) {
            const packages = hits.map((h) => ({
                name: h._source?.package?.name ?? 'Unknown',
                version: h._source?.package?.version ?? '',
                architecture: h._source?.package?.architecture ?? null,
                vendor: h._source?.package?.vendor ?? null,
                install_time: h._source?.package?.install_time ?? null,
            }));
            res.json({ packages, agent_id: agentId, total: packages.length, source: 'indexer' });
            return;
        }
    } catch (err) {
        // A missing index throws here — expected on pre-4.8, so fall through to the Manager API
        // rather than failing. Kept for the diagnostic below if that path is empty too.
        indexerError = errMsg(err);
    }

    if (!wazuhConfigured()) {
        res.json({ packages: [], agent_id: agentId, total: 0, error: 'Wazuh Manager API not configured', indexer_error: indexerError });
        return;
    }

    try {
        const packages = await getAgentInventory(agentId);
        res.json({
            packages,
            agent_id: agentId,
            total: packages.length,
            source: 'manager-api',
            ...(packages.length === 0 && {
                error: 'No package inventory reported. Enable the syscollector wodle on this agent with <packages>yes</packages> — an empty list here does not mean the host has no software installed.',
                indexer_error: indexerError,
            }),
        });
    } catch (err) {
        console.error('[wazuh/agents/:id/packages] failed:', errMsg(err));
        res.json({
            packages: [], agent_id: agentId, total: 0,
            error: 'Syscollector unavailable - the agent may not have run an inventory scan yet',
            indexer_error: indexerError,
        });
    }
});

// GET /api/wazuh/agents/:id/alerts — this agent's recent alerts from the indexer.
router.get('/agents/:id/alerts', async (req, res) => {
    interface AlertHit {
        _id?: string;
        _source?: {
            id?: string;
            timestamp?: string;
            rule?: { description?: string; level?: number; id?: string; groups?: string[]; mitre?: { tactic?: string[]; id?: string[] } };
            agent?: { id?: string; name?: string };
        } & Record<string, unknown>;
    }
    interface AlertSearch { hits?: { hits?: AlertHit[] } }

    const owned = await ownedAgent(req, res);
    if (!owned) return;
    const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 100);

    try {
        const result = await search<AlertSearch>('wazuh-alerts-4.x-*', {
            size: limit,
            sort: [{ timestamp: { order: 'desc' } }],
            query: { bool: { filter: [{ term: { 'agent.id': owned.agentId } }] } },
        });

        const alerts = (result?.hits?.hits ?? []).map((h) => {
            const level = h._source?.rule?.level ?? 0;
            return {
                id: h._id ?? h._source?.id ?? null,
                timestamp: h._source?.timestamp ?? null,
                description: h._source?.rule?.description ?? null,
                level,
                rule_id: h._source?.rule?.id ?? null,
                severity: severityFromLevel(level),
                mitre_tactic: h._source?.rule?.mitre?.tactic?.[0] ?? null,
                mitre_id: h._source?.rule?.mitre?.id?.[0] ?? null,
                ...alertNetwork(h._source),
                source_ip: alertNetwork(h._source).src_ip,
            };
        });

        res.json({ alerts, agent_id: owned.agentId, total: alerts.length });
    } catch (err) {
        console.error('[wazuh/agents/:id/alerts] failed:', errMsg(err));
        res.json({ alerts: [], agent_id: owned.agentId, error: `Alert index unavailable: ${errMsg(err)}` });
    }
});

export default router;
