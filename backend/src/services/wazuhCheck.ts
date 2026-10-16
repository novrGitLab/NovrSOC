// Read-only Wazuh integration check for one organisation (phase P15). It answers, from the live
// installation the backend is configured for, what the VMS pipeline depends on:
//   • manager API   GET / (Wazuh server API root) → api_version, i.e. the installed Wazuh version
//   • agents        wazuh-monitoring-*: does the index answer, how many agents are in this
//                   organisation's mapped groups
//   • vulnerabilities  wazuh-states-vulnerabilities-* (the Wazuh 4.8+ vulnerability state index):
//                   does it exist, how many vulnerability records for this organisation's agents,
//                   by severity — counts only, no documents
//   • the last sync and its freshness (vms_wazuh_sync)
// Nothing is written except an audit entry by the caller. Credentials are never returned: only
// whether each variable is set. Every remote call has a timeout and reports a category on failure.

import { getSupabase } from './geoEnrichment';
import { search } from '../lib/wazuh-indexer';
import { wazuhGet } from '../lib/wazuh';
import { getAgentsForGroup, type WazuhAgent } from '../lib/wazuh-group';
import { unusableReply, wazuhFreshness, VULN_INDEX, type SearchReply } from './wazuhVulnSync';

type Reply = SearchReply | null;
export interface CheckDeps {
    search?: (index: string, body: unknown) => Promise<Reply>;
    managerGet?: (path: string) => Promise<{ status: number; json: unknown }>;
    agentsForGroup?: (group: string) => Promise<WazuhAgent[]>;
    env?: Record<string, string | undefined>;
    timeoutMs?: number;
}
type Part<T> = { ok: true } & T | { ok: false; error: string };

function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    const late = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(`${what} did not answer within ${Math.round(ms / 1000)} s`)), ms); });
    return Promise.race([p, late]).finally(() => clearTimeout(timer));
}
/** A failure as a category: never a credential, URL with credentials, or response body. */
function category(err: unknown): string {
    const m = err instanceof Error ? err.message : String(err);
    if (/environment variable is not set/i.test(m)) return m;
    if (/did not answer within/.test(m)) return m;
    if (/ECONNREFUSED/.test(m)) return 'connection refused';
    if (/ENOTFOUND|EAI_AGAIN/.test(m)) return 'host name does not resolve';
    if (/ETIMEDOUT|ECONNRESET|socket hang up/i.test(m)) return 'network timeout or reset';
    if (/authentication failed/i.test(m)) return 'authentication failed (check the API user and password)';
    return 'request failed';
}

export async function checkWazuhIntegration(org: string, deps: CheckDeps = {}) {
    const env = deps.env ?? process.env;
    const ms = deps.timeoutMs ?? 15_000;
    const doSearch = deps.search ?? (search as unknown as NonNullable<CheckDeps['search']>);
    const managerGet = deps.managerGet ?? wazuhGet;
    const agentsForGroup = deps.agentsForGroup ?? ((g: string) => getAgentsForGroup(g));
    const supabase = getSupabase()!;

    const configured = {
        manager_api: !!env.WAZUH_HOST && !!(env.WAZUH_API_PASSWORD || env.WAZUH_PASS),
        indexer: !!env.WAZUH_INDEXER_HOST && !!(env.WAZUH_INDEXER_PASSWORD || env.WAZUH_INDEXER_PASS),
    };

    // Manager API root: the installed version.
    let manager: Part<{ api_version: string | null; status: number }>;
    if (!configured.manager_api) manager = { ok: false, error: 'not configured (WAZUH_HOST and WAZUH_API_PASSWORD on the backend)' };
    else {
        try {
            const r = await withTimeout(managerGet('/'), ms, 'The Wazuh manager API');
            const v = (r.json as { data?: { api_version?: string } } | null)?.data?.api_version ?? null;
            manager = r.status >= 400 ? { ok: false, error: `the manager API answered HTTP ${r.status}` } : { ok: true, api_version: typeof v === 'string' ? v.slice(0, 40) : null, status: r.status };
        } catch (err) { manager = { ok: false, error: category(err) }; }
    }

    // This organisation's agents (mapped Wazuh groups).
    const { data: map } = await supabase.from('wazuh_group_org_map').select('wazuh_group').eq('org_id', org);
    const groups = (map ?? []).map((m) => String(m.wazuh_group));
    let agents: Part<{ groups: string[]; count: number; active: number }>;
    let names: string[] = [];
    if (!configured.indexer) agents = { ok: false, error: 'not configured (WAZUH_INDEXER_HOST and WAZUH_INDEXER_PASSWORD on the backend)' };
    else if (!groups.length) agents = { ok: false, error: 'no Wazuh group is mapped to this organisation (Settings → Wazuh Groups)' };
    else {
        try {
            const probe = await withTimeout(doSearch('wazuh-monitoring-*', { size: 0, track_total_hits: true, query: { match_all: {} } }), ms, 'The Wazuh indexer');
            const bad = unusableReply(probe, 'wazuh-monitoring-*');
            if (bad) agents = { ok: false, error: bad };
            else {
                const all = new Map<string, WazuhAgent>();
                for (const g of groups) for (const a of await withTimeout(agentsForGroup(g), ms, 'The Wazuh indexer')) all.set(a.id, a);
                names = [...all.values()].map((a) => a.name);
                agents = { ok: true, groups, count: all.size, active: [...all.values()].filter((a) => a.status === 'active').length };
            }
        } catch (err) { agents = { ok: false, error: category(err) }; }
    }

    // Vulnerability state index: present? how many records for these agents?
    let vulnerabilities: Part<{ index: string; index_present: true; records_for_org: number; by_severity: Record<string, number> }>;
    if (!configured.indexer) vulnerabilities = { ok: false, error: 'not configured' };
    else {
        try {
            const r = await withTimeout(doSearch(VULN_INDEX, {
                size: 0, track_total_hits: true,
                query: names.length ? { bool: { filter: [{ terms: { 'agent.name': names.slice(0, 1000) } }] } } : { match_none: {} },
                aggs: { severity: { terms: { field: 'vulnerability.severity', size: 10 } } },
            }), ms, 'The Wazuh indexer');
            const bad = unusableReply(r);
            if (bad || !r) vulnerabilities = { ok: false, error: bad ?? 'no answer' };
            else {
                const total = typeof r.hits?.total === 'number' ? r.hits.total : r.hits?.total?.value ?? 0;
                const buckets = ((r as { aggregations?: { severity?: { buckets?: { key: string; doc_count: number }[] } } }).aggregations?.severity?.buckets ?? []);
                vulnerabilities = { ok: true, index: VULN_INDEX, index_present: true, records_for_org: total, by_severity: Object.fromEntries(buckets.map((b) => [String(b.key).slice(0, 20), b.doc_count])) };
            }
        } catch (err) { vulnerabilities = { ok: false, error: category(err) }; }
    }

    const { data: sync } = await supabase.from('vms_wazuh_sync').select('last_synced_at, last_result').eq('org_id', org).maybeSingle();
    const freshness = wazuhFreshness(sync);
    const verdict = !configured.indexer ? 'not_configured'
        : !agents.ok || !vulnerabilities.ok ? 'not_working'
        : !freshness.last_complete_at ? 'reachable_not_synced'
        : 'working';
    return { checked_at: new Date().toISOString(), verdict, configured, manager, agents, vulnerabilities, sync: freshness };
}
