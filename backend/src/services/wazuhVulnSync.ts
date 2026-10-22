// Wazuh endpoints and their vulnerabilities into VMS (phase P5).
//
// For every organisation in the Wazuh group map: its agents (from wazuh-monitoring-*, the same
// source as the endpoint pages) become `endpoint` assets, and the vulnerabilities Wazuh reports for
// them (wazuh-states-vulnerabilities-*, the same index as the Wazuh Vulnerabilities page) become
// findings with source_class 'wazuh' — kept apart from active-scan findings.
//
// An agent whose groups map to more than one organisation is skipped, never guessed.
//
// Closing on absence is evidence-based and guarded: a Wazuh finding is verified only when a
// COMPLETE sync (every page fetched) returned vulnerability data for that agent and no longer
// lists the finding. An agent that returned nothing is left alone — that can mean "fully
// patched", but it can also mean the indexer was down (as it was 9–13 Oct 2026), so nothing is
// concluded from silence.
//
// What counts as an answer (P15): the indexer replies with parsed JSON even to errors. A reply with
// an `error` (bad credentials, missing permission) or one that searched no shard at all (the
// wildcard matched no index: Wazuh before 4.8, or vulnerability detection off) is NOT "no
// vulnerabilities": the sync is incomplete, with the reason. vms_wazuh_sync.last_synced_at is when
// the sync last ran; last_result.last_complete_at is when it last ran completely (kept across
// incomplete runs), and is what freshness should be judged on.

import { getSupabase } from './geoEnrichment';
import { search } from '../lib/wazuh-indexer';
import { getAgentsForGroup, type WazuhAgent } from '../lib/wazuh-group';
import { riskScore, DUE_DAYS, type Severity } from '../lib/riskScore';
import { cleanCves, computeRisk } from './vmsFindings';
import { ensureCves } from './cveIntel';
import { refreshEligibility, missingP19, withoutP19, type EligibilityStatus } from './vmsEligibility';

export const VULN_INDEX = 'wazuh-states-vulnerabilities-*';
const INDEX = VULN_INDEX;
const AGENTS_PER_QUERY = 20;
const PAGE = 5000;

interface VulnDoc {
    agent?: { id?: string; name?: string };
    package?: { name?: string; version?: string };
    vulnerability?: { id?: string; severity?: string; description?: string; reference?: string; score?: { base?: number } };
}
export type SearchReply = { hits?: { total?: { value?: number } | number; hits?: { _source?: VulnDoc }[] }; _shards?: { total?: number; failed?: number }; error?: unknown; status?: number };
type SearchFn = (index: string, body: unknown) => Promise<SearchReply | null>;

/** Why an indexer reply cannot be read as "these are all the vulnerabilities", or null when it can. */
export function unusableReply(r: SearchReply | null, index = INDEX): string | null {
    if (!r) return 'the indexer returned no readable answer';
    if (r.error !== undefined) {
        const e = r.error as { type?: string; reason?: string } | string;
        const type = typeof e === 'string' ? e : e?.type ?? 'error';
        if (r.status === 401 || /security_exception/.test(String(type))) return `the indexer refused the query (${type}${r.status ? `, HTTP ${r.status}` : ''}): check WAZUH_INDEXER_USER and its read permission on ${index}`;
        return `the indexer returned ${type}${r.status ? ` (HTTP ${r.status})` : ''}`;
    }
    if (r._shards && (r._shards.total ?? 0) === 0) return index === VULN_INDEX ? `no index matches ${index}: Wazuh before 4.8, or vulnerability detection is not enabled` : `no index matches ${index}`;
    if (r._shards && (r._shards.failed ?? 0) > 0) return `${r._shards.failed} of ${r._shards.total} indexer shard(s) failed`;
    return null;
}
type AgentsFn = (group: string) => Promise<WazuhAgent[]>;

const SEV: Record<string, Severity> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', none: 'info', untriaged: 'info' };
const isPublic = (ip: string | null) => !!ip && !/^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip);

export interface WazuhSyncResult { org: string; agents: number; ambiguous_agents: number; vulnerabilities: number; new_findings: number; verified: number; complete: boolean; errors: string[]; last_complete_at?: string | null; eligibility?: Record<EligibilityStatus, number> | null }

/** Freshness of one vms_wazuh_sync row: last attempt, last complete sync (rows from before P15
 *  carry no last_complete_at: a complete last run counts from last_synced_at), and why the last run was incomplete. */
export function wazuhFreshness(row: { last_synced_at?: string | null; last_result?: unknown } | null | undefined): { last_attempt_at: string | null; last_complete_at: string | null; complete: boolean | null; problem: string | null } {
    if (!row?.last_synced_at) return { last_attempt_at: null, last_complete_at: null, complete: null, problem: null };
    const r = (row.last_result ?? {}) as { complete?: boolean; last_complete_at?: string | null; errors?: string[] };
    const complete = r.complete !== false;
    return { last_attempt_at: row.last_synced_at, last_complete_at: r.last_complete_at !== undefined ? r.last_complete_at ?? null : complete ? row.last_synced_at : null, complete, problem: complete ? null : (r.errors ?? [])[0] ?? 'incomplete' };
}

export async function syncWazuhVulnerabilities(deps: { search?: SearchFn; agentsForGroup?: AgentsFn } = {}): Promise<WazuhSyncResult[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    const doSearch = (deps.search ?? (search as unknown as SearchFn));
    const agentsForGroup = deps.agentsForGroup ?? ((g: string) => getAgentsForGroup(g));
    const { data: map, error } = await supabase.from('wazuh_group_org_map').select('wazuh_group, org_id');
    if (error) throw new Error(`group map read failed: ${error.message}`);

    // agent id -> orgs it belongs to
    const agentOrgs = new Map<string, { agent: WazuhAgent; orgs: Set<string> }>();
    for (const m of map ?? []) {
        for (const a of await agentsForGroup(m.wazuh_group)) {
            const cur = agentOrgs.get(a.id) ?? { agent: a, orgs: new Set<string>() };
            cur.orgs.add(m.org_id);
            agentOrgs.set(a.id, cur);
        }
    }
    const results: WazuhSyncResult[] = [];
    for (const org of [...new Set((map ?? []).map((m) => m.org_id as string))]) {
        const res: WazuhSyncResult = { org, agents: 0, ambiguous_agents: 0, vulnerabilities: 0, new_findings: 0, verified: 0, complete: true, errors: [] };
        const started = new Date().toISOString();
        const agents = [...agentOrgs.values()].filter((x) => x.orgs.has(org));
        res.ambiguous_agents = agents.filter((x) => x.orgs.size > 1).length;
        const mine = agents.filter((x) => x.orgs.size === 1).map((x) => x.agent);
        res.agents = mine.length;

        // Endpoint assets (P19: matched by agent id, with what the agent reports about itself).
        const assetByAgent = new Map<string, string>();
        let p19 = true;
        const write = async <T>(op: (f: Record<string, unknown>) => PromiseLike<{ data: T | null; error: { message: string; code?: string } | null }>, f: Record<string, unknown>) => {
            let r = await op(p19 ? f : withoutP19(f));
            if (p19 && missingP19(r.error)) { p19 = false; r = await op(withoutP19(f)); }
            return r;
        };
        for (const a of mine) {
            const value = a.name.toLowerCase();
            // lib/wazuh-group.ts no longer lists the manager (agent 000); when a listing still
            // supplies it, its OS and keep-alive are not reported by Wazuh and stay unknown.
            const synthetic = a.id === '000';
            const keepalive = !synthetic && a.lastKeepAlive && !Number.isNaN(Date.parse(a.lastKeepAlive)) ? new Date(a.lastKeepAlive).toISOString() : null;
            const ips = a.ip ? [a.ip] : [];
            const fields: Record<string, unknown> = {
                wazuh_agent_id: a.id, ips, exposure: a.ip ? (isPublic(a.ip) ? 'internet' : 'internal') : 'unknown', alive: a.status === 'active',
                // last_seen: present in Wazuh's agent inventory at this sync. The agent's own last
                // contact is agent_last_keepalive.
                last_seen: started, status: 'active',
                os: synthetic ? null : a.os, agent_status: a.status, agent_last_keepalive: keepalive, agent_groups: a.group ?? [],
            };
            const byId = a.id ? await supabase.from('vms_assets').select('id, value, ips').eq('org_id', org).eq('asset_type', 'endpoint').eq('wazuh_agent_id', a.id).limit(1).maybeSingle() : { data: null };
            const ex = byId.data ?? (await supabase.from('vms_assets').select('id, value, ips').eq('org_id', org).eq('asset_type', 'endpoint').eq('value', value).maybeSingle()).data;
            if (ex) {
                const upd = await write((f) => supabase.from('vms_assets').update(f).eq('id', ex.id).select('id'), fields);
                if (upd.error) { res.errors.push(`asset ${value}: ${upd.error.message}`); continue; }
                assetByAgent.set(a.name, ex.id);
                const before = [...((ex.ips as string[] | null) ?? [])].sort().join(',');
                const changes: Record<string, unknown> = {};
                if (before !== [...ips].sort().join(',')) changes.ips = { from: ex.ips ?? [], to: ips };
                if (ex.value !== value) {
                    // A renamed agent keeps its asset; the name follows unless another endpoint holds it.
                    const ren = await supabase.from('vms_assets').update({ value }).eq('id', ex.id).select('id');
                    if (!ren.error) changes.name = { from: ex.value, to: value };
                }
                if (Object.keys(changes).length) await supabase.from('vms_asset_events').insert({ org_id: org, asset_id: ex.id, event: 'asset_changed', details: { ...changes, source: 'wazuh' } });
            } else {
                const ins = await write((f) => supabase.from('vms_assets').insert({ org_id: org, asset_type: 'endpoint', value, hostnames: [], discovery_sources: ['wazuh'], first_seen: started, ...f }).select('id').single(), fields);
                if (ins.error || !ins.data) { res.errors.push(`asset ${value}: ${ins.error?.message ?? 'not stored'}`); continue; }
                const id = (ins.data as { id: string }).id;
                assetByAgent.set(a.name, id);
                await supabase.from('vms_asset_events').insert({ org_id: org, asset_id: id, event: 'asset_new', details: { value, source: 'wazuh' } });
            }
        }
        // Where each endpoint may be scanned, given today's scope and workers (P19).
        try {
            const el = await refreshEligibility(org);
            res.eligibility = el.stored ? el.counts : null;
        } catch (err) {
            res.errors.push(`eligibility: ${err instanceof Error ? err.message : String(err)}`);
        }

        // Vulnerabilities, in chunks of agents.
        const seenKeys = new Set<string>();
        const agentsWithData = new Set<string>();
        for (let i = 0; i < mine.length; i += AGENTS_PER_QUERY) {
            const names = mine.slice(i, i + AGENTS_PER_QUERY).map((a) => a.name);
            let r;
            try {
                r = await doSearch(INDEX, { size: PAGE, track_total_hits: true, query: { bool: { filter: [{ terms: { 'agent.name': names } }] } },
                    _source: ['agent.id', 'agent.name', 'package.name', 'package.version', 'vulnerability.id', 'vulnerability.severity', 'vulnerability.description', 'vulnerability.reference', 'vulnerability.score.base'] });
            } catch (err) { res.complete = false; res.errors.push(`indexer: ${err instanceof Error ? err.message : err}`); continue; }
            const bad = unusableReply(r);
            if (bad || !r) { res.complete = false; res.errors.push(`indexer: ${bad}`); continue; }
            const hits = r.hits?.hits ?? [];
            const total = typeof r.hits?.total === 'number' ? r.hits.total : r.hits?.total?.value ?? hits.length;
            if (total > hits.length) { res.complete = false; res.errors.push(`more than ${PAGE} vulnerabilities for one agent chunk; absence not evaluated for it`); }
            for (const h of hits) {
                const d = h._source ?? {};
                const agentName = d.agent?.name ?? '';
                const cve = cleanCves([d.vulnerability?.id ?? ''])[0];
                const assetId = assetByAgent.get(agentName);
                if (!cve || !assetId) continue;
                if (total <= hits.length) agentsWithData.add(agentName);
                res.vulnerabilities++;
                const pkg = d.package?.name?.slice(0, 120) ?? 'unknown package';
                const key = `endpoint:${agentName.toLowerCase()}|-|${cve}|${pkg}`;
                seenKeys.add(key);
                const severity: Severity = SEV[(d.vulnerability?.severity ?? '').toLowerCase()] ?? 'info';
                const cvss = typeof d.vulnerability?.score?.base === 'number' && d.vulnerability.score.base >= 0 && d.vulnerability.score.base <= 10 ? d.vulnerability.score.base : null;
                const title = `${cve} in ${pkg}${d.package?.version ? ` ${d.package.version.slice(0, 60)}` : ''}`;
                const { data: ex } = await supabase.from('vms_findings').select('id, status, title').eq('org_id', org).eq('dedupe_key', key).maybeSingle();
                if (ex) {
                    const reopen = ex.status === 'verified' || ex.status === 'fixed_pending_verification';
                    // The package version moved (an update that did not fix this CVE): keep the old
                    // evidence, add the new sighting, and say what Wazuh reports now (P16).
                    const moved = ex.title !== title;
                    await supabase.from('vms_findings').update({ last_seen: started, ...(moved ? { title } : {}), ...(reopen ? { status: 'reopened', verified_at: null, closed_at: null } : {}), updated_at: started }).eq('id', ex.id);
                    if (moved) await supabase.from('vms_finding_evidence').insert({ org_id: org, finding_id: ex.id, source: 'wazuh', observed_at: started, matched_at: `${pkg} ${d.package?.version ?? ''}`.trim(), evidence: { agent_id: d.agent?.id ?? null, package: d.package ?? null, severity: d.vulnerability?.severity ?? null } });
                    if (reopen) await supabase.from('vms_finding_events').insert({ org_id: org, finding_id: ex.id, actor: 'wazuh', action: 'reopened', from_value: ex.status, to_value: 'reopened', details: 'Wazuh still reports this vulnerability' });
                    continue;
                }
                await ensureCves([cve]);
                const risk = await computeRisk({ cve_ids: [cve], scanner_severity: severity, scanner_cvss: cvss, asset_id: assetId }).catch(() => riskScore({ scanner_severity: severity, cvss, kev: null, epss: null, exposure: 'unknown', criticality: 'medium' }));
                const ins = await supabase.from('vms_findings').insert({
                    org_id: org, dedupe_key: key, asset_id: assetId, asset_value: agentName, source_class: 'wazuh', detected_by: ['wazuh'], rule_id: cve,
                    title, description: d.vulnerability?.description?.slice(0, 8000) ?? null,
                    cve_ids: [cve], scanner_severity: severity, scanner_cvss: cvss, references_urls: d.vulnerability?.reference && /^https?:\/\//.test(d.vulnerability.reference) ? [d.vulnerability.reference.slice(0, 1000)] : [],
                    risk_score: risk.score, priority: risk.priority, risk_factors: risk.factors, first_seen: started, last_seen: started,
                    due_at: new Date(Date.parse(started) + DUE_DAYS[risk.priority] * 86_400_000).toISOString(),
                }).select('id').single();
                if (ins.error) { res.errors.push(`finding ${cve}: ${ins.error.message}`); continue; }
                res.new_findings++;
                await supabase.from('vms_finding_evidence').insert({ org_id: org, finding_id: ins.data.id, source: 'wazuh', observed_at: started, matched_at: `${pkg} ${d.package?.version ?? ''}`.trim(), evidence: { agent_id: d.agent?.id ?? null, package: d.package ?? null, severity: d.vulnerability?.severity ?? null } });
                await supabase.from('vms_finding_events').insert({ org_id: org, finding_id: ins.data.id, actor: 'wazuh', action: 'detected', to_value: 'open', details: `Reported by Wazuh on ${agentName}` });
            }
        }

        // Absence: only for agents that returned data in this complete sync.
        if (res.complete) {
            const { data: open } = await supabase.from('vms_findings').select('id, status, dedupe_key, asset_value')
                .eq('org_id', org).eq('source_class', 'wazuh').in('status', ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened']);
            for (const f of open ?? []) {
                if (seenKeys.has(f.dedupe_key) || !agentsWithData.has(f.asset_value)) continue;
                await supabase.from('vms_findings').update({ status: 'verified', verified_at: started, closed_at: started, updated_at: started }).eq('id', f.id);
                await supabase.from('vms_finding_events').insert({ org_id: org, finding_id: f.id, actor: 'wazuh', action: 'verified', from_value: f.status, to_value: 'verified', details: 'No longer reported by Wazuh for this endpoint (complete sync with data for the agent)' });
                res.verified++;
            }
        }
        // Freshness: when the sync last completed, carried over an incomplete run.
        if (res.complete) res.last_complete_at = started;
        else {
            const { data: prev } = await supabase.from('vms_wazuh_sync').select('last_result').eq('org_id', org).maybeSingle();
            const p = prev?.last_result as { complete?: boolean; last_complete_at?: string } | null | undefined;
            res.last_complete_at = p?.last_complete_at ?? null;
        }
        await supabase.from('vms_wazuh_sync').upsert({ org_id: org, last_synced_at: started, last_result: res }, { onConflict: 'org_id' });
        results.push(res);
    }
    return results;
}
