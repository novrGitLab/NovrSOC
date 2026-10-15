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

import { getSupabase } from './geoEnrichment';
import { search } from '../lib/wazuh-indexer';
import { getAgentsForGroup, type WazuhAgent } from '../lib/wazuh-group';
import { riskScore, DUE_DAYS, type Severity } from '../lib/riskScore';
import { cleanCves, computeRisk } from './vmsFindings';
import { ensureCves } from './cveIntel';

const INDEX = 'wazuh-states-vulnerabilities-*';
const AGENTS_PER_QUERY = 20;
const PAGE = 5000;

interface VulnDoc {
    agent?: { id?: string; name?: string };
    package?: { name?: string; version?: string };
    vulnerability?: { id?: string; severity?: string; description?: string; reference?: string; score?: { base?: number } };
}
type SearchFn = (index: string, body: unknown) => Promise<{ hits?: { total?: { value?: number } | number; hits?: { _source?: VulnDoc }[] } } | null>;
type AgentsFn = (group: string) => Promise<WazuhAgent[]>;

const SEV: Record<string, Severity> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', none: 'info', untriaged: 'info' };
const isPublic = (ip: string | null) => !!ip && !/^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip);

export interface WazuhSyncResult { org: string; agents: number; ambiguous_agents: number; vulnerabilities: number; new_findings: number; verified: number; complete: boolean; errors: string[] }

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

        // Endpoint assets.
        const assetByAgent = new Map<string, string>();
        for (const a of mine) {
            const value = a.name.toLowerCase();
            const fields = { wazuh_agent_id: a.id, ips: a.ip ? [a.ip] : [], exposure: a.ip ? (isPublic(a.ip) ? 'internet' : 'internal') : 'unknown', alive: a.status === 'active', last_seen: started, status: 'active' };
            const { data: ex } = await supabase.from('vms_assets').select('id').eq('org_id', org).eq('asset_type', 'endpoint').eq('value', value).maybeSingle();
            if (ex) { await supabase.from('vms_assets').update(fields).eq('id', ex.id); assetByAgent.set(a.name, ex.id); }
            else {
                const ins = await supabase.from('vms_assets').insert({ org_id: org, asset_type: 'endpoint', value, hostnames: [], discovery_sources: ['wazuh'], first_seen: started, ...fields }).select('id').single();
                if (ins.error) { res.errors.push(`asset ${value}: ${ins.error.message}`); continue; }
                assetByAgent.set(a.name, ins.data.id);
                await supabase.from('vms_asset_events').insert({ org_id: org, asset_id: ins.data.id, event: 'asset_new', details: { value, source: 'wazuh' } });
            }
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
            if (!r) { res.complete = false; res.errors.push('indexer returned no answer'); continue; }
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
                const { data: ex } = await supabase.from('vms_findings').select('id, status').eq('org_id', org).eq('dedupe_key', key).maybeSingle();
                if (ex) {
                    const reopen = ex.status === 'verified' || ex.status === 'fixed_pending_verification';
                    await supabase.from('vms_findings').update({ last_seen: started, ...(reopen ? { status: 'reopened', verified_at: null, closed_at: null } : {}), updated_at: started }).eq('id', ex.id);
                    if (reopen) await supabase.from('vms_finding_events').insert({ org_id: org, finding_id: ex.id, actor: 'wazuh', action: 'reopened', from_value: ex.status, to_value: 'reopened', details: 'Wazuh still reports this vulnerability' });
                    continue;
                }
                await ensureCves([cve]);
                const risk = await computeRisk({ cve_ids: [cve], scanner_severity: severity, scanner_cvss: cvss, asset_id: assetId }).catch(() => riskScore({ scanner_severity: severity, cvss, kev: null, epss: null, exposure: 'unknown', criticality: 'medium' }));
                const ins = await supabase.from('vms_findings').insert({
                    org_id: org, dedupe_key: key, asset_id: assetId, asset_value: agentName, source_class: 'wazuh', detected_by: ['wazuh'], rule_id: cve,
                    title: `${cve} in ${pkg}${d.package?.version ? ` ${d.package.version.slice(0, 60)}` : ''}`, description: d.vulnerability?.description?.slice(0, 8000) ?? null,
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
        await supabase.from('vms_wazuh_sync').upsert({ org_id: org, last_synced_at: started, last_result: res }, { onConflict: 'org_id' });
        results.push(res);
    }
    return results;
}
