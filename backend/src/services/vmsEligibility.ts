// Scan eligibility of Wazuh endpoints (phase P19): whether an endpoint may be assessed automatically,
// and at which address.
//
// An address Wazuh reports is telemetry, not authorisation. An endpoint is eligible only at an
// address that is inside an active, unexpired scope entry of its own organisation allowing
// vulnerability scans (the organisation's agreed coverage) and that a scanner worker can reach.
// It is NOT eligible, with the reason recorded, when:
//   offline            Wazuh reports the agent not active: a scan would not reach it
//   no_address         Wazuh reports no usable IP address
//   duplicate_address  the address is also reported by another endpoint of the organisation (DHCP
//                      reuse, a cloned agent), or a public address reported by endpoints of several
//                      organisations or several endpoints (NAT: scanning it assesses the gateway,
//                      not the endpoint)
//   not_covered        no reported address is inside agreed coverage
//   private_no_route   covered, but private, and no scanner worker declares a route to it
// A scan that runs anyway still reports per-target outcomes; nothing here marks anything assessed.

import { isIP } from 'net';
import { getSupabase } from './geoEnrichment';
import { coveringScope, type ScopeEntry, type Activity } from '../lib/vmsScope';
import { isNonPublicIp, workerCanReach } from '../lib/netClass';

export type EligibilityStatus = 'eligible' | 'not_covered' | 'private_no_route' | 'offline' | 'no_address' | 'duplicate_address';
export interface Eligibility { status: EligibilityStatus; reason: string; target: string | null; scope_id: string | null; evaluated_at: string }
export interface EndpointLike { id: string; ips?: string[] | null; agent_status?: string | null; alive?: boolean | null }

const norm = (ip: string) => ip.trim().toLowerCase();

/** Pure: eligibility of one endpoint for an activity (vuln: Standard/Full profiles; ports: Discovery).
 *  `networks` = private networks the scanner workers declare. */
export function endpointEligibility(a: EndpointLike, scopes: ScopeEntry[], networks: readonly string[], duplicates: ReadonlySet<string>, now = Date.now(), activity: Activity = 'vuln'): Eligibility {
    const at = new Date(now).toISOString();
    const out = (status: EligibilityStatus, reason: string, target: string | null = null, scope_id: string | null = null): Eligibility => ({ status, reason, target, scope_id, evaluated_at: at });
    const ips = [...new Set((a.ips ?? []).map(norm).filter((ip) => isIP(ip) !== 0))];
    const agentDown = a.agent_status ? a.agent_status !== 'active' : a.alive === false;
    if (agentDown) return out('offline', `Wazuh reports the agent ${a.agent_status ?? 'not active'}; a scan would not reach it. It is assessed again once the agent is active`);
    if (!ips.length) return out('no_address', 'Wazuh reports no IP address for this endpoint');
    const unique = ips.filter((ip) => !duplicates.has(ip));
    if (!unique.length) return out('duplicate_address', `${ips.join(', ')} is also reported by another endpoint (DHCP reuse, a cloned agent, or NAT, where scanning the address would assess the gateway instead); not scanned automatically until the address is unique`);
    const live = scopes.filter((s) => s.status === 'active' && Date.parse(s.expires_at) > now);
    const covered = unique.map((ip) => ({ ip, scope: coveringScope({ type: 'ip', value: ip }, live, activity, now) })).filter((c): c is { ip: string; scope: ScopeEntry } => !!c.scope);
    const what = activity === 'vuln' ? 'vulnerability scanning' : activity === 'ports' ? 'port scanning' : 'discovery';
    if (!covered.length) return out('not_covered', `${unique.join(', ')} ${unique.length > 1 ? 'are' : 'is'} not inside any active authorised scope entry of this organisation that allows ${what}. A reported address alone never authorises a scan: add the organisation's agreed ranges to scope`);
    const reachable = covered.filter((c) => workerCanReach(c.ip, networks));
    if (!reachable.length) return out('private_no_route', `${covered.map((c) => c.ip).join(', ')} ${covered.length > 1 ? 'are private addresses' : 'is a private address'} and no scanner worker declares a route to ${covered.length > 1 ? 'them' : 'it'} (VMS_WORKER_NETWORKS); a worker inside that network is needed`);
    // A public address first: it is what the internet sees.
    const pick = reachable.find((c) => !isNonPublicIp(c.ip)) ?? reachable[0];
    return out('eligible', `Assessed at ${pick.ip}, covered by authorised scope ${pick.scope.kind} ${pick.scope.value}`, pick.ip, pick.scope.id);
}

/** Pure: addresses that do not identify one endpoint. Within an organisation, any address on more
 *  than one active endpoint; across organisations, public addresses only (private ranges repeat
 *  across separate client networks by design). */
export function duplicateAddresses(org: string, endpoints: { id: string; org_id: string; ips?: string[] | null; status?: string }[]): Set<string> {
    const holders = new Map<string, { ids: Set<string>; orgs: Set<string> }>();
    for (const e of endpoints) {
        if (e.status && e.status !== 'active') continue;
        for (const raw of new Set((e.ips ?? []).map(norm))) {
            if (isIP(raw) === 0) continue;
            const h = holders.get(raw) ?? { ids: new Set(), orgs: new Set() };
            h.ids.add(e.id); h.orgs.add(e.org_id);
            holders.set(raw, h);
        }
    }
    const dup = new Set<string>();
    for (const [ip, h] of holders) {
        if (!h.orgs.has(org)) continue;
        const inOrg = endpoints.filter((e) => e.org_id === org && h.ids.has(e.id)).length;
        if (inOrg > 1 || (!isNonPublicIp(ip) && h.ids.size > 1)) dup.add(ip);
    }
    return dup;
}

/** Private networks declared by the workers known to the backend (any state: a route is a property of the host). */
export async function workerNetworks(): Promise<string[]> {
    const { data, error } = await getSupabase()!.from('vms_workers').select('networks');
    if (error) return [];
    return [...new Set((data ?? []).flatMap((w) => (w.networks as string[] | null) ?? []))];
}

export const P19_MISSING = 'Scan eligibility is not set up yet (run sql/2026-10-25_p19_vms_automation.sql)';
/** A write that failed only because a P19 column does not exist yet. */
export const missingP19 = (e: { message?: string; code?: string } | null) => !!e && (e.code === 'PGRST204' || e.code === '42703') && /scan_eligibility|next_scan_at|agent_status|agent_last_keepalive|agent_groups|'os'|\bos\b column/.test(e.message ?? '');
/** The P19 columns, for retrying a write without them before the migration runs. */
export const P19_ASSET_COLUMNS = ['os', 'agent_status', 'agent_last_keepalive', 'agent_groups', 'scan_eligibility', 'next_scan_at'] as const;
export const withoutP19 = (fields: Record<string, unknown>) => Object.fromEntries(Object.entries(fields).filter(([k]) => !(P19_ASSET_COLUMNS as readonly string[]).includes(k)));

/**
 * Evaluates every active Wazuh endpoint of an organisation and stores the result on the asset.
 * Returns the evaluations by asset id; `stored` is false when the P19 columns do not exist yet
 * (the evaluations are still returned and used).
 */
export async function refreshEligibility(org: string, now = Date.now(), activity: Activity = 'vuln'): Promise<{ byAsset: Map<string, Eligibility>; stored: boolean; counts: Record<EligibilityStatus, number> }> {
    const supabase = getSupabase()!;
    const [{ data: scopes }, { data: all }, networks] = await Promise.all([
        supabase.from('vms_scopes').select('*').eq('org_id', org).eq('status', 'active'),
        // Every active endpoint across organisations: a public address shared with another one is NAT.
        supabase.from('vms_assets').select('*').eq('asset_type', 'endpoint').eq('status', 'active').limit(20_000),
        workerNetworks(),
    ]);
    const endpoints = (all ?? []) as (EndpointLike & { org_id: string; status: string; scan_eligibility?: Eligibility | null })[];
    const dups = duplicateAddresses(org, endpoints);
    const byAsset = new Map<string, Eligibility>();
    const counts = { eligible: 0, not_covered: 0, private_no_route: 0, offline: 0, no_address: 0, duplicate_address: 0 } as Record<EligibilityStatus, number>;
    // What is stored and shown is eligibility for vulnerability assessment; other activities are computed only.
    let stored = activity === 'vuln';
    for (const e of endpoints.filter((x) => x.org_id === org)) {
        const el = endpointEligibility(e, (scopes ?? []) as ScopeEntry[], networks, dups, now, activity);
        byAsset.set(e.id, el);
        counts[el.status]++;
        const prev = e.scan_eligibility;
        if (!stored || (prev && prev.status === el.status && prev.target === el.target && prev.reason === el.reason)) continue;
        const { error } = await supabase.from('vms_assets').update({ scan_eligibility: el }).eq('id', e.id);
        if (missingP19(error)) stored = false;
    }
    return { byAsset, stored: stored && activity === 'vuln', counts };
}

/** Eligibility of one endpoint now (manual assessments of an endpoint). */
export async function eligibilityFor(org: string, assetId: string, activity: Activity = 'vuln'): Promise<Eligibility | null> {
    const r = await refreshEligibility(org, Date.now(), activity);
    return r.byAsset.get(assetId) ?? null;
}
