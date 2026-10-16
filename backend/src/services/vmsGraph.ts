// Attack-surface relationships for one asset (phase P14), derived only from stored records — no
// relationship is invented, and none implies ownership. Every edge says how it is known:
//   confirmed  our own scanner checked it, or the Wazuh agent itself reported it
//   observed   seen in a stored observation (DNS answer, port scan, HTTP probe, Wazuh sync)
//   inferred   derived by matching (same address in two records, a name under a domain, a
//              third-party claim) — useful to explore, not proof
// Wazuh endpoints and scan assets are never merged: a scan asset at an address a Wazuh agent
// reports is shown as a separate node linked by "same address", labelled inferred, because NAT,
// VPN and DHCP addresses are shared and change.

import { getSupabase } from './geoEnrichment';

export type Basis = 'confirmed' | 'observed' | 'inferred';
export interface GraphNode { id: string; kind: 'asset' | 'ip' | 'service' | 'technology' | 'finding'; label: string; asset_id?: string; asset_type?: string; detail?: Record<string, unknown> }
export interface GraphEdge { from: string; to: string; type: string; basis: Basis; source: string; observed_at: string | null }

interface AssetRow { id: string; asset_type: string; value: string; ips: string[] | null; hostnames: string[] | null; dns: { a?: string[]; aaaa?: string[]; cname?: string[] } | null; exposure: string; criticality: string; discovery_sources: string[] | null; last_seen: string; wazuh_agent_id: string | null; status: string; last_assessment?: { outcome?: string } | null }

const OPEN = ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened'];
const MAX_NODES = 300;

/** Nodes and edges around an asset: its addresses, the assets sharing them, names under it, services, technologies, open findings. */
export async function assetGraph(org: string, assetId: string): Promise<{ root: string; nodes: GraphNode[]; edges: GraphEdge[]; truncated: boolean } | null> {
    const supabase = getSupabase()!;
    const { data: root } = await supabase.from('vms_assets').select('*').eq('id', assetId).eq('org_id', org).maybeSingle();
    if (!root) return null;
    const nodes = new Map<string, GraphNode>();
    const edges: GraphEdge[] = [];
    const seenEdge = new Set<string>();
    const addNode = (n: GraphNode) => { if (!nodes.has(n.id) && nodes.size < MAX_NODES) nodes.set(n.id, n); return nodes.has(n.id); };
    const addEdge = (e: GraphEdge) => {
        const k = `${e.from}|${e.to}|${e.type}`;
        if (seenEdge.has(k) || !nodes.has(e.from) || !nodes.has(e.to)) return;
        seenEdge.add(k); edges.push(e);
    };
    const assetNode = (a: AssetRow): GraphNode => ({ id: `asset:${a.id}`, kind: 'asset', label: a.value, asset_id: a.id, asset_type: a.asset_type,
        detail: { exposure: a.exposure, criticality: a.criticality, sources: a.discovery_sources ?? [], status: a.status, last_seen: a.last_seen, assessment: a.last_assessment?.outcome ?? null } });
    const ipNode = (ip: string): GraphNode => ({ id: `ip:${ip}`, kind: 'ip', label: ip });

    // The neighbourhood: the root, assets sharing its addresses, and names under it (one hop each).
    const r = root as AssetRow;
    const addrs = [...new Set([...(r.ips ?? []), ...(r.asset_type === 'ip' ? [r.value] : [])].map((x) => x.toLowerCase()))];
    const [byIp, byValue, under] = await Promise.all([
        addrs.length ? supabase.from('vms_assets').select('*').eq('org_id', org).overlaps('ips', addrs).limit(100) : Promise.resolve({ data: [] }),
        addrs.length ? supabase.from('vms_assets').select('*').eq('org_id', org).in('value', addrs).limit(100) : Promise.resolve({ data: [] }),
        (r.asset_type === 'domain' || r.asset_type === 'host') ? supabase.from('vms_assets').select('*').eq('org_id', org).like('value', `%.${r.value}`).limit(150) : Promise.resolve({ data: [] }),
    ]);
    const group = new Map<string, AssetRow>([[r.id, r]]);
    for (const a of [...((byIp.data ?? []) as AssetRow[]), ...((byValue.data ?? []) as AssetRow[]), ...((under.data ?? []) as AssetRow[])]) group.set(a.id, a);

    for (const a of group.values()) addNode(assetNode(a));
    for (const a of group.values()) {
        const an = `asset:${a.id}`;
        // Names under a domain: a CT-log/discovery name inside the domain, not proof of ownership.
        if (a.id !== r.id && (r.asset_type === 'domain' || r.asset_type === 'host') && a.value.endsWith(`.${r.value}`)) {
            addEdge({ from: `asset:${r.id}`, to: an, type: 'subdomain', basis: 'inferred', source: (a.discovery_sources ?? []).join(', ') || 'inventory', observed_at: a.last_seen });
        }
        const resolved = [...(a.dns?.a ?? []), ...(a.dns?.aaaa ?? [])].map((x) => x.toLowerCase());
        for (const ip of new Set([...(a.ips ?? []).map((x) => x.toLowerCase()), ...resolved])) {
            addNode(ipNode(ip));
            if (a.asset_type === 'endpoint') addEdge({ from: an, to: `ip:${ip}`, type: 'reported_address', basis: 'confirmed', source: 'wazuh agent', observed_at: a.last_seen });
            else if (a.asset_type === 'ip' && a.value === ip) addEdge({ from: an, to: `ip:${ip}`, type: 'is_address', basis: 'confirmed', source: 'inventory', observed_at: a.last_seen });
            else addEdge({ from: an, to: `ip:${ip}`, type: 'resolves_to', basis: resolved.includes(ip) ? 'observed' : 'inferred', source: resolved.includes(ip) ? 'dns' : 'inventory', observed_at: a.last_seen });
        }
    }
    // Same address in a Wazuh endpoint and a scan asset: linked, never merged.
    const endpoints = [...group.values()].filter((a) => a.asset_type === 'endpoint');
    for (const e of endpoints) for (const a of group.values()) {
        if (a.asset_type === 'ip' && (e.ips ?? []).map((x) => x.toLowerCase()).includes(a.value)) {
            addEdge({ from: `asset:${e.id}`, to: `asset:${a.id}`, type: 'same_address', basis: 'inferred', source: 'address match (Wazuh agent address = scanned address)', observed_at: a.last_seen });
        }
    }

    const ids = [...group.keys()];
    const [svcs, techs, finds, obs] = await Promise.all([
        supabase.from('vms_services').select('id, asset_id, port, protocol, service, product, version, source, status, last_seen').in('asset_id', ids).eq('status', 'active').limit(500),
        supabase.from('vms_technologies').select('id, asset_id, name, version, source, last_seen').in('asset_id', ids).limit(300),
        supabase.from('vms_findings').select('id, asset_id, title, priority, evidence_class, source_class, status, last_seen').eq('org_id', org).in('asset_id', ids).in('status', OPEN).limit(300),
        supabase.from('vms_observations').select('id, asset_id, source, kind, key, confidence, last_seen').eq('org_id', org).in('asset_id', ids).eq('kind', 'service').limit(200),
    ]);
    for (const s of svcs.data ?? []) {
        if (!addNode({ id: `service:${s.id}`, kind: 'service', label: `${s.port}/${s.protocol}${s.service ? ` ${s.service}` : ''}`, detail: { product: s.product, version: s.version } })) continue;
        addEdge({ from: `asset:${s.asset_id}`, to: `service:${s.id}`, type: 'exposes', basis: 'observed', source: s.source, observed_at: s.last_seen });
    }
    // Ports a third party (Shodan/Censys via SpiderFoot) claims: inferred, never our own observation.
    for (const o of obs.data ?? []) {
        if (!addNode({ id: `obs:${o.id}`, kind: 'service', label: `${o.key} (reported)`, detail: { confidence: o.confidence } })) continue;
        addEdge({ from: `asset:${o.asset_id}`, to: `obs:${o.id}`, type: 'reported_service', basis: 'inferred', source: o.source, observed_at: o.last_seen });
    }
    for (const t of techs.data ?? []) {
        if (!addNode({ id: `tech:${t.id}`, kind: 'technology', label: `${t.name}${t.version ? ` ${t.version}` : ''}` })) continue;
        addEdge({ from: `asset:${t.asset_id}`, to: `tech:${t.id}`, type: 'runs', basis: 'observed', source: t.source, observed_at: t.last_seen });
    }
    for (const f of finds.data ?? []) {
        if (!addNode({ id: `finding:${f.id}`, kind: 'finding', label: `${f.priority ?? '—'} ${f.title}`.slice(0, 80), detail: { evidence_class: f.evidence_class, source: f.source_class, status: f.status } })) continue;
        const confirmed = f.evidence_class === 'scanner_check' || f.evidence_class === 'package_inventory';
        addEdge({ from: `asset:${f.asset_id}`, to: `finding:${f.id}`, type: 'affected_by', basis: confirmed ? 'confirmed' : 'inferred', source: f.source_class, observed_at: f.last_seen });
    }
    return { root: `asset:${r.id}`, nodes: [...nodes.values()], edges, truncated: nodes.size >= MAX_NODES };
}
