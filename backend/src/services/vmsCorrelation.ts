// Cross-source CVE correlation (phase P16). Findings that name the same CVE are linked only when a
// stored record says how their assets relate; findings, assets, sources, severities, timestamps,
// evidence and remediation state are never merged or changed. Correlations are DERIVED on read
// from vms_findings and vms_assets, so they are idempotent by construction (re-ingesting cannot
// create a duplicate link: there is no link row) and explainable: each one names the CVE, the
// relationship, how it is known and the record values it rests on.
//
//   same_asset     both findings are on the same inventory record (e.g. Nuclei and a version-match
//                  claim on one host)                                               confirmed
//   same_address   a Wazuh endpoint whose agent reports address A, and the scanned IP asset A — the
//                  existing "linked records" relationship (routes/vms.ts, services/vmsGraph.ts)
//                                                                                    inferred
// Not linked: two assets that merely share a CVE, hostnames resolving to an address (DNS changes and
// CDNs share addresses), or anything across organisations. An address is inferred because NAT, VPN
// and DHCP addresses are shared and reassigned; it is shown as a lead, never as proof.

import { getSupabase } from './geoEnrichment';

export type CorrelationBasis = 'confirmed' | 'inferred';
export interface CorrFinding { id: string; asset_id: string | null; asset_value: string; source_class: string; detected_by: string[] | null; cve_ids: string[] | null; status: string; scanner_severity?: string | null; priority?: string | null; evidence_class?: string | null; last_seen?: string | null }
export interface CorrAsset { id: string; asset_type: string; value: string; ips: string[] | null }
export interface Correlation {
    finding_id: string; cves: string[]; relation: 'same_asset' | 'same_address'; basis: CorrelationBasis; explanation: string; basis_record: Record<string, string>;
    other: { id: string; asset_id: string | null; asset_value: string; asset_type: string | null; source_class: string; detected_by: string[]; evidence_class: string | null; status: string; scanner_severity: string | null; priority: string | null; last_seen: string | null };
}

const MAX_CVES = 500;
const MAX_CANDIDATES = 5000;
const OTHER_COLUMNS = 'id, asset_id, asset_value, source_class, detected_by, cve_ids, status, scanner_severity, priority, evidence_class, last_seen';

/** How two assets are related by a stored record, or null. Pure. */
export function assetRelation(a: CorrAsset | undefined, b: CorrAsset | undefined): { relation: Correlation['relation']; basis: CorrelationBasis; explanation: string; basis_record: Record<string, string> } | null {
    if (!a || !b) return null;
    if (a.id === b.id) return { relation: 'same_asset', basis: 'confirmed', explanation: `Both findings are on the same inventory record (${a.value}).`, basis_record: { asset_id: a.id } };
    const pair = a.asset_type === 'endpoint' && b.asset_type === 'ip' ? [a, b] : b.asset_type === 'endpoint' && a.asset_type === 'ip' ? [b, a] : null;
    if (!pair) return null;
    const [endpoint, ip] = pair;
    if (!(endpoint.ips ?? []).map((x) => x.toLowerCase()).includes(ip.value.toLowerCase())) return null;
    return {
        relation: 'same_address', basis: 'inferred',
        explanation: `The Wazuh agent on ${endpoint.value} reports the address ${ip.value}, which is the scanned asset ${ip.value}. Inferred: an address can be shared (NAT, VPN) or reassigned (DHCP), so confirm it is the same machine before acting on both.`,
        basis_record: { endpoint_asset_id: endpoint.id, endpoint: endpoint.value, reported_address: ip.value, ip_asset_id: ip.id },
    };
}

/** Correlations for each of `findings` among `candidates`, using `assets`. Pure; one entry per pair of findings. */
export function correlatePure(findings: CorrFinding[], candidates: CorrFinding[], assets: CorrAsset[]): Map<string, Correlation[]> {
    const byId = new Map(assets.map((a) => [a.id, a]));
    const out = new Map<string, Correlation[]>();
    for (const f of findings) {
        const mine = new Set((f.cve_ids ?? []).map((c) => c.toUpperCase()));
        const list: Correlation[] = [];
        const seen = new Set<string>();
        if (!mine.size || !f.asset_id) { out.set(f.id, list); continue; }
        for (const g of candidates) {
            if (g.id === f.id || seen.has(g.id) || !g.asset_id) continue;
            const shared = (g.cve_ids ?? []).map((c) => c.toUpperCase()).filter((c) => mine.has(c));
            if (!shared.length) continue;
            const rel = assetRelation(byId.get(f.asset_id), byId.get(g.asset_id));
            if (!rel) continue;
            seen.add(g.id);
            const ga = byId.get(g.asset_id);
            list.push({
                finding_id: f.id, cves: [...new Set(shared)].sort(), ...rel,
                other: { id: g.id, asset_id: g.asset_id, asset_value: g.asset_value, asset_type: ga?.asset_type ?? null, source_class: g.source_class, detected_by: g.detected_by ?? [], evidence_class: g.evidence_class ?? null, status: g.status, scanner_severity: g.scanner_severity ?? null, priority: g.priority ?? null, last_seen: g.last_seen ?? null },
            });
        }
        // Confirmed relationships first, then by the other finding's id for a stable order.
        list.sort((x, y) => (x.basis === y.basis ? x.other.id.localeCompare(y.other.id) : x.basis === 'confirmed' ? -1 : 1));
        out.set(f.id, list);
    }
    return out;
}

/** Correlations for findings of one organisation, read from the database. Never crosses organisations. */
export async function correlateFindings(org: string, findings: CorrFinding[]): Promise<Map<string, Correlation[]>> {
    const supabase = getSupabase()!;
    const cves = [...new Set(findings.flatMap((f) => f.cve_ids ?? []).map((c) => c.toUpperCase()))].slice(0, MAX_CVES);
    if (!cves.length) return correlatePure(findings, [], []);
    const { data: cand, error } = await supabase.from('vms_findings').select(OTHER_COLUMNS).eq('org_id', org).overlaps('cve_ids', cves).limit(MAX_CANDIDATES);
    if (error) throw new Error(`correlation read failed: ${error.message}`);
    const candidates = (cand ?? []) as CorrFinding[];
    const assetIds = [...new Set([...findings, ...candidates].map((f) => f.asset_id).filter((x): x is string => !!x))];
    const assets: CorrAsset[] = [];
    for (let i = 0; i < assetIds.length; i += 200) {
        const { data, error: aErr } = await supabase.from('vms_assets').select('id, asset_type, value, ips').eq('org_id', org).in('id', assetIds.slice(i, i + 200));
        if (aErr) throw new Error(`correlation asset read failed: ${aErr.message}`);
        assets.push(...((data ?? []) as CorrAsset[]));
    }
    return correlatePure(findings, candidates, assets);
}
