// Threat Intelligence correlation lookups for alerts and cases (R3.3C). The same
// verified-vs-contextual, TLP-aware join routes/cniiNational.ts's loadTi() already proved correct
// for CNII assets (R3.3B) — entity_type here is 'alert' or 'case' instead of 'asset'. The
// candidates themselves are generated and written by services/threatInfo.ts's alertCandidates()/
// correlateOrg() (run by jobs/threatInfoJob.ts); this module only reads what's already stored —
// it was simply never surfaced in the alert/case detail responses before this release.
//
// 'dismissed' matches are an analyst's verdict that the match isn't relevant and are excluded;
// everything else is kept, with 'promoted' or a linked case_id treated as a verified association
// and 'new'/'reviewed' as contextual/possible only — a shared indicator or CVE appearing is never
// itself proof of a confirmed attack or compromise.

import { getSupabase } from '../services/geoEnrichment';
import { mostRestrictive, type Tlp } from '../services/tiPolicy';

export interface TiMatch {
    id: string;
    status: string;
    case_id: string | null;
    indicator_id: string;
    indicator: { id: string; type: string; value: string; max_confidence: number | null; malware_families: string[] | null; threat_types: string[] | null; status: string | null } | null;
}

/** Matches for a set of alert or case ids, excluding dismissed, grouped by entity id. */
export async function matchesFor(entityType: 'alert' | 'case', entityIds: string[]): Promise<Map<string, TiMatch[]>> {
    const out = new Map<string, TiMatch[]>();
    if (!entityIds.length) return out;
    const supabase = getSupabase();
    if (!supabase) return out;
    const { data } = await supabase.from('ti_matches')
        .select('id, entity_id, status, case_id, indicator_id, ti_indicators(id, type, value, max_confidence, malware_families, threat_types, status)')
        .eq('entity_type', entityType).in('entity_id', entityIds).neq('status', 'dismissed').limit(2000);
    for (const m of (data ?? []) as unknown as (TiMatch & { entity_id: string; ti_indicators: TiMatch['indicator'] })[]) {
        const row: TiMatch = { id: m.id, status: m.status, case_id: m.case_id, indicator_id: m.indicator_id, indicator: m.ti_indicators };
        const list = out.get(m.entity_id) ?? [];
        list.push(row);
        out.set(m.entity_id, list);
    }
    return out;
}

/** The most restrictive TLP among each indicator's sources; 'amber' (the conservative default
 * services/tiPolicy.ts's tlpFromTags() uses for an untagged record) when an indicator has none. */
export async function tlpFor(indicatorIds: string[]): Promise<Map<string, Tlp>> {
    const out = new Map<string, Tlp>();
    if (!indicatorIds.length) return out;
    const supabase = getSupabase();
    if (!supabase) return out;
    const { data } = await supabase.from('ti_indicator_sources').select('indicator_id, tlp').in('indicator_id', indicatorIds).limit(5000);
    const byIndicator = new Map<string, Tlp[]>();
    for (const s of data ?? []) byIndicator.set(s.indicator_id, [...(byIndicator.get(s.indicator_id) ?? []), s.tlp as Tlp]);
    for (const id of indicatorIds) out.set(id, byIndicator.has(id) ? mostRestrictive(byIndicator.get(id)!) : 'amber');
    return out;
}

export interface TiMatchView {
    indicator_type: string | null;
    indicator_value: string | null;
    confidence: number | null;
    malware_families: string[];
    threat_types: string[];
    verified: boolean;
    status: string;
    case_id: string | null;
    tlp: Tlp;
    /** The indicator's own lifecycle state when it matched. R3.3D: this was already fetched
     * (matchesFor's embed includes it) but silently dropped before this view, so a match whose
     * indicator later expired looked identical to one still active — stale intelligence shown as
     * current. 'active' when the indicator record is missing is the conservative default (most
     * matches predate this field; absence is not evidence of expiry). */
    indicator_active: boolean;
}

/** Full detail view for one entity's matches, ready to put straight in a detail response. */
export async function tiDetailFor(entityType: 'alert' | 'case', entityId: string): Promise<TiMatchView[]> {
    const byEntity = await matchesFor(entityType, [entityId]);
    const rows = byEntity.get(entityId) ?? [];
    const tlpByIndicator = await tlpFor([...new Set(rows.map((r) => r.indicator_id))]);
    return rows.map((m) => ({
        indicator_type: m.indicator?.type ?? null, indicator_value: m.indicator?.value ?? null,
        confidence: m.indicator?.max_confidence ?? null, malware_families: m.indicator?.malware_families ?? [], threat_types: m.indicator?.threat_types ?? [],
        verified: m.status === 'promoted' || !!m.case_id, status: m.status, case_id: m.case_id,
        tlp: tlpByIndicator.get(m.indicator_id) ?? 'amber',
        indicator_active: m.indicator?.status !== 'expired',
    }));
}
