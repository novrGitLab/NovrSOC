// Threat-intelligence context for the SecOps AI purposes (phase P26): when an alert or case — or
// an alert in the case — matched a stored indicator, the AI sees that match and what each source
// said about the indicator, MISP included. Only this organisation's matches are read.
//
// Sharing markings apply to the provider as for the Threat Intelligence purposes: TLP:RED never
// enters a prompt; an external provider (the default, NVIDIA) receives only CLEAR and GREEN
// records; the platform's own model (AI_PROVIDER=ollama) may also read AMBER and AMBER+STRICT.
// The provider for these purposes is AI_PROVIDER (TI_AI_PROVIDER covers only the TI purposes).

import { getSupabase } from './geoEnrichment';
import { TLP_ORDER, isTlp, type Tlp } from './tiPolicy';
import type { SourceRef } from './ai';

export const secopsAiTlpCeiling = (): Tlp => ((process.env.AI_PROVIDER ?? '').trim().toLowerCase() === 'ollama' ? 'amber+strict' : 'green');
const allowed = (tlp: unknown, ceiling: Tlp) => { const t: Tlp = isTlp(tlp) ? tlp : 'amber'; return t !== 'red' && TLP_ORDER.indexOf(t) <= TLP_ORDER.indexOf(ceiling); };

/** Records (kind ti_match / ti_source_record) for the given entities' matches in this organisation. */
export async function tiContextFor(org: string, entities: { type: 'alert' | 'case'; id: string }[]): Promise<{ records: Record<string, unknown>[]; refs: SourceRef[] }> {
    const records: Record<string, unknown>[] = [];
    const refs: SourceRef[] = [];
    const supabase = getSupabase();
    if (!supabase || !entities.length) return { records, refs };
    const ceiling = secopsAiTlpCeiling();
    const matches: Record<string, unknown>[] = [];
    for (const type of ['alert', 'case'] as const) {
        const ids = entities.filter((e) => e.type === type).map((e) => e.id).slice(0, 50);
        if (!ids.length) continue;
        const { data, error } = await supabase.from('ti_matches').select('id, indicator_id, entity_type, entity_id, matched_field, status, first_matched_at').eq('org_id', org).eq('entity_type', type).in('entity_id', ids).limit(40);
        if (error) return { records, refs }; // TI not set up: the summary works without it
        matches.push(...(data ?? []));
    }
    const indIds = [...new Set(matches.map((m) => m.indicator_id as string))].slice(0, 20);
    if (!indIds.length) return { records, refs };
    const [inds, srcs] = await Promise.all([
        supabase.from('ti_indicators').select('id, type, value, status, first_seen, last_seen, source_count').in('id', indIds),
        supabase.from('ti_indicator_sources').select('id, indicator_id, feed_id, source_ref, confidence, first_seen, last_seen, tlp, context').in('indicator_id', indIds).limit(200),
    ]);
    const byInd = new Map((inds.data ?? []).map((i) => [i.id as string, i]));
    let withheld = 0;
    for (const m of matches) {
        const ind = byInd.get(m.indicator_id as string);
        if (!ind) continue;
        const ref = `ti_match:${m.id}`;
        records.push({ ref, kind: 'ti_match', note: 'This value was seen in the record named by entity_type/entity_id.', ...m, indicator: { type: ind.type, value: ind.value, status: ind.status, last_seen: ind.last_seen } });
        refs.push({ ref, type: 'ti_match', id: String(m.id), label: `${ind.type} ${ind.value}` });
    }
    for (const s of srcs.data ?? []) {
        if (!allowed(s.tlp, ceiling)) { withheld++; continue; }
        const ctx = (s.context ?? {}) as Record<string, unknown>;
        const pick = (k: string) => (typeof ctx[k] === 'string' || typeof ctx[k] === 'boolean' ? ctx[k] : null);
        const ref = `ti_source_record:${s.id}`;
        records.push({
            ref, kind: 'ti_source_record', note: 'What this source claimed about the indicator — attribute it to the source; it is not confirmed by NovrSOC.',
            indicator_id: s.indicator_id, feed: s.feed_id, source_ref: s.source_ref, source_confidence: s.confidence, first_seen: s.first_seen, last_seen: s.last_seen, tlp: s.tlp,
            threat_type: pick('threat_type'), malware: pick('malware'), category: pick('category'), event_info: pick('event_info'), event_org: pick('event_org'), reporter: pick('reporter'),
            comment: typeof ctx.comment === 'string' ? ctx.comment.slice(0, 300) : null,
        });
        refs.push({ ref, type: 'ti_source_record', id: String(s.id), label: `${s.feed_id}#${s.source_ref}` });
    }
    if (withheld) {
        records.push({ ref: 'note:ti_withheld', kind: 'note', note: `${withheld} threat-intelligence source record(s) are not shown to the AI because of their sharing marking.` });
        refs.push({ ref: 'note:ti_withheld', type: 'note', id: 'ti_withheld' });
    }
    return { records, refs };
}

/** The sentence the SecOps tasks add so threat-intelligence claims stay attributed. */
export const TI_CONTEXT_RULE = ' Records of kind ti_match show this value was seen here; records of kind ti_source_record are what a feed or partner (MISP) claimed about it — attribute them to that source, never present them as confirmed, and never name a threat actor that no record names.';
