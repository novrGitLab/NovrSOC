// Hosting location of IP indicators (phase P25), for the Nigeria map's "Nigeria-hosted
// infrastructure" layer. This is where an address is hosted — never where an attack came from
// or what it targeted. Order of evidence:
//   1. source_stated — a feed said which country hosts it (Feodo Tracker's `country`); country only.
//   2. geoip — services/geoEnrichment.ts enrichIP (IPregistry, then AFRINIC, then RIPE Stat).
// precision is 'state' only when the provider named a Nigerian state that matches one of the 37;
// otherwise 'country' (or 'unknown' with no country at all). Nothing is placed more precisely
// than its evidence. Lookups are budgeted per run (TI_GEO_BATCH, default 100).

import { getSupabase, enrichIP } from './geoEnrichment';

export const NIGERIA_STATES = [
    'Abia', 'Adamawa', 'Akwa Ibom', 'Anambra', 'Bauchi', 'Bayelsa', 'Benue', 'Borno', 'Cross River', 'Delta', 'Ebonyi', 'Edo', 'Ekiti', 'Enugu',
    'Federal Capital Territory', 'Gombe', 'Imo', 'Jigawa', 'Kaduna', 'Kano', 'Katsina', 'Kebbi', 'Kogi', 'Kwara', 'Lagos', 'Nasarawa', 'Niger', 'Ogun',
    'Ondo', 'Osun', 'Oyo', 'Plateau', 'Rivers', 'Sokoto', 'Taraba', 'Yobe', 'Zamfara',
] as const;
export type NigeriaState = typeof NIGERIA_STATES[number];

const ALIASES: Record<string, NigeriaState> = {
    fct: 'Federal Capital Territory', abuja: 'Federal Capital Territory', 'abuja federal capital territory': 'Federal Capital Territory', 'fct abuja': 'Federal Capital Territory',
    'akwa-ibom': 'Akwa Ibom', nassarawa: 'Nasarawa', 'cross-river': 'Cross River',
};

/** The map's state name for a provider's region string, or null when it names no Nigerian state. */
export function nigeriaState(region: string | null | undefined): NigeriaState | null {
    if (!region) return null;
    const r = region.trim().toLowerCase().replace(/\s+state$/, '').replace(/\s+/g, ' ');
    const hit = NIGERIA_STATES.find((s) => s.toLowerCase() === r);
    return hit ?? ALIASES[r] ?? null;
}

export interface GeoRow {
    indicator_id: string; country_code: string | null; country: string | null; region: string | null; city: string | null;
    asn: string | null; as_org: string | null; method: 'source_stated' | 'geoip'; provider: string; precision: 'state' | 'country' | 'unknown';
}

/** A row from a source's own statement (country only), or null when the source stated none. */
export function geoFromSource(indicatorId: string, feedId: string, context: Record<string, unknown> | null): GeoRow | null {
    const c = typeof context?.country === 'string' ? context.country.trim().toUpperCase() : '';
    if (!/^[A-Z]{2}$/.test(c)) return null;
    return { indicator_id: indicatorId, country_code: c, country: null, region: null, city: null, asn: null, as_org: typeof context?.as_name === 'string' ? context.as_name.slice(0, 120) : null, method: 'source_stated', provider: feedId, precision: 'country' };
}

/** A row from a GeoIP answer. A region counts only when it is a Nigerian state. */
export function geoFromLookup(indicatorId: string, g: { country_code: string | null; country: string | null; region: string | null; city: string | null; asn: string | null; org: string | null; source: string }): GeoRow {
    const cc = g.country_code && g.country_code !== 'XX' ? g.country_code.toUpperCase() : null;
    const state = cc === 'NG' ? nigeriaState(g.region) : null;
    return {
        indicator_id: indicatorId, country_code: cc, country: cc ? g.country : null, region: state ?? (cc === 'NG' ? null : g.region), city: state ? g.city : null,
        asn: g.asn, as_org: g.org, method: 'geoip', provider: g.source, precision: state ? 'state' : cc ? 'country' : 'unknown',
    };
}

type Lookup = (ip: string) => Promise<{ country_code: string | null; country: string | null; region: string | null; city: string | null; asn: string | null; org: string | null; source: string }>;

/** Locates up to `budget` active IP indicators that have no location yet. Returns how many were stored. */
export async function locateIndicators(budget = Number(process.env.TI_GEO_BATCH) || 100, lookup: Lookup = enrichIP): Promise<{ located: number; source_stated: number; geoip: number }> {
    const supabase = getSupabase();
    const out = { located: 0, source_stated: 0, geoip: 0 };
    if (!supabase) return out;
    const { data: ips } = await supabase.from('ti_indicators').select('id, value').eq('type', 'ip').eq('status', 'active').order('last_seen', { ascending: false }).limit(2000);
    const ids = (ips ?? []).map((i) => i.id as string);
    const known = new Set<string>();
    for (let i = 0; i < ids.length; i += 200) {
        const { data } = await supabase.from('ti_indicator_geo').select('indicator_id').in('indicator_id', ids.slice(i, i + 200));
        for (const r of data ?? []) known.add(r.indicator_id as string);
    }
    const todo = (ips ?? []).filter((i) => !known.has(i.id as string)).slice(0, Math.max(0, budget));
    for (const ind of todo) {
        const { data: srcs } = await supabase.from('ti_indicator_sources').select('feed_id, context').eq('indicator_id', ind.id).limit(10);
        let row: GeoRow | null = null;
        for (const s of srcs ?? []) { row = geoFromSource(ind.id as string, s.feed_id as string, s.context as Record<string, unknown>); if (row) break; }
        if (!row) {
            try { row = geoFromLookup(ind.id as string, await lookup(ind.value as string)); } catch { continue; }
        }
        const { error } = await supabase.from('ti_indicator_geo').upsert({ ...row, looked_up_at: new Date().toISOString() }, { onConflict: 'indicator_id' });
        if (error) throw new Error(`location write failed: ${error.message}`);
        out.located++;
        if (row.method === 'source_stated') out.source_stated++; else out.geoip++;
    }
    return out;
}
