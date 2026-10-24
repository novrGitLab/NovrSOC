// Nigeria Threat Map data (phase P25). Three layers, each saying exactly what it is:
//
//   targeting   source reports that explicitly tag Nigeria as a target (MISP target-information
//               galaxy), and Nigerian advisories (labelled advisories, not incidents). Location is
//               the country: no source states a state, so none is placed on one.
//   hosted      indicator infrastructure hosted in Nigeria (services/tiGeo.ts): placed on a state
//               only when the location provider named one (precision 'state'); otherwise listed
//               as "state unknown". Hosting is never an attack origin or target.
//   exposure    this organisation's matches whose indicator is hosted in Nigeria.
//
// No attack counts, no coordinates, nothing inferred from GeoIP beyond hosting. The platform
// records no "confirmed incident" verdict on cases, so no case is shown as a confirmed attack.
// Demo rows from the retired seeder (tag demo-data) are excluded.

import { getSupabase } from './geoEnrichment';
import { NIGERIA_STATES } from './tiGeo';
import { TLP_ORDER, isTlp, type Tlp } from './tiPolicy';

export interface MapQuery { org: string; days: number; sector: string | null; viewerCeiling: Tlp }

const visibleTo = (tlp: unknown, ceiling: Tlp) => TLP_ORDER.indexOf(isTlp(tlp) ? tlp : 'amber') <= TLP_ORDER.indexOf(ceiling);
const sectorOfTags = (tags: string[] | null) => (tags ?? []).filter((t) => t.startsWith('sector:')).map((t) => t.slice(7));

export async function nigeriaMap(q: MapQuery) {
    const supabase = getSupabase()!;
    const until = new Date();
    const since = new Date(until.getTime() - q.days * 86_400_000);
    const sector = q.sector?.toLowerCase() ?? null;
    const sectorMatch = (xs: string[]) => !sector || xs.some((s) => s.toLowerCase().includes(sector));

    const [reports, advisories, geo] = await Promise.all([
        supabase.from('ti_reports').select('id, feed_id, source_ref, title, published_at, tlp, threat_level, target_sectors, actors, malware, attack_patterns').contains('target_countries', ['NG']).gte('published_at', since.toISOString()).order('published_at', { ascending: false }).limit(500),
        supabase.from('nigeria_advisories').select('advisory_id, source, title, severity, threat_type, tags, source_url, published_at').gte('published_at', since.toISOString()).order('published_at', { ascending: false }).limit(300),
        supabase.from('ti_indicator_geo').select('indicator_id, region, city, precision, method, provider, asn, as_org').eq('country_code', 'NG').limit(10000),
    ]);
    const reportsMissing = !!reports.error && /ti_reports/.test(reports.error.message);

    let withheld = 0;
    const targeting = [
        ...(reports.data ?? []).filter((r) => { const ok = visibleTo(r.tlp, q.viewerCeiling); if (!ok) withheld++; return ok; }).filter((r) => sectorMatch(r.target_sectors ?? [])).map((r) => ({
            id: r.id as string, kind: 'source_report' as const, title: r.title as string, source: r.feed_id === 'misp_events' ? 'MISP' : (r.feed_id as string), source_ref: r.source_ref as string,
            published_at: r.published_at as string | null, tlp: r.tlp as Tlp, sectors: (r.target_sectors ?? []) as string[], actors: (r.actors ?? []) as string[], malware: (r.malware ?? []) as string[],
            attribution: (r.actors ?? []).length ? 'named by the source' : 'none stated', basis: 'The source tagged Nigeria as a target.', location: { precision: 'country' as const, state: null }, url: null,
        })),
        ...(advisories.data ?? []).filter((a) => !(a.tags ?? []).includes('demo-data')).filter((a) => sectorMatch(sectorOfTags(a.tags))).map((a) => ({
            id: a.advisory_id as string, kind: 'advisory' as const, title: a.title as string, source: a.source as string, source_ref: a.advisory_id as string,
            published_at: a.published_at as string | null, tlp: 'clear' as Tlp, sectors: sectorOfTags(a.tags), actors: [] as string[], malware: [] as string[],
            attribution: 'none stated', basis: 'A published Nigerian advisory. Not a confirmed incident.', location: { precision: 'country' as const, state: null }, url: (a.source_url as string | null) ?? null,
        })),
    ].sort((a, b) => Date.parse(b.published_at ?? '') - Date.parse(a.published_at ?? ''));

    // Hosted infrastructure: active indicators only, seen within the period.
    const geoRows = geo.data ?? [];
    const ids = geoRows.map((g) => g.indicator_id as string);
    const active = new Map<string, { id: string; type: string; value: string; last_seen: string; malware_families: string[] }>();
    for (let i = 0; i < ids.length; i += 300) {
        const { data } = await supabase.from('ti_indicators').select('id, type, value, last_seen, malware_families').in('id', ids.slice(i, i + 300)).eq('status', 'active').gte('last_seen', since.toISOString());
        for (const d of data ?? []) active.set(d.id as string, d as never);
    }
    const hosted = geoRows.filter((g) => active.has(g.indicator_id as string)).map((g) => {
        const ind = active.get(g.indicator_id as string)!;
        return {
            indicator_id: ind.id, type: ind.type, value: ind.value, last_seen: ind.last_seen, malware: ind.malware_families ?? [],
            state: g.precision === 'state' ? (g.region as string) : null, precision: g.precision as 'state' | 'country', method: g.method as string, provider: g.provider as string,
            asn: (g.asn as string | null) ?? null, as_org: (g.as_org as string | null) ?? null,
        };
    });

    // Exposure: this organisation's matches on Nigeria-hosted indicators.
    const hostedIds = hosted.map((h) => h.indicator_id);
    const exposure: { match_id: string; indicator_id: string; value: string; entity_type: string; matched_field: string; status: string; first_matched_at: string; state: string | null; precision: string }[] = [];
    for (let i = 0; i < hostedIds.length; i += 300) {
        const { data } = await supabase.from('ti_matches').select('id, indicator_id, entity_type, matched_field, status, first_matched_at').eq('org_id', q.org).in('indicator_id', hostedIds.slice(i, i + 300)).limit(1000);
        for (const m of data ?? []) {
            const h = hosted.find((x) => x.indicator_id === m.indicator_id)!;
            exposure.push({ match_id: m.id as string, indicator_id: h.indicator_id, value: h.value, entity_type: m.entity_type as string, matched_field: m.matched_field as string, status: m.status as string, first_matched_at: m.first_matched_at as string, state: h.state, precision: h.precision });
        }
    }

    const states = NIGERIA_STATES.map((s) => ({
        state: s,
        hosted: hosted.filter((h) => h.state === s).length,
        exposure: exposure.filter((e) => e.state === s).length,
    }));
    const sectors = [...new Set(targeting.flatMap((t) => t.sectors))].sort();
    return {
        period: { from: since.toISOString(), to: until.toISOString(), days: q.days },
        states,
        country_level: { targeting: targeting.length, hosted_state_unknown: hosted.filter((h) => !h.state).length, exposure_state_unknown: exposure.filter((e) => !e.state).length },
        targeting, hosted: hosted.slice(0, 1000), exposure, sectors,
        withheld_reports: withheld,
        setup: { reports_table: !reportsMissing },
        limitations: [
            'Targeting comes only from sources that explicitly tag Nigeria as a target; no source states a state, so targeting is shown for the country, not on a state.',
            'Hosting location is where an address is hosted (GeoIP or the feed\'s statement). It is not where an attack came from or what it targeted.',
            'An indicator is placed on a state only when the location provider named one; the rest are listed as "state unknown".',
            ...(withheld ? [`${withheld} source report(s) are hidden because of their sharing marking.`] : []),
        ],
    };
}
