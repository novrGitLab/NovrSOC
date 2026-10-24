// Source reports (phase P25): MISP events as the source described them. A report is the source's
// claim — its title, its date, and the galaxy and taxonomy tags it attached — never the
// platform's own assessment. Targeting is recorded only from explicit target tags
// (misp-galaxy:target-information), never inferred from where an indicator is hosted; actors and
// malware only from the galaxy clusters the source attached.
//
// Feed: misp_events — events changed in the last 30 days, metadata only (no attributes), up to
// 5 pages of 200. NovrSOC's own collection event (MISP_NIGERIA_EVENT_ID) is left out, like the
// attribute feed. Each report keeps the event's TLP (AMBER when untagged) and distribution.

import { getSupabase } from './geoEnrichment';
import { isMISPConfigured, mispEventSearch } from './misp';
import { tlpFromTags, type Tlp } from './tiPolicy';

export interface ReportRecord {
    source_ref: string; title: string; published_at: string | null; source_updated_at: string | null;
    tlp: Tlp; distribution: number | null; threat_level: string | null; tags: string[];
    target_countries: string[]; target_sectors: string[]; actors: string[]; malware: string[]; attack_patterns: string[];
    attribute_count: number | null;
}

// ISO 3166-1 alpha-2 codes by English name, from the runtime's own ICU data.
const COUNTRY_CODE: Map<string, string> = (() => {
    const out = new Map<string, string>();
    const names = new Intl.DisplayNames(['en'], { type: 'region' });
    for (let a = 65; a <= 90; a++) for (let b = 65; b <= 90; b++) {
        const code = String.fromCharCode(a, b);
        let name: string | undefined;
        try { name = names.of(code); } catch { continue; }
        if (name && name !== code) out.set(name.toLowerCase(), code);
    }
    out.set('ivory coast', 'CI'); out.set('cote d\'ivoire', 'CI'); out.set('democratic republic of the congo', 'CD');
    return out;
})();

/** ISO alpha-2 for a country as a source writes it ("Nigeria", "NG", "nigeria"); null if unknown. */
export function countryCode(v: string): string | null {
    const s = v.trim();
    if (/^[A-Za-z]{2}$/.test(s)) { const c = s.toUpperCase(); return [...COUNTRY_CODE.values()].includes(c) ? c : null; }
    return COUNTRY_CODE.get(s.toLowerCase()) ?? null;
}

const GALAXY = /^misp-galaxy:([a-z0-9-]+)="(.+)"$/i;
const TECHNIQUE = /\bT\d{4}(?:\.\d{3})?\b/;
const THREAT_LEVEL: Record<string, string> = { '1': 'high', '2': 'medium', '3': 'low', '4': 'undefined' };
const MALWARE_GALAXIES = new Set(['malpedia', 'tool', 'ransomware', 'rat', 'banker', 'botnet', 'stealer', 'backdoor', 'exploit-kit', 'android', 'mitre-malware', 'mitre-tool']);
const ACTOR_GALAXIES = new Set(['threat-actor', 'mitre-intrusion-set', 'microsoft-activity-group']);
const uniq = (xs: string[], n = 30) => [...new Set(xs.filter(Boolean))].slice(0, n);
const toIso = (v: unknown, epochSeconds = false): string | null => {
    if (v === null || v === undefined || v === '') return null;
    const t = epochSeconds ? Number(v) * 1000 : Date.parse(String(v));
    return Number.isFinite(t) && t > 0 ? new Date(t).toISOString() : null;
};

/** What a set of event tags says, by kind. Values are the source's wording, trimmed. */
export function classifyTags(tags: string[]): Pick<ReportRecord, 'target_countries' | 'target_sectors' | 'actors' | 'malware' | 'attack_patterns'> {
    const countries: string[] = [], sectors: string[] = [], actors: string[] = [], malware: string[] = [], patterns: string[] = [];
    for (const t of tags) {
        const m = GALAXY.exec(t.trim());
        if (!m) continue;
        const galaxy = m[1].toLowerCase();
        const value = m[2].trim().slice(0, 120);
        if (galaxy === 'target-information') { const c = countryCode(value); if (c) countries.push(c); }
        else if (galaxy === 'sector') sectors.push(value);
        else if (ACTOR_GALAXIES.has(galaxy)) actors.push(value.replace(/\s+-\s+G\d{4}$/, ''));
        else if (MALWARE_GALAXIES.has(galaxy)) malware.push(value.replace(/\s+-\s+S\d{4}$/, ''));
        else if (galaxy === 'mitre-attack-pattern' || galaxy === 'mitre-enterprise-attack-attack-pattern') { const id = TECHNIQUE.exec(value)?.[0]; if (id) patterns.push(id); }
    }
    return { target_countries: uniq(countries), target_sectors: uniq(sectors), actors: uniq(actors), malware: uniq(malware), attack_patterns: uniq(patterns, 60) };
}

/** MISP events/restSearch (metadata) → reports. `excludeEvent` is the event NovrSOC writes to. */
export function fromMispEvents(json: unknown, excludeEvent: string | null): ReportRecord[] {
    const rows = (json as { response?: unknown })?.response;
    if (!Array.isArray(rows)) throw new Error('MISP: unexpected response');
    return (rows as Record<string, unknown>[]).map((r) => (r.Event ?? r) as Record<string, unknown>)
        .filter((e) => !excludeEvent || String(e.id) !== excludeEvent)
        .map((e) => {
            const eventTags = Array.isArray(e.Tag) ? (e.Tag as { name?: string }[]).map((t) => String(t.name ?? '')) : [];
            const galaxyTags = Array.isArray(e.Galaxy) ? (e.Galaxy as { GalaxyCluster?: { tag_name?: string }[] }[]).flatMap((g) => (g.GalaxyCluster ?? []).map((c) => String(c.tag_name ?? ''))) : [];
            const tags = uniq([...eventTags, ...galaxyTags].map((t) => t.slice(0, 160)), 80);
            const dist = e.distribution === undefined || e.distribution === null || e.distribution === '' ? null : Number(e.distribution);
            return {
                source_ref: String(e.uuid ?? ''), title: String(e.info ?? '').slice(0, 300),
                published_at: toIso(e.date), source_updated_at: toIso(e.timestamp, true),
                tlp: tlpFromTags(tags, 'amber'), distribution: Number.isNaN(dist) ? null : dist,
                threat_level: THREAT_LEVEL[String(e.threat_level_id)] ?? null, tags,
                ...classifyTags(tags),
                attribute_count: e.attribute_count === undefined ? null : Number(e.attribute_count) || 0,
            };
        });
}

export const REPORT_FEEDS: Record<string, { fetch: () => Promise<ReportRecord[]> }> = {
    misp_events: { fetch: async () => {
        if (!isMISPConfigured()) throw new Error('MISP is not configured (MISP_URL, MISP_API_KEY)');
        const exclude = (process.env.MISP_NIGERIA_EVENT_ID || '1').trim() || null;
        const out: ReportRecord[] = [];
        for (let page = 1; page <= 5; page++) {
            const json = await mispEventSearch({ returnFormat: 'json', last: '30d', metadata: true, limit: 200, page });
            const batch = fromMispEvents(json, exclude);
            out.push(...batch);
            if (((json as { response?: unknown[] }).response ?? []).length < 200) break;
        }
        return out;
    } },
};

/** Stores reports, one row per source event; re-running updates in place. Counts like feeds. */
export async function storeReports(feedId: string, reports: ReportRecord[]): Promise<{ fetched: number; new: number; updated: number; duplicates: number; invalid: number }> {
    const supabase = getSupabase()!;
    const counts = { fetched: reports.length, new: 0, updated: 0, duplicates: 0, invalid: 0 };
    const seen = new Set<string>();
    for (const r of reports) {
        if (!r.source_ref || !r.title) { counts.invalid++; continue; }
        if (seen.has(r.source_ref)) { counts.duplicates++; continue; }
        seen.add(r.source_ref);
        const { data: had, error: readErr } = await supabase.from('ti_reports').select('id').eq('feed_id', feedId).eq('source_ref', r.source_ref).maybeSingle();
        if (readErr) throw new Error(`report read failed: ${readErr.message}`);
        const { error } = await supabase.from('ti_reports').upsert({ feed_id: feedId, ...r, updated_at: new Date().toISOString() }, { onConflict: 'feed_id,source_ref' });
        if (error) throw new Error(`report write failed: ${error.message}`);
        if (had) counts.updated++; else counts.new++;
    }
    return counts;
}
