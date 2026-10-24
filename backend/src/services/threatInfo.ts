// Threat Information System (phase P6): feed ingestion, normalisation, provenance, expiry and
// correlation with an organisation's records.
//
// Feeds (real, authoritative, nothing invented):
//   threatfox  abuse.ch ThreatFox — IOCs of the last day (needs THREATFOX_API_KEY, abuse.ch Auth-Key)
//   urlhaus    abuse.ch URLhaus — recent malware distribution URLs (same key)
//   feodo      abuse.ch Feodo Tracker — botnet C2 IP blocklist (public)
//   cisa_kev   CISA Known Exploited Vulnerabilities catalogue (public), also feeding cve_intel
//   misp       this platform's own MISP: to_ids attributes of the last day (phase P9; needs MISP_URL
//              + MISP_API_KEY, a read-only key is enough). The event NovrSOC itself writes to
//              (MISP_NIGERIA_EVENT_ID) is left out, so the platform does not read its own
//              collection back as a second source. Each record keeps the TLP and distribution MISP
//              gave it (phase P25); an untagged record is AMBER, so it is never shared by accident.
//   misp_events  MISP event reports (services/tiReports.ts, phase P25): titles and the galaxy and
//              taxonomy tags the source attached — targeted countries and sectors, actors, malware.
//   opencti    retired in P25 (OpenCTI is no longer used). Its stored provenance is kept; the feed
//              is never configured and never runs.
// A feed whose connector is not configured is not run and shows as "not configured", not failing.
// Public feeds are TLP:CLEAR (services/tiPolicy.ts decides what may be exported).
// Each source record is kept as provenance (ti_indicator_sources) with exactly what that source
// said: its own confidence (or none), its malware/threat labels, reporter and reference. An
// indicator's ATT&CK techniques are only ids a source itself listed. Nothing is attributed to a
// threat actor here: these feeds do not attribute, so neither does the platform.
// Failures are surfaced: a run that cannot fetch or parse its feed is recorded as failed with the
// reason, and the feed's health shows it.

import { isIP } from 'net';
import { getSupabase } from './geoEnrichment';
import { parseKev, KEV_URL, CVE_RE } from './cveIntel';
import { isMISPConfigured, mispAttributeSearch } from './misp';
import { tlpFromTags, type Tlp } from './tiPolicy';
import { REPORT_FEEDS, storeReports } from './tiReports';

export type IndicatorType = 'ip' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256' | 'cve';
export interface SourceRecord {
    type: IndicatorType; value: string; source_ref: string; confidence: number | null; first_seen: string | null; last_seen: string | null;
    tags: string[]; malware: string | null; threat_type: string | null; context: Record<string, unknown>;
    /** The marking the source applied; absent = the feed's default (FEED_DEFAULT_TLP, else AMBER). */
    tlp?: Tlp;
    /** MISP distribution level, when the source has one. */
    distribution?: number | null;
}

/** Public feeds publish openly; anything else without a marking is treated as AMBER. */
export const FEED_DEFAULT_TLP: Record<string, Tlp> = { threatfox: 'clear', urlhaus: 'clear', feodo: 'clear', cisa_kev: 'clear' };
const tlpOf = (feedId: string, r: SourceRecord): Tlp => r.tlp ?? FEED_DEFAULT_TLP[feedId] ?? 'amber';

const HEX = { md5: /^[a-f0-9]{32}$/, sha1: /^[a-f0-9]{40}$/, sha256: /^[a-f0-9]{64}$/ } as const;
const DOMAIN = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const TECHNIQUE = /^T\d{4}(\.\d{3})?$/;

/** The canonical form of an indicator, or null when the value isn't a valid indicator of that type. */
export function normalizeIndicator(type: IndicatorType, raw: string): string | null {
    const v = (raw ?? '').trim();
    if (!v || v.length > 2048) return null;
    switch (type) {
        case 'ip': return isIP(v) ? v.toLowerCase() : null;
        case 'domain': { const d = v.toLowerCase().replace(/\.$/, ''); return DOMAIN.test(d) ? d : null; }
        case 'url': return /^(https?|ftp):\/\/[^\s]+$/i.test(v) ? v : null;
        case 'cve': { const c = v.toUpperCase(); return CVE_RE.test(c) ? c : null; }
        default: { const h = v.toLowerCase(); return HEX[type].test(h) ? h : null; }
    }
}
const toIso = (v: unknown): string | null => {
    if (typeof v !== 'string' || !v.trim()) return null;
    const t = Date.parse(v.includes('T') || v.endsWith('Z') ? v : `${v.replace(' UTC', '').replace(' ', 'T')}Z`);
    return Number.isNaN(t) ? null : new Date(t).toISOString();
};
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string').map((x) => x.slice(0, 80)).slice(0, 30) : []);

// ── Adapters: each turns one feed's response into SourceRecords, or throws with the reason ────
export function fromThreatFox(json: unknown): SourceRecord[] {
    const j = json as { query_status?: string; data?: unknown };
    if (j?.query_status === 'no_result') return [];
    if (j?.query_status !== 'ok' || !Array.isArray(j.data)) throw new Error(`ThreatFox: ${j?.query_status ?? 'unexpected response'}`);
    const map: Record<string, IndicatorType> = { 'ip:port': 'ip', domain: 'domain', url: 'url', md5_hash: 'md5', sha1_hash: 'sha1', sha256_hash: 'sha256' };
    return (j.data as Record<string, unknown>[]).map((d) => {
        const type = map[String(d.ioc_type)];
        const value = type === 'ip' ? String(d.ioc ?? '').replace(/:\d+$/, '') : String(d.ioc ?? '');
        const tags = strs(d.tags);
        const conf = typeof d.confidence_level === 'number' && d.confidence_level >= 0 && d.confidence_level <= 100 ? d.confidence_level : null;
        return {
            type, value, source_ref: String(d.id ?? ''), confidence: conf, first_seen: toIso(d.first_seen), last_seen: toIso(d.last_seen) ?? toIso(d.first_seen),
            tags, malware: typeof d.malware_printable === 'string' ? d.malware_printable.slice(0, 120) : null, threat_type: typeof d.threat_type === 'string' ? d.threat_type.slice(0, 60) : null,
            context: { reporter: d.reporter ?? null, reference: d.reference ?? null, malware_alias: d.malware_alias ?? null, malpedia: d.malware_malpedia ?? null, port: type === 'ip' ? String(d.ioc ?? '').split(':')[1] ?? null : null, techniques: tags.filter((t) => TECHNIQUE.test(t)) },
        } as SourceRecord;
    }).filter((r) => r.type);
}

export function fromUrlhaus(json: unknown): SourceRecord[] {
    const j = json as { query_status?: string; urls?: unknown };
    if (j?.query_status === 'no_results') return [];
    if (j?.query_status !== 'ok' || !Array.isArray(j.urls)) throw new Error(`URLhaus: ${j?.query_status ?? 'unexpected response'}`);
    return (j.urls as Record<string, unknown>[]).map((u) => ({
        type: 'url' as const, value: String(u.url ?? ''), source_ref: String(u.id ?? ''), confidence: null, first_seen: toIso(u.date_added), last_seen: toIso(u.date_added),
        tags: strs(u.tags), malware: null, threat_type: typeof u.threat === 'string' ? u.threat.slice(0, 60) : null,
        context: { url_status: u.url_status ?? null, host: u.host ?? null, reporter: u.reporter ?? null, reference: u.urlhaus_reference ?? null },
    }));
}

export function fromFeodo(json: unknown): SourceRecord[] {
    if (!Array.isArray(json)) throw new Error('Feodo Tracker: unexpected response');
    return (json as Record<string, unknown>[]).map((e) => ({
        type: 'ip' as const, value: String(e.ip_address ?? ''), source_ref: `${e.ip_address}:${e.port}`, confidence: null,
        first_seen: toIso(e.first_seen), last_seen: toIso(e.last_online) ?? toIso(e.first_seen), tags: [], malware: typeof e.malware === 'string' ? e.malware.slice(0, 120) : null,
        threat_type: 'botnet_cc', context: { port: e.port ?? null, status: e.status ?? null, as_name: e.as_name ?? null, country: e.country ?? null },
    }));
}

export function fromKev(json: unknown): SourceRecord[] {
    const kev = parseKev(json);
    const items = (json as { vulnerabilities: Record<string, unknown>[] }).vulnerabilities;
    const byId = new Map(items.map((v) => [String(v.cveID), v]));
    return [...kev.entries()].map(([cve, k]) => {
        const v = byId.get(cve) ?? {};
        return {
            type: 'cve' as const, value: cve, source_ref: cve, confidence: null, first_seen: k.date_added ? `${k.date_added}T00:00:00.000Z` : null, last_seen: k.date_added ? `${k.date_added}T00:00:00.000Z` : null,
            tags: [], malware: null, threat_type: 'known_exploited_vulnerability',
            context: { vendor: v.vendorProject ?? null, product: v.product ?? null, name: v.vulnerabilityName ?? null, required_action: k.required_action, due_date: k.due_date, ransomware: k.ransomware },
        };
    });
}

// ── STIX patterns, OpenCTI (retired in P25) and MISP (phase P9) ──────────────────────────────
// Only single-comparison STIX patterns are indicators here; anything else is counted invalid.
// fromOpenCti is kept as a parser for stored OpenCTI exports; the OpenCTI feed no longer runs.
const STIX = /^\[\s*(ipv4-addr|ipv6-addr|domain-name|url|file)\s*:\s*(value|hashes\s*\.\s*'?(MD5|SHA-1|SHA1|SHA-256|SHA256)'?)\s*=\s*'((?:[^'\\]|\\.)*)'\s*\]$/i;
export function stixToIndicator(pattern: string | null | undefined): { type: IndicatorType; value: string } | null {
    const m = STIX.exec((pattern ?? '').trim());
    if (!m) return null;
    const obj = m[1].toLowerCase();
    const value = m[4].replace(/\\(.)/g, '$1');
    if (obj === 'ipv4-addr' || obj === 'ipv6-addr') return m[2].toLowerCase() === 'value' ? { type: 'ip', value: value.replace(/\/(32|128)$/, '') } : null;
    if (obj === 'domain-name') return m[2].toLowerCase() === 'value' ? { type: 'domain', value } : null;
    if (obj === 'url') return m[2].toLowerCase() === 'value' ? { type: 'url', value } : null;
    const h = (m[3] ?? '').toUpperCase().replace('-', '');
    return h === 'MD5' ? { type: 'md5', value } : h === 'SHA1' ? { type: 'sha1', value } : h === 'SHA256' ? { type: 'sha256', value } : null;
}

interface OctiIndicator {
    id: string; standard_id?: string; name?: string; pattern?: string; pattern_type?: string; confidence?: number | null; revoked?: boolean;
    valid_from?: string | null; valid_until?: string | null; created?: string | null; updated_at?: string | null; x_opencti_score?: number | null;
    indicator_types?: string[] | null; createdBy?: { name?: string } | null; objectLabel?: { value?: string }[] | { edges?: { node: { value?: string } }[] } | null;
    killChainPhases?: { kill_chain_name?: string; phase_name?: string }[] | null;
}
const labelsOf = (l: OctiIndicator['objectLabel']): string[] => (Array.isArray(l) ? l.map((x) => x.value) : (l?.edges ?? []).map((e) => e.node.value)).filter((x): x is string => typeof x === 'string').map((x) => x.slice(0, 80)).slice(0, 30);

/** OpenCTI indicators → records. Revoked ones are left out; complex patterns count as invalid. */
export function fromOpenCti(json: unknown): SourceRecord[] {
    const edges = (json as { indicators?: { edges?: { node: OctiIndicator }[] } })?.indicators?.edges;
    if (!Array.isArray(edges)) throw new Error('OpenCTI: unexpected response');
    return edges.map((e) => e.node).filter((n) => !n.revoked).map((n) => {
        const ind = n.pattern_type === 'stix' ? stixToIndicator(n.pattern) : null;
        const labels = labelsOf(n.objectLabel);
        const conf = typeof n.confidence === 'number' && n.confidence >= 0 && n.confidence <= 100 ? n.confidence : null;
        return {
            type: ind?.type as IndicatorType, value: ind?.value ?? '', source_ref: n.standard_id ?? n.id, confidence: conf,
            first_seen: toIso(n.valid_from ?? n.created ?? undefined), last_seen: toIso(n.updated_at ?? undefined) ?? toIso(n.valid_from ?? undefined),
            tags: labels, malware: null, threat_type: n.indicator_types?.[0]?.slice(0, 60) ?? null,
            context: {
                name: n.name ?? null, author: n.createdBy?.name ?? null, opencti_score: n.x_opencti_score ?? null, valid_until: n.valid_until ?? null,
                indicator_types: n.indicator_types ?? [], opencti_id: n.id,
                techniques: [...labels, ...(n.killChainPhases ?? []).map((k) => String(k.phase_name ?? ''))].filter((t) => TECHNIQUE.test(t)),
            },
        };
    });
}

const MISP_TYPES: Record<string, IndicatorType> = {
    'ip-src': 'ip', 'ip-dst': 'ip', 'ip-src|port': 'ip', 'ip-dst|port': 'ip', domain: 'domain', hostname: 'domain', url: 'url',
    md5: 'md5', sha1: 'sha1', sha256: 'sha256', vulnerability: 'cve',
};
export const MISP_FEED_TYPES = Object.keys(MISP_TYPES);

/**
 * MISP distribution of an attribute: its own level, or its event's when it inherits (5). An
 * unresolved inherit stays 5, which the sharing policy never exports.
 */
export function mispDistribution(attr: unknown, event: unknown): number | null {
    const num = (v: unknown) => (v === null || v === undefined || v === '' || Number.isNaN(Number(v)) ? null : Number(v));
    const own = num((attr as Record<string, unknown>)?.distribution);
    if (own !== 5) return own;
    const ev = num((event as Record<string, unknown>)?.distribution);
    return ev ?? 5;
}

/** MISP restSearch attributes → records. `excludeEvent` is the event NovrSOC itself writes to. */
export function fromMisp(json: unknown, excludeEvent: string | null): SourceRecord[] {
    const attrs = (json as { response?: { Attribute?: unknown } })?.response?.Attribute;
    if (!Array.isArray(attrs)) throw new Error('MISP: unexpected response');
    return (attrs as Record<string, unknown>[]).filter((a) => !excludeEvent || String(a.event_id) !== excludeEvent).map((a) => {
        const type = MISP_TYPES[String(a.type)];
        const raw = String(a.value ?? '');
        const value = String(a.type).endsWith('|port') ? raw.split('|')[0] : raw;
        const ts = typeof a.timestamp === 'string' || typeof a.timestamp === 'number' ? new Date(Number(a.timestamp) * 1000).toISOString() : null;
        const ev = (a.Event ?? {}) as Record<string, unknown>;
        // With includeEventTags the attribute's Tag list also carries its event's tags (TLP is
        // usually set on the event).
        const tags = Array.isArray(a.Tag) ? (a.Tag as { name?: string }[]).map((t) => String(t.name ?? '').slice(0, 80)).filter(Boolean).slice(0, 30) : [];
        return {
            type, value, source_ref: String(a.uuid ?? a.id ?? ''), confidence: null, first_seen: ts, last_seen: ts,
            tags, malware: null, threat_type: typeof a.category === 'string' ? a.category.slice(0, 60) : null,
            tlp: tlpFromTags(tags, 'amber'), distribution: mispDistribution(a, ev),
            context: { event_id: a.event_id ?? null, event_uuid: typeof ev.uuid === 'string' ? ev.uuid : null, event_info: typeof ev.info === 'string' ? ev.info.slice(0, 200) : null, comment: typeof a.comment === 'string' ? a.comment.slice(0, 300) : null, techniques: tags.map((t) => /T\d{4}(\.\d{3})?/.exec(t)?.[0]).filter((t): t is string => !!t) },
        } as SourceRecord;
    });
}

/** Feeds retired from the platform: their history is kept, they never run. */
export const RETIRED_FEEDS = new Set(['opencti']);
/** Feeds that need a connector, and whether it is configured. Others are always runnable. */
export const FEED_CONFIGURED: Record<string, () => boolean> = { misp: isMISPConfigured, misp_events: isMISPConfigured };
export const feedConfigured = (id: string) => (RETIRED_FEEDS.has(id) ? false : FEED_CONFIGURED[id] ? FEED_CONFIGURED[id]() : true);

export const FEEDS: Record<string, { fetch: () => Promise<SourceRecord[]> }> = {
    threatfox: { fetch: async () => {
        const key = process.env.THREATFOX_API_KEY?.trim();
        if (!key) throw new Error('THREATFOX_API_KEY is not set (abuse.ch Auth-Key)');
        const r = await fetch('https://threatfox-api.abuse.ch/api/v1/', { method: 'POST', headers: { 'Auth-Key': key, 'Content-Type': 'application/json' }, body: JSON.stringify({ query: 'get_iocs', days: 1 }), signal: AbortSignal.timeout(60_000) });
        if (!r.ok) throw new Error(`ThreatFox: HTTP ${r.status}`);
        return fromThreatFox(await r.json());
    } },
    urlhaus: { fetch: async () => {
        const key = process.env.THREATFOX_API_KEY?.trim();
        if (!key) throw new Error('THREATFOX_API_KEY is not set (abuse.ch Auth-Key, shared by URLhaus)');
        const r = await fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/?limit=1000', { headers: { 'Auth-Key': key }, signal: AbortSignal.timeout(60_000) });
        if (!r.ok) throw new Error(`URLhaus: HTTP ${r.status}`);
        return fromUrlhaus(await r.json());
    } },
    feodo: { fetch: async () => {
        const r = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist.json', { signal: AbortSignal.timeout(60_000) });
        if (!r.ok) throw new Error(`Feodo Tracker: HTTP ${r.status}`);
        return fromFeodo(await r.json());
    } },
    cisa_kev: { fetch: async () => {
        const r = await fetch(KEV_URL, { signal: AbortSignal.timeout(60_000) });
        if (!r.ok) throw new Error(`CISA KEV: HTTP ${r.status}`);
        return fromKev(await r.json());
    } },
    // Event tags are included so the event's TLP marking reaches each attribute.
    misp: { fetch: async () => {
        const json = await mispAttributeSearch({ returnFormat: 'json', to_ids: true, last: '1d', type: MISP_FEED_TYPES, limit: 5000, includeEventTags: true, includeEventUuid: true });
        return fromMisp(json, (process.env.MISP_NIGERIA_EVENT_ID || '1').trim() || null);
    } },
};

/** A feed is stale when it has not succeeded for this long (runs every 6 h; KEV daily). */
export const FEED_STALE_HOURS: Record<string, number> = { threatfox: 12, urlhaus: 12, feodo: 12, cisa_kev: 48, misp: 12, misp_events: 12 };

/** Every feed that can run: indicator feeds and report feeds. */
export const isRunnableFeed = (id: string) => !RETIRED_FEEDS.has(id) && (!!FEEDS[id] || !!REPORT_FEEDS[id]);

export interface RunCounts { fetched: number; new: number; updated: number; duplicates: number; invalid: number }

/** Stores one feed's records: new indicators, refreshed ones, and their provenance. */
export async function storeRecords(feedId: string, records: SourceRecord[], validityDays: number | null): Promise<RunCounts> {
    const supabase = getSupabase()!;
    const counts: RunCounts = { fetched: records.length, new: 0, updated: 0, duplicates: 0, invalid: 0 };
    const seen = new Set<string>();
    const clean: (SourceRecord & { norm: string })[] = [];
    for (const r of records) {
        const norm = r.type ? normalizeIndicator(r.type, r.value) : null;
        if (!norm || !r.source_ref) { counts.invalid++; continue; }
        const k = `${r.type}|${norm}|${r.source_ref}`;
        if (seen.has(k)) { counts.duplicates++; continue; }
        seen.add(k);
        clean.push({ ...r, norm });
    }
    const now = new Date().toISOString();
    for (const type of [...new Set(clean.map((r) => r.type))]) {
        const ofType = clean.filter((r) => r.type === type);
        for (let i = 0; i < ofType.length; i += 200) {
            const chunk = ofType.slice(i, i + 200);
            const { data: existing, error } = await supabase.from('ti_indicators').select('id, value, max_confidence, tags, malware_families, threat_types, mitre_techniques, first_seen, last_seen, valid_until, status').eq('type', type).in('value', [...new Set(chunk.map((c) => c.norm))]);
            if (error) throw new Error(`indicator read failed: ${error.message}`);
            const byValue = new Map((existing ?? []).map((e) => [e.value as string, e]));
            for (const r of chunk) {
                const seenAt = r.last_seen ?? now;
                const validUntil = validityDays ? new Date(Math.max(Date.parse(seenAt), Date.now()) + validityDays * 86_400_000).toISOString() : null;
                const techniques = Array.isArray(r.context.techniques) ? (r.context.techniques as string[]) : [];
                let ind = byValue.get(r.norm);
                if (!ind) {
                    const ins = await supabase.from('ti_indicators').insert({
                        type, value: r.norm, first_seen: r.first_seen ?? now, last_seen: seenAt, valid_until: validUntil, status: 'active', max_confidence: r.confidence,
                        tags: r.tags, malware_families: r.malware ? [r.malware] : [], threat_types: r.threat_type ? [r.threat_type] : [], mitre_techniques: techniques, source_count: 0,
                        created_at: now, updated_at: now,
                    }).select('id, value, max_confidence, tags, malware_families, threat_types, mitre_techniques, first_seen, last_seen, valid_until, status').single();
                    if (ins.error) throw new Error(`indicator insert failed: ${ins.error.message}`);
                    ind = ins.data;
                    byValue.set(r.norm, ind);
                    counts.new++;
                } else {
                    const merge = (a: string[] | null, b: string[]) => [...new Set([...(a ?? []), ...b])].slice(0, 50);
                    const next = {
                        last_seen: Date.parse(seenAt) > Date.parse(ind.last_seen) ? seenAt : ind.last_seen, status: 'active',
                        // the longest validity any source gives (none = no expiry)
                        valid_until: validUntil === null || ind.valid_until === null ? null : (Date.parse(validUntil) > Date.parse(ind.valid_until) ? validUntil : ind.valid_until),
                        max_confidence: r.confidence !== null ? Math.max(r.confidence, ind.max_confidence ?? 0) : ind.max_confidence,
                        tags: merge(ind.tags, r.tags), malware_families: merge(ind.malware_families, r.malware ? [r.malware] : []),
                        threat_types: merge(ind.threat_types, r.threat_type ? [r.threat_type] : []), mitre_techniques: merge(ind.mitre_techniques, techniques),
                    };
                    // updated_at is the exported object's version (STIX modified): it moves only
                    // when what an export carries changes, not on every re-sighting.
                    const changed = exportedChange(ind, next);
                    await supabase.from('ti_indicators').update(changed ? { ...next, updated_at: now } : next).eq('id', ind.id);
                    Object.assign(ind, next);
                    counts.updated++;
                }
                const ref = r.source_ref.slice(0, 200);
                // A source record first seen now is a change to the exported object too.
                const { data: had } = await supabase.from('ti_indicator_sources').select('id').eq('indicator_id', ind!.id).eq('feed_id', feedId).eq('source_ref', ref).maybeSingle();
                const src = await supabase.from('ti_indicator_sources').upsert({
                    indicator_id: ind!.id, feed_id: feedId, source_ref: ref, confidence: r.confidence, first_seen: r.first_seen, last_seen: seenAt,
                    tlp: tlpOf(feedId, r), distribution: r.distribution ?? null,
                    context: { ...r.context, tags: r.tags, malware: r.malware, threat_type: r.threat_type },
                }, { onConflict: 'indicator_id,feed_id,source_ref' });
                if (!had && !src.error) await supabase.from('ti_indicators').update({ updated_at: now }).eq('id', ind!.id);
                if (src.error) throw new Error(`provenance write failed: ${src.error.message}`);
            }
        }
    }
    // Recount sources for touched indicators.
    const touched = [...new Set(clean.map((r) => r.norm))];
    for (let i = 0; i < touched.length; i += 200) {
        const { data: inds } = await supabase.from('ti_indicators').select('id').in('value', touched.slice(i, i + 200));
        for (const ind of inds ?? []) {
            const { count } = await supabase.from('ti_indicator_sources').select('id', { count: 'exact', head: true }).eq('indicator_id', ind.id);
            await supabase.from('ti_indicators').update({ source_count: count ?? 0 }).eq('id', ind.id);
        }
    }
    return counts;
}

const DAY_MS = 86_400_000;
type StoredIndicator = { tags: string[] | null; malware_families: string[] | null; threat_types: string[] | null; mitre_techniques: string[] | null; valid_until: string | null; status?: string };
/** Did a refresh change what an export of this indicator carries? (valid_until counts past a day.) */
export function exportedChange(before: StoredIndicator, after: StoredIndicator): boolean {
    const same = (a: string[] | null, b: string[] | null) => JSON.stringify([...(a ?? [])].sort()) === JSON.stringify([...(b ?? [])].sort());
    if (!same(before.tags, after.tags) || !same(before.malware_families, after.malware_families) || !same(before.threat_types, after.threat_types) || !same(before.mitre_techniques, after.mitre_techniques)) return true;
    if (before.status !== undefined && after.status !== undefined && before.status !== after.status) return true;
    if ((before.valid_until === null) !== (after.valid_until === null)) return true;
    return before.valid_until !== null && after.valid_until !== null && Math.abs(Date.parse(after.valid_until) - Date.parse(before.valid_until)) > DAY_MS;
}

/** Runs one feed end to end and records the outcome (ok or failed with the reason). */
export async function runFeed(feedId: string, fetcher = FEEDS[feedId]?.fetch): Promise<{ status: 'ok' | 'failed'; counts?: RunCounts; error?: string }> {
    const supabase = getSupabase();
    if (!supabase) return { status: 'failed', error: 'database not configured' };
    const { data: feed } = await supabase.from('ti_feeds').select('id, enabled, validity_days').eq('id', feedId).maybeSingle();
    const report = REPORT_FEEDS[feedId];
    if (!feed || RETIRED_FEEDS.has(feedId) || (!fetcher && !report)) return { status: 'failed', error: 'unknown feed' };
    const started = new Date().toISOString();
    const run = await supabase.from('ti_feed_runs').insert({ feed_id: feedId, started_at: started, status: 'running' }).select('id').single();
    try {
        const counts = report && !fetcher ? await storeReports(feedId, await report.fetch()) : await storeRecords(feedId, await fetcher!(), feed.validity_days);
        if (feedId === 'cisa_kev') await syncKevToCveIntel();
        const finished = new Date().toISOString();
        await supabase.from('ti_feed_runs').update({ status: 'ok', finished_at: finished, ...counts }).eq('id', run.data?.id);
        await supabase.from('ti_feeds').update({ last_run_at: finished, last_success_at: finished, last_error: null, last_counts: counts }).eq('id', feedId);
        return { status: 'ok', counts };
    } catch (err) {
        const msg = (err instanceof Error ? err.message : String(err)).slice(0, 500);
        await supabase.from('ti_feed_runs').update({ status: 'failed', finished_at: new Date().toISOString(), error: msg }).eq('id', run.data?.id);
        await supabase.from('ti_feeds').update({ last_run_at: new Date().toISOString(), last_error: msg }).eq('id', feedId);
        return { status: 'failed', error: msg };
    }
}

/** KEV indicators also mark the shared CVE intelligence used by VMS risk scoring. */
async function syncKevToCveIntel(): Promise<void> {
    const supabase = getSupabase()!;
    const { data: tracked } = await supabase.from('cve_intel').select('cve_id').limit(20_000);
    const ids = (tracked ?? []).map((t) => t.cve_id as string);
    for (let i = 0; i < ids.length; i += 200) {
        const { data: kev } = await supabase.from('ti_indicators').select('value').eq('type', 'cve').in('value', ids.slice(i, i + 200));
        const set = new Set((kev ?? []).map((k) => k.value));
        for (const id of ids.slice(i, i + 200)) await supabase.from('cve_intel').update({ kev: set.has(id), kev_checked_at: new Date().toISOString() }).eq('cve_id', id);
    }
}

export async function expireIndicators(): Promise<number> {
    const supabase = getSupabase();
    if (!supabase) return 0;
    const now = new Date().toISOString();
    const { data } = await supabase.from('ti_indicators').update({ status: 'expired', updated_at: now }).eq('status', 'active').lt('valid_until', now).select('id');
    return (data ?? []).length;
}

// ── Correlation ──────────────────────────────────────────────────────────────────────────────
type Candidate = { type: IndicatorType; value: string; entity_type: 'alert' | 'asset' | 'finding' | 'case'; entity_id: string; field: string };

/** Indicator-shaped values in a stored alert (addresses, URLs, queried names, file hashes). */
export function alertCandidates(a: { id: string; agent_ip?: string | null; raw?: unknown; raw_truncated?: boolean | null }): Candidate[] {
    const out: Candidate[] = [];
    const add = (type: IndicatorType, v: unknown, field: string) => {
        const n = typeof v === 'string' ? normalizeIndicator(type, v) : null;
        if (n) out.push({ type, value: n, entity_type: 'alert', entity_id: a.id, field });
    };
    if (a.raw_truncated || !a.raw || typeof a.raw !== 'object') return out;
    const raw = a.raw as Record<string, unknown>;
    const data = (raw.data ?? {}) as Record<string, unknown>;
    const win = ((data.win as Record<string, unknown> | undefined)?.eventdata ?? {}) as Record<string, unknown>;
    const sys = (raw.syscheck ?? {}) as Record<string, unknown>;
    add('ip', data.srcip, 'data.srcip'); add('ip', data.dstip, 'data.dstip');
    add('ip', win.sourceIp, 'sysmon.sourceIp'); add('ip', win.destinationIp, 'sysmon.destinationIp');
    add('url', data.url, 'data.url'); add('domain', win.queryName, 'sysmon.queryName'); add('domain', data.hostname, 'data.hostname');
    add('md5', sys.md5_after, 'syscheck.md5'); add('sha1', sys.sha1_after, 'syscheck.sha1'); add('sha256', sys.sha256_after, 'syscheck.sha256');
    if (typeof win.hashes === 'string') for (const part of win.hashes.split(',')) {
        const [k, v] = part.split('=');
        if (k === 'MD5') add('md5', v, 'sysmon.hashes'); if (k === 'SHA1') add('sha1', v, 'sysmon.hashes'); if (k === 'SHA256') add('sha256', v, 'sysmon.hashes');
    }
    return out;
}

/** Finds active indicators in an organisation's new alerts and its assets, findings and cases. */
export async function correlateOrg(org: string): Promise<{ candidates: number; matches_new: number; matches_seen: number }> {
    const supabase = getSupabase()!;
    const out = { candidates: 0, matches_new: 0, matches_seen: 0 };
    const { data: st } = await supabase.from('ti_correlation_state').select('last_alert_seen').eq('org_id', org).maybeSingle();
    const since = st?.last_alert_seen ?? new Date(Date.now() - 7 * 86_400_000).toISOString();
    const cands: Candidate[] = [];
    const { data: alerts } = await supabase.from('alerts').select('id, agent_ip, raw, raw_truncated, received_at').eq('org_id', org).gt('received_at', since).order('received_at', { ascending: true }).limit(5000);
    for (const a of alerts ?? []) cands.push(...alertCandidates(a));
    const lastAlert = alerts?.length ? alerts[alerts.length - 1].received_at : since;
    const { data: assets } = await supabase.from('vms_assets').select('id, asset_type, value, ips').eq('org_id', org).eq('status', 'active').limit(5000);
    for (const a of assets ?? []) {
        for (const ip of a.ips ?? []) { const n = normalizeIndicator('ip', ip); if (n) cands.push({ type: 'ip', value: n, entity_type: 'asset', entity_id: a.id, field: 'ips' }); }
        if (a.asset_type === 'host' || a.asset_type === 'domain') { const n = normalizeIndicator('domain', a.value); if (n) cands.push({ type: 'domain', value: n, entity_type: 'asset', entity_id: a.id, field: 'hostname' }); }
        if (a.asset_type === 'ip' && !(a.ips ?? []).length) { const n = normalizeIndicator('ip', a.value); if (n) cands.push({ type: 'ip', value: n, entity_type: 'asset', entity_id: a.id, field: 'value' }); }
    }
    const { data: findings } = await supabase.from('vms_findings').select('id, cve_ids').eq('org_id', org).in('status', ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened']).limit(10000);
    for (const f of findings ?? []) for (const c of f.cve_ids ?? []) cands.push({ type: 'cve', value: c, entity_type: 'finding', entity_id: f.id, field: 'cve_ids' });
    const { data: cases } = await supabase.from('cases').select('id, source_ip').eq('org_id', org).neq('status', 'resolved').limit(2000);
    for (const c of cases ?? []) { const n = c.source_ip ? normalizeIndicator('ip', c.source_ip) : null; if (n) cands.push({ type: 'ip', value: n, entity_type: 'case', entity_id: c.id, field: 'source_ip' }); }
    out.candidates = cands.length;

    const now = new Date().toISOString();
    for (const type of [...new Set(cands.map((c) => c.type))]) {
        const values = [...new Set(cands.filter((c) => c.type === type).map((c) => c.value))];
        for (let i = 0; i < values.length; i += 200) {
            const { data: inds } = await supabase.from('ti_indicators').select('id, value').eq('type', type).eq('status', 'active').in('value', values.slice(i, i + 200));
            const byVal = new Map((inds ?? []).map((x) => [x.value as string, x.id as string]));
            for (const c of cands.filter((x) => x.type === type && byVal.has(x.value))) {
                const indicatorId = byVal.get(c.value)!;
                const { data: ex } = await supabase.from('ti_matches').select('id').eq('org_id', org).eq('indicator_id', indicatorId).eq('entity_type', c.entity_type).eq('entity_id', c.entity_id).maybeSingle();
                if (ex) { await supabase.from('ti_matches').update({ last_matched_at: now }).eq('id', ex.id); out.matches_seen++; }
                else { await supabase.from('ti_matches').insert({ org_id: org, indicator_id: indicatorId, entity_type: c.entity_type, entity_id: c.entity_id, matched_field: c.field, matched_value: c.value }); out.matches_new++; }
            }
        }
    }
    await supabase.from('ti_correlation_state').upsert({ org_id: org, last_alert_seen: lastAlert, last_run_at: now, last_result: out }, { onConflict: 'org_id' });
    return out;
}
