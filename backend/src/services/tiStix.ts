// STIX 2.1 objects for the Threat Intelligence exchange (phase P25), built from ti_indicators and
// the source records the sharing policy lets out (services/tiPolicy.ts).
//
//   • Identifiers are deterministic UUIDv5 (indicator over type:value, vulnerability over the
//     CVE id), so a consumer re-importing updates in place instead of accumulating duplicates.
//     Bundles get a random UUIDv4: a bundle is a transient container.
//   • created is when the platform first recorded the indicator; modified moves only when what
//     the object carries changes (threatInfo.ts exportedChange). valid_from is the earliest time a
//     shared source saw it.
//   • Everything in an object — labels, malware names, references, description — comes only from
//     the source records that may be shared at the requested ceiling. An indicator a public feed
//     and a private MISP event both list is exported with the public feed's claims alone.
//   • Markings: the STIX 2.1 predefined TLP marking definitions (spec §7.2.1.4); TLP 2.0 CLEAR is
//     carried as TLP:WHITE, its 1.0 equivalent. The object's marking is the most restrictive
//     among the source records it includes.
//   • No confidence is asserted by the platform: a source's own stated confidence travels in the
//     NovrSOC property extension (source_confidence), attributed to the sources, with the
//     indicator's status and KEV details — STIX 2.1 extensions, not bare custom properties.
//     Organisation data never appears.

import { randomUUID } from 'crypto';
import { uuidv5, STIX_NAMESPACE, buildPattern } from './stix';
import { exportable, mostRestrictive, type ExportCeiling, type Tlp } from './tiPolicy';

export const TLP_MARKINGS: Record<'clear' | 'green' | 'amber' | 'red', { id: string; name: string; tlp: string }> = {
    clear: { id: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9', name: 'TLP:WHITE', tlp: 'white' },
    green: { id: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da', name: 'TLP:GREEN', tlp: 'green' },
    amber: { id: 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82', name: 'TLP:AMBER', tlp: 'amber' },
    red: { id: 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed', name: 'TLP:RED', tlp: 'red' },
};
const MARKING_CREATED = '2017-01-20T00:00:00.000Z';
export function markingDefinition(tlp: keyof typeof TLP_MARKINGS) {
    const m = TLP_MARKINGS[tlp];
    return { type: 'marking-definition', spec_version: '2.1', id: m.id, created: MARKING_CREATED, definition_type: 'tlp', name: m.name, definition: { tlp: m.tlp } };
}
const markingId = (t: Tlp) => TLP_MARKINGS[t === 'clear' || t === 'green' || t === 'amber' ? t : 'red'].id;

// The producer. Fixed timestamps: the object never changes.
const PRODUCER_CREATED = '2026-10-30T00:00:00.000Z';
export const PRODUCER_ID = `identity--${uuidv5('novrsoc-threat-intelligence-producer', STIX_NAMESPACE)}`;
export function producerIdentity() {
    return {
        type: 'identity', spec_version: '2.1', id: PRODUCER_ID, created: PRODUCER_CREATED, modified: PRODUCER_CREATED,
        name: 'NovrSOC Threat Intelligence', identity_class: 'organization',
        description: 'Indicators collected by the NovrSOC platform from public threat feeds and partner sources, with the provenance of each source record.',
        object_marking_refs: [TLP_MARKINGS.clear.id],
    };
}

// The NovrSOC property extension (STIX 2.1 §7.3): one extension-definition object, referenced by
// id from each object that carries NovrSOC properties.
export const EXTENSION_ID = `extension-definition--${uuidv5('novrsoc-ti-property-extension-v1', STIX_NAMESPACE)}`;
export function extensionDefinition() {
    return {
        type: 'extension-definition', spec_version: '2.1', id: EXTENSION_ID, created: PRODUCER_CREATED, modified: PRODUCER_CREATED, created_by_ref: PRODUCER_ID,
        name: 'NovrSOC threat intelligence properties', version: '1.0.0', extension_types: ['property-extension'],
        description: 'Properties NovrSOC adds to the objects it shares.',
        schema: 'status (string): "active" or "expired" in NovrSOC. source_confidence (integer 0-100): the highest confidence a listed source itself stated — the sources\' claim, not NovrSOC\'s. kev (object): CISA KEV due_date and known_ransomware_use, as CISA states them.',
        object_marking_refs: [TLP_MARKINGS.clear.id],
    };
}
const ext = (props: Record<string, unknown>) => ({ extensions: { [EXTENSION_ID]: { extension_type: 'property-extension', ...props } } });

export interface IndicatorRow {
    id: string; type: string; value: string; status: string; valid_until: string | null;
    created_at: string; updated_at: string; first_seen: string;
}
export interface SourceRow {
    feed_id: string; source_ref: string; confidence: number | null; first_seen: string | null; last_seen: string | null;
    tlp: Tlp; distribution: number | null; context: Record<string, unknown> | null;
}

const FEED_LABEL: Record<string, string> = { threatfox: 'ThreatFox (abuse.ch)', urlhaus: 'URLhaus (abuse.ch)', feodo: 'Feodo Tracker (abuse.ch)', cisa_kev: 'CISA KEV', misp: 'MISP (partner sharing)', opencti: 'OpenCTI' };
/** A public link to the source's own record, where the source publishes one. Private sources get none. */
function sourceUrl(s: SourceRow, value: string): string | undefined {
    if (s.feed_id === 'threatfox' && /^\d+$/.test(s.source_ref)) return `https://threatfox.abuse.ch/ioc/${s.source_ref}/`;
    if (s.feed_id === 'urlhaus' && /^\d+$/.test(s.source_ref)) return `https://urlhaus.abuse.ch/url/${s.source_ref}/`;
    if (s.feed_id === 'feodo') return `https://feodotracker.abuse.ch/browse/host/${encodeURIComponent(value)}/`;
    if (s.feed_id === 'cisa_kev') return 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog';
    return undefined;
}

const STIX_TS = (iso: string) => new Date(iso).toISOString();
const label = (s: string) => s.toLowerCase().replace(/[^a-z0-9._:+-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64);
const strArr = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);

export const indicatorStixId = (type: string, value: string) => `indicator--${uuidv5(`${type}:${value}`, STIX_NAMESPACE)}`;
export const malwareStixId = (name: string) => `malware--${uuidv5(`malware:${name.trim().toLowerCase()}`, STIX_NAMESPACE)}`;
export const vulnerabilityStixId = (cve: string) => `vulnerability--${uuidv5(`cve:${cve.toUpperCase()}`, STIX_NAMESPACE)}`;

/** The pattern type stix.ts understands for an indicator type, or null (CVEs are not indicators). */
const patternType = (t: string) => (t === 'ip' || t === 'domain' || t === 'url' ? t : t === 'md5' || t === 'sha1' || t === 'sha256' ? 'hash' : null);

export interface BuiltIndicator { object: Record<string, unknown>; marking: Tlp; malware: string[]; sources: SourceRow[] }

/**
 * The STIX indicator for one stored indicator at a ceiling, or null when no source record may
 * be shared (or no valid pattern exists). `malware` lists the family names the shared sources gave.
 */
export function buildIndicator(ind: IndicatorRow, sources: SourceRow[], ceiling: ExportCeiling): BuiltIndicator | null {
    const pt = patternType(ind.type);
    const pattern = pt ? buildPattern(pt, ind.value) : null;
    if (!pattern) return null;
    const shared = sources.filter((s) => exportable(s, ceiling));
    if (!shared.length) return null;
    const marking = mostRestrictive(shared.map((s) => s.tlp));
    const malware = [...new Set(shared.map((s) => (typeof s.context?.malware === 'string' ? s.context.malware.trim() : '')).filter(Boolean))].slice(0, 10);
    const threatTypes = [...new Set(shared.map((s) => (typeof s.context?.threat_type === 'string' ? s.context.threat_type : '')).filter(Boolean))];
    const labels = [...new Set([...shared.flatMap((s) => strArr(s.context?.tags)), ...threatTypes].map(label).filter(Boolean))].slice(0, 30);
    const created = STIX_TS(ind.created_at);
    const modified = Date.parse(ind.updated_at) >= Date.parse(created) ? STIX_TS(ind.updated_at) : created;
    const seen = shared.map((s) => s.first_seen).filter((x): x is string => !!x).map((x) => Date.parse(x)).filter(Number.isFinite);
    const validFrom = new Date(Math.min(...seen, Date.parse(ind.first_seen), Date.parse(created))).toISOString();
    const validUntil = ind.valid_until && Date.parse(ind.valid_until) > Date.parse(validFrom) ? STIX_TS(ind.valid_until) : undefined;
    const confidences = shared.map((s) => s.confidence).filter((c): c is number => typeof c === 'number');
    const claims = shared.map((s) => {
        const what = [typeof s.context?.threat_type === 'string' ? s.context.threat_type : null, typeof s.context?.malware === 'string' ? `malware ${s.context.malware}` : null].filter(Boolean).join(', ');
        return `${FEED_LABEL[s.feed_id] ?? s.feed_id} record ${s.source_ref}${what ? ` (${what})` : ''}`;
    });
    const object: Record<string, unknown> = {
        type: 'indicator', spec_version: '2.1', id: indicatorStixId(ind.type, ind.value), created, modified, created_by_ref: PRODUCER_ID,
        name: `${ind.type.toUpperCase()} ${ind.value}`.slice(0, 250),
        description: `Listed by ${claims.join('; ')}. These are the sources' own claims; NovrSOC has not independently confirmed them.`.slice(0, 4000),
        indicator_types: ['malicious-activity'],
        pattern, pattern_type: 'stix', pattern_version: '2.1', valid_from: validFrom,
        ...(validUntil ? { valid_until: validUntil } : {}),
        ...(labels.length ? { labels } : {}),
        external_references: shared.slice(0, 20).map((s) => {
            const url = sourceUrl(s, ind.value);
            return { source_name: FEED_LABEL[s.feed_id] ?? s.feed_id, external_id: s.source_ref, ...(url ? { url } : {}) };
        }),
        object_marking_refs: [markingId(marking)],
        ...ext({ status: ind.status === 'expired' ? 'expired' : 'active', ...(confidences.length ? { source_confidence: Math.max(...confidences) } : {}) }),
    };
    return { object, marking, malware, sources: shared };
}

/** The STIX vulnerability for a KEV CVE at a ceiling, or null when no source may be shared. */
export function buildVulnerability(ind: IndicatorRow, sources: SourceRow[], ceiling: ExportCeiling): { object: Record<string, unknown>; marking: Tlp } | null {
    if (ind.type !== 'cve' || !/^CVE-\d{4}-\d{4,}$/.test(ind.value)) return null;
    const shared = sources.filter((s) => exportable(s, ceiling));
    if (!shared.length) return null;
    const marking = mostRestrictive(shared.map((s) => s.tlp));
    const kev = shared.find((s) => s.feed_id === 'cisa_kev')?.context ?? null;
    const created = STIX_TS(ind.created_at);
    const modified = Date.parse(ind.updated_at) >= Date.parse(created) ? STIX_TS(ind.updated_at) : created;
    const text = (k: string) => (typeof kev?.[k] === 'string' ? (kev[k] as string) : null);
    return {
        marking,
        object: {
            type: 'vulnerability', spec_version: '2.1', id: vulnerabilityStixId(ind.value), created, modified, created_by_ref: PRODUCER_ID,
            name: ind.value,
            ...(kev ? { description: [text('name'), text('vendor') && text('product') ? `${text('vendor')} ${text('product')}` : null, text('required_action') ? `CISA required action: ${text('required_action')}` : null].filter(Boolean).join('. ').slice(0, 4000) || undefined } : {}),
            // A CVE id as external_id is reserved for source_name 'cve' (STIX 2.1 §2.5.1).
            external_references: [{ source_name: 'cve', external_id: ind.value }, ...(kev ? [{ source_name: 'CISA KEV', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', description: `Listed in the CISA Known Exploited Vulnerabilities catalogue as ${ind.value}.` }] : [])],
            object_marking_refs: [markingId(marking)],
            ...(kev ? ext({ kev: { due_date: text('due_date'), known_ransomware_use: text('ransomware') } }) : {}),
        },
    };
}

/** malware SDOs and `indicates` relationships for built indicators (bundle export only). */
export function malwareGraph(built: BuiltIndicator[]): Record<string, unknown>[] {
    const malware = new Map<string, { name: string; markings: Tlp[]; created: string }>();
    const rels: Record<string, unknown>[] = [];
    for (const b of built) {
        for (const name of b.malware) {
            const id = malwareStixId(name);
            const m = malware.get(id) ?? { name, markings: [], created: PRODUCER_CREATED };
            m.markings.push(b.marking);
            malware.set(id, m);
            rels.push({
                type: 'relationship', spec_version: '2.1', id: `relationship--${uuidv5(`indicates:${b.object.id}:${id}`, STIX_NAMESPACE)}`,
                created: b.object.created, modified: b.object.modified, created_by_ref: PRODUCER_ID, relationship_type: 'indicates',
                source_ref: b.object.id, target_ref: id, description: 'A source record that lists this indicator names this malware family.',
                object_marking_refs: [markingId(b.marking)],
            });
        }
    }
    const sdos = [...malware.entries()].map(([id, m]) => ({
        type: 'malware', spec_version: '2.1', id, created: m.created, modified: m.created, created_by_ref: PRODUCER_ID,
        name: m.name, is_family: true, object_marking_refs: [markingId(mostRestrictive(m.markings))],
    }));
    return [...sdos, ...rels];
}

/** A complete bundle: producer identity, the marking definitions used, and the objects. */
export function bundle(objects: Record<string, unknown>[]): { type: 'bundle'; id: string; objects: Record<string, unknown>[] } {
    const used = new Set(objects.flatMap((o) => strArr(o.object_marking_refs)));
    used.add(TLP_MARKINGS.clear.id); // the identity's
    const markings = (Object.keys(TLP_MARKINGS) as (keyof typeof TLP_MARKINGS)[]).filter((k) => used.has(TLP_MARKINGS[k].id)).map(markingDefinition);
    const usesExtension = objects.some((o) => !!(o.extensions as Record<string, unknown> | undefined)?.[EXTENSION_ID]);
    return { type: 'bundle', id: `bundle--${randomUUID()}`, objects: [...markings, producerIdentity(), ...(usesExtension ? [extensionDefinition()] : []), ...objects] };
}
