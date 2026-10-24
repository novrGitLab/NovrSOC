// Threat Intelligence sharing policy (phase P25): which source records may leave the platform,
// and under which marking. One rule for every export path (STIX download, TAXII collections).
//
// A source record is exportable at a ceiling (the client's or the request's max TLP) only when
//   • its TLP is at or below the ceiling, and never AMBER+STRICT or RED (those stay in the
//     platform: AMBER+STRICT is limited to the recipient organisation, RED to named people);
//   • its MISP distribution, when it has one, allows re-sharing outside the instance: 2
//     (connected communities) or 3 (all communities). 0 (organisation only), 1 (this community
//     only), 4 (sharing group) and 5 (inherit, unresolved) are never exported.
// An exported object carries only what its exportable source records said, and the most
// restrictive marking among them. An indicator with no exportable source record is not exported
// at all. Organisation data (matches, verdicts, cases) is never part of an export.

export type Tlp = 'clear' | 'green' | 'amber' | 'amber+strict' | 'red';
export type ExportCeiling = 'clear' | 'green' | 'amber';

export const TLP_ORDER: Tlp[] = ['clear', 'green', 'amber', 'amber+strict', 'red'];
const rank = (t: Tlp) => TLP_ORDER.indexOf(t);
export const isTlp = (v: unknown): v is Tlp => typeof v === 'string' && (TLP_ORDER as string[]).includes(v);
export const isCeiling = (v: unknown): v is ExportCeiling => v === 'clear' || v === 'green' || v === 'amber';

/** The TLP named by a tag such as "tlp:amber", "tlp:white" (TLP 1.0) or "tlp:amber+strict"; null if none. */
export function tlpFromTag(tag: string): Tlp | null {
    const m = /^tlp\s*:\s*(clear|white|green|amber\+strict|amber|red)$/i.exec(tag.trim());
    if (!m) return null;
    const v = m[1].toLowerCase();
    return v === 'white' ? 'clear' : (v as Tlp);
}

/**
 * The marking a set of tags carries: the most restrictive TLP tag present. With no TLP tag,
 * `fallback` — AMBER for private sources, so an unmarked record is never shared by accident.
 */
export function tlpFromTags(tags: string[], fallback: Tlp): Tlp {
    const found = tags.map(tlpFromTag).filter((t): t is Tlp => !!t);
    return found.length ? mostRestrictive(found) : fallback;
}

export function mostRestrictive(tlps: Tlp[]): Tlp {
    return tlps.reduce((a, b) => (rank(b) > rank(a) ? b : a), 'clear' as Tlp);
}

/** MISP distribution levels that allow re-sharing outside the instance. */
const SHAREABLE_DISTRIBUTION = new Set([2, 3]);

export interface Marked { tlp: Tlp; distribution: number | null }

export function exportable(r: Marked, ceiling: ExportCeiling): boolean {
    if (r.tlp === 'amber+strict' || r.tlp === 'red') return false;
    if (rank(r.tlp) > rank(ceiling)) return false;
    if (r.distribution !== null && r.distribution !== undefined && !SHAREABLE_DISTRIBUTION.has(r.distribution)) return false;
    return true;
}

/** Why a record is not exportable at this ceiling (for the Sources page and audit), or null. */
export function exportBlockReason(r: Marked, ceiling: ExportCeiling): string | null {
    if (r.tlp === 'amber+strict' || r.tlp === 'red') return `TLP:${r.tlp.toUpperCase()} is never shared outside the platform`;
    if (rank(r.tlp) > rank(ceiling)) return `TLP:${r.tlp.toUpperCase()} is above the TLP:${ceiling.toUpperCase()} ceiling`;
    if (r.distribution !== null && r.distribution !== undefined && !SHAREABLE_DISTRIBUTION.has(r.distribution)) return `MISP distribution ${r.distribution} does not allow re-sharing`;
    return null;
}

// ── TAXII / STIX collections ─────────────────────────────────────────────────────────────────
// Fixed ids, so a consumer's configuration survives redeploys. Both hold shared intelligence
// only; neither holds anything an organisation contributed.
export type CollectionContent = 'indicators' | 'vulnerabilities';
export interface CollectionDef { id: string; alias: string; title: string; description: string; content: CollectionContent }

export const COLLECTIONS: CollectionDef[] = [
    {
        id: '4f0b6a3e-6d1c-4c5e-9a6b-2d0c1b7e5a01', alias: 'indicators', title: 'NovrSOC threat indicators',
        description: 'Active network and file indicators (IP, domain, URL, file hash) collected from the platform\'s threat feeds, with the provenance of each source record that may be shared. Organisation data is never included.',
        content: 'indicators',
    },
    {
        id: '4f0b6a3e-6d1c-4c5e-9a6b-2d0c1b7e5a02', alias: 'known-exploited-vulnerabilities', title: 'Known exploited vulnerabilities',
        description: 'Vulnerabilities listed in the CISA Known Exploited Vulnerabilities catalogue, as STIX vulnerability objects.',
        content: 'vulnerabilities',
    },
];
export const collectionById = (id: string) => COLLECTIONS.find((c) => c.id === id) ?? null;
