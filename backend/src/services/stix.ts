// STIX 2.1 bundle export for the platform's enriched IOCs.
//
// Produces a `bundle` containing one `identity` SDO (the producing organisation) and one
// `indicator` SDO per IOC, each with a STIX pattern so the bundle is directly consumable by
// MISP, OpenCTI, TheHive, Anomali and anything else that speaks STIX.
//
// On object IDs: the 2.1 spec says SDOs SHOULD use UUIDv4, but a random id means every export
// of the same IOC produces a *different* indicator, so a TIP re-importing this feed accumulates
// duplicates instead of updating in place. This uses deterministic UUIDv5 over the IOC's type
// and value instead, which is the common practice for exactly that reason — re-exporting the
// same IOC yields the same indicator id, and consumers can dedupe.

import { createHash } from 'crypto';

// RFC 4122 §4.3 name-based UUIDv5 (SHA-1). Node has randomUUID but no v5, and pulling in a
// dependency for ~15 lines isn't worth it.
function uuidv5(name: string, namespace: string): string {
    const nsBytes = Buffer.from(namespace.replace(/-/g, ''), 'hex');
    const hash = createHash('sha1').update(Buffer.concat([nsBytes, Buffer.from(name, 'utf8')])).digest();
    const bytes = Buffer.from(hash.subarray(0, 16));
    bytes[6] = (bytes[6] & 0x0f) | 0x50; // version 5
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant
    const hex = bytes.toString('hex');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// The namespace OASIS defines for STIX 2.1 deterministic identifiers.
const STIX_NAMESPACE = '00abedb4-aa42-466c-9c01-fed23315a9b7';

export type StixIOCType = 'ip' | 'domain' | 'url' | 'hash';

export interface ExportableIOC {
    ioc_value: string;
    ioc_type: string;
    risk_score: number | null;
    tags: string[] | null;
    first_seen: string | null;
    last_seen: string | null;
    country_name?: string | null;
    isp?: string | null;
}

// STIX pattern strings are single-quoted, so a value containing a quote or backslash would
// break out of the literal and produce an unparseable pattern.
function escapeStixValue(value: string): string {
    return value.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

// Hash algorithm is inferred from digest length — the table stores the value but not which
// algorithm produced it.
function hashAlgorithm(value: string): string | null {
    switch (value.trim().length) {
        case 32: return 'MD5';
        case 40: return 'SHA-1';
        case 64: return 'SHA-256';
        case 128: return 'SHA-512';
        default: return null;
    }
}

// Returns null when no valid pattern can be built — an indicator without a parseable pattern is
// rejected by strict consumers, so those rows are skipped rather than exported broken.
export function buildPattern(iocType: string, rawValue: string): string | null {
    const value = escapeStixValue(rawValue.trim());
    if (!value) return null;

    switch (iocType) {
        case 'ip':
            return IPV4_RE.test(rawValue.trim())
                ? `[ipv4-addr:value = '${value}']`
                : `[ipv6-addr:value = '${value}']`;
        case 'domain':
            return `[domain-name:value = '${value}']`;
        case 'url':
            return `[url:value = '${value}']`;
        case 'hash': {
            const algo = hashAlgorithm(rawValue);
            return algo ? `[file:hashes.'${algo}' = '${value}']` : null;
        }
        default:
            return null;
    }
}

// STIX `indicator_types` is an open vocabulary; these are the entries from
// indicator-type-ov that map cleanly to this platform's verdicts.
function indicatorTypes(riskScore: number | null, tags: string[]): string[] {
    const types = new Set<string>();
    const score = riskScore ?? 0;
    if (score >= 70) types.add('malicious-activity');
    else if (score >= 30) types.add('anomalous-activity');
    else types.add('benign');

    const lower = tags.map((t) => t.toLowerCase());
    if (lower.some((t) => t.includes('phish'))) types.add('attribution');
    if (lower.some((t) => t.includes('c2') || t.includes('botnet'))) types.add('command-and-control');
    if (lower.some((t) => t.includes('tor') || t.includes('anonymi'))) types.add('anonymization');
    return [...types];
}

export interface StixObject {
    type: string;
    spec_version: string;
    id: string;
    created: string;
    modified: string;
    [key: string]: unknown;
}

export interface StixBundle {
    type: 'bundle';
    id: string;
    objects: StixObject[];
}

export interface BuildBundleOptions {
    orgName?: string;
    /** IOCs scoring below this are omitted. 0 exports everything. */
    minRiskScore?: number;
}

export function buildStixBundle(iocs: ExportableIOC[], options: BuildBundleOptions = {}): {
    bundle: StixBundle;
    exported: number;
    skipped: number;
} {
    const orgName = options.orgName || 'NovrSOC';
    const minRisk = options.minRiskScore ?? 0;
    const now = new Date().toISOString();

    // Deterministic identity id so every export attributes to the same producer object.
    const identityId = `identity--${uuidv5(`novrsoc-identity:${orgName}`, STIX_NAMESPACE)}`;
    const identity: StixObject = {
        type: 'identity',
        spec_version: '2.1',
        id: identityId,
        created: '2026-01-01T00:00:00.000Z',
        modified: '2026-01-01T00:00:00.000Z',
        name: orgName,
        identity_class: 'organization',
        sectors: ['technology'],
        description: 'Threat intelligence produced by the NovrSOC platform.',
    };

    const objects: StixObject[] = [identity];
    let skipped = 0;

    for (const ioc of iocs) {
        if ((ioc.risk_score ?? 0) < minRisk) {
            skipped++;
            continue;
        }

        const pattern = buildPattern(ioc.ioc_type, ioc.ioc_value);
        if (!pattern) {
            skipped++;
            continue;
        }

        const tags = ioc.tags ?? [];
        // Same IOC (type + value) always yields the same indicator id across exports.
        const id = `indicator--${uuidv5(`${ioc.ioc_type}:${ioc.ioc_value}`, STIX_NAMESPACE)}`;
        const created = ioc.first_seen ?? now;
        const modified = ioc.last_seen ?? created;

        const descriptionParts = [
            `Observed by ${orgName} with a composite risk score of ${ioc.risk_score ?? 0}/100.`,
            ioc.country_name ? `Geolocated to ${ioc.country_name}.` : '',
            ioc.isp ? `Network: ${ioc.isp}.` : '',
        ].filter(Boolean);

        objects.push({
            type: 'indicator',
            spec_version: '2.1',
            id,
            created,
            modified,
            created_by_ref: identityId,
            name: `${ioc.ioc_type.toUpperCase()}: ${ioc.ioc_value}`,
            description: descriptionParts.join(' '),
            indicator_types: indicatorTypes(ioc.risk_score, tags),
            pattern,
            pattern_type: 'stix',
            pattern_version: '2.1',
            valid_from: created,
            // STIX confidence is 0-100, the same scale this platform's risk score uses.
            confidence: Math.max(0, Math.min(100, ioc.risk_score ?? 0)),
            labels: tags.length > 0 ? tags : undefined,
        });
    }

    return {
        bundle: {
            type: 'bundle',
            // Bundle ids are explicitly NOT deterministic in STIX — each bundle is a distinct
            // transient container, so a fresh v4-shaped id per export is correct here.
            id: `bundle--${uuidv5(`novrsoc-bundle:${now}`, STIX_NAMESPACE)}`,
            objects,
        },
        exported: objects.length - 1, // minus the identity object
        skipped,
    };
}
