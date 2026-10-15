// VMS scope rules (phase P4) — the one place that decides whether a target may be touched.
//
// A target is a hostname or an IP address. It is in scope only when an ACTIVE, unexpired scope
// entry of its organisation covers it:
//   domain  example.com           → example.com itself, and its subdomains when include_subdomains
//   ip      203.0.113.10          → that address
//   cidr    203.0.113.0/28        → addresses inside the range (IPv4 /22 or smaller, IPv6 /120 or smaller)
//   asn     AS37282               → registers an autonomous system for passive monitoring only; it
//                                   covers no host or address
// Each activity needs its own permission on the entry:
//   passive    third parties are asked about the target (registries, CT logs, Shodan, OpenCTI);
//              nothing connects to it — allowed by any active entry
//   discovery  the worker resolves names and sends one HTTP request per host — allow_discovery
//              (true unless the entry was registered for passive monitoring only)
//   ports      allow_port_scan        vuln   allow_vuln_scan
// Wildcards, URLs, ports, credentials and malformed names are never targets.

import { isIP } from 'net';
import { parseCidr, ipAllowed } from './cidr';

export type ScopeKind = 'domain' | 'ip' | 'cidr' | 'asn';
export type Activity = 'passive' | 'discovery' | 'ports' | 'vuln';
export interface ScopeEntry {
    id: string; org_id: string; kind: ScopeKind; value: string; include_subdomains: boolean;
    allow_port_scan: boolean; allow_vuln_scan: boolean; status: 'active' | 'revoked'; expires_at: string;
    /** Absent on rows written before P9: treated as true, the meaning those rows were approved with. */
    allow_discovery?: boolean;
}

/** worker_id of the backend's own passive-collection runner (jobs/cniiPassiveJob.ts): its heartbeats say nothing about the scanner worker. */
export const PASSIVE_RUNNER_ID = 'novrsoc-passive';

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
export const MAX_IPV4_PREFIX = 22;
export const MAX_IPV6_PREFIX = 120;

/** A lowercase hostname with at least two labels, or null. */
export function normalizeHostname(input: string): string | null {
    if (typeof input !== 'string') return null;
    const h = input.trim().toLowerCase().replace(/\.$/, '');
    if (!h || h.length > 253 || isIP(h)) return null;
    const labels = h.split('.');
    if (labels.length < 2 || !labels.every((l) => LABEL.test(l))) return null;
    if (/^\d+$/.test(labels[labels.length - 1])) return null; // numeric TLD = not a hostname
    return h;
}

/** Validates a proposed scope entry's value; returns the canonical value or an error. */
export function validateScopeValue(kind: ScopeKind, value: string): { ok: true; value: string } | { ok: false; error: string } {
    if (kind === 'domain') {
        const h = normalizeHostname(value);
        return h ? { ok: true, value: h } : { ok: false, error: 'Not a valid domain name (no wildcards, URLs or ports)' };
    }
    if (kind === 'asn') {
        const m = /^(?:AS)?(\d{1,10})$/i.exec(value.trim());
        const n = m ? Number(m[1]) : NaN;
        return m && n > 0 && n < 4_294_967_296 ? { ok: true, value: `AS${n}` } : { ok: false, error: 'Not a valid AS number (e.g. AS37282)' };
    }
    if (kind === 'ip') {
        const v = value.trim();
        return isIP(v) ? { ok: true, value: v.toLowerCase() } : { ok: false, error: 'Not a valid IP address' };
    }
    const c = parseCidr(value);
    if (!c || !value.includes('/')) return { ok: false, error: 'Not a valid CIDR range' };
    const min = c.family === 'ipv4' ? MAX_IPV4_PREFIX : MAX_IPV6_PREFIX;
    if (c.prefix < min) return { ok: false, error: `Range too large: use /${min} or smaller and add several entries if needed` };
    return { ok: true, value: `${c.address.toLowerCase()}/${c.prefix}` };
}

export type Target = { type: 'host'; value: string } | { type: 'ip'; value: string };
/** Parses a scan target; null when it is not a plain hostname or IP. */
export function parseTarget(input: string): Target | null {
    const s = typeof input === 'string' ? input.trim() : '';
    if (isIP(s)) return { type: 'ip', value: s.toLowerCase() };
    const h = normalizeHostname(s);
    return h ? { type: 'host', value: h } : null;
}

const usable = (e: ScopeEntry, now: number) => e.status === 'active' && Date.parse(e.expires_at) > now;
const allows = (e: ScopeEntry, a: Activity) => a === 'passive' || (a === 'discovery' && e.allow_discovery !== false) || (a === 'ports' && e.allow_port_scan) || (a === 'vuln' && e.allow_vuln_scan);

/** The scope entry that covers a target for an activity, or null. */
export function coveringScope(target: Target, entries: ScopeEntry[], activity: Activity, now = Date.now()): ScopeEntry | null {
    for (const e of entries) {
        if (!usable(e, now) || !allows(e, activity)) continue;
        if (target.type === 'host' && e.kind === 'domain' && (target.value === e.value || (e.include_subdomains && target.value.endsWith(`.${e.value}`)))) return e;
        if (target.type === 'ip' && e.kind === 'ip' && target.value === e.value) return e;
        if (target.type === 'ip' && e.kind === 'cidr' && ipAllowed(target.value, [e.value])) return e;
    }
    return null;
}

export function inScope(input: string, entries: ScopeEntry[], activity: Activity, now = Date.now()): boolean {
    const t = parseTarget(input);
    return !!t && coveringScope(t, entries, activity, now) !== null;
}
