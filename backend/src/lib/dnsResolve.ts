// DNS lookups the backend makes itself (CNII intake, P17; pinned CNII authorisations, P18). Only
// names are resolved — the backend never connects to the answers. Injectable for tests (no network).

import { Resolver } from 'dns/promises';

export interface DnsDeps { resolve4: (h: string) => Promise<string[]>; resolve6: (h: string) => Promise<string[]>; reverse: (ip: string) => Promise<string[]> }
let override: Partial<DnsDeps> | null = null;
export function setDnsForTests(d: Partial<DnsDeps> | null): void { override = d; }
export function dns(): DnsDeps {
    const r = new Resolver({ timeout: 3000, tries: 2 });
    return { resolve4: (h) => r.resolve4(h), resolve6: (h) => r.resolve6(h), reverse: (ip) => r.reverse(ip), ...(override ?? {}) };
}

const NO_ANSWER = ['ENOTFOUND', 'ENODATA', 'NXDOMAIN'];
/** A and AAAA answers for a name, lowercased and sorted; error is set when the lookup itself failed. */
export async function resolveAddresses(host: string): Promise<{ addresses: string[]; error: string | null }> {
    const d = dns();
    const one = async (p: Promise<string[]>) => {
        try { return { v: await p, e: null as string | null }; } catch (e) { const code = (e as { code?: string }).code ?? ''; return { v: [] as string[], e: NO_ANSWER.includes(code) ? null : (code || 'lookup failed') }; }
    };
    const [a, aaaa] = await Promise.all([one(d.resolve4(host)), one(d.resolve6(host))]);
    return { addresses: [...new Set([...a.v, ...aaaa.v].map((x) => x.toLowerCase()))].sort(), error: a.e ?? aaaa.e };
}

/**
 * Pinned addresses (P18): a CNII scan authorisation for a domain names the addresses it resolved to
 * when a manager approved it. The name may be scanned only while every address it resolves to now is
 * one of those — so a DNS change (new hosting, takeover, rebinding) is never scanned on the old approval.
 */
export function pinsSatisfied(current: string[], pins: readonly string[]): { ok: boolean; reason: string | null } {
    if (!pins.length) return { ok: true, reason: null };
    if (!current.length) return { ok: false, reason: 'it does not resolve now' };
    const pinned = new Set(pins.map((p) => p.toLowerCase()));
    const extra = current.filter((a) => !pinned.has(a.toLowerCase()));
    return extra.length ? { ok: false, reason: `it now resolves to ${extra.join(', ')}, which the CNII approval did not cover (approved: ${pins.join(', ')})` } : { ok: true, reason: null };
}
