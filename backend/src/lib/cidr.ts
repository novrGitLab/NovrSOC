// CIDR allow-lists for machine clients (vendor export, phase X1), on Node's net.BlockList.

import { BlockList, isIP } from 'net';

export interface Cidr { address: string; prefix: number; family: 'ipv4' | 'ipv6' }

/** "203.0.113.0/24", "2001:db8::/32", or a bare address (= /32 or /128). null if invalid or /0. */
export function parseCidr(input: string): Cidr | null {
    if (typeof input !== 'string') return null;
    const [addr, prefixStr, extra] = input.trim().split('/');
    if (extra !== undefined || !addr) return null;
    const v = isIP(addr);
    if (!v) return null;
    const family = v === 4 ? 'ipv4' : 'ipv6';
    const max = v === 4 ? 32 : 128;
    if (prefixStr === undefined) return { address: addr, prefix: max, family };
    if (!/^\d{1,3}$/.test(prefixStr)) return null;
    const prefix = Number(prefixStr);
    // /0 would admit every address — an allow-list that allows everything is refused.
    if (prefix < 1 || prefix > max) return null;
    return { address: addr, prefix, family };
}

/** "::ffff:203.0.113.5" -> "203.0.113.5"; null when not an IP. */
export function normalizeIp(ip: string | undefined | null): string | null {
    if (!ip) return null;
    const s = ip.trim();
    const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(s);
    const out = mapped ? mapped[1] : s;
    return isIP(out) ? out : null;
}

/** True only when `ip` is a valid address inside one of `cidrs`. Invalid CIDRs are skipped. */
export function ipAllowed(ip: string | null, cidrs: readonly string[]): boolean {
    if (!ip) return false;
    const list = new BlockList();
    let any = false;
    for (const c of cidrs) {
        const p = parseCidr(c);
        if (!p) continue;
        list.addSubnet(p.address, p.prefix, p.family);
        any = true;
    }
    if (!any) return false;
    return list.check(ip, isIP(ip) === 4 ? 'ipv4' : 'ipv6');
}
