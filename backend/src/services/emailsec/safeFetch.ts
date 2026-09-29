// Defensive HTTP client for inspecting suspicious URLs and websites.
//
// Anything a phishing page or an email can name ends up here, so the rules are strict:
//   • http / https only, default ports only (80 / 443), no credentials in the URL.
//   • The hostname is resolved first and EVERY address must be public — loopback, RFC 1918,
//     link-local (incl. cloud metadata 169.254.169.254), CGNAT, multicast, reserved, ULA and
//     IPv4-mapped IPv6 are refused. The connection is then pinned to the address that was
//     checked (custom `lookup`), so a DNS answer that changes between check and connect (DNS
//     rebinding) cannot redirect the request inside the network.
//   • Redirects are followed by hand, at most 5, and each hop goes through the same checks.
//   • GET only, no cookies, no request body, 10 s timeout, response capped at 512 KB.
//   • Nothing is ever submitted to the site: no forms, no credentials, no scripts executed.
import http from 'http';
import https from 'https';
import { lookup as dnsLookup } from 'dns/promises';
import { isIP } from 'net';
import type { TLSSocket, PeerCertificate } from 'tls';

export const USER_AGENT = 'NovrSOC-Inspector/1.0 (defensive security analysis; no data submitted)';
const MAX_BYTES = 512 * 1024;
const TIMEOUT_MS = 10_000;
const MAX_REDIRECTS = 5;

export class BlockedTargetError extends Error {
    constructor(message: string) { super(message); this.name = 'BlockedTargetError'; }
}

function ipv4ToInt(ip: string): number {
    return ip.split('.').reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}
const V4_BLOCKED: [string, number][] = [
    ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
    ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
    ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
];

/** True if `ip` is not a publicly routable unicast address. */
export function isPrivateAddress(ip: string): boolean {
    const v = isIP(ip);
    if (v === 4) {
        const n = ipv4ToInt(ip);
        return V4_BLOCKED.some(([base, bits]) => (n >>> (32 - bits)) === (ipv4ToInt(base) >>> (32 - bits)));
    }
    if (v === 6) {
        const lower = ip.toLowerCase();
        const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
        if (mapped) return isPrivateAddress(mapped[1]);
        if (lower === '::' || lower === '::1') return true;
        const first = parseInt(lower.split(':')[0] || '0', 16);
        return (first & 0xfe00) === 0xfc00      // fc00::/7 unique local
            || (first & 0xffc0) === 0xfe80      // fe80::/10 link local
            || (first & 0xff00) === 0xff00      // ff00::/8 multicast
            || lower.startsWith('2001:db8')     // documentation
            || lower.startsWith('64:ff9b');     // NAT64 — can reach private v4
    }
    return true;
}

export interface ValidatedTarget { url: URL; address: string; family: 4 | 6 }

/** Check a URL against the rules above and resolve it to one public address to pin. */
export async function validateTarget(raw: string): Promise<ValidatedTarget> {
    let url: URL;
    try { url = new URL(raw); } catch { throw new BlockedTargetError('Not a valid URL.'); }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new BlockedTargetError(`Scheme ${url.protocol} is not allowed; only http and https.`);
    if (url.username || url.password) throw new BlockedTargetError('URLs with embedded credentials are not fetched.');
    if (url.port && !((url.protocol === 'http:' && url.port === '80') || (url.protocol === 'https:' && url.port === '443'))) {
        throw new BlockedTargetError(`Port ${url.port} is not allowed; only the default web ports are inspected.`);
    }
    const host = url.hostname.replace(/^\[|\]$/g, '');
    if (!host || /^localhost$|\.localhost$|\.internal$|\.local$/i.test(host)) throw new BlockedTargetError('Internal hostnames are not fetched.');
    const addrs = isIP(host) ? [{ address: host, family: isIP(host) as 4 | 6 }] : await dnsLookup(host, { all: true, verbatim: true }).catch(() => []);
    if (addrs.length === 0) throw new BlockedTargetError(`${host} does not resolve.`);
    const bad = addrs.find((a) => isPrivateAddress(a.address));
    if (bad) throw new BlockedTargetError(`${host} resolves to a non-public address (${bad.address}); refused to prevent server-side request forgery.`);
    return { url, address: addrs[0].address, family: addrs[0].family as 4 | 6 };
}

export interface TlsInfo {
    authorized: boolean;
    authorization_error: string | null;
    subject: string | null;
    issuer: string | null;
    valid_from: string | null;
    valid_to: string | null;
    san: string[];
    protocol: string | null;
}
export interface Hop { url: string; status: number; location: string | null; address: string }
export interface SafeResponse {
    final_url: string;
    status: number;
    headers: Record<string, string>;
    body: string;
    truncated: boolean;
    content_type: string | null;
    redirects: Hop[];
    tls: TlsInfo | null;
}

function tlsInfo(sock: TLSSocket): TlsInfo {
    const cert = sock.getPeerCertificate() as PeerCertificate | undefined;
    const has = cert && Object.keys(cert).length > 0;
    const name = (o?: Record<string, unknown>) => (o ? (o.CN as string) ?? (o.O as string) ?? null : null);
    return {
        authorized: sock.authorized,
        authorization_error: sock.authorizationError ? String(sock.authorizationError) : null,
        subject: has ? name(cert.subject as unknown as Record<string, unknown>) : null,
        issuer: has ? name(cert.issuer as unknown as Record<string, unknown>) : null,
        valid_from: has ? new Date(cert.valid_from).toISOString() : null,
        valid_to: has ? new Date(cert.valid_to).toISOString() : null,
        san: has && cert.subjectaltname ? cert.subjectaltname.split(',').map((s) => s.trim().replace(/^DNS:/, '')).slice(0, 50) : [],
        protocol: sock.getProtocol() ?? null,
    };
}

function requestOnce(t: ValidatedTarget): Promise<{ status: number; headers: Record<string, string>; body: string; truncated: boolean; tls: TlsInfo | null }> {
    return new Promise((resolve, reject) => {
        const isHttps = t.url.protocol === 'https:';
        const mod = isHttps ? https : http;
        const req = mod.request({
            method: 'GET',
            host: t.url.hostname,
            path: `${t.url.pathname}${t.url.search}`,
            port: isHttps ? 443 : 80,
            headers: { 'User-Agent': USER_AGENT, Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5', 'Accept-Encoding': 'identity' },
            // Pin to the validated address — the reason this doesn't use fetch().
            lookup: (_host: string, _opts: unknown, cb: (err: Error | null, address: string, family: number) => void) => cb(null, t.address, t.family),
            timeout: TIMEOUT_MS,
            // Phishing sites often have bad certificates; inspect them anyway and record why.
            rejectUnauthorized: false,
            servername: isIP(t.url.hostname) ? undefined : t.url.hostname,
            agent: false,
        } as https.RequestOptions, (res) => {
            let tls: TlsInfo | null = null;
            if (isHttps) tls = tlsInfo(res.socket as TLSSocket);
            const chunks: Buffer[] = [];
            let size = 0;
            let truncated = false;
            res.on('data', (c: Buffer) => {
                if (size >= MAX_BYTES) { truncated = true; res.destroy(); return; }
                chunks.push(c); size += c.length;
            });
            const done = () => {
                const headers: Record<string, string> = {};
                for (const [k, v] of Object.entries(res.headers)) if (v !== undefined) headers[k] = Array.isArray(v) ? v.join(', ') : String(v);
                resolve({ status: res.statusCode ?? 0, headers, body: Buffer.concat(chunks).subarray(0, MAX_BYTES).toString('utf8'), truncated, tls });
            };
            res.on('end', done);
            res.on('close', done);
            res.on('error', reject);
        });
        req.on('timeout', () => req.destroy(new Error(`Timed out after ${TIMEOUT_MS / 1000}s`)));
        req.on('error', reject);
        req.end();
    });
}

/** GET a URL under the rules at the top of this file, following redirects by hand. */
export async function safeGet(raw: string): Promise<SafeResponse> {
    const redirects: Hop[] = [];
    let current = raw;
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
        const target = await validateTarget(current);
        const r = await requestOnce(target);
        const location = r.status >= 300 && r.status < 400 ? r.headers.location ?? null : null;
        redirects.push({ url: target.url.toString(), status: r.status, location, address: target.address });
        if (location && hop < MAX_REDIRECTS) {
            current = new URL(location, target.url).toString();
            continue;
        }
        return {
            final_url: target.url.toString(), status: r.status, headers: r.headers, body: r.body, truncated: r.truncated,
            content_type: r.headers['content-type'] ?? null, redirects: redirects.slice(0, -1), tls: r.tls,
        };
    }
    throw new BlockedTargetError(`More than ${MAX_REDIRECTS} redirects.`);
}
