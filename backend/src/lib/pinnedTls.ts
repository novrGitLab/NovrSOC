// Certificate pinning for one specific self-signed service, instead of switching TLS
// verification off for the whole process (NODE_TLS_REJECT_UNAUTHORIZED=0 did that before).
//
// The pinned certificate is used as the ONLY trusted CA for that connection, so verification
// stays ON (rejectUnauthorized: true) and a wrong certificate fails the handshake before any
// request data — including API keys — is sent. The hostname check is relaxed only when the
// server presents exactly the pinned certificate (self-signed appliances such as MISP usually
// carry CN=localhost while being reached by IP).
import https from 'https';
import { checkServerIdentity, type PeerCertificate } from 'tls';
import { X509Certificate } from 'crypto';

export interface Pin { pem: string; fingerprint256: string }

/** Parse a PEM certificate (raw, with \n escapes, or base64 of the PEM). Null if absent/invalid. */
export function parsePin(value: string | undefined): Pin | null {
    const raw = (value ?? '').trim();
    if (!raw) return null;
    let pem = raw.replace(/\\n/g, '\n');
    if (!pem.includes('BEGIN CERTIFICATE')) {
        try { pem = Buffer.from(raw, 'base64').toString('utf8'); } catch { return null; }
    }
    try {
        const cert = new X509Certificate(pem);
        return { pem, fingerprint256: cert.fingerprint256 };
    } catch {
        return null;
    }
}

/** fetch()-shaped request that trusts only `pin`. Supports what the MISP client uses. */
export function pinnedFetch(url: string, init: { method?: string; headers?: Record<string, string>; body?: string; timeoutMs?: number }, pin: Pin): Promise<Response> {
    return new Promise((resolve, reject) => {
        const u = new URL(url);
        if (u.protocol !== 'https:') { reject(new Error('Pinned requests must use https')); return; }
        const req = https.request({
            method: init.method ?? 'GET',
            hostname: u.hostname,
            port: u.port || 443,
            path: `${u.pathname}${u.search}`,
            headers: init.body ? { ...init.headers, 'Content-Length': String(Buffer.byteLength(init.body)) } : init.headers,
            ca: pin.pem,
            rejectUnauthorized: true,
            agent: false,
            checkServerIdentity: (host: string, cert: PeerCertificate) => {
                if (cert.fingerprint256 === pin.fingerprint256) return undefined; // exactly the pinned certificate
                return checkServerIdentity(host, cert);
            },
            timeout: init.timeoutMs ?? 8000,
        }, (res) => {
            const chunks: Buffer[] = [];
            res.on('data', (c: Buffer) => chunks.push(c));
            res.on('end', () => {
                const headers = new Headers();
                for (const [k, v] of Object.entries(res.headers)) if (v !== undefined) headers.set(k, Array.isArray(v) ? v.join(', ') : String(v));
                const status = res.statusCode ?? 502;
                resolve(new Response([101, 204, 205, 304].includes(status) ? null : Buffer.concat(chunks), { status, headers }));
            });
            res.on('error', reject);
        });
        const deadline = setTimeout(() => req.destroy(new Error('Request timed out')), init.timeoutMs ?? 8000);
        deadline.unref();
        req.on('close', () => clearTimeout(deadline));
        req.on('timeout', () => req.destroy(new Error('Request timed out')));
        req.on('error', reject);
        if (init.body) req.write(init.body);
        req.end();
    });
}

/**
 * Process-wide TLS verification must stay on. If NODE_TLS_REJECT_UNAUTHORIZED=0 arrives from any
 * environment (a local .env, a hosting dashboard), remove it and say so loudly. Node reads the
 * variable at connection time, so clearing it at startup restores verification for every client.
 */
export function enforceTlsVerification(): void {
    if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') {
        delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
        console.error('[tls] NODE_TLS_REJECT_UNAUTHORIZED=0 was set in the environment. It disables certificate');
        console.error('[tls] verification for EVERY outbound connection, so it has been ignored. Remove it from the');
        console.error('[tls] environment. For a self-signed service, pin its certificate instead (e.g. MISP_CA_CERT).');
    }
}
