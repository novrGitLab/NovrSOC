// FOFA — network-asset search engine, used alongside LeakIX for host exposure lookups.
//
// Dormant by design: FOFA_API_KEY and FOFA_EMAIL are not set in this environment, so every
// export below reports "not configured" and performs no network call. It activates with no code
// change once both are set, the same way ANTHROPIC_API_KEY activates Claude in NovrAI.
//
// Not verified against a live response — there are no credentials here to verify with — so this
// is written to FOFA's documented v1 contract and degrades to null/[] on any shape it doesn't
// recognise rather than assuming fields exist. The query is base64-encoded ("qbase64"), which
// is FOFA's required encoding, not a plain string.

const FOFA_BASE = 'https://fofa.info/api/v1';

function getCredentials(): { key: string; email: string } | null {
    const key = (process.env.FOFA_API_KEY || '').trim();
    const email = (process.env.FOFA_EMAIL || '').trim();
    if (!key || !email) return null;
    return { key, email };
}

export function isConfigured(): boolean {
    return getCredentials() !== null;
}

export interface FOFAResult {
    configured: boolean;
    total: number;
    results: string[][];
    source: 'fofa';
    error?: string;
}

function empty(error?: string): FOFAResult {
    return { configured: isConfigured(), total: 0, results: [], source: 'fofa', error };
}

interface FOFARawResponse {
    error?: boolean | string;
    errmsg?: string;
    size?: number;
    results?: string[][];
}

// `query` is FOFA syntax, e.g. `ip="8.8.8.8"` or `domain="example.com"`.
export async function searchFOFA(query: string, size = 10): Promise<FOFAResult> {
    const creds = getCredentials();
    if (!creds) return empty('FOFA_API_KEY/FOFA_EMAIL not set');

    try {
        const params = new URLSearchParams({
            email: creds.email,
            key: creds.key,
            qbase64: Buffer.from(query).toString('base64'),
            fields: 'ip,port,protocol,host,title',
            size: String(size),
        });
        const res = await fetch(`${FOFA_BASE}/search/all?${params}`, { signal: AbortSignal.timeout(10000) });
        if (!res.ok) return empty(`FOFA returned HTTP ${res.status}`);

        const data = (await res.json()) as FOFARawResponse;
        // FOFA signals failure in the body with error:true, not via HTTP status.
        if (data.error) return empty(data.errmsg || 'FOFA reported an error');

        return {
            configured: true,
            total: data.size ?? 0,
            results: Array.isArray(data.results) ? data.results : [],
            source: 'fofa',
        };
    } catch (err) {
        return empty(err instanceof Error ? err.message : 'unreachable');
    }
}

export async function getFOFAHost(ip: string): Promise<FOFAResult> {
    return searchFOFA(`ip="${ip}"`);
}

export interface FOFANigerianHost {
    ip: string;
    port: string;
    protocol: string;
    /** FOFA's own region/city string — NOT a validated Nigerian state name. */
    region: string;
}

// Exposed services on Nigerian networks, for the Nigeria threat map.
//
// Dormant until FOFA_API_KEY and FOFA_EMAIL are set; returns [] rather than throwing, so the
// collector can call it unconditionally.
//
// The `fields` order below is what the response rows are positionally destructured against —
// FOFA returns results as arrays, not objects, so the two must stay in sync. Region is captured
// but deliberately NOT trusted as a Nigerian state name: FOFA's region strings don't reliably
// match this platform's 37-state vocabulary, so the collector resolves state from the IP via
// IPregistry the same way it does for every other source, and only uses this as context.
export async function searchFOFANigeria(limit = 40): Promise<FOFANigerianHost[]> {
    if (!isConfigured()) return [];

    const queries = [
        'country="NG"',
        'asn="29465"', // MTN Nigeria
        'asn="36873"', // Airtel Networks
    ];

    const byIp = new Map<string, FOFANigerianHost>();

    for (const query of queries) {
        if (byIp.size >= limit) break;
        const result = await searchFOFA(query, Math.min(50, limit));
        if (result.error) {
            console.warn(`[FOFA-NG] "${query}": ${result.error}`);
            continue;
        }
        for (const row of result.results) {
            // fields=ip,port,protocol,host,title — see searchFOFA above.
            const [ip, port, protocol] = row;
            if (!ip || byIp.has(ip)) continue;
            byIp.set(ip, { ip, port: port ?? '', protocol: protocol ?? '', region: '' });
        }
    }

    return [...byIp.values()].slice(0, limit);
}
