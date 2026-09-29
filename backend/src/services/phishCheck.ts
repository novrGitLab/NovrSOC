// Free phishing-URL checking (PhishTank + OpenPhish), used by the Email Security module's URL
// intelligence (services/emailsec/urlIntel.ts) and Phish ID domain intelligence.
//
// Verified live before writing this:
// - PhishTank's checkurl endpoint answers WITHOUT an API key (app_key is optional, exactly as
//   the free tier promises), but confirmed live it returns HTTP 403 on every call regardless —
//   with a real, valid JSON body in the response anyway (`results.in_database`, etc.). Parsing
//   only fails if the body itself isn't valid JSON, so this reads the body first and treats a
//   non-403-with-real-JSON as success, rather than gating on res.ok the way a normal API client
//   would.
// - OpenPhish's feed.txt 302-redirects to a GitHub-hosted mirror
//   (raw.githubusercontent.com/openphish/public_feed) — real, working, plain-text one-URL-per-
//   line list. fetch() follows redirects by default, so no special handling needed there.

const PHISHTANK_URL = 'https://checkurl.phishtank.com/checkurl/';
const OPENPHISH_FEED_URL = 'https://openphish.com/feed.txt';
const OPENPHISH_REFRESH_MS = 6 * 60 * 60 * 1000; // 6 hours

export interface PhishCheckResult {
    is_phishing: boolean;
    verified?: boolean;
    source: string;
    error?: string;
}

export async function checkPhishTank(url: string): Promise<PhishCheckResult> {
    const apiKey = process.env.PHISHTANK_API_KEY;
    try {
        const params = new URLSearchParams({ url, format: 'json' });
        if (apiKey) params.set('app_key', apiKey);

        const r = await fetch(PHISHTANK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'novrsoc-phishid' },
            body: params.toString(),
            signal: AbortSignal.timeout(8000),
        });

        let data: { results?: { in_database?: boolean; valid?: boolean; verified?: boolean } };
        try {
            data = await r.json();
        } catch {
            return { is_phishing: false, source: 'phishtank', error: `HTTP ${r.status}, non-JSON response` };
        }

        // `valid` is PhishTank's own "confirmed phishing" flag (false for known-legitimate
        // entries even when in_database is true) — checked live against a benign URL that was
        // in_database:true, valid:false.
        return {
            is_phishing: !!(data.results?.in_database && data.results?.valid),
            verified: data.results?.verified,
            source: 'phishtank',
        };
    } catch (err) {
        return { is_phishing: false, source: 'phishtank', error: err instanceof Error ? err.message : 'unreachable' };
    }
}

let openPhishUrls: Set<string> = new Set();
let lastOpenPhishFetch = 0;

export async function checkOpenPhish(url: string): Promise<PhishCheckResult> {
    if (Date.now() - lastOpenPhishFetch > OPENPHISH_REFRESH_MS) {
        try {
            const r = await fetch(OPENPHISH_FEED_URL, { signal: AbortSignal.timeout(10000) });
            if (r.ok) {
                const text = await r.text();
                openPhishUrls = new Set(text.split('\n').map((u) => u.trim()).filter(Boolean));
                lastOpenPhishFetch = Date.now();
            }
        } catch {
            // Keep existing cache if the refresh fails — a stale feed beats no feed.
        }
    }

    let domain: string | null = null;
    try {
        domain = new URL(url).hostname;
    } catch {
        // Not a parseable URL — exact-match against the feed only, no domain fallback.
    }

    const isPhishing = openPhishUrls.has(url) || (domain !== null && [...openPhishUrls].some((u) => {
        try {
            return new URL(u).hostname === domain;
        } catch {
            return false;
        }
    }));

    return { is_phishing: isPhishing, source: 'openphish' };
}

// Runs both in parallel — used by PHISHID's classify route alongside the Claude/heuristic
// verdict, not as a replacement for it.
export async function checkPhishSources(url: string): Promise<{ is_phishing: boolean; hits: string[]; details: PhishCheckResult[] }> {
    const [pt, op] = await Promise.allSettled([checkPhishTank(url), checkOpenPhish(url)]);
    const ptResult = pt.status === 'fulfilled' ? pt.value : { is_phishing: false, source: 'phishtank', error: 'failed' };
    const opResult = op.status === 'fulfilled' ? op.value : { is_phishing: false, source: 'openphish', error: 'failed' };

    const hits = [ptResult, opResult].filter((r) => r.is_phishing).map((r) => r.source);
    return { is_phishing: hits.length > 0, hits, details: [ptResult, opResult] };
}
