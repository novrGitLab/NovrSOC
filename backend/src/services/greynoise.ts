// GreyNoise — "is this IP mass-scanning the internet" context, plus internet-wide scanning
// statistics by country.
//
// Verified live (both a benign and a known-scanner-ish IP): the community endpoint
// (api.greynoise.io/v3/community/{ip}) returns a real JSON body — {ip, noise, riot, message} —
// on both 200 and 404 status codes; a 404 here means "not observed", not "endpoint missing", so
// the body is parsed either way rather than discarded on non-200.
//
// API-version note, confirmed live 2026-09-08: GreyNoise's ENTIRE v2 API is retired — every v2
// path tried (/v2/noise/context/{ip}, /v2/meta/ping, /v2/meta/metadata,
// /v2/experimental/gnql/stats) returns 410 "This v2 endpoint has been deprecated". The keyed
// branch of checkGreyNoise() below used to call /v2/noise/context/{ip}, so with
// GREYNOISE_API_KEY set — as it is in this environment — every enrichment lookup was silently
// failing with HTTP 410 while the keyless branch kept working. Both branches now use
// /v3/community/{ip}, which accepts the key and returns classification/name/last_seen.

export interface GreyNoiseResult {
    noise: boolean; // actively scanning/crawling the internet (mass-scanner, not necessarily malicious)
    riot: boolean; // a known-benign business service (CDN, cloud provider, etc.)
    classification: 'malicious' | 'benign' | 'unknown';
    name?: string;
    tags?: string[];
    source: string;
    error?: string;
}

export async function checkGreyNoise(ip: string): Promise<GreyNoiseResult> {
    const apiKey = process.env.GREYNOISE_API_KEY;

    try {
        const r = await fetch(`https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`, {
            // The key is optional here — sending it when present raises the rate limit and is
            // what the paid tier expects, and the endpoint ignores it when absent.
            headers: apiKey ? { key: apiKey } : undefined,
            signal: AbortSignal.timeout(6000),
        });
        let data: { noise?: boolean; riot?: boolean; classification?: string; name?: string; message?: string };
        try {
            data = await r.json();
        } catch {
            return { noise: false, riot: false, classification: 'unknown', source: 'greynoise', error: `HTTP ${r.status}, non-JSON response` };
        }
        const classification = data.classification === 'malicious' || data.classification === 'benign' ? data.classification : 'unknown';
        return { noise: !!data.noise, riot: !!data.riot, classification, name: data.name, source: 'greynoise' };
    } catch (err) {
        return { noise: false, riot: false, classification: 'unknown', source: 'greynoise', error: err instanceof Error ? err.message : 'unreachable' };
    }
}

// ── INTERNET-WIDE SCANNING STATS ──────────────────────────────────

export interface GreyNoiseCountryStat {
    country: string; // full country name as GreyNoise reports it, e.g. "United States"
    count: number;   // distinct IPs from that country matching the query
}

export function isGreyNoiseConfigured(): boolean {
    return !!process.env.GREYNOISE_API_KEY;
}

// Per-country counts of IPs GreyNoise currently classifies as malicious — i.e. where internet
// background scanning/attack traffic is actually originating right now.
//
// Endpoint note: the aggregation lives at /v3/gnql/stats. The /v2/meta/trends path this was
// originally specified against does NOT exist (404 "endpoint not found") and all of v2 is
// retired anyway (410). Verified live with this environment's key (plan "Business - Free"):
// /v3/gnql/stats?query=classification:malicious returns ~291k IPs bucketed into
// stats.source_countries as [{country, count}] — full country NAMES, not the {country_code,
// noise_ip_count} shape the draft assumed, which is why the caller maps names to ISO codes.
export async function getGreyNoiseCountryStats(limit = 50): Promise<GreyNoiseCountryStat[]> {
    const apiKey = process.env.GREYNOISE_API_KEY;
    if (!apiKey) return [];

    try {
        const r = await fetch(
            `https://api.greynoise.io/v3/gnql/stats?query=${encodeURIComponent('classification:malicious')}&count=${limit}`,
            { headers: { key: apiKey, Accept: 'application/json' }, signal: AbortSignal.timeout(10000) }
        );
        if (!r.ok) {
            console.warn(`[GreyNoise] Country stats returned HTTP ${r.status}`);
            return [];
        }
        const data = (await r.json()) as { stats?: { source_countries?: Array<{ country?: string; count?: number }> } };
        return (data.stats?.source_countries ?? [])
            .filter((c): c is { country: string; count: number } => !!c.country && typeof c.count === 'number')
            .map((c) => ({ country: c.country, count: c.count }));
    } catch (err) {
        console.warn('[GreyNoise] Country stats failed:', err instanceof Error ? err.message : err);
        return [];
    }
}
