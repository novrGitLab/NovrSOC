// RIPE Stat — ASN routing intelligence (holder, announced prefixes, authoritative RIR).
// Free, no key needed. https://stat.ripe.net/docs/data_api
//
// "AFRINIC lookup" here means: RIPE Stat's own `whois` data call reports which RIR is
// authoritative for a resource (its `authorities` field — e.g. "afrinic", "ripe", "arin").
// There is no separate public AFRINIC JSON API comparable to RIPE Stat's, so this is the
// honest way to answer "is this an AFRINIC allocation" — not a second call to some AFRINIC
// service. Verified live against real Nigerian ISP ASNs while building this: AS29465 (MTN
// Nigeria) is actually RIPE-registered (a legacy registration predating AFRINIC's 2005
// founding), while AS36873 (Airtel), AS37148 (Glo), AS37076 (9mobile/EMTS), AS37282
// (MainOne), and AS37340 (Spectranet) are all AFRINIC-registered.

const RIPE_STAT_BASE = 'https://stat.ripe.net/data';

export interface ASNInfo {
    asn: string;
    holder: string;
    is_announced: boolean;
    authoritative_rir: string | null; // e.g. 'afrinic', 'ripe', 'arin', 'apnic', 'lacnic'
    is_afrinic: boolean;
    top_country: string | null;
    prefix_count: number;
    prefixes: string[];
}

function normalizeResource(input: string): string {
    const trimmed = input.trim().toUpperCase();
    return trimmed.startsWith('AS') ? trimmed : `AS${trimmed}`;
}

async function fetchRipeStat<T = Record<string, unknown>>(path: string, resource: string): Promise<T | null> {
    try {
        const res = await fetch(`${RIPE_STAT_BASE}/${path}/data.json?resource=${encodeURIComponent(resource)}`, {
            signal: AbortSignal.timeout(8000),
        });
        if (!res.ok) return null;
        const json = await res.json();
        return json?.status === 'ok' ? (json.data as T) : null;
    } catch {
        return null;
    }
}

/** Just the registered holder name for an ASN (one call), or null if RIPE Stat has none. */
export async function asHolder(asnInput: string): Promise<string | null> {
    const resource = normalizeResource(asnInput);
    if (!/^AS\d+$/.test(resource)) return null;
    const overview = await fetchRipeStat<{ holder?: string }>('as-overview', resource);
    return overview?.holder?.trim() || null;
}

export async function lookupASN(asnInput: string): Promise<ASNInfo> {
    const resource = normalizeResource(asnInput);
    if (!/^AS\d+$/.test(resource)) {
        throw new Error(`Invalid ASN: ${asnInput}`);
    }

    const [overview, announced, whois] = await Promise.all([
        fetchRipeStat<{ holder?: string; announced?: boolean }>('as-overview', resource),
        fetchRipeStat<{ prefixes?: Array<{ prefix: string }> }>('announced-prefixes', resource),
        fetchRipeStat<{ authorities?: string[] }>('whois', resource),
    ]);

    if (!overview) {
        throw new Error(`RIPE Stat has no data for ${resource}`);
    }

    const prefixes = (announced?.prefixes ?? []).map((p) => p.prefix);
    const authoritativeRir = whois?.authorities?.[0]?.toLowerCase() ?? null;

    // geoloc doesn't accept an ASN resource directly (RIPE Stat requires a prefix) — geolocate
    // the ASN's first announced prefix as a proxy for "country of registration."
    let topCountry: string | null = null;
    if (prefixes.length > 0) {
        const geoloc = await fetchRipeStat<{ located_resources?: Array<{ locations?: Array<{ country?: string }> }> }>('geoloc', prefixes[0]);
        topCountry = geoloc?.located_resources?.[0]?.locations?.[0]?.country ?? null;
    }

    return {
        asn: resource,
        holder: overview.holder ?? 'Unknown',
        is_announced: overview.announced ?? false,
        authoritative_rir: authoritativeRir,
        is_afrinic: authoritativeRir === 'afrinic',
        top_country: topCountry,
        prefix_count: prefixes.length,
        prefixes: prefixes.slice(0, 25),
    };
}
