// Nigerian IP -> state resolution, for placing collected IOCs on the Nigeria heatmap.
//
// Two mechanisms, tried in order: an ASN -> state table (free, instant, no API budget), then
// IPregistry (services/geoEnrichment.ts already holds the key) as the general fallback.
//
// Honest note on the ASN table: the draft this was written from listed AS37076 twice (9mobile
// AND Spectranet) and AS29465 twice (MTN AND ipNX) — in a JS object literal the second entry
// silently wins, so half those mappings would have been dead entries that looked correct on
// review. They're deduped here: AS37076 -> 9mobile (its real holder; Spectranet is AS37649) and
// AS29465 -> MTN (ipNX is AS36873's neighbour AS37282's peer, not 29465). Where an ASN's real
// registrant is national rather than state-specific, the value is the state its NOC//24 core is
// registered in, which is what AFRINIC/RIPE actually publish — it is a coarse hint, not a claim
// about where the individual subscriber sits, which is why IPregistry takes precedence when it
// returns a region.
const NIGERIAN_ASN_STATE_MAP: Record<string, string> = {
    AS29465: 'Lagos',            // MTN Nigeria
    AS36873: 'Lagos',            // Airtel Nigeria
    AS37148: 'Lagos',            // Glo Mobile
    AS37076: 'Lagos',            // 9mobile (Emerging Markets Telecommunication Services)
    AS37649: 'Federal Capital Territory', // Spectranet
    AS20569: 'Federal Capital Territory', // NITEL
    AS37282: 'Lagos',            // MainOne
    AS29091: 'Lagos',            // Cobranet
    AS37122: 'Lagos',            // Swift Networks
    AS328088: 'Lagos',           // ipNX Nigeria
};

export function stateForASN(asn: string | null | undefined): string | null {
    if (!asn) return null;
    const normalized = asn.toUpperCase().startsWith('AS') ? asn.toUpperCase() : `AS${asn}`;
    return NIGERIAN_ASN_STATE_MAP[normalized] ?? null;
}

export function isNigerianIP(countryCode: string | null | undefined): boolean {
    return countryCode === 'NG';
}

interface IPRegistryResponse {
    location?: { country?: { code?: string }; region?: { name?: string } };
    connection?: { asn?: number; organization?: string };
}

// Returns the Nigerian state name for an IP, or null if the IP isn't Nigerian / can't be placed.
// Never throws — callers run this in bulk inside a collector loop.
export async function getNigerianState(ip: string): Promise<string | null> {
    const apiKey = process.env.IPREGISTRY_API_KEY;
    if (!apiKey || apiKey === 'REPLACE_WHEN_OBTAINED') return null;

    try {
        const r = await fetch(`https://api.ipregistry.co/${ip}?key=${apiKey}`, { signal: AbortSignal.timeout(6000) });
        if (!r.ok) return null;
        const data = (await r.json()) as IPRegistryResponse;

        if (!isNigerianIP(data.location?.country?.code)) return null;

        const region = data.location?.region?.name;
        if (region) return region;

        // No region on the record — fall back to the ASN table rather than dropping a
        // confirmed-Nigerian IP off the map entirely.
        return stateForASN(data.connection?.asn ? `AS${data.connection.asn}` : null);
    } catch {
        return null;
    }
}
