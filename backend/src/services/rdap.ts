// RDAP — Domain WHOIS/registrar data
// Free, no key needed
//
// Note: backend/src/lib/dns-intel.ts already has fetchWhois() used by the existing Domain Suite
// (routes/domains.ts). This is a separate, dedicated RDAP client for the new services/ layer.

const RDAP_BASE = 'https://rdap.org';

interface VCardEntry extends Array<unknown> {
    0: string;
    3: string;
}

interface RDAPEntity {
    roles?: string[];
    vcardArray?: [string, VCardEntry[]];
    publicIds?: Array<{ type: string; identifier: string }>;
}

export interface RDAPResponse {
    ldhName: string;
    status: string[];
    events: Array<{ eventAction: string; eventDate: string }>;
    entities: RDAPEntity[];
    nameservers: Array<{ ldhName: string }>;
    secureDNS?: { delegationSigned: boolean };
}

export interface ParsedWhois {
    domain: string;
    registrar: string;
    created: string | null;
    updated: string | null;
    expires: string | null;
    nameservers: string[];
    status: string[];
    dnssec: boolean;
    daysUntilExpiry: number | null;
}

// Timeout is 20s, not 10s: rdap.org doesn't answer directly, it 302s to the authoritative
// registry (rdap.org/domain/google.com -> rdap.verisign.com/com/v1/domain/google.com), so every
// lookup is two round trips to two different hosts. Measured at ~6s from a developer machine,
// and lookups were returning null from Railway where the egress path is slower — 10s was not
// enough headroom for a two-hop request.
//
// Failures are logged rather than swallowed. This returns null for "no RDAP record" (plenty of
// ccTLDs publish none) AND for "the request failed", and callers can't tell those apart — the
// Domain Intelligence page renders both as an empty WHOIS tab. Without a log line there is
// nothing to distinguish a domain with no RDAP data from an outbound network problem.
const RDAP_TIMEOUT_MS = 20000;

export async function lookupDomain(domain: string): Promise<ParsedWhois | null> {
    try {
        const res = await fetch(`${RDAP_BASE}/domain/${domain}`, {
            signal: AbortSignal.timeout(RDAP_TIMEOUT_MS),
            headers: { Accept: 'application/json' },
        });

        if (!res.ok) {
            // 404 is the normal "this TLD/domain has no RDAP record" answer, not a fault.
            if (res.status !== 404) console.warn(`[rdap] ${domain}: upstream returned HTTP ${res.status}`);
            return null;
        }
        const data = (await res.json()) as RDAPResponse;
        return parseRDAP(domain, data);
    } catch (err) {
        console.warn(`[rdap] ${domain}: lookup failed —`, err instanceof Error ? err.message : err);
        return null;
    }
}

function parseRDAP(domain: string, data: RDAPResponse): ParsedWhois {
    const events = data.events || [];
    const getEvent = (action: string) => events.find((e) => e.eventAction === action)?.eventDate ?? null;

    const registrarEntity = data.entities?.find((e) => e.roles?.includes('registrar'));
    const registrar = registrarEntity?.vcardArray?.[1]?.find((v) => v[0] === 'fn')?.[3] ?? 'Unknown';

    const expires = getEvent('expiration');
    const daysUntilExpiry = expires ? Math.floor((new Date(expires).getTime() - Date.now()) / (1000 * 60 * 60 * 24)) : null;

    return {
        domain,
        registrar,
        created: getEvent('registration'),
        updated: getEvent('last changed'),
        expires,
        nameservers: (data.nameservers || []).map((ns) => ns.ldhName.toLowerCase()),
        status: data.status || [],
        dnssec: data.secureDNS?.delegationSigned ?? false,
        daysUntilExpiry,
    };
}
