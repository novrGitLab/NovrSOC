// Live SPF / DKIM / DMARC inspection for one domain. DNS goes through node's resolver with a
// per-query timeout; a record that isn't published (NXDOMAIN / NODATA) is "absent", while a
// lookup that fails for any other reason is reported as an error — never as "absent".
import { Resolver } from 'dns/promises';
import {
    parseSpf, parseDmarc, parseDkim, COMMON_DKIM_SELECTORS, authenticationHealth, domainStatusFromScore,
    spfStatus, dmarcStatus, dkimStatus, type SpfRecord, type DmarcRecord, type DkimRecord, type HealthPart, type CheckStatus,
} from './authRecords';

export interface DnsClient {
    txt(name: string): Promise<string[]>;
    mx(name: string): Promise<{ exchange: string; priority: number }[]>;
    /** First PTR name for an IP, or null. Never throws. */
    reverse(ip: string): Promise<string | null>;
}

const ABSENT = new Set(['ENOTFOUND', 'ENODATA', 'NXDOMAIN', 'ENONAME']);

function systemDns(): DnsClient {
    const r = new Resolver({ timeout: 4000, tries: 2 });
    const absent = (err: unknown) => ABSENT.has((err as { code?: string })?.code ?? '');
    return {
        async txt(name) {
            try { return (await r.resolveTxt(name)).map((chunks) => chunks.join('')); }
            catch (err) { if (absent(err)) return []; throw err; }
        },
        async mx(name) {
            try { return await r.resolveMx(name); }
            catch (err) { if (absent(err)) return []; throw err; }
        },
        async reverse(ip) {
            try { return (await r.reverse(ip))[0] ?? null; } catch { return null; }
        },
    };
}

let dnsOverride: DnsClient | null = null;
/** Tests only. */
export function setDnsClient(c: DnsClient | null): void { dnsOverride = c; }
export function dnsClient(): DnsClient { return dnsOverride ?? systemDns(); }

export interface DomainInspection {
    domain: string;
    checked_at: string;
    mx: { exchange: string; priority: number }[];
    spf: SpfRecord & { total_lookups: number | null; include_errors: string[] };
    dmarc: DmarcRecord;
    dkim: { selectors_checked: string[]; found: DkimRecord[] };
    statuses: { spf: CheckStatus; dkim: CheckStatus; dmarc: CheckStatus };
    health: { score: number; parts: HealthPart[]; status: 'healthy' | 'warning' | 'critical' };
    lookup_errors: string[];
}

const DOMAIN_RE = /^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$/i;
export function normalizeDomain(input: string): string | null {
    const d = input.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/\.$/, '');
    return DOMAIN_RE.test(d) ? d : null;
}

// Total DNS lookups including nested includes (RFC 7208 limit is 10), walked to depth 5.
async function countSpfLookups(dns: DnsClient, record: SpfRecord, errors: string[], depth = 0, seen = new Set<string>()): Promise<number> {
    let total = record.lookups;
    if (depth >= 5) return total;
    for (const inc of [...record.includes, ...(record.modifiers.redirect ? [record.modifiers.redirect] : [])]) {
        if (seen.has(inc)) continue;
        seen.add(inc);
        try {
            const nested = parseSpf(await dns.txt(inc));
            if (!nested.exists) { errors.push(`include:${inc} has no SPF record — receivers return permerror.`); continue; }
            total += await countSpfLookups(dns, nested, errors, depth + 1, seen);
        } catch (err) {
            errors.push(`include:${inc} could not be resolved (${(err as Error).message}).`);
        }
    }
    return total;
}

export async function inspectDomain(domain: string, extraSelectors: string[] = []): Promise<DomainInspection> {
    const dns = dnsClient();
    const lookupErrors: string[] = [];
    const safe = async <T>(label: string, fn: () => Promise<T>, fallback: T): Promise<T> => {
        try { return await fn(); } catch (err) { lookupErrors.push(`${label}: ${(err as Error).message}`); return fallback; }
    };

    const [rootTxt, dmarcTxt, mx] = await Promise.all([
        safe('TXT lookup', () => dns.txt(domain), [] as string[]),
        safe('DMARC lookup', () => dns.txt(`_dmarc.${domain}`), [] as string[]),
        safe('MX lookup', () => dns.mx(domain), [] as { exchange: string; priority: number }[]),
    ]);
    const spfBase = parseSpf(rootTxt);
    const includeErrors: string[] = [];
    const total = spfBase.exists ? await countSpfLookups(dns, spfBase, includeErrors) : null;
    const spf = { ...spfBase, total_lookups: total, include_errors: includeErrors };
    if (total !== null && total > 10 && spfBase.lookups <= 10) {
        spf.errors.push(`Including nested includes this record needs ${total} DNS lookups; the limit is 10, so receivers return permerror.`);
    }
    spf.errors.push(...includeErrors);

    const dmarc = parseDmarc(dmarcTxt);
    const selectors = [...new Set([...extraSelectors.map((s) => s.trim().toLowerCase()).filter(Boolean), ...COMMON_DKIM_SELECTORS])];
    const dkimFound: DkimRecord[] = [];
    // Probed in small batches: dozens of parallel queries to one authoritative server look like abuse.
    for (let i = 0; i < selectors.length; i += 8) {
        const batch = await Promise.all(selectors.slice(i, i + 8).map(async (sel) => {
            try { return parseDkim(sel, await dns.txt(`${sel}._domainkey.${domain}`)); } catch { return null; }
        }));
        for (const k of batch) if (k?.exists) dkimFound.push(k);
    }

    const health = authenticationHealth(spf, dmarc, dkimFound);
    return {
        domain,
        checked_at: new Date().toISOString(),
        mx,
        spf,
        dmarc,
        dkim: { selectors_checked: selectors, found: dkimFound },
        statuses: { spf: spfStatus(spf), dkim: dkimStatus(dkimFound), dmarc: dmarcStatus(dmarc) },
        health: { ...health, status: domainStatusFromScore(health.score) },
        lookup_errors: lookupErrors,
    };
}
