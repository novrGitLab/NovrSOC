const DOH_URL = 'https://cloudflare-dns.com/dns-query';
const CRTSH_URL = 'https://crt.sh/';
const RDAP_URL = 'https://rdap.org/domain';
import { CTIP_URL } from './legacyBackend';

export const DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA'] as const;
export type DnsRecordType = typeof DNS_RECORD_TYPES[number];

export function normalizeDomain(input: string): string {
    return input
        .trim()
        .toLowerCase()
        .replace(/^https?:\/\//, '')
        .replace(/\/.*$/, '')
        .replace(/^\*\./, '');
}

async function fetchWithTimeout(url: string, init: RequestInit = {}, timeoutMs = 8000): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        return await fetch(url, { ...init, signal: controller.signal });
    } finally {
        clearTimeout(timer);
    }
}

interface DohAnswer {
    name: string;
    type: number;
    TTL: number;
    data: string;
}
interface DohResponse {
    Status: number;
    Answer?: DohAnswer[];
}

async function queryDoh(domain: string, type: DnsRecordType): Promise<DohAnswer[]> {
    try {
        const res = await fetchWithTimeout(
            `${DOH_URL}?name=${encodeURIComponent(domain)}&type=${type}`,
            { headers: { Accept: 'application/dns-json' }, cache: 'no-store' }
        );
        if (!res.ok) return [];
        const data: DohResponse = await res.json();
        return data.Answer ?? [];
    } catch {
        return [];
    }
}

export interface MxRecord { name: string; ttl: number; priority: number; exchange: string; }
export interface TxtRecord { name: string; ttl: number; value: string; }
export interface SoaRecord { name: string; ttl: number; mname: string; rname: string; serial: string; refresh: string; retry: string; expire: string; minimum: string; }
export interface SimpleRecord { name: string; ttl: number; data: string; }

export interface DnsRecordSet {
    A: SimpleRecord[];
    AAAA: SimpleRecord[];
    MX: MxRecord[];
    TXT: TxtRecord[];
    NS: SimpleRecord[];
    CNAME: SimpleRecord[];
    SOA: SoaRecord[];
}

export async function resolveRecords(domain: string, types: DnsRecordType[]): Promise<DnsRecordSet> {
    const result: DnsRecordSet = { A: [], AAAA: [], MX: [], TXT: [], NS: [], CNAME: [], SOA: [] };

    await Promise.all(
        types.map(async (type) => {
            const answers = await queryDoh(domain, type);
            switch (type) {
                case 'MX':
                    result.MX = answers.map((a) => {
                        const [priority, ...rest] = a.data.split(' ');
                        return { name: a.name, ttl: a.TTL, priority: Number(priority) || 0, exchange: rest.join(' ') };
                    });
                    break;
                case 'TXT':
                    result.TXT = answers.map((a) => ({ name: a.name, ttl: a.TTL, value: a.data.replace(/^"|"$/g, '') }));
                    break;
                case 'SOA':
                    result.SOA = answers.map((a) => {
                        const parts = a.data.split(' ');
                        const [mname, rname, serial, refresh, retry, expire, minimum] = parts;
                        return { name: a.name, ttl: a.TTL, mname, rname, serial, refresh, retry, expire, minimum };
                    });
                    break;
                case 'A':
                    result.A = answers.map((a) => ({ name: a.name, ttl: a.TTL, data: a.data }));
                    break;
                case 'AAAA':
                    result.AAAA = answers.map((a) => ({ name: a.name, ttl: a.TTL, data: a.data }));
                    break;
                case 'NS':
                    result.NS = answers.map((a) => ({ name: a.name, ttl: a.TTL, data: a.data }));
                    break;
                case 'CNAME':
                    result.CNAME = answers.map((a) => ({ name: a.name, ttl: a.TTL, data: a.data }));
                    break;
            }
        })
    );

    return result;
}

export async function resolveIpAddresses(domain: string): Promise<string[]> {
    const answers = await queryDoh(domain, 'A');
    return Array.from(new Set(answers.map((a) => a.data)));
}

interface CrtShEntry {
    issuer_name: string;
    common_name: string;
    name_value: string;
    not_before: string;
    not_after: string;
    serial_number: string;
}

async function fetchCrtSh(query: string): Promise<CrtShEntry[]> {
    for (let attempt = 0; attempt < 2; attempt++) {
        try {
            const res = await fetchWithTimeout(
                `${CRTSH_URL}?q=${encodeURIComponent(query)}&output=json`,
                { cache: 'no-store' },
                15000
            );
            if (!res.ok) continue;
            const data = await res.json();
            return Array.isArray(data) ? data : [];
        } catch {
            // crt.sh is frequently rate-limited / flaky — retry once, then give up quietly.
        }
    }
    return [];
}

export interface CertEntry {
    issuer: string;
    common_name: string;
    san: string[];
    not_before: string;
    not_after: string;
    expired: boolean;
}

export async function fetchCertificates(domain: string): Promise<CertEntry[]> {
    const entries = await fetchCrtSh(domain);
    const now = Date.now();
    const seen = new Map<string, CertEntry>();

    for (const entry of entries) {
        const key = entry.serial_number || `${entry.common_name}-${entry.not_before}-${entry.not_after}`;
        if (seen.has(key)) continue;
        const san = Array.from(new Set(entry.name_value.split('\n').map((s) => s.trim()).filter(Boolean)));
        seen.set(key, {
            issuer: entry.issuer_name,
            common_name: entry.common_name,
            san,
            not_before: entry.not_before,
            not_after: entry.not_after,
            expired: new Date(entry.not_after).getTime() < now,
        });
    }

    return Array.from(seen.values()).sort((a, b) => new Date(b.not_before).getTime() - new Date(a.not_before).getTime());
}

export async function fetchSubdomains(domain: string): Promise<string[]> {
    const entries = await fetchCrtSh(`%.${domain}`);
    const subdomains = new Set<string>();

    for (const entry of entries) {
        for (const raw of entry.name_value.split('\n')) {
            const name = raw.trim().toLowerCase().replace(/^\*\./, '');
            if (name && name !== domain && name.endsWith(`.${domain}`)) {
                subdomains.add(name);
            }
        }
    }

    return Array.from(subdomains).sort();
}

export interface WhoisInfo {
    registrar: string | null;
    registered: string | null;
    expires: string | null;
    days_until_expiry: number | null;
}

interface RdapEntity {
    roles?: string[];
    vcardArray?: [string, [string, Record<string, unknown>, string, string][]];
}
interface RdapEvent {
    eventAction: string;
    eventDate: string;
}
interface RdapResponse {
    entities?: RdapEntity[];
    events?: RdapEvent[];
}

function vcardField(entity: RdapEntity, field: string): string | null {
    const arr = entity.vcardArray?.[1];
    if (!arr) return null;
    const match = arr.find((v) => v[0] === field);
    return match ? String(match[3]) : null;
}

export async function fetchWhois(domain: string): Promise<WhoisInfo> {
    try {
        const res = await fetchWithTimeout(`${RDAP_URL}/${encodeURIComponent(domain)}`, { cache: 'no-store' }, 10000);
        if (!res.ok) return { registrar: null, registered: null, expires: null, days_until_expiry: null };
        const data: RdapResponse = await res.json();

        const registrarEntity = data.entities?.find((e) => e.roles?.includes('registrar')) ?? null;
        const registrar = registrarEntity ? vcardField(registrarEntity, 'fn') : null;

        const registered = data.events?.find((e) => e.eventAction === 'registration')?.eventDate ?? null;
        const expires = data.events?.find((e) => e.eventAction === 'expiration')?.eventDate ?? null;

        const days_until_expiry = expires
            ? Math.round((new Date(expires).getTime() - Date.now()) / (1000 * 60 * 60 * 24))
            : null;

        return { registrar, registered, expires, days_until_expiry };
    } catch {
        return { registrar: null, registered: null, expires: null, days_until_expiry: null };
    }
}

export interface CtipMatch {
    confidence?: number;
    source?: string;
    threat_type?: string | null;
}

export async function checkCtipIoc(value: string): Promise<{ found: boolean; matches: CtipMatch[] }> {
    try {
        const res = await fetchWithTimeout(`${CTIP_URL}/api/ctip/iocs/${encodeURIComponent(value)}`, { cache: 'no-store' }, 8000);
        if (!res.ok) return { found: false, matches: [] };
        const data = await res.json();
        return { found: Boolean(data?.found), matches: Array.isArray(data?.matches) ? data.matches : [] };
    } catch {
        return { found: false, matches: [] };
    }
}

const SUSPICIOUS_SUBDOMAIN_KEYWORDS = ['login', 'secure', 'verify', 'account', 'update', 'confirm', 'signin', 'billing', 'reset'];

export function findSuspiciousSubdomains(subdomains: string[]): string[] {
    return subdomains.filter((s) => SUSPICIOUS_SUBDOMAIN_KEYWORDS.some((kw) => s.includes(kw)));
}
