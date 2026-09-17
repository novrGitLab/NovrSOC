// URLHaus — Malicious URL and phishing link database
// Abuse.ch project — free, shares URLHAUS_API_KEY with services/threatfox.ts

const URLHAUS_BASE = 'https://urlhaus-api.abuse.ch/v1';
const KEY = process.env.URLHAUS_API_KEY ?? '';

export interface URLHausUrlEntry {
    id: string;
    url_status: string;
    date_added: string;
    url: string;
    threat: string;
    tags: string[] | null;
}

export interface URLHausResult {
    query_status: string;
    urlhaus_reference: string;
    url: string;
    url_status: string; // online | offline | unknown
    date_added: string;
    threat: string;     // malware_download | botnet_cc | phishing
    blacklists: { gsb_listing: string; surbl: string; spamhaus_dbl: string };
    tags: string[] | null;
    urls_on_this_host: URLHausUrlEntry[];
}

export interface URLHausHostResult {
    query_status: string;
    urlhaus_reference: string;
    url_count: number;
    blacklists: Record<string, string>;
    urls: URLHausUrlEntry[];
}

async function urlhausPost<T>(path: string, body: URLSearchParams): Promise<T | null> {
    try {
        const res = await fetch(`${URLHAUS_BASE}${path}`, {
            method: 'POST',
            headers: { 'Auth-Key': KEY, 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body.toString(),
            signal: AbortSignal.timeout(6000),
        });
        if (!res.ok) return null;
        const data = await res.json();
        if (data.query_status === 'no_results') return null;
        return data as T;
    } catch {
        return null;
    }
}

// Lookup a URL
export async function urlhausLookupURL(url: string): Promise<URLHausResult | null> {
    return urlhausPost<URLHausResult>('/url/', new URLSearchParams({ url }));
}

// Lookup a host (domain or IP)
export async function urlhausLookupHost(host: string): Promise<URLHausHostResult | null> {
    return urlhausPost<URLHausHostResult>('/host/', new URLSearchParams({ host }));
}

export interface URLHausPayloadResult {
    query_status: string;
    md5_hash: string;
    sha256_hash: string;
    file_type: string;
    file_size: string;
    signature: string | null;
    firstseen: string;
    urlhaus_download: string;
}

// Lookup by file hash (MD5 or SHA256)
export async function urlhausLookupHash(hash: string): Promise<URLHausPayloadResult | null> {
    return urlhausPost<URLHausPayloadResult>('/payload/', new URLSearchParams({ md5_hash: hash }));
}

// Recent malicious URLs for the live IOC feed — a bulk pull, not a lookup.
//
// Uses GET, unlike every other call in this file: the /urls/recent/ endpoint rejects POST with
// 405 `{"query_status":"http_get_expected"}` (confirmed live on 2026-09-17), so it can't share
// urlhausPost() above.
export interface URLHausRecentEntry {
    id: string;
    url: string;
    url_status: string;
    host: string;
    date_added: string;
    threat: string;
    tags: string[] | null;
    reporter: string | null;
    urlhaus_reference: string;
}

export async function urlhausGetRecent(limit = 100): Promise<URLHausRecentEntry[]> {
    try {
        const res = await fetch(`${URLHAUS_BASE}/urls/recent/?limit=${Math.min(limit, 1000)}`, {
            headers: { 'Auth-Key': KEY },
            signal: AbortSignal.timeout(10000),
        });
        if (!res.ok) return [];
        const data = (await res.json()) as { query_status?: string; urls?: URLHausRecentEntry[] };
        if (data.query_status !== 'ok' || !Array.isArray(data.urls)) return [];
        return data.urls;
    } catch {
        return [];
    }
}
