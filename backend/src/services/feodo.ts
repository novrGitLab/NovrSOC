// Feodo Tracker — abuse.ch's botnet C2 blocklist (Dridex, Emotet, TrickBot, QakBot, …).
//
// Keyless, unlike the rest of abuse.ch's APIs: it's a static JSON file, not the v1 API, so it
// needs no Auth-Key and keeps working if THREATFOX_API_KEY/URLHAUS_API_KEY are ever unset.
//
// Expect a SHORT list. Confirmed live on 2026-09-17 this returned 5 entries, only 1 of them
// still 'online' — it tracks currently-known C2 servers, not a historical archive, so a handful
// of rows is the normal state and not a sign the fetch failed. The live IOC feed leans on
// ThreatFox (~1,500/day) for volume and uses this for high-confidence C2 attribution.

const FEODO_URL = 'https://feodotracker.abuse.ch/downloads/ipblocklist.json';

export interface FeodoEntry {
    ip_address: string;
    port: number;
    status: string; // 'online' | 'offline'
    hostname: string | null;
    as_number: number | null;
    as_name: string | null;
    country: string | null;
    first_seen: string | null;
    last_online: string | null;
    malware: string | null;
}

export async function feodoGetBlocklist(): Promise<FeodoEntry[]> {
    try {
        const res = await fetch(FEODO_URL, { signal: AbortSignal.timeout(10000) });
        if (!res.ok) return [];
        const data = await res.json();
        return Array.isArray(data) ? (data as FeodoEntry[]) : [];
    } catch {
        return [];
    }
}
