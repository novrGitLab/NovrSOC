// CIRCL OSINT feed — the public MISP feed published by CIRCL (Computer Incident Response
// Center Luxembourg). Free, no API key, no registration. Replaces AlienVault OTX as this
// platform's threat-pulse source.
//
// Verified live on 2026-09-09 before this was written:
//   * https://www.circl.lu/doc/misp/feed-osint/ is an Apache DIRECTORY INDEX (text/html), not a
//     JSON document. Fetching it as JSON returns a 500KB HTML page. The real machine-readable
//     entry point is manifest.json.
//   * manifest.json is ~1.4MB of `{ "<event-uuid>": { info, date, Orgc, Tag[], timestamp, ... } }`
//     — one entry per published MISP event. That metadata alone is enough to render a pulse
//     feed, so the common path never downloads a single event file.
//   * Individual events live at `<uuid>.json` and contain the actual IOCs (Event.Attribute[]).
//     Those are fetched only when indicators are explicitly requested, since pulling every event
//     would mean thousands of requests.
//
// The manifest is large and changes at most a few times a day, so it's cached in-process.

const FEED_BASE = 'https://www.circl.lu/doc/misp/feed-osint';
const MANIFEST_TTL_MS = 6 * 60 * 60 * 1000; // 6h

// Deliberately mirrors the OTXPulse shape this platform's routes and the `threat_pulses` table
// already speak, so CIRCL is a drop-in replacement for the OTX pulse feed and nothing
// downstream had to change its field names.
export interface CIRCLPulse {
    id: string;
    name: string;
    description: string;
    tags: string[];
    attack_ids: Array<{ id: string; display_name: string }>;
    malware_families: Array<{ id: string; display_name: string }>;
    created: string;
    author: string;
    tlp: string;
}

interface ManifestEntry {
    info?: string;
    date?: string;
    timestamp?: string | number;
    analysis?: number;
    threat_level_id?: number;
    Orgc?: { name?: string; uuid?: string };
    Tag?: Array<{ name?: string; colour?: string }>;
}
type Manifest = Record<string, ManifestEntry>;

let manifestCache: { data: Manifest; expires: number } | null = null;

async function fetchManifest(): Promise<Manifest | null> {
    if (manifestCache && manifestCache.expires > Date.now()) return manifestCache.data;
    try {
        // 20s: the manifest is ~1.4MB and CIRCL's server is not fast. This runs at most once
        // every 6 hours per process.
        const res = await fetch(`${FEED_BASE}/manifest.json`, { signal: AbortSignal.timeout(20000) });
        if (!res.ok) {
            console.warn(`[CIRCL] manifest.json -> HTTP ${res.status}`);
            return manifestCache?.data ?? null;
        }
        const data = (await res.json()) as Manifest;
        manifestCache = { data, expires: Date.now() + MANIFEST_TTL_MS };
        return data;
    } catch (err) {
        console.warn('[CIRCL] manifest fetch failed:', err instanceof Error ? err.message : err);
        // Serve stale rather than nothing — an expired manifest is still useful threat context.
        return manifestCache?.data ?? null;
    }
}

// MISP tags carry structured meaning in their names. Pull the MITRE technique ids and TLP out
// of them so pulses keep the same fields the OTX-shaped consumers read.
function parseTags(entry: ManifestEntry): { tags: string[]; attackIds: Array<{ id: string; display_name: string }>; tlp: string } {
    const rawTags = (entry.Tag ?? []).map((t) => t.name ?? '').filter(Boolean);
    const attackIds: Array<{ id: string; display_name: string }> = [];
    let tlp = 'white';

    for (const tag of rawTags) {
        const lower = tag.toLowerCase();
        if (lower.startsWith('tlp:')) {
            tlp = lower.slice(4);
            continue;
        }
        // e.g. misp-galaxy:mitre-attack-pattern="Phishing - T1566"
        const attack = tag.match(/\bT\d{4}(?:\.\d{3})?\b/);
        if (attack && /mitre|attack/i.test(tag)) {
            const display = tag.includes('=') ? tag.split('=').pop()!.replace(/"/g, '') : attack[0];
            attackIds.push({ id: attack[0], display_name: display });
        }
    }

    return { tags: rawTags, attackIds, tlp };
}

function entryToPulse(uuid: string, entry: ManifestEntry): CIRCLPulse {
    const { tags, attackIds, tlp } = parseTags(entry);
    // `timestamp` is unix seconds as a string; `date` is YYYY-MM-DD. Prefer the precise one.
    const ts = Number(entry.timestamp);
    const created = Number.isFinite(ts) && ts > 0
        ? new Date(ts * 1000).toISOString()
        : entry.date
            ? new Date(`${entry.date}T00:00:00Z`).toISOString()
            : new Date().toISOString();

    return {
        id: uuid,
        name: entry.info ?? 'Untitled CIRCL event',
        description: entry.info ?? '',
        tags,
        attack_ids: attackIds,
        malware_families: [],
        created,
        author: entry.Orgc?.name ?? 'CIRCL',
        tlp,
    };
}

// Most recent events first. This is the CIRCL equivalent of otxGetPulses().
export async function circlGetPulses(limit = 20): Promise<CIRCLPulse[]> {
    const manifest = await fetchManifest();
    if (!manifest) return [];

    return Object.entries(manifest)
        .map(([uuid, entry]) => entryToPulse(uuid, entry))
        .sort((a, b) => b.created.localeCompare(a.created))
        .slice(0, limit);
}

// Free-text search across event titles and tags — the CIRCL equivalent of otxSearchPulses().
export async function circlSearchPulses(query: string, limit = 20): Promise<CIRCLPulse[]> {
    const manifest = await fetchManifest();
    if (!manifest) return [];

    const q = query.toLowerCase();
    return Object.entries(manifest)
        .map(([uuid, entry]) => entryToPulse(uuid, entry))
        .filter((p) => p.name.toLowerCase().includes(q) || p.tags.some((t) => t.toLowerCase().includes(q)))
        .sort((a, b) => b.created.localeCompare(a.created))
        .slice(0, limit);
}

export interface CIRCLIndicator {
    type: string;
    value: string;
    category: string;
    comment: string;
}

interface MISPEventFile {
    Event?: {
        Attribute?: Array<{ type?: string; value?: string; category?: string; comment?: string }>;
    };
}

// Pulls the actual IOCs out of one event. Only called for a specific event the caller already
// chose from the manifest — never in a loop over the whole feed.
export async function circlGetPulseIndicators(uuid: string): Promise<CIRCLIndicator[]> {
    try {
        const res = await fetch(`${FEED_BASE}/${encodeURIComponent(uuid)}.json`, { signal: AbortSignal.timeout(15000) });
        if (!res.ok) return [];
        const data = (await res.json()) as MISPEventFile;
        return (data.Event?.Attribute ?? [])
            .filter((a) => a.value)
            .map((a) => ({
                type: a.type ?? 'unknown',
                value: a.value!,
                category: a.category ?? '',
                comment: a.comment ?? '',
            }));
    } catch {
        return [];
    }
}

// No key to check — the feed is open. Reports whether it's actually reachable, which is the only
// meaningful health question for a keyless source.
export async function isCIRCLReachable(): Promise<boolean> {
    const manifest = await fetchManifest();
    return manifest !== null;
}
