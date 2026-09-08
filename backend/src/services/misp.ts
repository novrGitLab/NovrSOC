// MISP — central threat-intelligence brain. Events/attributes are read for CTI enrichment and
// written when the Nigerian collector finds a new IOC.
//
// Live-verified against the configured instance on 2026-09-07, before any of this was written:
//   * The host IS a real MISP and IS reachable — but ONLY over https. Plain http 301-redirects
//     (nginx), and a 301 turns a POST into a GET in both fetch() and curl, so every write would
//     have silently become a no-op read against the configured http:// URL. normalizeBase()
//     below upgrades http -> https for this reason; MISP_URL can stay as-is in the environment.
//   * Its TLS certificate is self-signed, so Node rejects it unless NODE_TLS_REJECT_UNAUTHORIZED=0
//     is set (it is, in backend/.env — see the warning that prints on boot).
//   * The configured MISP_API_KEY is REJECTED: every endpoint tried (/servers/getVersion,
//     /servers/getPyMISPVersion, /events/index, /attributes/restSearch) returns
//     403 {"name":"Authentication failed. Please make sure you pass the API key of an API
//     enabled user along in the Authorization header."}. The key is the right shape (40 chars),
//     so this is a wrong/expired key or a user without API access enabled — not a bug here.
//     Everything below therefore degrades to null/[]/no-op rather than throwing, and
//     getMISPStats() reports `auth_failed` so Platform Health can show WHY it's down instead of
//     just "unreachable". It starts returning real data the moment a working key is set.

function normalizeBase(): string {
    const raw = (process.env.MISP_URL || '').trim().replace(/\/+$/, '');
    if (!raw) return '';
    // http:// 301s to https:// on this instance — follow that up front so POSTs keep their body.
    return raw.startsWith('http://') ? raw.replace(/^http:\/\//, 'https://') : raw;
}

function getKey(): string {
    return (process.env.MISP_API_KEY || '').trim();
}

export function isMISPConfigured(): boolean {
    return !!(normalizeBase() && getKey());
}

function mispHeaders(): Record<string, string> {
    return {
        Authorization: getKey(),
        'Content-Type': 'application/json',
        Accept: 'application/json',
    };
}

// Every call funnels through here so auth failures are logged once, consistently, and never
// bubble up as exceptions into a route handler or a background job.
async function mispFetch<T>(path: string, init: RequestInit = {}, timeoutMs = 8000): Promise<T | null> {
    if (!isMISPConfigured()) return null;
    try {
        const res = await fetch(`${normalizeBase()}${path}`, {
            ...init,
            headers: { ...mispHeaders(), ...(init.headers as Record<string, string> | undefined) },
            signal: AbortSignal.timeout(timeoutMs),
        });
        if (res.status === 401 || res.status === 403) {
            console.warn(`[MISP] Auth rejected on ${path} — check MISP_API_KEY belongs to an API-enabled user`);
            return null;
        }
        if (!res.ok) {
            console.warn(`[MISP] ${path} -> HTTP ${res.status}`);
            return null;
        }
        return (await res.json()) as T;
    } catch (err) {
        console.warn(`[MISP] ${path} request failed:`, err instanceof Error ? err.message : err);
        return null;
    }
}

export interface MISPEvent {
    id?: string;
    info?: string;
    date?: string;
    threat_level_id?: string;
    Tag?: Array<{ name?: string }>;
}

// GET recent events. MISP returns either a bare array or { response: [...] } depending on
// version/endpoint, and wraps each row in an `Event` key — normalized to a flat list here.
export async function getMISPEvents(limit = 20): Promise<MISPEvent[]> {
    const data = await mispFetch<unknown>(`/events/index/limit:${limit}/sort:date/direction:desc`);
    if (!data) return [];
    const rows: unknown[] = Array.isArray(data)
        ? data
        : Array.isArray((data as { response?: unknown[] }).response)
            ? ((data as { response: unknown[] }).response)
            : [];
    return rows.map((row) => {
        const r = row as { Event?: MISPEvent } & MISPEvent;
        return r.Event ?? r;
    });
}

export interface MISPSearchResult {
    found: boolean;
    count: number;
    events: string[];
    attributes: Array<{ type?: string; value?: string; category?: string; event_id?: string; comment?: string }>;
    source: 'misp';
}

// Search MISP for a single IOC value (IP, domain, hash, URL).
export async function searchMISP(value: string): Promise<MISPSearchResult | null> {
    const data = await mispFetch<{ response?: { Attribute?: MISPSearchResult['attributes'] } }>(
        '/attributes/restSearch',
        { method: 'POST', body: JSON.stringify({ returnFormat: 'json', value, limit: 10 }) }
    );
    const attrs = data?.response?.Attribute ?? [];
    if (attrs.length === 0) return null;
    return {
        found: true,
        count: attrs.length,
        events: [...new Set(attrs.map((a) => a.event_id).filter((id): id is string => !!id))],
        attributes: attrs.slice(0, 5),
        source: 'misp',
    };
}

// Create an event and attach one attribute to it. Returns the new event id, or null if MISP
// isn't usable (unconfigured, unreachable, or — as today — rejecting the key).
export async function addToMISP(params: {
    title: string;
    iocType: string;
    iocValue: string;
    tags: string[];
}): Promise<string | null> {
    const event = await mispFetch<{ Event?: { id?: string } }>('/events/add', {
        method: 'POST',
        body: JSON.stringify({
            Event: {
                info: params.title,
                distribution: 0,
                threat_level_id: 2,
                analysis: 1,
                date: new Date().toISOString().split('T')[0],
                Tag: params.tags.map((name) => ({ name })),
            },
        }),
    });
    const eventId = event?.Event?.id;
    if (!eventId) return null;

    await mispFetch(`/attributes/add/${eventId}`, {
        method: 'POST',
        body: JSON.stringify({
            type: params.iocType,
            value: params.iocValue,
            to_ids: true,
            category: 'Network activity',
        }),
    }, 5000);
    return eventId;
}

// Attach an attribute to an existing event — used by the Nigerian collector, which keeps all of
// its IOCs on one long-lived event rather than creating one event per indicator.
export async function addAttributeToEvent(eventId: string, ioc: { type: string; value: string; comment: string }): Promise<boolean> {
    const result = await mispFetch(`/attributes/add/${eventId}`, {
        method: 'POST',
        body: JSON.stringify({
            type: ioc.type,
            value: ioc.value,
            comment: ioc.comment,
            to_ids: true,
            category: 'Network activity',
        }),
    }, 5000);
    return result !== null;
}

export interface MISPStats {
    configured: boolean;
    reachable: boolean;
    auth_ok: boolean;
    events: number;
    attributes: number;
    error?: string;
}

// Distinguishes the three failure modes that matter operationally: not configured at all,
// configured but the host won't answer, and configured + reachable but the key is rejected
// (which is the state this instance is in as of 2026-09-07).
export async function getMISPStats(): Promise<MISPStats> {
    if (!isMISPConfigured()) {
        return { configured: false, reachable: false, auth_ok: false, events: 0, attributes: 0, error: 'MISP_URL/MISP_API_KEY not set' };
    }
    try {
        const res = await fetch(`${normalizeBase()}/users/statistics`, {
            headers: mispHeaders(),
            signal: AbortSignal.timeout(6000),
        });
        if (res.status === 401 || res.status === 403) {
            return { configured: true, reachable: true, auth_ok: false, events: 0, attributes: 0, error: 'MISP rejected the API key (403) — key is invalid, expired, or its user is not API-enabled' };
        }
        if (!res.ok) {
            return { configured: true, reachable: true, auth_ok: false, events: 0, attributes: 0, error: `MISP returned HTTP ${res.status}` };
        }
        const data = (await res.json()) as { stats?: { event_count?: number; attribute_count?: number } };
        return {
            configured: true,
            reachable: true,
            auth_ok: true,
            events: data.stats?.event_count ?? 0,
            attributes: data.stats?.attribute_count ?? 0,
        };
    } catch (err) {
        return {
            configured: true,
            reachable: false,
            auth_ok: false,
            events: 0,
            attributes: 0,
            error: err instanceof Error ? err.message : 'unreachable',
        };
    }
}
