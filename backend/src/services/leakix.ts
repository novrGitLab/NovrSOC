// LeakIX — open-service and data-leak exposure lookups per host. Replaces Censys for network
// exposure enrichment.
//
// Verified live on 2026-09-09, and two things differ from how this is usually documented:
//   * There is NO /api/v1/host/{ip} route. It returns 404 {"title":"Not Found","description":
//     "No matching route found"}. The working route is GET https://leakix.net/host/{ip} with
//     `Accept: application/json`.
//   * The free tier is NOT keyless. With no key (or an empty one) every request returns
//     401 "Invalid API key". A free key is available by registering at leakix.net/settings/api.
//
// Both matter because the obvious implementation — treat any non-200 as "nothing found" and
// return `{ exposed: false }` — would report EVERY host as clean forever while unconfigured.
// In a security product a false "not exposed" is worse than an error, so an unconfigured or
// failing lookup is reported as `status: 'unconfigured' | 'error'`, never as a clean result.
// Only a genuine 404 from the real route means "this host isn't in LeakIX", which is a real
// negative finding and is reported as such.

const LEAKIX_BASE = 'https://leakix.net';

export interface LeakIXService {
    port: number | null;
    protocol: string | null;
    software: string | null;
    version: string | null;
    summary: string | null;
}

export interface LeakIXLeak {
    severity: string | null;
    plugin: string | null;
    summary: string | null;
    time: string | null;
}

export interface LeakIXResult {
    // 'ok'        — LeakIX answered; `exposed` and the arrays below are meaningful
    // 'not_found' — LeakIX answered 404; the host genuinely has no records (a real negative)
    // 'unconfigured' — no LEAKIX_API_KEY set, so nothing was asked. NOT a clean result.
    // 'error'     — LeakIX rejected the key, rate-limited, or was unreachable. NOT a clean result.
    status: 'ok' | 'not_found' | 'unconfigured' | 'error';
    exposed: boolean;
    services: LeakIXService[];
    leaks: LeakIXLeak[];
    source: 'leakix';
    error?: string;
}

function getKey(): string {
    return (process.env.LEAKIX_API_KEY || '').trim();
}

export function isConfigured(): boolean {
    return getKey().length > 0;
}

function emptyResult(status: LeakIXResult['status'], error?: string): LeakIXResult {
    return { status, exposed: false, services: [], leaks: [], source: 'leakix', error };
}

interface LeakIXRawService {
    port?: number | string;
    protocol?: string;
    software?: { name?: string; version?: string };
    summary?: string;
}
interface LeakIXRawLeak {
    severity?: string;
    plugin?: string;
    summary?: string;
    time?: string;
    event_source?: string;
}
interface LeakIXRawResponse {
    Services?: LeakIXRawService[];
    Leaks?: LeakIXRawLeak[];
}

export async function checkLeakIX(ip: string): Promise<LeakIXResult> {
    if (!isConfigured()) {
        return emptyResult('unconfigured', 'LEAKIX_API_KEY not set — register a free key at leakix.net/settings/api');
    }

    try {
        const res = await fetch(`${LEAKIX_BASE}/host/${encodeURIComponent(ip)}`, {
            headers: { 'api-key': getKey(), Accept: 'application/json' },
            signal: AbortSignal.timeout(8000),
        });

        // A real 404 from the real route is a genuine "no records for this host".
        if (res.status === 404) return { ...emptyResult('not_found'), status: 'not_found' };

        if (res.status === 401 || res.status === 403) {
            console.warn('[LeakIX] Auth rejected — check LEAKIX_API_KEY');
            return emptyResult('error', 'LeakIX rejected the API key');
        }
        if (res.status === 429) return emptyResult('error', 'LeakIX rate limit reached');
        if (!res.ok) return emptyResult('error', `LeakIX returned HTTP ${res.status}`);

        const data = (await res.json()) as LeakIXRawResponse;

        const services: LeakIXService[] = (data.Services ?? []).map((s) => ({
            port: s.port != null ? Number(s.port) : null,
            protocol: s.protocol ?? null,
            software: s.software?.name ?? null,
            version: s.software?.version ?? null,
            summary: s.summary ?? null,
        }));

        const leaks: LeakIXLeak[] = (data.Leaks ?? []).map((l) => ({
            severity: l.severity ?? null,
            plugin: l.plugin ?? l.event_source ?? null,
            summary: l.summary ?? null,
            time: l.time ?? null,
        }));

        return {
            status: 'ok',
            exposed: services.length > 0 || leaks.length > 0,
            services,
            leaks,
            source: 'leakix',
        };
    } catch (err) {
        return emptyResult('error', err instanceof Error ? err.message : 'unreachable');
    }
}
