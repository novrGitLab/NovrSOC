// HTTP for provider connectors: timeouts, bounded retries with backoff, Retry-After on 429 /
// 503, and errors typed by what the UI needs to say (auth vs permission vs sync).
export class ConnectorAuthError extends Error { constructor(m: string) { super(m); this.name = 'ConnectorAuthError'; } }
export class ConnectorPermissionError extends Error { constructor(m: string) { super(m); this.name = 'ConnectorPermissionError'; } }
export class ConnectorSyncError extends Error { constructor(m: string) { super(m); this.name = 'ConnectorSyncError'; } }

type FetchFn = typeof fetch;
let fetchImpl: FetchFn = (...a) => fetch(...a);
/** Tests only. */
export function setConnectorFetch(fn: FetchFn | null): void { fetchImpl = fn ?? ((...a) => fetch(...a)); }

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function requestJson<T>(url: string, init: RequestInit, label: string, retries = 3): Promise<T> {
    for (let attempt = 0; ; attempt++) {
        let res: Response;
        try {
            res = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(20_000) });
        } catch (err) {
            if (attempt < retries) { await sleep(500 * 2 ** attempt); continue; }
            throw new ConnectorSyncError(`${label}: network error — ${(err as Error).message}`);
        }
        if ((res.status === 429 || res.status === 503 || res.status >= 500) && attempt < retries) {
            const after = Number(res.headers.get('retry-after'));
            await sleep(Number.isFinite(after) && after > 0 ? Math.min(after, 60) * 1000 : 1000 * 2 ** attempt);
            continue;
        }
        const body = await res.json().catch(() => null) as (T & { error?: unknown; error_description?: string }) | null;
        if (res.ok && body) return body;
        const detail = (body as { error?: { message?: string } | string; error_description?: string } | null);
        // Graph: { error: { message } }. OAuth: { error: "code", error_description } — keep the
        // code, callers classify on it (e.g. Google's unauthorized_client).
        const msg = typeof detail?.error === 'object' ? detail.error?.message
            : typeof detail?.error === 'string' ? (detail.error_description ? `${detail.error}: ${detail.error_description}` : detail.error) : null;
        if (res.status === 401) throw new ConnectorAuthError(`${label}: ${msg ?? 'authentication failed (HTTP 401)'}`);
        if (res.status === 403) throw new ConnectorPermissionError(`${label}: ${msg ?? 'permission denied (HTTP 403)'}`);
        throw new ConnectorSyncError(`${label}: HTTP ${res.status}${msg ? ` — ${msg}` : ''}`);
    }
}
