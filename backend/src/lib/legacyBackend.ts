// The two external services this backend used to proxy to, and the single place their base URLs
// are resolved.
//
// Both previously defaulted to a hardcoded `http://138.197.188.132:4000` / `:8001` in ~14 files.
// That host is unreachable from Railway (PRODUCTION_NOTES.md, Known Issues #1), so every one of
// those proxies spent its full AbortSignal.timeout budget — up to 5 seconds — waiting on a dead
// TCP connect before falling back. Multiply that across a page that fans out to several of them
// and the UI just sits there.
//
// Defaulting to an empty string instead makes an unconfigured proxy fail in microseconds
// (fetch('') throws a TypeError synchronously rather than opening a socket), which every call
// site already handles: they're all wrapped in try/catch with an honest empty/502 fallback. Use
// the `is*Configured()` guards to skip the attempt entirely and return the honest answer
// directly, which is clearer than relying on a thrown URL parse error.

export const APP_BACKEND_URL = process.env.APP_API_BASE_URL || '';
export const CTIP_URL = process.env.CTIP_API_URL || '';

export function isAppBackendConfigured(): boolean {
    return APP_BACKEND_URL.length > 0;
}

export function isCTIPConfigured(): boolean {
    return CTIP_URL.length > 0;
}

// Logged once per process per service rather than per request — these are steady-state
// conditions, not incidents, and a per-request warning would drown the Railway logs.
const warned = new Set<string>();
export function warnUnconfiguredOnce(service: 'APP_API_BASE_URL' | 'CTIP_API_URL', context: string): void {
    if (warned.has(service)) return;
    warned.add(service);
    console.warn(`[${service}] not configured — ${context} returns an empty result until it is set.`);
}
