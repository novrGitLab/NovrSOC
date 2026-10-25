// Client-side JWT helpers shared by lib/admin-auth.ts and lib/portal-auth.ts. Display/expiry
// checks only — the backend is the sole source of truth for authorization; nothing here
// verifies a signature.

/** issueToken() (backend/src/routes/auth.ts) encodes each segment as base64URL (Buffer's
 * 'base64url'), which uses `-`/`_` and no padding — plain atob() expects standard base64
 * (`+`/`/`, padded) and throws on `-`/`_`. Every payload whose encoding happens to need those
 * characters (common; not every token) failed to decode here, silently (caught, returns null),
 * which read as "no exp claim" rather than a decode failure. */
function base64UrlToBase64(segment: string): string {
    const b64 = segment.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
    return b64 + pad;
}

/** The token's JSON payload, or null if it is missing or unreadable. Decode only — never used
 * for authorization (see module header). */
export function decodeJwtPayload(token: string): Record<string, unknown> | null {
    try {
        return JSON.parse(atob(base64UrlToBase64(token.split('.')[1] ?? '')));
    } catch {
        return null;
    }
}

/** The token's `exp` claim in epoch milliseconds, or null if it is missing or unreadable. */
export function decodeJwtExpiry(token: string): number | null {
    const payload = decodeJwtPayload(token);
    return typeof payload?.exp === 'number' ? payload.exp * 1000 : null;
}

/** A token with a readable, future `exp` claim. A token with no `exp` claim at all is treated
 * as not-expired (the backend still rejects it once it actually fails signature/claim checks);
 * only a present, past `exp` makes this false. */
export function isJwtLive(token: string): boolean {
    const expiry = decodeJwtExpiry(token);
    return expiry === null || Date.now() < expiry;
}
