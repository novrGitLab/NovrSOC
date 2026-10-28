import { getAuthToken } from './account';
import { adminSignOut } from './admin-auth';
import { portalSignOut } from './portal-auth';
import { orgContextHeaderFor } from './orgContext';
import { isDemoModeEnabled, getDemoOrg } from './demo/state';
import { demoResponseFor } from './demo/router';

// Base URL of the standalone NovrSOC backend (see /backend). All same-origin `/api/...`
// fetch calls in this app are routed through apiUrl() so the origin lives in one place.
//
// Falls back to the deployed Railway backend, not localhost — so a Vercel build with
// NEXT_PUBLIC_BACKEND_URL unset still works instead of silently trying to call
// localhost:4001 from the browser. Local dev overrides this via frontend/.env.local.
//
// Updated 2026-09-09: the Railway service moved to novrsoc-production-1fb6. The old
// novrsoc-production host is gone, so any preview/production build deployed WITHOUT
// NEXT_PUBLIC_BACKEND_URL set was falling back to a dead origin and failing every call —
// which looks identical to a CORS problem in the browser console but isn't one.
// NEXT_PUBLIC_* is inlined at build time, so changing it in Vercel needs a redeploy to
// take effect; this fallback is what covers a build where it was never set.
export function apiUrl(path: string): string {
    const base = process.env.NEXT_PUBLIC_BACKEND_URL || 'https://novrsoc-production-1fb6.up.railway.app';
    return `${base}${path}`;
}

// Drop-in replacement for fetch() against apiUrl() targets — attaches whichever token this
// browser currently holds (portal_token for client-portal sessions, admin_token for admin
// sessions; see lib/account.ts's getAuthToken(), which already reads both) as a Bearer
// Authorization header, and signs the caller out on a 401.
//
// NOT every backend route verifies this header yet — most still don't (see
// backend/src/index.ts's mount list and its comment on why). Sending the header regardless
// is harmless: an unprotected route just ignores it. This wrapper exists so that whenever a
// route DOES start enforcing auth, every call site is already sending what it needs — no
// second migration required.
export async function apiFetch(input: string, init: RequestInit = {}): Promise<Response> {
    // Demo Mode (lib/demo/) answers every /api/* call from synthetic, seeded data and NEVER
    // falls through to the real network — not even for a path this file's router doesn't
    // recognise (those get a generic empty-but-valid body) — so enabling it can never leak a
    // real request to Wazuh, Supabase production, or any client endpoint. Checked first, before
    // auth headers or org context are even built.
    if (typeof window !== 'undefined' && isDemoModeEnabled()) {
        return demoFetch(input, init);
    }

    const token = getAuthToken();
    const headers = new Headers(init.headers);
    if (token) headers.set('Authorization', `Bearer ${token}`);
    // The organisation a staff session is viewing (lib/orgContext.ts; 2026 redesign Stage 2,
    // promoted from the VMS-only selector). The backend authorises and audits it; a client
    // session (executive, portal_user) never has this set, and the backend ignores the header
    // for those roles regardless.
    const org = orgContextHeaderFor(input);
    if (org && !headers.has('X-Org-Id')) headers.set('X-Org-Id', org);

    const res = await fetch(input, { ...init, headers });

    if (res.status === 401 && typeof window !== 'undefined') {
        // Sign out of whichever session actually sent this request's token — not just
        // whichever of the two tokens happens to be sitting in storage (a browser can hold
        // both at once; see lib/account.ts's getAuthToken()). Falls back to the current
        // route's own portal when no token was sent at all (never signed in on this path).
        if (token && token === localStorage.getItem('portal_token')) portalSignOut();
        else if (token && token === localStorage.getItem('admin_token')) adminSignOut();
        else if (window.location.pathname.startsWith('/client')) portalSignOut();
        else adminSignOut();
    }

    return res;
}

// Builds a synthetic Response for Demo Mode. `input` is always a full apiUrl() string here, so
// `new URL()` always succeeds; a malformed/relative input (shouldn't happen — every call site
// goes through apiUrl()) falls back to a safe empty 200 rather than throwing, since Demo Mode
// must never be the thing that crashes a screen.
function demoFetch(input: string, init: RequestInit): Promise<Response> {
    let pathname = '';
    let search = new URLSearchParams();
    try {
        const u = new URL(input);
        pathname = u.pathname;
        search = u.searchParams;
    } catch {
        // leave pathname empty — demoResponseFor() won't match anything, so the generic
        // empty-body fallback below still applies.
    }
    let requestBody: unknown;
    if (typeof init.body === 'string') {
        try { requestBody = JSON.parse(init.body); } catch { /* not JSON — leave undefined, as if no body was sent */ }
    }
    const result = (demoResponseFor(pathname, search, init.method ?? 'GET', getDemoOrg(), requestBody) ?? {}) as Record<string, unknown>;
    // '__demoStatus' (router.ts's withStatus()) lets a handful of endpoints answer with a
    // non-200 — e.g. AiPanel.tsx's existing "AI unavailable" state — instead of every demo
    // response being a fixed 200.
    const { __demoStatus, ...body } = result;
    const res = new Response(JSON.stringify(body), {
        status: typeof __demoStatus === 'number' ? __demoStatus : 200,
        headers: { 'Content-Type': 'application/json', 'X-Demo-Mode': '1' },
    });
    return Promise.resolve(res);
}
