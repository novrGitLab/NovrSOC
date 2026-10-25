// The organisation a staff session is viewing (2026 redesign, Stage 2 — promoted from the
// VMS-only selector, lib/vmsOrg.ts). Staff (super_admin, soc_manager, analyst) may view another
// organisation: every request apiFetch() sends then carries the X-Org-Id header. The backend
// decides on every request (lib/resolveOrg.ts) — it honours the header for staff roles only,
// checks the organisation exists, limits an analyst to organisations they are assigned to
// (staff_org_assignments), and records the access in the audit log; for a client role
// (executive, portal_user) the header is always ignored, whatever this holds.
// Held for this browser tab only (sessionStorage), so it never outlives the session, and persists
// across internal navigation within it (a page reload keeps the same tab's sessionStorage).
//
// NOT every backend route resolves this header yet (lib/permissions.ts's requireOrg /
// requirePermission do; some older routes, e.g. Brand Protection, have no organisation concept at
// all) — sending it regardless is harmless, the same reasoning as the Authorization header in
// apiFetch() below. See NOVRSOC_REDESIGN_TECHNICAL_AUDIT_V2.md F-05 / F-11 for which routes were
// specifically audited and fixed as part of adopting this broadly.

const KEY = 'novrsoc_org_context';
const EVENT = 'novrsoc:org-context';

export function getOrgContext(): string {
    if (typeof window === 'undefined') return '';
    try { return sessionStorage.getItem(KEY) ?? ''; } catch { return ''; }
}

export function setOrgContext(slug: string): void {
    try { if (slug) sessionStorage.setItem(KEY, slug); else sessionStorage.removeItem(KEY); } catch { /* storage blocked: stay on own organisation */ }
    window.dispatchEvent(new Event(EVENT));
}

export function subscribeOrgContext(cb: () => void): () => void {
    window.addEventListener(EVENT, cb);
    return () => window.removeEventListener(EVENT, cb);
}

/** The X-Org-Id value for a request to `url` — any /api/* call, while a staff session is viewing another organisation. */
export function orgContextHeaderFor(url: string): string {
    if (typeof window === 'undefined') return '';
    if (!/\/api\//.test(url)) return '';
    return getOrgContext();
}
