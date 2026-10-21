// The organisation the VMS pages are viewing (redesign, phase P20). Staff may view another
// organisation: every /api/vms and /api/ai request made while a VMS page is open then carries the
// X-Org-Id header. The backend decides — it honours the header for staff roles only, checks the
// organisation exists and records the access in the audit log; for anyone else it is ignored.
// Held for this browser tab only (sessionStorage), so it never outlives the session.

const KEY = 'novrsoc_vms_org';
const EVENT = 'novrsoc:vms-org';

export function getVmsOrg(): string {
    if (typeof window === 'undefined') return '';
    try { return sessionStorage.getItem(KEY) ?? ''; } catch { return ''; }
}

export function setVmsOrg(slug: string): void {
    try { if (slug) sessionStorage.setItem(KEY, slug); else sessionStorage.removeItem(KEY); } catch { /* storage blocked: stay on own organisation */ }
    window.dispatchEvent(new Event(EVENT));
}

export function subscribeVmsOrg(cb: () => void): () => void {
    window.addEventListener(EVENT, cb);
    return () => window.removeEventListener(EVENT, cb);
}

/** The X-Org-Id value for a request to `url`, or '' — only VMS and AI calls made from a VMS page. */
export function vmsOrgHeaderFor(url: string): string {
    if (typeof window === 'undefined' || !window.location.pathname.startsWith('/admin/vms')) return '';
    if (!/\/api\/(vms|ai)(\/|\?|$)/.test(url)) return '';
    return getVmsOrg();
}
