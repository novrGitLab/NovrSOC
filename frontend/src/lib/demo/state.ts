// Demo Mode state (management-demo preparation). Deliberately separate from lib/orgContext.ts's
// real staff organisation switcher — enabling Demo Mode or picking a demo organisation here never
// touches orgContext, never sends a real X-Org-Id, and never changes which real organisation's
// data a staff session is authorised to see. This is a second, independent piece of client-only
// state, held in sessionStorage (this tab only, gone when the tab closes), exactly like
// orgContext.ts's own pattern.
//
// The actual safety boundary is in lib/api.ts's apiFetch(): while isDemoModeEnabled() is true,
// EVERY /api/* call is answered from lib/demo/router.ts, in-browser, and the real network is
// never touched — not "falls through to production for anything unmapped," always intercepted.

import type { DemoOrgId } from './types';
import { DEMO_ORG_IDS } from './orgs';
import { clearAllDemoOverlays } from './mutations';

const ENABLED_KEY = 'novrsoc_demo_mode';
const ORG_KEY = 'novrsoc_demo_org';
const EVENT = 'novrsoc:demo-mode';

export function isDemoModeEnabled(): boolean {
    if (typeof window === 'undefined') return false;
    try { return sessionStorage.getItem(ENABLED_KEY) === 'true'; } catch { return false; }
}

export function getDemoOrg(): DemoOrgId {
    if (typeof window === 'undefined') return 'lapo';
    try {
        const v = sessionStorage.getItem(ORG_KEY);
        return (DEMO_ORG_IDS as string[]).includes(v ?? '') ? (v as DemoOrgId) : 'lapo';
    } catch { return 'lapo'; }
}

export function setDemoMode(enabled: boolean, org?: DemoOrgId): void {
    try {
        sessionStorage.setItem(ENABLED_KEY, enabled ? 'true' : 'false');
        if (org) sessionStorage.setItem(ORG_KEY, org);
    } catch { /* storage blocked: demo mode cannot be turned on, which is the safe failure */ }
    // Turning Demo Mode off resets every organisation's simulated clicks (lib/demo/mutations.ts)
    // so the next walkthrough starts from the same clean seeded state as the last one.
    if (!enabled) clearAllDemoOverlays();
    window.dispatchEvent(new Event(EVENT));
}

export function setDemoOrg(org: DemoOrgId): void {
    try { sessionStorage.setItem(ORG_KEY, org); } catch { /* ignore */ }
    window.dispatchEvent(new Event(EVENT));
}

export function subscribeDemoMode(cb: () => void): () => void {
    window.addEventListener(EVENT, cb);
    return () => window.removeEventListener(EVENT, cb);
}
