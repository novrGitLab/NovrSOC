// Session-scoped local demo-state overlay (demo finalization sprint). A "simulated mutation" in
// Demo Mode is not just a stubbed success — a handful of the actions a presenter is actually
// likely to click during the walkthrough (verify a remediation, change a case's status, approve
// a response) now visibly take effect for the rest of this browser tab's session, exactly as a
// real action would, without ever leaving the browser. Anything not covered here still gets an
// explicit "simulated — nothing was sent" response (see router.ts) rather than a silent no-op
// dressed up as success.
import type { DemoOrgId } from './types';

const PREFIX = 'novrsoc_demo_overlay';
export type DemoOverlayKind = 'vms-findings' | 'cases' | 'response-approvals';

function storageKey(org: DemoOrgId, kind: DemoOverlayKind): string {
    return `${PREFIX}:${org}:${kind}`;
}

function readAll(org: DemoOrgId, kind: DemoOverlayKind): Record<string, Record<string, unknown>> {
    if (typeof window === 'undefined') return {};
    try {
        const raw = window.sessionStorage.getItem(storageKey(org, kind));
        return raw ? JSON.parse(raw) : {};
    } catch { return {}; }
}

function writeAll(org: DemoOrgId, kind: DemoOverlayKind, all: Record<string, Record<string, unknown>>): void {
    if (typeof window === 'undefined') return;
    try { window.sessionStorage.setItem(storageKey(org, kind), JSON.stringify(all)); } catch { /* storage blocked — the click still "succeeds" via router.ts, it just won't visibly persist */ }
}

/** Merges a patch into one entity's session overlay — e.g. a finding's status after a simulated
 * "mark verified" click. Shallow-merged onto whatever the seeded generator already produced. */
export function setDemoOverlay(org: DemoOrgId, kind: DemoOverlayKind, id: string, patch: Record<string, unknown>): void {
    const all = readAll(org, kind);
    all[id] = { ...all[id], ...patch };
    writeAll(org, kind, all);
}

/** Prepends `item` onto an array field of one entity's overlay (e.g. appending a new case note). */
export function prependDemoListField(org: DemoOrgId, kind: DemoOverlayKind, id: string, listField: string, item: unknown): void {
    const all = readAll(org, kind);
    const existing = (all[id]?.[listField] as unknown[] | undefined) ?? [];
    all[id] = { ...all[id], [listField]: [item, ...existing] };
    writeAll(org, kind, all);
}

/** Applies a stored overlay patch onto one entity for a GET read, if one exists. Base object
 * fields always come from the deterministic seeded generator; only overlay keys override them. */
export function applyDemoOverlay<T extends { id: string }>(org: DemoOrgId, kind: DemoOverlayKind, item: T): T {
    const patch = readAll(org, kind)[item.id];
    return patch ? { ...item, ...patch } : item;
}

/** Clears every overlay for every demo organisation — called when Demo Mode is switched off
 * (lib/demo/state.ts), so the next time it's turned on, every org starts clean again. Overlays
 * otherwise persist across org switches within the same session — a presenter flipping back to
 * an org they already clicked something in should still see that change. */
export function clearAllDemoOverlays(): void {
    if (typeof window === 'undefined') return;
    try {
        for (let i = window.sessionStorage.length - 1; i >= 0; i--) {
            const k = window.sessionStorage.key(i);
            if (k?.startsWith(`${PREFIX}:`)) window.sessionStorage.removeItem(k);
        }
    } catch { /* storage blocked — nothing to clear */ }
}
