'use client';

// Data access for the VMS pages (redesign, phase P20). useVmsData loads one endpoint, keeps the
// previous data on screen while reloading, and reports failures with the HTTP status (403 = not for
// this role, 503 = not set up). vmsSend runs a change and returns the backend's answer — the backend
// checks the permission and organisation, the page only reflects the result.

import { useCallback, useEffect, useState, useSyncExternalStore } from 'react';
import { loadJson } from '@/lib/alerts';
import { apiFetch, apiUrl } from '@/lib/api';
import { getAdminUser } from '@/lib/admin-auth';
import { getVmsOrg, subscribeVmsOrg } from '@/lib/vmsOrg';

export type Load<T> = { state: 'loading' } | { state: 'ok'; data: T } | { state: 'error'; error: string; status?: number };

/** The organisation being viewed ('' = the user's own); pages reload when it changes. */
export function useVmsOrg(): string {
    return useSyncExternalStore(subscribeVmsOrg, getVmsOrg, () => '');
}

export function useVmsData<T>(path: string | null): { load: Load<T>; data: T | null; reload: () => void; at: number | null } {
    const org = useVmsOrg();
    const [tick, setTick] = useState(0);
    const [res, setRes] = useState<{ key: string; load: Load<T>; at: number } | null>(null);
    const key = `${path}|${org}|${tick}`;
    useEffect(() => {
        if (!path) return;
        let active = true;
        void loadJson<T>(path, { signal: AbortSignal.timeout(30_000) }).then((r) => {
            if (!active) return;
            setRes({ key: `${path}|${org}|${tick}`, at: Date.now(), load: r.ok ? { state: 'ok', data: r.data } : { state: 'error', error: r.error, status: r.status } });
        });
        return () => { active = false; };
    }, [path, org, tick]);
    const reload = useCallback(() => setTick((t) => t + 1), []);
    // While a new request is in flight, keep showing the last good data (no skeleton flash).
    const load: Load<T> = !res ? { state: 'loading' } : res.key === key || res.load.state === 'ok' ? res.load : { state: 'loading' };
    return { load, data: res?.load.state === 'ok' ? res.load.data : null, reload, at: res?.at ?? null };
}

export async function vmsSend<T = Record<string, unknown>>(method: 'POST' | 'PATCH' | 'DELETE', path: string, body?: unknown): Promise<{ ok: true; data: T } | { ok: false; error: string; status: number }> {
    try {
        const r = await apiFetch(apiUrl(path), { method, headers: body === undefined ? undefined : { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
        const d = await r.json().catch(() => null);
        return r.ok ? { ok: true, data: (d ?? {}) as T } : { ok: false, error: d?.error ?? `HTTP ${r.status}`, status: r.status };
    } catch {
        return { ok: false, error: 'Could not reach the backend', status: 0 };
    }
}

export type VmsRole = 'super_admin' | 'soc_manager' | 'analyst' | 'executive' | 'portal_user' | string;
/**
 * What the signed-in role may do, mirroring backend/src/lib/permissions.ts. Used only to hide
 * controls that would be refused; the backend enforces every one of these on each request.
 */
export function useVmsCan() {
    const [role] = useState<VmsRole>(() => (typeof window === 'undefined' ? '' : getAdminUser().role));
    const staff = role === 'super_admin' || role === 'soc_manager' || role === 'analyst';
    // authorize (P27): the organisation's administrator (executive) or a super_admin approves scan authorisation.
    return { role, manage: staff, scan: staff, scope: role === 'super_admin' || role === 'soc_manager', authorize: role === 'executive' || role === 'super_admin', readOnly: !staff, superAdmin: role === 'super_admin' };
}
