'use client';

// Real service status for the header (2026 redesign, Stage 1) — replaces the two permanently
// green "Telemetry Online" / "Cloud Node" pills, which never reflected anything (lib/api.ts and
// this component now do). What is shown depends on what this role can honestly read:
//   super_admin            GET /api/platform/health — the real, per-service platform check
//   soc_manager / analyst  the alert feed's own freshness (same meaning as AlertFeedStatus),
//                          since this role can't read platform-wide health
//   anything else          nothing — an executive or client-portal session has neither
//                          permission, and a status pill it can't honestly populate is worse
//                          than no pill at all.
import { useEffect, useState } from 'react';
import { apiUrl, apiFetch } from '@/lib/api';
import { usePolling } from '@/lib/usePolling';
import { fetchAlertStats, isStale, STALE_AFTER_MINUTES, watTime } from '@/lib/alerts';
import { StatusPill, Tip, type Tone } from '@/components/features/vms/ui';

interface PlatformHealth { overall: 'operational' | 'degraded' | 'outage'; services: { name: string; status: string; latency_ms?: number }[]; checked_at: string }

function usePlatformHealth() {
    const [health, setHealth] = useState<PlatformHealth | null | 'unavailable'>(null);
    const load = () =>
        apiFetch(apiUrl('/api/platform/health'), { cache: 'no-store' })
            .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
            .then((data: PlatformHealth) => setHealth(data))
            .catch(() => setHealth('unavailable'));
    useEffect(() => { load(); }, []);
    usePolling(load, 60_000);
    return health;
}

function PlatformPill() {
    const health = usePlatformHealth();
    if (health === null) return null;
    if (health === 'unavailable') return <StatusPill tone="neutral" label="Platform status unavailable" />;
    const tone: Tone = health.overall === 'operational' ? 'good' : health.overall === 'degraded' ? 'warning' : 'critical';
    const label = health.overall === 'operational' ? 'Operational' : health.overall === 'degraded' ? 'Degraded' : 'Outage';
    const detail = health.services.map((s) => `${s.name}: ${s.status}`).join(' · ');
    return (
        <Tip label={`${detail} · checked ${watTime(health.checked_at)}`}>
            <StatusPill tone={tone} label={label} />
        </Tip>
    );
}

function AlertFeedPill() {
    // checkedAt is captured once per load (not at render time) — same reasoning as
    // AlertFeedStatus.tsx: staleness is measured against when the page last asked, not against
    // whatever instant a re-render happens to occur at.
    const [state, setState] = useState<{ loaded: boolean; lastReceivedAt: string | null; notConnected: boolean; checkedAt: number } | null>(null);
    const load = () =>
        fetchAlertStats('24h').then((r) => {
            const checkedAt = Date.now();
            setState(r.ok ? { loaded: true, lastReceivedAt: r.data.last_received_at, notConnected: false, checkedAt } : { loaded: true, lastReceivedAt: null, notConnected: r.notConnected, checkedAt });
        });
    useEffect(() => { load(); }, []);
    usePolling(load, 60_000);
    if (!state?.loaded) return null;
    if (state.notConnected) return <StatusPill tone="neutral" label="Alert store not connected" />;
    if (state.lastReceivedAt === null) return <StatusPill tone="neutral" label="No alerts yet" />;
    const stale = isStale(state.lastReceivedAt, state.checkedAt, STALE_AFTER_MINUTES);
    return (
        <Tip label={`Last alert ${watTime(state.lastReceivedAt)}`}>
            <StatusPill tone={stale ? 'warning' : 'good'} label={stale ? 'Alerts stale' : 'Alerts flowing'} />
        </Tip>
    );
}

export function HeaderStatus({ role }: { role: string }) {
    if (role === 'super_admin') return <PlatformPill />;
    if (role === 'soc_manager' || role === 'analyst') return <AlertFeedPill />;
    return null;
}
