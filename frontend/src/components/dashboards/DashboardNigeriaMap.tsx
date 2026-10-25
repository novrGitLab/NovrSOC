'use client';

// The dashboard's Nigeria map (2026 redesign, Stage 4) — reuses the Threat Intelligence map's own
// component and data source (GET /api/ti/map) instead of the dashboard's previous, separately
// maintained map (components/geo/NigeriaThreatMap.tsx + NigeriaMap2.tsx, built from the since-
// removed Nigerian intel collector's cumulative, never-deduplicated counters, retired alongside
// this change — see NOVRSOC_REDESIGN_TECHNICAL_AUDIT_V2.md F-04). The global threat map
// (components/geo/GlobalThreatMap.tsx) is removed from the dashboard outright, per the brief —
// it mixed two unrelated things on one map (internet-wide scanning telemetry when GreyNoise is
// configured, or else this organisation's own alert sources) under a single "threats" label.
//
// Shows the "hosted infrastructure" layer (country-wide, not org-specific) by default — a
// compact summary belongs on a shared dashboard; the full page (with the exposure layer, period
// and sector filters, and per-report detail) is one click away.
import Link from 'next/link';
import { ChevronRight, Map as MapIcon } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { useState, useEffect, useMemo } from 'react';
import { NigeriaStateMap } from '@/components/features/ti/NigeriaStateMap';
import type { MapData } from '@/lib/ti';

type Load = { state: 'loading' } | { state: 'ok'; data: MapData } | { state: 'error'; error: string };

export function DashboardNigeriaMap() {
    const [load, setLoad] = useState<Load>({ state: 'loading' });

    useEffect(() => {
        let active = true;
        apiFetch(apiUrl('/api/ti/map?days=30'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(async (r) => {
                const data = await r.json().catch(() => null);
                if (!active) return;
                if (!r.ok || !data) { setLoad({ state: 'error', error: data?.error ?? `HTTP ${r.status}` }); return; }
                setLoad({ state: 'ok', data });
            })
            .catch((e: unknown) => { if (active) setLoad({ state: 'error', error: e instanceof Error ? e.message : 'Could not reach the backend' }); });
        return () => { active = false; };
    }, []);

    const counts = useMemo(() => new Map((load.state === 'ok' ? load.data.states : []).map((s) => [s.state, s.hosted])), [load]);

    return (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
            <div className="h-[3px] bg-blue" />
            <div className="p-4 flex items-center justify-between">
                <div>
                    <p className="text-xs font-black text-foreground flex items-center gap-1.5"><MapIcon size={13} aria-hidden /> Nigeria Threat Map</p>
                    <p className="text-[10px] text-foreground-muted">Indicator infrastructure hosted in Nigeria, last 30 days · hosting is not an attack origin</p>
                </div>
                <Link href="/admin/ti/map" className="flex items-center gap-1 text-[10px] font-bold text-blue hover:underline shrink-0">
                    Open Threat Intelligence <ChevronRight size={12} />
                </Link>
            </div>
            <div className="px-4 pb-4">
                {load.state === 'loading' ? (
                    <div className="h-64 bg-card-muted rounded-xl animate-pulse" />
                ) : load.state === 'error' ? (
                    <p className="text-xs text-foreground-muted text-center py-8">Map unavailable — {load.error}</p>
                ) : (
                    <NigeriaStateMap counts={counts} layer="hosted" compact />
                )}
            </div>
        </div>
    );
}
