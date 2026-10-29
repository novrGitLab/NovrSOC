'use client';

// Nigeria Threat Heatmap (2026 redesign; extended for the interactive heatmap brief). Reuses the
// existing NigeriaStateMap choropleth and its real data source (GET /api/ti/map) — indicator
// infrastructure hosted or matched in Nigeria, last 30 days.
//
// This used to also offer an illustrative "Sample" tab (synthetic per-state events, since no
// per-state network 5-tuple exists anywhere in this codebase) that loaded by default. Removed
// entirely, not just relabelled — the dashboard should never show synthetic data as its default
// view. Presentation Mode (lib/demo/) still works here without any of that: while it's on,
// apiFetch transparently answers this same GET /api/ti/map call with that organisation's sample
// data (clearly banner-labelled at the page level), so there is still a consistent, honest way to
// demo this widget — it just isn't a second, separate toggle living inside the widget itself.
import Link from 'next/link';
import { ChevronRight, Map as MapIcon, ZoomIn, ZoomOut } from 'lucide-react';
import { useState, useEffect, useMemo } from 'react';
import { apiUrl, apiFetch } from '@/lib/api';
import { NigeriaStateMap } from '@/components/features/ti/NigeriaStateMap';
import { useReducedMotion } from '@/components/features/vms/ui';
import type { MapData } from '@/lib/ti';

type Load = { state: 'loading' } | { state: 'ok'; data: MapData } | { state: 'error'; error: string };

export function DashboardNigeriaMap({ title = 'Nigeria Threat Map', description, context = 'dashboard' }: { title?: string; description?: string; context?: 'dashboard' | 'cnii' }) {
    const [load, setLoad] = useState<Load>({ state: 'loading' });
    const [selected, setSelected] = useState<string | null>(null);
    const [zoom, setZoom] = useState(1);
    const reducedMotion = useReducedMotion();

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

    const counts = useMemo(() => new Map((load.state === 'ok' ? load.data.states : []).map((s) => [s.state, s.hosted + s.exposure])), [load]);

    return (
        <div className="bg-card border border-border rounded-xl overflow-hidden relative">
            <div className="h-[3px] bg-blue" />
            <div className="p-4 flex items-center justify-between gap-2 flex-wrap">
                <div>
                    <p className="text-xs font-black text-foreground flex items-center gap-1.5"><MapIcon size={13} aria-hidden /> {title}</p>
                    <p className="text-[10px] text-foreground-muted">{description ?? 'Indicator infrastructure hosted or matched in Nigeria, last 30 days · hosting is not an attack origin'}</p>
                </div>
                {context === 'dashboard' && <Link href="/admin/ti/map" className="flex items-center gap-1 text-[10px] font-bold text-blue hover:underline shrink-0">Open TI <ChevronRight size={12} /></Link>}
            </div>

            <div className="px-4 pb-4 relative">
                {load.state === 'loading' ? (
                    <div className="h-64 bg-card-muted rounded-xl animate-pulse" />
                ) : load.state === 'error' ? (
                    <p className="text-xs text-foreground-muted text-center py-8">Map unavailable — {load.error}</p>
                ) : (
                    <>
                        <div className="absolute top-2 right-2 z-10 flex flex-col gap-1">
                            <button onClick={() => setZoom((z) => Math.min(2, z + 0.25))} aria-label="Zoom in" className="bg-card border border-border rounded-md p-1 hover:bg-card-muted"><ZoomIn className="w-3.5 h-3.5" /></button>
                            <button onClick={() => setZoom((z) => Math.max(1, z - 0.25))} aria-label="Zoom out" className="bg-card border border-border rounded-md p-1 hover:bg-card-muted"><ZoomOut className="w-3.5 h-3.5" /></button>
                        </div>
                        <div style={{ transform: `scale(${zoom})`, transformOrigin: 'center top', transition: reducedMotion ? undefined : 'transform 150ms ease-out' }}>
                            <NigeriaStateMap counts={counts} layer="other" countLabel="hosted + matched" selected={selected} onSelect={(s) => setSelected((cur) => (cur === s ? null : s))} compact shades="severity" />
                        </div>
                    </>
                )}

                {selected && (
                    <div className="mt-3 lg:absolute lg:top-2 lg:left-2 lg:max-w-xs lg:mt-0 lg:shadow-xl z-20 bg-card border border-purple/40 rounded-xl p-3 space-y-2">
                        <div className="flex items-center justify-between">
                            <p className="text-xs font-black text-foreground">{selected}</p>
                            <button onClick={() => setSelected(null)} aria-label="Close" className="text-foreground-muted hover:text-foreground">✕</button>
                        </div>
                        <p className="text-[11px] text-foreground-muted">{counts.get(selected) ?? 0} hosted/matched record(s). Open the full Threat Intelligence map for per-source reports.</p>
                    </div>
                )}
            </div>
        </div>
    );
}
