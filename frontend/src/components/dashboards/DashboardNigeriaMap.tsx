'use client';

// Nigeria Threat Heatmap (2026 redesign; extended for the interactive heatmap brief). Reuses the
// existing NigeriaStateMap choropleth and its real data source (GET /api/ti/map) for Live mode —
// no new backend route. No per-state network 5-tuple exists anywhere in this codebase (TI data
// has no event-level detail; CNII organisation profiles carry no geography at all — see the
// Sprint-2 frontend audit), so the interactive "latest event" panel below is honestly Demo Mode:
// clearly labelled, synthetic, and never mixed into the real counts. Demo state severities and
// events are fixed-but-shuffled client-side data, not derived from any IP's geolocation — per
// the brief, nothing here infers a location from an address.
import Link from 'next/link';
import { ChevronRight, Map as MapIcon, Radio, X, ZoomIn, ZoomOut, AlertTriangle } from 'lucide-react';
import { useState, useEffect, useMemo } from 'react';
import { apiUrl, apiFetch } from '@/lib/api';
import { NigeriaStateMap } from '@/components/features/ti/NigeriaStateMap';
import { NIGERIA_STATE_PATHS } from '@/components/features/ti/nigeriaPaths';
import { useReducedMotion } from '@/components/features/vms/ui';
import type { MapData } from '@/lib/ti';

type Load = { state: 'loading' } | { state: 'ok'; data: MapData } | { state: 'error'; error: string };
type Severity = 1 | 2 | 3 | 4;
const SEVERITY_LABEL: Record<Severity, string> = { 1: 'Low', 2: 'Moderate', 3: 'High', 4: 'Critical' };
const SEVERITY_COLOR: Record<Severity, string> = { 1: 'text-green', 2: 'text-amber', 3: 'text-orange', 4: 'text-red' };

interface DemoEvent { id: string; src_ip: string; dst_ip: string; src_port: number; dst_port: number; protocol: 'TCP' | 'UDP'; attack_type: string }
interface DemoState { severity: Severity; count: number; events: DemoEvent[] }

const ATTACK_TYPES = ['Brute Force Login', 'Port Scan', 'SQL Injection Attempt', 'Malware C2 Beacon', 'DDoS Probe', 'Credential Stuffing', 'Phishing Payload Retrieval', 'Lateral Movement Attempt'];
const PORTS = [22, 3389, 443, 80, 8080, 445, 3306, 21, 23, 5900];

// IANA-reserved documentation ranges (RFC 5737 / RFC 2544) — guaranteed not to be a real,
// routable address, so a demo 5-tuple can never be mistaken for a real attacker or asset.
function demoIp(rangeOctet: 113 | 100 | 2 | 18): string {
    const base = rangeOctet === 113 ? '203.0.113' : rangeOctet === 100 ? '198.51.100' : rangeOctet === 2 ? '192.0.2' : '198.18.0';
    return `${base}.${1 + Math.floor(Math.random() * 253)}`;
}
function makeEvent(i: number): DemoEvent {
    return {
        id: `demo-${i}-${Math.random().toString(36).slice(2, 8)}`,
        src_ip: demoIp(113), dst_ip: demoIp(18),
        src_port: PORTS[Math.floor(Math.random() * PORTS.length)], dst_port: PORTS[Math.floor(Math.random() * PORTS.length)],
        protocol: Math.random() > 0.3 ? 'TCP' : 'UDP',
        attack_type: ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)],
    };
}
/** One fixed-for-this-session synthetic severity + a small rotating event list per state — built
 * once (not re-randomised every render) so a selected state's events stay stable between ticks. */
function buildDemoData(): Map<string, DemoState> {
    const out = new Map<string, DemoState>();
    for (const p of NIGERIA_STATE_PATHS) {
        const r = Math.random();
        const severity: Severity = r > 0.92 ? 4 : r > 0.75 ? 3 : r > 0.45 ? 2 : 1;
        const count = severity * 4 + Math.floor(Math.random() * 4);
        const events = Array.from({ length: severity + 1 }, (_, i) => makeEvent(i));
        out.set(p.name === 'Nassarawa' ? 'Nasarawa' : p.name, { severity, count, events });
    }
    return out;
}

export function DashboardNigeriaMap({ title = 'Nigeria Threat Map', description, context = 'dashboard' }: { title?: string; description?: string; context?: 'dashboard' | 'cnii' }) {
    const [load, setLoad] = useState<Load>({ state: 'loading' });
    const [mode, setMode] = useState<'demo' | 'live'>('demo');
    const [selected, setSelected] = useState<string | null>(null);
    const [zoom, setZoom] = useState(1);
    const [eventIdx, setEventIdx] = useState(0);
    const reducedMotion = useReducedMotion();
    const demo = useMemo(() => buildDemoData(), []); // one fixed synthetic dataset per page load, not re-rolled on every render

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

    // Cycles the selected state's displayed demo event every 2s — only while demo mode is on and
    // a state with events is selected; nothing ticks for the real "live" layer, which has no
    // per-event detail to cycle through.
    useEffect(() => {
        if (mode !== 'demo' || !selected) return;
        // No explicit reset to 0 on selection change: the render below already wraps with
        // `% events.length`, so resuming mid-cycle on a newly selected state is harmless and
        // avoids a synchronous setState directly in the effect body.
        const id = setInterval(() => setEventIdx((i) => i + 1), 2000);
        return () => clearInterval(id);
    }, [mode, selected]);

    const realCounts = useMemo(() => new Map((load.state === 'ok' ? load.data.states : []).map((s) => [s.state, s.hosted + s.exposure])), [load]);
    const demoCounts = useMemo(() => new Map([...demo.entries()].map(([k, v]) => [k, v.count])), [demo]);
    const counts = mode === 'live' ? realCounts : demoCounts;
    const selectedDemo = selected ? demo.get(selected) : null;
    const currentEvent = selectedDemo && selectedDemo.events.length > 0 ? selectedDemo.events[eventIdx % selectedDemo.events.length] : null;

    return (
        <div className="bg-card border border-border rounded-xl overflow-hidden relative">
            <div className="h-[3px] bg-blue" />
            <div className="p-4 flex items-center justify-between gap-2 flex-wrap">
                <div>
                    <p className="text-xs font-black text-foreground flex items-center gap-1.5"><MapIcon size={13} aria-hidden /> {title}</p>
                    <p className="text-[10px] text-foreground-muted">{description ?? (mode === 'live' ? 'Indicator infrastructure hosted or matched in Nigeria, last 30 days · hosting is not an attack origin' : 'Simulated state threat activity for demonstration — see the DEMO badge below')}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                    <div className="flex gap-1 bg-card-muted rounded-lg p-0.5">
                        {(['demo', 'live'] as const).map((m) => (
                            <button key={m} onClick={() => { setMode(m); setSelected(null); }} className={`text-[10px] font-bold px-2 py-1 rounded-md ${mode === m ? 'bg-blue text-white' : 'text-foreground-muted'}`}>{m === 'demo' ? 'Demo' : 'Live'}</button>
                        ))}
                    </div>
                    {context === 'dashboard' && <Link href="/admin/ti/map" className="flex items-center gap-1 text-[10px] font-bold text-blue hover:underline">Open TI <ChevronRight size={12} /></Link>}
                </div>
            </div>

            {mode === 'demo' && (
                <div className="mx-4 mb-2 rounded-lg border border-amber/40 bg-amber/10 px-3 py-1.5 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber shrink-0" aria-hidden />
                    <p className="text-[10px] font-bold text-amber">DEMO MODE — every state severity and network event below is simulated for demonstration. None of it is a real threat.</p>
                </div>
            )}

            <div className="px-4 pb-4 relative">
                {load.state === 'loading' && mode === 'live' ? (
                    <div className="h-64 bg-card-muted rounded-xl animate-pulse" />
                ) : mode === 'live' && load.state === 'error' ? (
                    <p className="text-xs text-foreground-muted text-center py-8">Map unavailable — {load.error}</p>
                ) : (
                    <>
                        <div className="absolute top-2 right-2 z-10 flex flex-col gap-1">
                            <button onClick={() => setZoom((z) => Math.min(2, z + 0.25))} aria-label="Zoom in" className="bg-card border border-border rounded-md p-1 hover:bg-card-muted"><ZoomIn className="w-3.5 h-3.5" /></button>
                            <button onClick={() => setZoom((z) => Math.max(1, z - 0.25))} aria-label="Zoom out" className="bg-card border border-border rounded-md p-1 hover:bg-card-muted"><ZoomOut className="w-3.5 h-3.5" /></button>
                        </div>
                        <div style={{ transform: `scale(${zoom})`, transformOrigin: 'center top', transition: reducedMotion ? undefined : 'transform 150ms ease-out' }}>
                            <NigeriaStateMap counts={counts} layer={mode === 'live' ? 'other' : 'other'} countLabel={mode === 'live' ? 'hosted + matched' : 'simulated threat event(s)'} selected={selected} onSelect={(s) => setSelected((cur) => (cur === s ? null : s))} compact shades="severity" />
                        </div>
                    </>
                )}

                {selected && (
                    <div className="mt-3 lg:absolute lg:top-2 lg:left-2 lg:max-w-xs lg:mt-0 lg:shadow-xl z-20 bg-card border border-purple/40 rounded-xl p-3 space-y-2">
                        <div className="flex items-center justify-between">
                            <p className="text-xs font-black text-foreground">{selected}</p>
                            <button onClick={() => setSelected(null)} aria-label="Close" className="text-foreground-muted hover:text-foreground"><X className="w-3.5 h-3.5" /></button>
                        </div>
                        {mode === 'live' ? (
                            <p className="text-[11px] text-foreground-muted">{realCounts.get(selected) ?? 0} hosted/matched record(s) — no live per-event detail for this real layer. Switch to Demo Mode to see simulated event detail, or open the full Threat Intelligence map for real source reports.</p>
                        ) : selectedDemo && (
                            <>
                                <div className="flex items-center gap-2">
                                    <span className="relative flex h-2 w-2 shrink-0">
                                        {!reducedMotion && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red opacity-60" />}
                                        <span className="relative inline-flex h-2 w-2 rounded-full bg-red" />
                                    </span>
                                    <span className="text-[10px] font-bold text-red">DEMO · {selectedDemo.count} simulated event(s)</span>
                                    <span className={`text-[10px] font-bold ml-auto ${SEVERITY_COLOR[selectedDemo.severity]}`}>{SEVERITY_LABEL[selectedDemo.severity]}</span>
                                </div>
                                {currentEvent && (
                                    <div className="rounded-lg bg-card-muted p-2 text-[11px] space-y-1">
                                        <p className="font-bold text-foreground flex items-center justify-between"><span>{currentEvent.attack_type}</span><span className="text-[9px] text-foreground-muted font-normal">just now (demo)</span></p>
                                        <p className="font-mono text-foreground-muted">{currentEvent.src_ip}:{currentEvent.src_port} → {currentEvent.dst_ip}:{currentEvent.dst_port}</p>
                                        <p className="text-foreground-muted">Protocol: <span className="font-mono text-foreground">{currentEvent.protocol}</span></p>
                                    </div>
                                )}
                                <p className="text-[9px] text-foreground-muted flex items-center gap-1"><Radio className="w-3 h-3" aria-hidden /> Cycling every 2s · simulated data, not a real feed</p>
                            </>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
