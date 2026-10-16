'use client';

// Attack-surface map for one asset (phase P14): its addresses, assets sharing them, names under it,
// services, technologies and open findings — only relationships stored records support, each drawn
// by how it is known: confirmed (solid), observed (dashed) or inferred (dotted). Search, filters,
// zoom and pan; selecting an asset node opens that asset. Data: GET /api/vms/assets/:id/graph.

import { useEffect, useMemo, useRef, useState } from 'react';
import { ZoomIn, ZoomOut, Maximize2 } from 'lucide-react';
import { loadJson } from '@/lib/alerts';
import { fmtWat } from '@/lib/vms';

type Basis = 'confirmed' | 'observed' | 'inferred';
interface GNode { id: string; kind: 'asset' | 'ip' | 'service' | 'technology' | 'finding'; label: string; asset_id?: string; asset_type?: string; detail?: Record<string, unknown> }
interface GEdge { from: string; to: string; type: string; basis: Basis; source: string; observed_at: string | null }
interface Graph { root: string; nodes: GNode[]; edges: GEdge[]; truncated: boolean }

const KIND_COLOR: Record<GNode['kind'], string> = { asset: '#7c3aed', ip: '#2563eb', service: '#059669', technology: '#64748b', finding: '#dc2626' };
const DASH: Record<Basis, string> = { confirmed: '', observed: '6 4', inferred: '2 4' };
const W = 900;
const H = 560;

/** Rings by hop distance from the root, nodes spread evenly on each ring. */
function layout(g: Graph): Map<string, { x: number; y: number }> {
    const adj = new Map<string, string[]>();
    for (const e of g.edges) { adj.set(e.from, [...(adj.get(e.from) ?? []), e.to]); adj.set(e.to, [...(adj.get(e.to) ?? []), e.from]); }
    const dist = new Map<string, number>([[g.root, 0]]);
    const queue = [g.root];
    while (queue.length) { const n = queue.shift()!; for (const m of adj.get(n) ?? []) if (!dist.has(m)) { dist.set(m, dist.get(n)! + 1); queue.push(m); } }
    const rings = new Map<number, string[]>();
    for (const n of g.nodes) { const d = dist.get(n.id) ?? 3; rings.set(d, [...(rings.get(d) ?? []), n.id]); }
    const pos = new Map<string, { x: number; y: number }>();
    for (const [d, ids] of rings) ids.forEach((id, i) => {
        if (d === 0) { pos.set(id, { x: W / 2, y: H / 2 }); return; }
        const r = Math.min(110 * d, 260);
        const a = (2 * Math.PI * i) / ids.length + d * 0.4;
        pos.set(id, { x: W / 2 + r * Math.cos(a), y: H / 2 + r * Math.sin(a) * 0.8 });
    });
    return pos;
}

export function AttackSurfaceMap({ assetId, onOpenAsset }: { assetId: string; onOpenAsset: (id: string) => void }) {
    const [graph, setGraph] = useState<Graph | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [bases, setBases] = useState<Record<Basis, boolean>>({ confirmed: true, observed: true, inferred: true });
    const [kinds, setKinds] = useState<Record<GNode['kind'], boolean>>({ asset: true, ip: true, service: true, technology: true, finding: true });
    const [q, setQ] = useState('');
    const [sel, setSel] = useState<string | null>(null);
    const [view, setView] = useState({ x: 0, y: 0, w: W, h: H });
    const drag = useRef<{ x: number; y: number } | null>(null);

    useEffect(() => {
        let active = true;
        void loadJson<Graph>(`/api/vms/assets/${assetId}/graph`).then((r) => { if (active) { setGraph(r.ok ? r.data : null); setError(r.ok ? null : r.error); } });
        return () => { active = false; };
    }, [assetId]);

    const pos = useMemo(() => (graph ? layout(graph) : new Map()), [graph]);
    if (error) return <p className="text-red">{error}</p>;
    if (!graph) return <p className="text-foreground-muted">Loading the map…</p>;

    const visible = new Set(graph.nodes.filter((n) => kinds[n.kind] || n.id === graph.root).map((n) => n.id));
    const edges = graph.edges.filter((e) => bases[e.basis] && visible.has(e.from) && visible.has(e.to));
    const match = (n: GNode) => !!q && n.label.toLowerCase().includes(q.toLowerCase());
    const zoom = (f: number) => setView((v) => { const w = Math.min(Math.max(v.w * f, 200), W * 3); const h = (w * H) / W; return { x: v.x + (v.w - w) / 2, y: v.y + (v.h - h) / 2, w, h }; });
    const selected = graph.nodes.find((n) => n.id === sel);
    const selEdges = graph.edges.filter((e) => e.from === sel || e.to === sel);
    const name = (id: string) => graph.nodes.find((n) => n.id === id)?.label ?? id;

    return (
        <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2 text-[11px]">
                <input className="bg-card-muted border border-border rounded-lg px-2 py-1 text-xs" placeholder="Search the map" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search the map" />
                {(['confirmed', 'observed', 'inferred'] as Basis[]).map((b) => (
                    <label key={b} className="flex items-center gap-1"><input type="checkbox" checked={bases[b]} onChange={(e) => setBases({ ...bases, [b]: e.target.checked })} />
                        <svg width="22" height="6"><line x1="0" y1="3" x2="22" y2="3" stroke="currentColor" strokeWidth="2" strokeDasharray={DASH[b]} /></svg>{b}</label>
                ))}
                {(Object.keys(kinds) as GNode['kind'][]).map((k) => (
                    <label key={k} className="flex items-center gap-1"><input type="checkbox" checked={kinds[k]} onChange={(e) => setKinds({ ...kinds, [k]: e.target.checked })} /><span className="w-2 h-2 rounded-full inline-block" style={{ background: KIND_COLOR[k] }} />{k}</label>
                ))}
                <button onClick={() => zoom(0.8)} aria-label="Zoom in"><ZoomIn className="w-4 h-4" /></button>
                <button onClick={() => zoom(1.25)} aria-label="Zoom out"><ZoomOut className="w-4 h-4" /></button>
                <button onClick={() => setView({ x: 0, y: 0, w: W, h: H })} aria-label="Reset view"><Maximize2 className="w-4 h-4" /></button>
            </div>
            <svg viewBox={`${view.x} ${view.y} ${view.w} ${view.h}`} className="w-full h-[420px] bg-card-muted rounded-lg border border-border cursor-grab select-none" role="img" aria-label="Attack-surface relationship map"
                onWheel={(e) => zoom(e.deltaY > 0 ? 1.1 : 0.9)}
                onMouseDown={(e) => { drag.current = { x: e.clientX, y: e.clientY }; }}
                onMouseUp={() => { drag.current = null; }} onMouseLeave={() => { drag.current = null; }}
                onMouseMove={(e) => { if (!drag.current) return; const k = view.w / e.currentTarget.clientWidth; const dx = (e.clientX - drag.current.x) * k; const dy = (e.clientY - drag.current.y) * k; drag.current = { x: e.clientX, y: e.clientY }; setView((v) => ({ ...v, x: v.x - dx, y: v.y - dy })); }}>
                {edges.map((e, i) => {
                    const a = pos.get(e.from); const b = pos.get(e.to);
                    if (!a || !b) return null;
                    const hot = sel && (e.from === sel || e.to === sel);
                    return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={hot ? '#7c3aed' : '#94a3b8'} strokeWidth={hot ? 2.5 : 1.3} strokeDasharray={DASH[e.basis]}><title>{`${e.type} (${e.basis}) · ${e.source}${e.observed_at ? ` · ${fmtWat(e.observed_at)}` : ''}`}</title></line>;
                })}
                {graph.nodes.filter((n) => visible.has(n.id)).map((n) => {
                    const p = pos.get(n.id);
                    if (!p) return null;
                    const root = n.id === graph.root;
                    return (
                        <g key={n.id} transform={`translate(${p.x},${p.y})`} onClick={() => setSel(n.id)} className="cursor-pointer">
                            <circle r={root ? 14 : 9} fill={KIND_COLOR[n.kind]} stroke={match(n) ? '#f59e0b' : sel === n.id ? '#111827' : '#fff'} strokeWidth={match(n) || sel === n.id ? 3 : 1.5} />
                            <text y={root ? 28 : 21} textAnchor="middle" fontSize="11" fill="currentColor" className="text-foreground">{n.label.length > 28 ? `${n.label.slice(0, 27)}…` : n.label}</text>
                        </g>
                    );
                })}
            </svg>
            {graph.truncated && <p className="text-amber">The map shows the first 300 related items.</p>}
            {graph.edges.length === 0 && <p className="text-foreground-muted">No stored relationships yet: run discovery or a port scan, or wait for the Wazuh sync.</p>}
            {selected && (
                <div className="border border-border rounded-lg p-2 space-y-1">
                    <p className="font-bold text-foreground">{selected.label} <span className="text-foreground-muted font-normal">· {selected.kind}{selected.asset_type ? ` (${selected.asset_type})` : ''}</span></p>
                    {selected.detail && <p className="text-foreground-muted">{Object.entries(selected.detail).filter(([, v]) => v !== null && v !== undefined && `${v}` !== '').map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : String(v)}`).join(' · ')}</p>}
                    <ul className="text-foreground-muted">{selEdges.map((e, i) => <li key={i}>{e.from === selected.id ? '→' : '←'} {name(e.from === selected.id ? e.to : e.from)}: {e.type.replace(/_/g, ' ')} · <span className="font-semibold">{e.basis}</span> · {e.source}</li>)}</ul>
                    {selected.asset_id && selected.id !== graph.root && <button onClick={() => onOpenAsset(selected.asset_id!)} className="text-[11px] font-bold text-purple">Open this asset</button>}
                </div>
            )}
        </div>
    );
}
