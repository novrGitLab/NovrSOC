'use client';

import { useState, useMemo, useEffect } from 'react';
import { Share2, Table2, Clock, Server, Wifi, X, Search, Globe2 } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Mock data only — real data is meant to come from Zeek conn.log via Wazuh once the EC2-3
// sensor is deployed, plus Wazuh process-monitoring for agent → external-IP connections in
// the meantime. No backend route exists for this yet.

interface TopologyNode {
    id: string;
    name: string;
    os: string;
    ip: string;
    type: 'endpoint' | 'server';
}
interface Connection {
    source: string;
    dest_ip: string;
    dest_country: string;
    dest_hostname: string | null;
    port: number;
    protocol: string;
    bytes_out: number;
    bytes_in: number;
    status: 'clean' | 'suspicious' | 'malicious';
    threat_score: number;
    time: string;
}

const MOCK_TOPOLOGY: { nodes: TopologyNode[]; connections: Connection[] } = {
    nodes: [
        { id: 'rayne-laptop', name: 'RayneOps', os: 'Windows 11', ip: '10.177.163.139', type: 'endpoint' },
        { id: 'novrsoc-server', name: 'novrsoc-contabo', os: 'Ubuntu 22.04', ip: '10.0.0.1', type: 'server' },
    ],
    connections: [
        { source: 'rayne-laptop', dest_ip: '76.76.21.21', dest_country: 'US', dest_hostname: 'vercel.com', port: 443, protocol: 'HTTPS', bytes_out: 24800, bytes_in: 847200, status: 'clean', threat_score: 0, time: '2026-08-24 09:41:22' },
        { source: 'rayne-laptop', dest_ip: '185.220.101.47', dest_country: 'DE', dest_hostname: null, port: 443, protocol: 'TCP', bytes_out: 1200, bytes_in: 800, status: 'malicious', threat_score: 94, time: '2026-08-24 02:14:33' },
        { source: 'novrsoc-server', dest_ip: '104.18.32.7', dest_country: 'US', dest_hostname: 'api.supabase.co', port: 443, protocol: 'HTTPS', bytes_out: 156000, bytes_in: 92300, status: 'clean', threat_score: 0, time: '2026-08-24 09:38:02' },
        { source: 'novrsoc-server', dest_ip: '45.155.205.233', dest_country: 'RU', dest_hostname: null, port: 22, protocol: 'TCP', bytes_out: 340, bytes_in: 0, status: 'suspicious', threat_score: 61, time: '2026-08-24 03:47:08' },
    ],
};

const STATUS_COLOR: Record<Connection['status'], string> = { clean: 'var(--color-green)', suspicious: 'var(--color-amber)', malicious: 'var(--brand-red)' };
const STATUS_TEXT: Record<Connection['status'], string> = { clean: 'text-green', suspicious: 'text-amber', malicious: 'text-red' };

const VIEWS = [
    { id: 'graph', label: 'Graph View', icon: Share2 },
    { id: 'table', label: 'Table View', icon: Table2 },
    { id: 'timeline', label: 'Timeline View', icon: Clock },
] as const;
type ViewMode = (typeof VIEWS)[number]['id'];

function bytesFmt(n: number): string {
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + ' MB';
    if (n >= 1_000) return (n / 1_000).toFixed(1) + ' KB';
    return n + ' B';
}

export function NetworkTopology() {
    const [view, setView] = useState<ViewMode>('graph');
    const [selected, setSelected] = useState<{ kind: 'node'; node: TopologyNode } | { kind: 'edge'; conn: Connection } | null>(null);
    const [deviceFilter, setDeviceFilter] = useState('all');
    const [countryFilter, setCountryFilter] = useState('all');
    const [statusFilter, setStatusFilter] = useState('all');

    // LeakIX host-exposure lookup — real, unlike the rest of this page (see the file header
    // comment: everything above is mock data pending a Zeek sensor). Replaced the Censys search
    // that used to sit here.
    //
    // LeakIX takes a single IP, not a search expression, so this is a host lookup rather than a
    // query box. Its free tier still requires a registered key, so an unconfigured lookup says
    // so plainly instead of rendering an empty result set that would read as "nothing exposed".
    const [leakixConfigured, setLeakixConfigured] = useState<boolean | null>(null);
    const [leakixIp, setLeakixIp] = useState('');
    const [leakixResult, setLeakixResult] = useState<{
        status: string;
        services: Array<{ port: number | null; protocol: string | null; software: string | null }>;
        leaks: Array<{ severity: string | null; summary: string | null }>;
    } | null>(null);
    const [leakixSearching, setLeakixSearching] = useState(false);

    useEffect(() => {
        // Probe with a well-known address purely to read back `configured`.
        apiFetch(apiUrl('/api/cti/leakix?ip=1.1.1.1'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => setLeakixConfigured(!!data?.configured))
            .catch(() => setLeakixConfigured(false));
    }, []);

    const runLeakixLookup = async () => {
        if (!leakixIp.trim()) return;
        setLeakixSearching(true);
        try {
            const res = await apiFetch(apiUrl(`/api/cti/leakix?ip=${encodeURIComponent(leakixIp.trim())}`), { cache: 'no-store' });
            const data = await res.json();
            setLeakixResult({ status: data.status ?? 'error', services: data.services ?? [], leaks: data.leaks ?? [] });
        } finally {
            setLeakixSearching(false);
        }
    };

    const filtered = MOCK_TOPOLOGY.connections.filter((c) =>
        (deviceFilter === 'all' || c.source === deviceFilter) &&
        (countryFilter === 'all' || c.dest_country === countryFilter) &&
        (statusFilter === 'all' || c.status === statusFilter)
    );

    // Simple radial layout — the two enrolled agents on the left, their external
    // destinations fanned out to the right. Positions are computed, not force-simulated:
    // with a handful of nodes a real d3-force layout adds instability for no visual gain.
    const layout = useMemo(() => {
        const nodeCount = MOCK_TOPOLOGY.nodes.length;
        const nodePos = new Map<string, { x: number; y: number }>();
        MOCK_TOPOLOGY.nodes.forEach((n, i) => {
            nodePos.set(n.id, { x: 90, y: 60 + (i * 340) / Math.max(1, nodeCount - 1 || 1) + (nodeCount === 1 ? 120 : 0) });
        });
        const destsBySource = new Map<string, Connection[]>();
        MOCK_TOPOLOGY.connections.forEach((c) => {
            const arr = destsBySource.get(c.source) ?? [];
            arr.push(c);
            destsBySource.set(c.source, arr);
        });
        const destPos = new Map<Connection, { x: number; y: number }>();
        destsBySource.forEach((conns, source) => {
            const origin = nodePos.get(source) ?? { x: 90, y: 200 };
            conns.forEach((c, i) => {
                const spread = 70;
                const y = origin.y - ((conns.length - 1) * spread) / 2 + i * spread;
                destPos.set(c, { x: 480, y: Math.max(30, Math.min(410, y)) });
            });
        });
        return { nodePos, destPos };
    }, []);

    return (
        <div className="space-y-4">
            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div>
                    <h1 className="text-lg font-black text-foreground">Network Topology</h1>
                    <p className="text-xs text-foreground-muted">Infrastructure · Map of enrolled devices and their external connections. Last updated: 2026-08-24 09:41 WAT.</p>
                </div>
                <div className="flex gap-1 bg-card-muted rounded-lg p-1 flex-shrink-0">
                    {VIEWS.map((v) => {
                        const Icon = v.icon;
                        return (
                            <button key={v.id} onClick={() => setView(v.id)}
                                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-bold transition-colors ${view === v.id ? 'bg-card text-blue shadow-sm' : 'text-foreground-muted hover:text-foreground'}`}>
                                <Icon size={13} /> {v.label}
                            </button>
                        );
                    })}
                </div>
            </div>

            <div className="bg-card border border-border rounded-xl p-4">
                <div className="flex items-center gap-2 mb-2">
                    <Globe2 size={14} className="text-purple" />
                    <h2 className="text-xs font-bold text-foreground uppercase tracking-wider">Host Exposure Lookup</h2>
                    <span className="text-[9px] text-foreground-muted">via LeakIX</span>
                </div>
                {leakixConfigured === false ? (
                    <p className="text-xs text-foreground-muted">
                        Not configured — add LEAKIX_API_KEY (free key at leakix.net/settings/api) to Railway to enable.
                    </p>
                ) : (
                    <>
                        <div className="flex gap-2">
                            <input
                                value={leakixIp}
                                onChange={(e) => setLeakixIp(e.target.value)}
                                onKeyDown={(e) => { if (e.key === 'Enter') runLeakixLookup(); }}
                                placeholder="e.g. 8.8.8.8"
                                className="flex-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-xs text-foreground focus:outline-none focus:border-purple"
                            />
                            <button
                                onClick={runLeakixLookup}
                                disabled={leakixSearching || !leakixIp.trim()}
                                className="flex items-center gap-1.5 bg-purple text-white text-xs font-bold px-4 py-2 rounded-lg disabled:opacity-50 transition-colors"
                            >
                                <Search size={13} /> {leakixSearching ? 'Checking…' : 'Check'}
                            </button>
                        </div>
                        {leakixResult && (
                            leakixResult.status === 'ok' ? (
                                <div className="mt-2 space-y-1">
                                    <p className="text-[11px] text-foreground-muted">
                                        {leakixResult.services.length} exposed service{leakixResult.services.length === 1 ? '' : 's'} ·{' '}
                                        {leakixResult.leaks.length} known leak{leakixResult.leaks.length === 1 ? '' : 's'}
                                    </p>
                                    {leakixResult.services.slice(0, 6).map((s, i) => (
                                        <p key={i} className="text-[11px] text-foreground">
                                            {s.port ?? '?'}/{s.protocol ?? '—'}{s.software ? ` · ${s.software}` : ''}
                                        </p>
                                    ))}
                                </div>
                            ) : leakixResult.status === 'not_found' ? (
                                <p className="text-[11px] text-foreground-muted mt-2">No LeakIX records for that host.</p>
                            ) : (
                                <p className="text-[11px] text-amber mt-2">Lookup unavailable — result not established.</p>
                            )
                        )}
                    </>
                )}
            </div>

            {view === 'graph' && (
                <div className="bg-card border border-border rounded-xl p-4">
                    <svg viewBox="0 0 560 440" className="w-full h-[440px]">
                        {MOCK_TOPOLOGY.connections.map((c, i) => {
                            const from = layout.nodePos.get(c.source);
                            const to = layout.destPos.get(c);
                            if (!from || !to) return null;
                            return (
                                <line key={i} x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                                    stroke={STATUS_COLOR[c.status]} strokeWidth={c.status === 'clean' ? 1.5 : 2.5}
                                    strokeDasharray={c.status === 'malicious' ? '4 3' : undefined}
                                    className="cursor-pointer" opacity={0.8}
                                    onClick={() => setSelected({ kind: 'edge', conn: c })} />
                            );
                        })}
                        {MOCK_TOPOLOGY.nodes.map((n) => {
                            const p = layout.nodePos.get(n.id)!;
                            const traffic = MOCK_TOPOLOGY.connections.filter((c) => c.source === n.id).reduce((s, c) => s + c.bytes_out + c.bytes_in, 0);
                            const r = Math.min(30, 16 + Math.sqrt(traffic) / 120);
                            return (
                                <g key={n.id} className="cursor-pointer" onClick={() => setSelected({ kind: 'node', node: n })}>
                                    <circle cx={p.x} cy={p.y} r={r} fill="var(--color-purple)" fillOpacity={0.15} stroke="var(--color-purple)" strokeWidth={2} />
                                    <text x={p.x} y={p.y + r + 16} textAnchor="middle" className="text-[11px] font-bold" fill="var(--color-foreground)">{n.name}</text>
                                    <text x={p.x} y={p.y + r + 28} textAnchor="middle" className="text-[9px]" fill="var(--color-foreground-muted)">{n.ip}</text>
                                </g>
                            );
                        })}
                        {MOCK_TOPOLOGY.connections.map((c, i) => {
                            const p = layout.destPos.get(c);
                            if (!p) return null;
                            return (
                                <g key={`d${i}`} className="cursor-pointer" onClick={() => setSelected({ kind: 'edge', conn: c })}>
                                    <circle cx={p.x} cy={p.y} r={9} fill={STATUS_COLOR[c.status]} fillOpacity={0.2} stroke={STATUS_COLOR[c.status]} strokeWidth={2} />
                                    <text x={p.x + 16} y={p.y - 4} className="text-[10px] font-bold" fill="var(--color-foreground)">{c.dest_hostname ?? c.dest_ip}</text>
                                    <text x={p.x + 16} y={p.y + 9} className="text-[9px]" fill="var(--color-foreground-muted)">{c.dest_country} · :{c.port}</text>
                                </g>
                            );
                        })}
                    </svg>
                    <div className="flex items-center gap-4 mt-2 text-[10px] text-foreground-muted">
                        <span className="flex items-center gap-1.5"><span className="w-2.5 h-0.5 bg-green inline-block" /> Clean</span>
                        <span className="flex items-center gap-1.5"><span className="w-2.5 h-0.5 bg-amber inline-block" /> Suspicious</span>
                        <span className="flex items-center gap-1.5"><span className="w-2.5 h-0.5 bg-red inline-block" /> Malicious</span>
                        <span className="ml-auto italic">Node size ∝ traffic volume · Sensor (Zeek/EC2-3) not deployed — showing Wazuh process-monitoring connections only</span>
                    </div>
                </div>
            )}

            {view === 'table' && (
                <div className="space-y-3">
                    <div className="flex flex-wrap gap-2">
                        <select value={deviceFilter} onChange={(e) => setDeviceFilter(e.target.value)} className="bg-card border border-border rounded-lg px-3 py-1.5 text-xs text-foreground focus:outline-none">
                            <option value="all">All devices</option>
                            {MOCK_TOPOLOGY.nodes.map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
                        </select>
                        <select value={countryFilter} onChange={(e) => setCountryFilter(e.target.value)} className="bg-card border border-border rounded-lg px-3 py-1.5 text-xs text-foreground focus:outline-none">
                            <option value="all">All countries</option>
                            {Array.from(new Set(MOCK_TOPOLOGY.connections.map((c) => c.dest_country))).map((c) => <option key={c} value={c}>{c}</option>)}
                        </select>
                        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="bg-card border border-border rounded-lg px-3 py-1.5 text-xs text-foreground focus:outline-none">
                            <option value="all">All statuses</option>
                            <option value="clean">Clean</option>
                            <option value="suspicious">Suspicious</option>
                            <option value="malicious">Malicious</option>
                        </select>
                    </div>
                    <div className="bg-card border border-border rounded-xl overflow-hidden">
                        <div className="overflow-x-auto scrollbar-thin">
                            <table className="w-full text-left">
                                <thead>
                                    <tr className="bg-grey-800">
                                        {['Source Device', 'Destination IP', 'Country', 'Port', 'Protocol', 'Bytes Out', 'Bytes In', 'Status', 'Time'].map((c) => (
                                            <th key={c} className="px-4 py-3 text-[10px] font-semibold text-white uppercase tracking-widest whitespace-nowrap">{c}</th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-border text-sm">
                                    {filtered.map((c, i) => (
                                        <tr key={i} className="hover:bg-card-muted cursor-pointer" onClick={() => setSelected({ kind: 'edge', conn: c })}>
                                            <td className="px-4 py-3 font-medium text-foreground whitespace-nowrap">{MOCK_TOPOLOGY.nodes.find((n) => n.id === c.source)?.name ?? c.source}</td>
                                            <td className="px-4 py-3 font-mono text-foreground-muted whitespace-nowrap">{c.dest_ip}</td>
                                            <td className="px-4 py-3 text-foreground-muted">{c.dest_country}</td>
                                            <td className="px-4 py-3 text-foreground-muted">{c.port}</td>
                                            <td className="px-4 py-3 text-foreground-muted">{c.protocol}</td>
                                            <td className="px-4 py-3 text-foreground-muted whitespace-nowrap">{bytesFmt(c.bytes_out)}</td>
                                            <td className="px-4 py-3 text-foreground-muted whitespace-nowrap">{bytesFmt(c.bytes_in)}</td>
                                            <td className="px-4 py-3"><span className={`text-xs font-bold ${STATUS_TEXT[c.status]}`}>{c.status}</span></td>
                                            <td className="px-4 py-3 text-foreground-muted whitespace-nowrap">{c.time}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            )}

            {view === 'timeline' && (
                <div className="bg-card border border-border rounded-xl p-5">
                    <div className="space-y-0">
                        {[...MOCK_TOPOLOGY.connections].sort((a, b) => b.time.localeCompare(a.time)).map((c, i) => (
                            <div key={i} className="flex gap-3 pb-4 relative">
                                {i < MOCK_TOPOLOGY.connections.length - 1 && <div className="absolute left-[5px] top-4 bottom-0 w-px bg-border" />}
                                <span className={`w-2.5 h-2.5 rounded-full mt-1.5 flex-shrink-0 z-10 ${c.status === 'clean' ? 'bg-green' : c.status === 'suspicious' ? 'bg-amber' : 'bg-red'}`} />
                                <div className="min-w-0">
                                    <p className="text-xs text-foreground-muted">{c.time}</p>
                                    <p className="text-sm text-foreground">
                                        <span className="font-bold">{MOCK_TOPOLOGY.nodes.find((n) => n.id === c.source)?.name}</span> → {c.dest_hostname ?? c.dest_ip} <span className="text-foreground-muted">({c.dest_country}, :{c.port})</span>
                                    </p>
                                    <span className={`text-[10px] font-bold ${STATUS_TEXT[c.status]}`}>{c.status.toUpperCase()}{c.threat_score > 0 ? ` · threat score ${c.threat_score}` : ''}</span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {selected && (
                <div className="fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-4" onClick={() => setSelected(null)}>
                    <div className="bg-card border border-border rounded-xl p-6 max-w-md w-full" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="font-heading font-semibold text-sm text-foreground flex items-center gap-2">
                                {selected.kind === 'node' ? <Server size={16} className="text-purple" /> : <Wifi size={16} className="text-purple" />}
                                {selected.kind === 'node' ? selected.node.name : (selected.conn.dest_hostname ?? selected.conn.dest_ip)}
                            </h3>
                            <button onClick={() => setSelected(null)} className="text-foreground-muted hover:text-foreground"><X size={16} /></button>
                        </div>
                        {selected.kind === 'node' ? (
                            <div className="space-y-2 text-xs">
                                <div className="flex justify-between border-b border-border pb-2"><span className="text-foreground-muted">IP Address</span><span className="font-mono font-bold text-foreground">{selected.node.ip}</span></div>
                                <div className="flex justify-between border-b border-border pb-2"><span className="text-foreground-muted">OS</span><span className="font-bold text-foreground">{selected.node.os}</span></div>
                                <div className="flex justify-between"><span className="text-foreground-muted">Type</span><span className="font-bold text-foreground capitalize">{selected.node.type}</span></div>
                            </div>
                        ) : (
                            <div className="space-y-2 text-xs">
                                <div className="flex justify-between border-b border-border pb-2"><span className="text-foreground-muted">Destination IP</span><span className="font-mono font-bold text-foreground">{selected.conn.dest_ip}</span></div>
                                <div className="flex justify-between border-b border-border pb-2"><span className="text-foreground-muted">Port / Protocol</span><span className="font-bold text-foreground">{selected.conn.port} / {selected.conn.protocol}</span></div>
                                <div className="flex justify-between border-b border-border pb-2"><span className="text-foreground-muted">Bytes Sent / Received</span><span className="font-bold text-foreground">{bytesFmt(selected.conn.bytes_out)} / {bytesFmt(selected.conn.bytes_in)}</span></div>
                                <div className="flex justify-between border-b border-border pb-2"><span className="text-foreground-muted">Status</span><span className={`font-bold ${STATUS_TEXT[selected.conn.status]}`}>{selected.conn.status}</span></div>
                                <div className="flex justify-between"><span className="text-foreground-muted">Threat Score</span><span className="font-bold text-foreground">{selected.conn.threat_score}/100</span></div>
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
