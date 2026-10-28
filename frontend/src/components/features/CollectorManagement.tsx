'use client';

// Collector Management (phase P31, Collector V1): enrollment, fleet overview, per-collector
// detail (sources, heartbeat history, diagnostics), and revoke/rotate access controls. Reads real
// data from /api/collectors — see backend/src/routes/collectors.ts.
//
// Staff only (collectors:read / collectors:manage — super_admin, soc_manager; not analyst,
// executive or portal_user): a collector's credential is live client-site infrastructure access,
// closer to Wazuh Groups / Sec Ops Management than to day-to-day SOC analyst work.
//
// Deliberately one page with tabs rather than eight separate routes — the same choice
// ReportingCenter.tsx made for the same reason: these are facets of one fleet, not independent
// features, and a shared "which collector is selected" state would otherwise have to live
// somewhere anyway.

import { useCallback, useEffect, useState } from 'react';
import { Server, Plus, ShieldAlert, RefreshCw, Trash2, Activity, Radio, FileText, Copy, Check } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { loadJson } from '@/lib/alerts';

type CollectorStatus = 'enrolling' | 'connected' | 'disconnected' | 'revoked';
interface Collector {
    id: string; name: string; status: CollectorStatus; effective_status: CollectorStatus;
    token_prefix: string; vector_version: string | null; last_heartbeat_at: string | null; last_ip: string | null;
    last_events_received: number; last_events_forwarded: number; last_delivery_failures: number; last_buffer_pct: number | null;
    config_version: number; created_by: string; created_at: string; enrollment_expires_at: string | null;
}
interface Source { source_key: string; kind: string; label: string | null; events_total: number; last_event_at: string | null }
interface Heartbeat { at: string; events_received: number; events_forwarded: number; delivery_failures: number; buffer_pct: number | null }
interface LogEvent { id: string; source_key: string; host: string | null; received_at: string; event_time: string | null; message: string; truncated: boolean }

const fmt = (iso: string | null) => (iso ? new Intl.DateTimeFormat('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(iso)) + ' WAT' : '—');
const STATUS_STYLE: Record<CollectorStatus, string> = {
    connected: 'bg-green/10 text-green', enrolling: 'bg-amber/10 text-amber',
    disconnected: 'bg-card-muted text-foreground-muted', revoked: 'bg-red/10 text-red',
};
const Badge = ({ s }: { s: CollectorStatus }) => <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase ${STATUS_STYLE[s]}`}>{s}</span>;

function CopyableToken({ token }: { token: string }) {
    const [copied, setCopied] = useState(false);
    return (
        <div className="bg-background border border-amber/40 rounded-lg p-3 space-y-2">
            <p className="text-xs font-bold text-amber flex items-center gap-1"><ShieldAlert className="w-3.5 h-3.5" /> This credential is shown once — it cannot be retrieved again.</p>
            <div className="flex items-center gap-2">
                <code className="text-[11px] font-mono text-foreground bg-card-muted px-2 py-1.5 rounded flex-1 overflow-x-auto whitespace-nowrap">{token}</code>
                <button onClick={() => { void navigator.clipboard.writeText(token); setCopied(true); setTimeout(() => setCopied(false), 2000); }} className="shrink-0 text-[11px] font-bold px-2 py-1.5 rounded-md bg-card-muted text-foreground flex items-center gap-1">
                    {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />} {copied ? 'Copied' : 'Copy'}
                </button>
            </div>
            <p className="text-[10px] text-foreground-muted">Paste it into the collector appliance&apos;s <code>.env</code> as <code>NOVRSOC_COLLECTOR_TOKEN</code>, then start it. See infra/novrsoc-collector/README.md.</p>
        </div>
    );
}

export function CollectorManagement() {
    const [tab, setTab] = useState<'overview' | 'collectors' | 'enroll'>('overview');
    const [collectors, setCollectors] = useState<Collector[] | null>(null);
    const [selected, setSelected] = useState<string | null>(null);
    const [detail, setDetail] = useState<{ sources: Source[]; heartbeats: Heartbeat[] } | null>(null);
    const [events, setEvents] = useState<LogEvent[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);
    const [reloadKey, setReloadKey] = useState(0);
    const reload = useCallback(() => setReloadKey((k) => k + 1), []);

    useEffect(() => {
        let active = true;
        void loadJson<{ collectors: Collector[] }>('/api/collectors').then((r) => { if (active) { setCollectors(r.ok ? r.data.collectors : null); setError(r.ok ? null : r.error); } });
        return () => { active = false; };
    }, [reloadKey]);

    useEffect(() => {
        if (!selected) return;
        let active = true;
        void loadJson<{ sources: Source[]; heartbeats: Heartbeat[] }>(`/api/collectors/${selected}`).then((r) => { if (active) setDetail(r.ok ? { sources: r.data.sources, heartbeats: r.data.heartbeats } : null); });
        void loadJson<{ events: LogEvent[] }>(`/api/collectors/${selected}/events?limit=50`).then((r) => { if (active) setEvents(r.ok ? r.data.events : null); });
        return () => { active = false; };
    }, [selected, reloadKey]);

    const post = async (path: string, body?: unknown) => {
        setBusy(true); setError(null);
        try {
            const r = await apiFetch(apiUrl(path), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
            const d = await r.json().catch(() => null);
            if (!r.ok) { setError(d?.error ?? `HTTP ${r.status}`); return null; }
            return d;
        } catch {
            setError('Could not reach the backend');
            return null;
        } finally {
            setBusy(false);
        }
    };

    const selectedCollector = collectors?.find((c) => c.id === selected) ?? null;
    const connected = collectors?.filter((c) => c.effective_status === 'connected').length ?? 0;

    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground flex items-center gap-2"><Server className="w-5 h-5" /> Collector Management</h1>
                <p className="text-xs text-foreground-muted">Client-site log collectors (syslog TCP/UDP/TLS) forwarding into NovrSOC. Raw logs, not scored alerts — see docs/collector-v1/WAZUH_COMPATIBILITY.md.</p>
            </div>
            <div className="flex gap-1 bg-card border border-border rounded-lg p-1">
                {([['overview', 'Overview', Activity], ['collectors', 'Collectors', Server], ['enroll', 'New collector', Plus]] as const).map(([k, label, Icon]) => (
                    <button key={k} onClick={() => setTab(k)} className={`text-[11px] font-bold px-2.5 py-1.5 rounded-md flex items-center gap-1 ${tab === k ? 'bg-blue text-white' : 'text-foreground-muted'}`}><Icon className="w-3.5 h-3.5" /> {label}</button>
                ))}
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}

            {tab === 'overview' && (
                collectors === null ? <p className="text-xs text-foreground-muted">Not connected.</p> : (
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                        <div className="bg-card border border-border rounded-xl p-4"><p className="text-[10px] font-bold text-foreground-muted uppercase">Enrolled</p><p className="text-2xl font-black text-foreground">{collectors.length}</p></div>
                        <div className="bg-card border border-border rounded-xl p-4"><p className="text-[10px] font-bold text-foreground-muted uppercase">Connected</p><p className="text-2xl font-black text-green">{connected}</p></div>
                        <div className="bg-card border border-border rounded-xl p-4"><p className="text-[10px] font-bold text-foreground-muted uppercase">Disconnected / stale</p><p className="text-2xl font-black text-amber">{collectors.filter((c) => c.effective_status === 'disconnected').length}</p></div>
                        <div className="bg-card border border-border rounded-xl p-4"><p className="text-[10px] font-bold text-foreground-muted uppercase">Delivery failures (last heartbeat)</p><p className="text-2xl font-black text-foreground">{collectors.reduce((n, c) => n + c.last_delivery_failures, 0)}</p></div>
                    </div>
                )
            )}

            {tab === 'enroll' && (
                <EnrollPanel busy={busy} onCreate={async (name) => { const d = await post('/api/collectors', { name }); if (d) { reload(); setTab('collectors'); setSelected(d.collector.id); } return d; }} />
            )}

            {tab === 'collectors' && (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                    <div className="bg-card border border-border rounded-xl divide-y divide-border lg:col-span-1">
                        {collectors === null ? <p className="text-xs text-foreground-muted p-3">Not connected.</p>
                            : collectors.length === 0 ? <p className="text-xs text-foreground-muted p-3">No collector enrolled yet.</p>
                            : collectors.map((c) => (
                                <button key={c.id} onClick={() => setSelected(c.id)} className={`w-full text-left p-3 text-xs ${selected === c.id ? 'bg-card-muted' : ''}`}>
                                    <p className="font-bold text-foreground flex items-center justify-between">{c.name} <Badge s={c.effective_status} /></p>
                                    <p className="text-foreground-muted mt-0.5">{c.vector_version ?? 'unknown version'} · last heartbeat {fmt(c.last_heartbeat_at)}</p>
                                </button>
                            ))}
                    </div>
                    <div className="lg:col-span-2 space-y-3">
                        {!selectedCollector ? <p className="text-xs text-foreground-muted">Select a collector.</p> : (
                            <CollectorDetail collector={selectedCollector} detail={detail} events={events} busy={busy}
                                onRevoke={async () => { if (await post(`/api/collectors/${selectedCollector.id}/revoke`)) reload(); }}
                                onRotate={async () => post(`/api/collectors/${selectedCollector.id}/rotate`)} />
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}

function EnrollPanel({ busy, onCreate }: { busy: boolean; onCreate: (name: string) => Promise<{ collector: Collector; enrollment_token: string } | null> }) {
    const [name, setName] = useState('');
    const [issued, setIssued] = useState<{ collector: Collector; enrollment_token: string } | null>(null);
    return (
        <div className="bg-card border border-border rounded-xl p-4 space-y-3 max-w-xl">
            <h2 className="text-sm font-black text-foreground">Enroll a new collector</h2>
            <p className="text-xs text-foreground-muted">One collector per client-site appliance. Deploy infra/novrsoc-collector/ there first (or in parallel) — see its README.</p>
            <div className="flex gap-2">
                <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. client-site-1" className="flex-1 bg-background border border-border rounded-lg px-2 py-1.5 text-xs" />
                <button disabled={busy || !name.trim()} onClick={async () => { const d = await onCreate(name.trim()); if (d) { setIssued(d); setName(''); } }} className="text-xs font-bold bg-blue text-white px-3 py-1.5 rounded-lg disabled:opacity-50">Enroll</button>
            </div>
            {issued && <CopyableToken token={issued.enrollment_token} />}
        </div>
    );
}

function CollectorDetail({ collector, detail, events, busy, onRevoke, onRotate }: {
    collector: Collector; detail: { sources: Source[]; heartbeats: Heartbeat[] } | null; events: LogEvent[] | null; busy: boolean;
    onRevoke: () => void; onRotate: () => Promise<{ enrollment_token: string } | { error: string } | null>;
}) {
    const [rotated, setRotated] = useState<string | null>(null);
    return (
        <>
            <div className="bg-card border border-border rounded-xl p-4 space-y-2">
                <div className="flex items-center justify-between">
                    <h2 className="text-sm font-black text-foreground flex items-center gap-2">{collector.name} <Badge s={collector.effective_status} /></h2>
                    <div className="flex gap-2">
                        <button disabled={busy} onClick={async () => { const r = await onRotate(); if (r && 'enrollment_token' in r) setRotated(r.enrollment_token); }} className="text-[11px] font-bold px-2 py-1 rounded-md bg-card-muted text-foreground flex items-center gap-1"><RefreshCw className="w-3.5 h-3.5" /> Rotate</button>
                        {collector.status !== 'revoked' && <button disabled={busy} onClick={() => { if (window.confirm(`Revoke ${collector.name}? Its appliance will stop authenticating immediately.`)) onRevoke(); }} className="text-[11px] font-bold px-2 py-1 rounded-md bg-red/10 text-red flex items-center gap-1"><Trash2 className="w-3.5 h-3.5" /> Revoke</button>}
                    </div>
                </div>
                {rotated && <CopyableToken token={rotated} />}
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-2 text-[11px]">
                    <p><span className="text-foreground-muted">Version</span><br /><span className="font-bold text-foreground">{collector.vector_version ?? '—'}</span></p>
                    <p><span className="text-foreground-muted">Last heartbeat</span><br /><span className="font-bold text-foreground">{fmt(collector.last_heartbeat_at)}</span></p>
                    <p><span className="text-foreground-muted">Last IP</span><br /><span className="font-bold text-foreground">{collector.last_ip ?? '—'}</span></p>
                    <p><span className="text-foreground-muted">Buffer</span><br /><span className="font-bold text-foreground">{collector.last_buffer_pct !== null ? `${collector.last_buffer_pct}%` : '—'}</span></p>
                    <p><span className="text-foreground-muted">Events received</span><br /><span className="font-bold text-foreground">{collector.last_events_received.toLocaleString()}</span></p>
                    <p><span className="text-foreground-muted">Events forwarded</span><br /><span className="font-bold text-foreground">{collector.last_events_forwarded.toLocaleString()}</span></p>
                    <p><span className="text-foreground-muted">Delivery failures</span><br /><span className={`font-bold ${collector.last_delivery_failures > 0 ? 'text-amber' : 'text-foreground'}`}>{collector.last_delivery_failures.toLocaleString()}</span></p>
                    <p><span className="text-foreground-muted">Config version</span><br /><span className="font-bold text-foreground">{collector.config_version}</span></p>
                </div>
                {collector.status === 'enrolling' && <p className="text-xs text-amber">Awaiting first heartbeat — enrollment window expires {fmt(collector.enrollment_expires_at)}.</p>}
            </div>

            <div className="bg-card border border-border rounded-xl p-4">
                <h3 className="text-xs font-black text-foreground mb-2 flex items-center gap-1"><Radio className="w-3.5 h-3.5" /> Connected sources</h3>
                {!detail ? <p className="text-xs text-foreground-muted">Loading…</p> : detail.sources.length === 0 ? <p className="text-xs text-foreground-muted">No source has reported yet.</p> : (
                    <table className="w-full text-xs"><thead><tr className="text-foreground-muted"><th className="text-left font-semibold">Source</th><th className="text-left font-semibold">Kind</th><th className="text-right font-semibold">Events</th><th className="text-right font-semibold">Last event</th></tr></thead>
                        <tbody>{detail.sources.map((s) => <tr key={s.source_key} className="border-t border-border"><td className="py-1">{s.label ?? s.source_key}</td><td>{s.kind}</td><td className="text-right tabular-nums">{s.events_total.toLocaleString()}</td><td className="text-right text-foreground-muted">{fmt(s.last_event_at)}</td></tr>)}</tbody>
                    </table>
                )}
            </div>

            <div className="bg-card border border-border rounded-xl p-4">
                <h3 className="text-xs font-black text-foreground mb-2 flex items-center gap-1"><Activity className="w-3.5 h-3.5" /> Recent heartbeats</h3>
                {!detail ? <p className="text-xs text-foreground-muted">Loading…</p> : detail.heartbeats.length === 0 ? <p className="text-xs text-foreground-muted">No heartbeat yet.</p> : (
                    <div className="overflow-x-auto"><table className="w-full text-xs"><thead><tr className="text-foreground-muted"><th className="text-left font-semibold">At</th><th className="text-right font-semibold">Received</th><th className="text-right font-semibold">Forwarded</th><th className="text-right font-semibold">Failures</th><th className="text-right font-semibold">Buffer</th></tr></thead>
                        <tbody>{[...detail.heartbeats].reverse().slice(0, 20).map((h, i) => <tr key={i} className="border-t border-border"><td className="py-1 text-foreground-muted">{fmt(h.at)}</td><td className="text-right tabular-nums">{h.events_received.toLocaleString()}</td><td className="text-right tabular-nums">{h.events_forwarded.toLocaleString()}</td><td className={`text-right tabular-nums ${h.delivery_failures > 0 ? 'text-amber' : ''}`}>{h.delivery_failures.toLocaleString()}</td><td className="text-right tabular-nums">{h.buffer_pct !== null ? `${h.buffer_pct}%` : '—'}</td></tr>)}</tbody>
                    </table></div>
                )}
            </div>

            <div className="bg-card border border-border rounded-xl p-4">
                <h3 className="text-xs font-black text-foreground mb-2 flex items-center gap-1"><FileText className="w-3.5 h-3.5" /> Diagnostics — recent raw log sample</h3>
                {!events ? <p className="text-xs text-foreground-muted">Loading…</p> : events.length === 0 ? <p className="text-xs text-foreground-muted">No log event received yet.</p> : (
                    <div className="space-y-1 max-h-80 overflow-y-auto font-mono text-[11px]">
                        {events.map((e) => (
                            <div key={e.id} className="border-b border-border pb-1">
                                <span className="text-foreground-muted">{fmt(e.received_at)} · {e.source_key}{e.host ? ` · ${e.host}` : ''}{e.truncated ? ' · truncated' : ''}</span>
                                <p className="text-foreground break-all whitespace-pre-wrap">{e.message}</p>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </>
    );
}
