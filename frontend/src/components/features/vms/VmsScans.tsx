'use client';

// Scans (phase P4) — queue a scan against authorised scope and watch it run. Status and progress
// are exactly what the worker reports through the backend; the page refreshes every 15 s while
// anything is queued or running. A queued scan with no live worker says so.

import { useCallback, useEffect, useState } from 'react';
import { Play, RefreshCw } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { loadJson } from '@/lib/alerts';
import { fmtWat, SCAN_KIND_LABEL, SCAN_STATUS_STYLE, type VmsScan, type VmsScope } from '@/lib/vms';

export function VmsScans() {
    const [scans, setScans] = useState<VmsScan[] | null>(null);
    const [scopes, setScopes] = useState<VmsScope[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [msg, setMsg] = useState<string | null>(null);
    const [form, setForm] = useState({ scope_id: '', kind: 'discovery' as 'discovery' | 'ports', targets: '', ports: 'top-1000' });
    const [reloadKey, setReloadKey] = useState(0);
    const reload = useCallback(() => setReloadKey((k) => k + 1), []);

    useEffect(() => {
        let active = true;
        void Promise.all([loadJson<{ scans: VmsScan[] }>('/api/vms/scans'), loadJson<{ scopes: VmsScope[] }>('/api/vms/scopes')]).then(([s, sc]) => {
            if (!active) return;
            setScans(s.ok ? s.data.scans : null);
            setError(s.ok ? null : s.error);
            setScopes(sc.ok ? sc.data.scopes.filter((x) => x.status === 'active' && Date.parse(x.expires_at) > Date.now()) : []);
        });
        return () => { active = false; };
    }, [reloadKey]);

    const live = scans?.some((s) => s.status === 'queued' || s.status === 'running');
    useEffect(() => {
        if (!live) return;
        const t = setInterval(reload, 15_000);
        return () => clearInterval(t);
    }, [live, reload]);

    const scope = scopes.find((s) => s.id === form.scope_id);
    async function queue() {
        setMsg(null);
        const targets = form.targets.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean);
        const r = await apiFetch(apiUrl('/api/vms/scans'), {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scope_id: form.scope_id, kind: form.kind, ...(targets.length ? { targets } : {}), ...(form.kind === 'ports' ? { ports: form.ports } : {}) }),
        });
        const d = await r.json().catch(() => null);
        setMsg(r.ok ? (d.existing ? 'That scan is already queued or running.' : 'Scan queued.') : d?.error ?? `HTTP ${r.status}`);
        reload();
    }
    async function cancel(s: VmsScan) {
        const r = await apiFetch(apiUrl(`/api/vms/scans/${s.id}/cancel`), { method: 'POST' });
        const d = await r.json().catch(() => null);
        setMsg(r.ok ? d.message : d?.error ?? `HTTP ${r.status}`);
        reload();
    }

    const input = 'bg-card-muted border border-border rounded-lg px-3 py-2 text-xs text-foreground';
    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-lg font-black text-foreground">Scans</h1>
                    <p className="text-xs text-foreground-muted">Queue and follow attack-surface scans. Only authorised scope can be chosen.</p>
                </div>
                <button onClick={reload} className="flex items-center gap-1.5 text-[11px] font-bold text-foreground-muted border border-border rounded-lg px-3 py-1.5"><RefreshCw className="w-3.5 h-3.5" /> Refresh</button>
            </div>
            <div className="bg-card border border-border rounded-xl p-4 grid grid-cols-1 md:grid-cols-4 gap-3 items-end">
                <label className="text-[11px] font-bold text-foreground-muted">Scope
                    <select className={`${input} w-full`} value={form.scope_id} onChange={(e) => setForm({ ...form, scope_id: e.target.value })}>
                        <option value="">Choose…</option>
                        {scopes.map((s) => <option key={s.id} value={s.id}>{s.value}</option>)}
                    </select>
                </label>
                <label className="text-[11px] font-bold text-foreground-muted">Scan
                    <select className={`${input} w-full`} value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value as 'discovery' | 'ports' })}>
                        <option value="discovery">{SCAN_KIND_LABEL.discovery}</option>
                        <option value="ports" disabled={!!scope && !scope.allow_port_scan}>{SCAN_KIND_LABEL.ports}{scope && !scope.allow_port_scan ? ' — not authorised for this scope' : ''}</option>
                    </select>
                </label>
                <label className="text-[11px] font-bold text-foreground-muted">Targets (optional)
                    <input className={`${input} w-full`} value={form.targets} onChange={(e) => setForm({ ...form, targets: e.target.value })} placeholder={scope ? `Default: ${scope.value}` : 'host or IP, comma-separated'} />
                </label>
                <div className="flex gap-2 items-end">
                    {form.kind === 'ports' && (
                        <label className="text-[11px] font-bold text-foreground-muted">Ports
                            <input className={`${input} w-28`} value={form.ports} onChange={(e) => setForm({ ...form, ports: e.target.value })} title="top-100, top-1000, 1-65535 or a list like 22,80,443" />
                        </label>
                    )}
                    <button disabled={!form.scope_id} onClick={() => void queue()} className="flex items-center gap-1.5 text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-2 disabled:opacity-50"><Play className="w-3.5 h-3.5" /> Queue scan</button>
                </div>
            </div>
            {msg && <p role="status" className="text-xs text-foreground font-semibold">{msg}</p>}
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {scans && scans.length === 0 && <p className="text-sm text-foreground-muted text-center py-10 bg-card border border-border rounded-xl">No data — no scan has been queued yet.</p>}
            {scans && scans.length > 0 && (
                <div className="bg-card border border-border rounded-xl divide-y divide-border">
                    {scans.map((s) => (
                        <div key={s.id} className="p-3 text-xs space-y-1">
                            <div className="flex items-center justify-between gap-2 flex-wrap">
                                <span className="font-bold text-foreground">{SCAN_KIND_LABEL[s.kind]}{s.options?.ports ? ` · ports ${s.options.ports}` : ''}{s.purpose === 'verification' ? ' · verification' : ''}</span>
                                <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${SCAN_STATUS_STYLE[s.status]}`}>{s.status}{s.cancel_requested && s.status === 'running' ? ' (stopping)' : ''}</span>
                            </div>
                            <p className="text-foreground-muted font-mono break-all">{s.targets.join(', ')}</p>
                            <p className="text-foreground-muted">Queued by {s.requested_by} · {fmtWat(s.requested_at)}{s.started_at ? ` · started ${fmtWat(s.started_at)}` : ''}{s.finished_at ? ` · finished ${fmtWat(s.finished_at)}` : ''}</p>
                            {s.status === 'running' && (
                                <p className="text-blue">{s.progress?.phase ?? 'running'}{s.progress?.total ? ` ${s.progress.done ?? 0}/${s.progress.total}` : ''}{s.progress?.message ? ` · ${s.progress.message}` : ''} · last heartbeat {fmtWat(s.heartbeat_at)}</p>
                            )}
                            {s.status === 'queued' && s.progress?.message && <p className="text-amber">{s.progress.message}</p>}
                            {s.error && <p className="text-red">{s.error}</p>}
                            {s.summary && Object.keys(s.summary).length > 0 && <p className="text-foreground-muted">{Object.entries(s.summary).map(([k, v]) => `${k.replace(/_/g, ' ')}: ${String(v)}`).join(' · ')}</p>}
                            {(s.status === 'queued' || s.status === 'running') && !s.cancel_requested && <button onClick={() => void cancel(s)} className="text-[11px] font-bold text-red">Cancel</button>}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
