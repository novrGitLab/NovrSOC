'use client';

// Scan schedules (phase P7): the same scan every interval, inside authorised scope. Managers create
// them; every run passes the same scope checks as a manual scan, and a schedule whose scope ends is
// stopped with the reason. P27: 'verification' schedules rescan findings marked fixed inside the
// scope; outside the scope's approved scan windows, or at a job limit, a run waits instead of failing.

import { useEffect, useState } from 'react';
import { CalendarClock } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { loadJson } from '@/lib/alerts';
import { fmtWat, SCAN_KIND_LABEL, type VmsScan, type VmsScope } from '@/lib/vms';

type ScheduleKind = VmsScan['kind'] | 'verification' | 'full_assessment';
const KIND_LABEL: Record<ScheduleKind, string> = { ...SCAN_KIND_LABEL, verification: 'Verification rescans (findings marked fixed)', full_assessment: 'Full assessment' };
interface Schedule {
    id: string; scope_id: string; kind: ScheduleKind; targets: string[]; ports: string | null; interval_hours: number; next_run_at: string;
    enabled: boolean; last_run_at: string | null; last_result: string | null; created_by: string;
    vms_scopes?: { value: string; expires_at: string; status: string } | null;
}
const INTERVALS = [[24, 'Daily'], [168, 'Weekly'], [336, 'Every 2 weeks'], [720, 'Every 30 days']] as const;
const every = (h: number) => INTERVALS.find(([v]) => v === h)?.[1] ?? `Every ${h} h`;

export function VmsSchedules() {
    const [rows, setRows] = useState<Schedule[] | null>(null);
    const [scopes, setScopes] = useState<VmsScope[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [msg, setMsg] = useState<string | null>(null);
    const [form, setForm] = useState({ scope_id: '', kind: 'discovery' as ScheduleKind, targets: '', ports: 'top-1000', interval_hours: 168 });
    const [reload, setReload] = useState(0);

    useEffect(() => {
        let active = true;
        void Promise.all([loadJson<{ schedules: Schedule[] }>('/api/vms/schedules'), loadJson<{ scopes: VmsScope[] }>('/api/vms/scopes')]).then(([s, sc]) => {
            if (!active) return;
            setRows(s.ok ? s.data.schedules : null);
            setError(s.ok ? null : s.error);
            setScopes(sc.ok ? sc.data.scopes.filter((x) => x.status === 'active') : []);
        });
        return () => { active = false; };
    }, [reload]);

    async function send(method: string, path: string, body?: unknown) {
        setMsg(null);
        const r = await apiFetch(apiUrl(path), { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
        const d = await r.json().catch(() => null);
        if (!r.ok) { setMsg(d?.error ?? `HTTP ${r.status}`); return false; }
        setReload((x) => x + 1);
        return true;
    }
    async function create(e: React.FormEvent) {
        e.preventDefault();
        const targets = form.targets.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean);
        const ok = await send('POST', '/api/vms/schedules', { scope_id: form.scope_id, kind: form.kind, interval_hours: form.interval_hours, ...(targets.length ? { targets } : {}), ...(form.kind === 'ports' ? { ports: form.ports } : {}) });
        if (ok) setMsg('Schedule created');
    }

    const scope = scopes.find((s) => s.id === form.scope_id);
    const kindAllowed = (k: ScheduleKind) => !scope || (k === 'ports' ? scope.allow_port_scan : k.startsWith('vuln_') || k === 'verification' ? scope.allow_vuln_scan : true);
    return (
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <h2 className="text-sm font-black text-foreground flex items-center gap-2"><CalendarClock className="w-4 h-4" /> Schedules</h2>
            <p className="text-[11px] text-foreground-muted">Repeat a scan inside approved scope — no further approval per run. Only SOC managers can create or change schedules; each run is checked against the scope again, waits for the scope&apos;s scan window or a free job slot, and stops when its scope is revoked or expires.</p>
            <form onSubmit={(e) => void create(e)} className="flex flex-wrap gap-2 items-end text-xs">
                <label className="text-[11px] font-bold text-foreground-muted">Scope
                    <select required value={form.scope_id} onChange={(e) => setForm({ ...form, scope_id: e.target.value })} className="block bg-card-muted border border-border rounded px-2 py-1 text-xs">
                        <option value="">Choose…</option>
                        {scopes.map((s) => <option key={s.id} value={s.id}>{s.value} (until {fmtWat(s.expires_at)})</option>)}
                    </select>
                </label>
                <label className="text-[11px] font-bold text-foreground-muted">Scan
                    <select value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value as ScheduleKind })} className="block bg-card-muted border border-border rounded px-2 py-1 text-xs">
                        {([...Object.keys(SCAN_KIND_LABEL), 'verification'] as ScheduleKind[]).map((k) => <option key={k} value={k} disabled={!kindAllowed(k)}>{KIND_LABEL[k]}{kindAllowed(k) ? '' : ' — not authorised'}</option>)}
                    </select>
                </label>
                <label className="text-[11px] font-bold text-foreground-muted">Targets (optional)
                    <input value={form.targets} onChange={(e) => setForm({ ...form, targets: e.target.value })} placeholder="whole scope" className="block bg-card-muted border border-border rounded px-2 py-1 text-xs w-48" />
                </label>
                {form.kind === 'ports' && (
                    <label className="text-[11px] font-bold text-foreground-muted">Ports
                        <input value={form.ports} onChange={(e) => setForm({ ...form, ports: e.target.value })} className="block bg-card-muted border border-border rounded px-2 py-1 text-xs w-28" />
                    </label>
                )}
                <label className="text-[11px] font-bold text-foreground-muted">How often
                    <select value={form.interval_hours} onChange={(e) => setForm({ ...form, interval_hours: Number(e.target.value) })} className="block bg-card-muted border border-border rounded px-2 py-1 text-xs">
                        {INTERVALS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                    </select>
                </label>
                <button className="text-[11px] font-bold text-white bg-blue rounded-lg px-3 py-1.5">Create schedule</button>
            </form>
            {msg && <p role="status" className="text-xs text-foreground font-semibold">{msg}</p>}
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {rows && rows.length === 0 && <p className="text-xs text-foreground-muted">No schedules.</p>}
            <div className="divide-y divide-border">
                {rows?.map((s) => (
                    <div key={s.id} className="py-2 text-xs flex flex-wrap items-start justify-between gap-2">
                        <div>
                            <p className="font-bold text-foreground">{KIND_LABEL[s.kind] ?? s.kind} · {every(s.interval_hours)} · {s.vms_scopes?.value ?? 'scope removed'}{s.targets.length ? ` (${s.targets.join(', ')})` : ''}</p>
                            <p className="text-foreground-muted">{s.enabled ? `${s.last_result?.startsWith('Waiting') ? 'Waiting — next try' : 'Next run'} ${fmtWat(s.next_run_at)}` : 'Stopped'} · last run {fmtWat(s.last_run_at)}{s.last_result ? ` · ${s.last_result}` : ''} · by {s.created_by}</p>
                        </div>
                        <div className="flex gap-2">
                            <button onClick={() => void send('PATCH', `/api/vms/schedules/${s.id}`, { enabled: !s.enabled })} className="text-[11px] font-bold border border-border rounded px-2 py-1">{s.enabled ? 'Pause' : 'Resume'}</button>
                            <button onClick={() => { if (window.confirm('Delete this schedule? Scans it already ran are kept.')) void send('DELETE', `/api/vms/schedules/${s.id}`); }} className="text-[11px] font-bold text-red border border-border rounded px-2 py-1">Delete</button>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}
