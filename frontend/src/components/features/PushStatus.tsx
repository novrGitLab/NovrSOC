'use client';

// Stellar Cyber push status (phase X3) — read from GET /api/admin/push-status (super_admin).
// Shows what the backend reports: configuration (host only, never the key), delivered / refused /
// retried counts, backlog, open dead letters and the job's last tick. Nothing here is computed or
// assumed client-side; a value the backend doesn't have is shown as "—".

import { useCallback, useEffect, useState } from 'react';
import { RefreshCw, Send } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { loadJson } from '@/lib/alerts';

interface PushStatusResponse {
    config: { enabled: boolean; valid: boolean; error: string | null; host: string | null; orgs: string[]; profile: string | null; max_per_min: number | null; timeout_ms: number | null; auth_header: string | null };
    runtime: { started_at: string | null; not_started_reason: string | null; last_tick_at: string | null; consecutive_failures: number; next_attempt_at: string | null; last_result: { error: string | null } | null };
    state: { last_seq: number; sent_count: number; skipped_count: number; retry_count: number; last_success_at: string | null; last_error: string | null; last_error_at: string | null } | null;
    backlog: number | null;
    dead_letters: { open: number; recent: { alert_id: string; status_code: number | null; attempts: number; retry_requested: boolean; created_at: string }[] } | null;
}

const fmt = (iso: string | null | undefined) => (iso ? new Intl.DateTimeFormat('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(iso)) + ' WAT' : '—');
const n = (v: number | null | undefined) => (v === null || v === undefined ? '—' : v.toLocaleString());

function Stat({ label, value, tone }: { label: string; value: string; tone?: 'bad' | 'good' }) {
    return (
        <div className="bg-card-muted rounded-lg px-3 py-2">
            <p className="text-[10px] uppercase tracking-wide text-foreground-muted font-bold">{label}</p>
            <p className={`text-sm font-black ${tone === 'bad' ? 'text-red-500' : tone === 'good' ? 'text-emerald-600' : 'text-foreground'}`}>{value}</p>
        </div>
    );
}

export function PushStatus() {
    const [s, setS] = useState<PushStatusResponse | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [msg, setMsg] = useState<string | null>(null);
    const [reloadKey, setReloadKey] = useState(0);
    const reload = useCallback(() => setReloadKey((k) => k + 1), []);

    useEffect(() => {
        let active = true;
        void loadJson<PushStatusResponse>('/api/admin/push-status').then((r) => {
            if (!active) return;
            setS(r.ok ? r.data : null);
            setError(r.ok ? null : r.notConnected ? 'Not connected — push status is unavailable.' : r.error);
        });
        return () => { active = false; };
    }, [reloadKey]);

    const retry = async () => {
        try {
            const r = await apiFetch(apiUrl('/api/admin/push-status/dead-letters/retry'), { method: 'POST' });
            const d = await r.json().catch(() => null);
            setMsg(r.ok ? `${d?.queued ?? 0} queued for retry` : d?.error ?? `HTTP ${r.status}`);
        } catch {
            setMsg('Could not reach the backend');
        }
        reload();
    };

    const c = s?.config;
    const status = !c ? null
        : !c.enabled ? { text: 'Off', tone: undefined }
        : !c.valid ? { text: `Misconfigured: ${c.error}`, tone: 'bad' as const }
        : s?.runtime.not_started_reason ? { text: `Not running: ${s.runtime.not_started_reason}`, tone: 'bad' as const }
        : s?.runtime.consecutive_failures ? { text: `Retrying (${s.runtime.consecutive_failures} failure${s.runtime.consecutive_failures > 1 ? 's' : ''})`, tone: 'bad' as const }
        : { text: 'Running', tone: 'good' as const };

    return (
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <Send className="w-4 h-4 text-purple" />
                    <div>
                        <h2 className="text-sm font-black text-foreground">Stellar Cyber push</h2>
                        <p className="text-[11px] text-foreground-muted">Outbound webhook delivery of stored alerts{c?.host ? ` to ${c.host}` : ''}</p>
                    </div>
                </div>
                <button onClick={reload} className="flex items-center gap-1.5 text-[11px] font-bold text-foreground-muted hover:text-foreground border border-border rounded-lg px-3 py-1.5">
                    <RefreshCw className="w-3.5 h-3.5" /> Refresh
                </button>
            </div>

            {error && <p role="alert" className="text-xs text-red-500 font-semibold">{error}</p>}
            {s && status && (
                <>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                        <Stat label="Status" value={status.text} tone={status.tone} />
                        <Stat label="Delivered" value={n(s.state?.sent_count)} />
                        <Stat label="Backlog" value={n(s.backlog)} />
                        <Stat label="Transient retries" value={n(s.state?.retry_count)} />
                        <Stat label="Refused (dead letters)" value={n(s.dead_letters?.open)} tone={s.dead_letters?.open ? 'bad' : undefined} />
                        <Stat label="Last success" value={fmt(s.state?.last_success_at)} />
                        <Stat label="Last tick" value={fmt(s.runtime.last_tick_at)} />
                        <Stat label="Next attempt" value={fmt(s.runtime.next_attempt_at)} />
                    </div>
                    <p className="text-[11px] text-foreground-muted">
                        Orgs: {c?.orgs.length ? c.orgs.join(', ') : '—'} · Profile: {c?.profile ?? '—'} · Rate cap: {c?.max_per_min ? `${c.max_per_min}/min` : '—'} · Auth header: {c?.auth_header ?? '—'}
                    </p>
                    {s.state?.last_error && (
                        <p className="text-[11px] text-red-500 font-semibold">Last error ({fmt(s.state.last_error_at)}): {s.state.last_error}</p>
                    )}
                    {!!s.dead_letters?.open && (
                        <div className="flex items-center gap-2">
                            <button onClick={() => void retry()} className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5">Retry refused alerts</button>
                            {msg && <span className="text-[11px] text-foreground-muted">{msg}</span>}
                        </div>
                    )}
                </>
            )}
        </div>
    );
}
