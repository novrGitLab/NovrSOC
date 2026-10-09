'use client';

// Alerts — the stored, org-scoped alert table (GET /api/alerts, phase R2), fed by the SOAR
// forwarder. Replaces the in-memory Wazuh list on this page. Triage writes
// PATCH /api/alerts/:id/status (needs alerts:triage). Nothing here is sample data: an unavailable
// store says "not connected", an empty one says "no data".

import { useCallback, useEffect, useState } from 'react';
import { RefreshCw, Shield } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import type { Severity } from '@/lib/severity';
import {
    fetchAlertStats, loadJson, watTime, STATUS_LABEL, STORED_ALERT_STATUSES,
    type AlertStats, type StoredAlert, type StoredAlertStatus,
} from '@/lib/alerts';
import { AlertFeedStatus } from '@/components/shared/AlertFeedStatus';

const SEV_STYLE: Record<Severity, string> = {
    critical: 'bg-red-500/10 text-red-500 border-red-500/30',
    high: 'bg-orange/10 text-orange border-orange/30',
    medium: 'bg-amber/10 text-amber border-amber/30',
    low: 'bg-card-muted text-foreground-muted border-border',
};
const STATUS_STYLE: Record<StoredAlertStatus, string> = {
    new: 'bg-red-500/10 text-red-500 border-red-500/30',
    triaged: 'bg-blue/10 text-blue border-blue/30',
    escalated: 'bg-orange/10 text-orange border-orange/30',
    closed: 'bg-card-muted text-foreground-muted border-border',
    false_positive: 'bg-card-muted text-foreground-muted border-border',
};

type Page = { alerts: StoredAlert[]; next_cursor: string | null };

export function AlertQueue() {
    const [severity, setSeverity] = useState<'all' | Severity>('all');
    const [status, setStatus] = useState<'all' | StoredAlertStatus>('all');
    const [alerts, setAlerts] = useState<StoredAlert[]>([]);
    const [cursor, setCursor] = useState<string | null>(null);
    const [stats, setStats] = useState<AlertStats | null>(null);
    const [loaded, setLoaded] = useState(false);
    const [loading, setLoading] = useState(true);
    const [notConnected, setNotConnected] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [selected, setSelected] = useState<StoredAlert | null>(null);
    const [busy, setBusy] = useState(false);
    const [actionMsg, setActionMsg] = useState<{ ok: boolean; text: string } | null>(null);
    const [reloadKey, setReloadKey] = useState(0);

    const query = useCallback((after: string | null) => {
        const p = new URLSearchParams({ limit: '50' });
        if (severity !== 'all') p.set('severity', severity);
        if (status !== 'all') p.set('status', status);
        if (after) p.set('cursor', after);
        return `/api/alerts?${p.toString()}`;
    }, [severity, status]);

    useEffect(() => {
        let active = true;
        void Promise.all([loadJson<Page>(query(null)), fetchAlertStats('24h')]).then(([list, st]) => {
            if (!active) return;
            const failed = !list.ok ? list : !st.ok ? st : null;
            setNotConnected(!!failed && failed.notConnected);
            setError(failed ? failed.error : null);
            setAlerts(list.ok ? list.data.alerts : []);
            setCursor(list.ok ? list.data.next_cursor : null);
            setStats(st.ok ? st.data : null);
            setLoaded(true);
            setLoading(false);
        });
        return () => { active = false; };
    }, [query, reloadKey]);

    const refresh = () => { setLoading(true); setReloadKey((k) => k + 1); };

    async function loadMore() {
        if (!cursor) return;
        setBusy(true);
        const r = await loadJson<Page>(query(cursor));
        if (r.ok) {
            setAlerts((prev) => [...prev, ...r.data.alerts]);
            setCursor(r.data.next_cursor);
        } else {
            setActionMsg({ ok: false, text: r.error });
        }
        setBusy(false);
    }

    async function open(a: StoredAlert) {
        setSelected(a);
        setActionMsg(null);
        const r = await loadJson<{ alert: StoredAlert }>(`/api/alerts/${a.id}`);
        if (r.ok) setSelected(r.data.alert);
    }

    async function setAlertStatus(a: StoredAlert, next: StoredAlertStatus) {
        setBusy(true);
        setActionMsg(null);
        try {
            const r = await apiFetch(apiUrl(`/api/alerts/${a.id}/status`), {
                method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status: next }),
            });
            const body = await r.json().catch(() => null);
            if (!r.ok) {
                setActionMsg({ ok: false, text: r.status === 403 ? 'You do not have permission to triage alerts.' : body?.error ?? `HTTP ${r.status}` });
                return;
            }
            setAlerts((prev) => prev.map((x) => (x.id === a.id ? { ...x, status: next } : x)));
            setSelected((s) => (s && s.id === a.id ? { ...s, status: next } : s));
            setActionMsg({ ok: true, text: `Marked ${STATUS_LABEL[next].toLowerCase()}` });
        } catch {
            setActionMsg({ ok: false, text: 'Could not reach the backend' });
        } finally {
            setBusy(false);
        }
    }

    const kpi = (v: number | undefined) => (stats ? String(v ?? 0) : '—');

    return (
        <div className="space-y-5">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-lg font-black text-foreground">Alerts</h1>
                    <p className="text-xs text-foreground-muted">SecOps &amp; Response · Stored Wazuh alerts for your organisation</p>
                </div>
                <button onClick={refresh} className="flex items-center gap-1.5 text-[11px] font-bold text-foreground-muted hover:text-foreground border border-border rounded-lg px-3 py-1.5">
                    <RefreshCw className="w-3.5 h-3.5" /> Refresh
                </button>
            </div>

            <AlertFeedStatus loaded={loaded} notConnected={notConnected} error={error} lastReceivedAt={stats?.last_received_at ?? null} />

            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
                {[
                    { label: 'Alerts (24h)', value: kpi(stats?.total), color: 'text-foreground' },
                    { label: 'Critical (24h)', value: kpi(stats?.by_severity.critical), color: 'text-red-500' },
                    { label: 'High (24h)', value: kpi(stats?.by_severity.high), color: 'text-orange' },
                    { label: 'Medium (24h)', value: kpi(stats?.by_severity.medium), color: 'text-amber' },
                    { label: 'New (24h)', value: kpi(stats?.by_status.new), color: 'text-red-500' },
                    { label: 'Triaged (24h)', value: kpi(stats?.by_status.triaged), color: 'text-blue' },
                ].map((k) => (
                    <div key={k.label} className="bg-card border border-border rounded-xl p-3">
                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{k.label}</p>
                        <p className={`text-xl font-black mt-1 ${k.color}`}>{k.value}</p>
                    </div>
                ))}
            </div>

            <div className="flex flex-wrap items-center gap-2">
                <div className="flex items-center gap-1 bg-card border border-border rounded-lg p-1">
                    {(['all', 'critical', 'high', 'medium', 'low'] as const).map((s) => (
                        <button key={s} onClick={() => { setLoading(true); setSeverity(s); }}
                            className={`text-[11px] font-bold px-2.5 py-1 rounded-md capitalize transition-colors ${severity === s ? 'bg-blue text-white' : 'text-foreground-muted hover:text-foreground'}`}>
                            {s}
                        </button>
                    ))}
                </div>
                <div className="flex items-center gap-1 bg-card border border-border rounded-lg p-1">
                    {(['all', ...STORED_ALERT_STATUSES] as const).map((s) => (
                        <button key={s} onClick={() => { setLoading(true); setStatus(s); }}
                            className={`text-[11px] font-bold px-2.5 py-1 rounded-md transition-colors ${status === s ? 'bg-blue text-white' : 'text-foreground-muted hover:text-foreground'}`}>
                            {s === 'all' ? 'All Status' : STATUS_LABEL[s]}
                        </button>
                    ))}
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
                <div className="lg:col-span-2 bg-card border border-border rounded-xl overflow-hidden">
                    <div className="p-3 border-b border-border">
                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">Alert Queue ({alerts.length}{cursor ? '+' : ''})</p>
                    </div>
                    {loading ? (
                        <div className="p-4 space-y-2">{Array.from({ length: 5 }).map((_, i) => <div key={i} className="h-14 bg-card-muted rounded animate-pulse" />)}</div>
                    ) : error ? (
                        <p className="text-xs text-red-500 text-center py-10 px-4">{notConnected ? 'Not connected' : 'Alerts unavailable'} — see above.</p>
                    ) : alerts.length === 0 ? (
                        <p className="text-sm font-bold text-foreground text-center py-10 px-4">No data{severity !== 'all' || status !== 'all' ? ' for these filters' : ''}</p>
                    ) : (
                        <div className="max-h-[640px] overflow-y-auto divide-y divide-border">
                            {alerts.map((a) => (
                                <button key={a.id} onClick={() => void open(a)}
                                    className={`w-full text-left p-3 hover:bg-card-muted transition-colors ${selected?.id === a.id ? 'bg-card-muted' : ''}`}>
                                    <div className="flex items-center justify-between gap-2">
                                        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase ${SEV_STYLE[a.severity]}`}>{a.severity}</span>
                                        <span className="text-[10px] text-foreground-muted">{watTime(a.event_time)}</span>
                                    </div>
                                    <p className="text-xs font-bold text-foreground mt-1.5 leading-snug">{a.rule_description ?? `Rule ${a.rule_id ?? 'unknown'}`}</p>
                                    <div className="flex items-center justify-between mt-1.5">
                                        <span className="text-[10px] text-foreground-muted font-mono">{a.agent_name ?? a.agent_id ?? '—'}</span>
                                        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${STATUS_STYLE[a.status]}`}>{STATUS_LABEL[a.status]}</span>
                                    </div>
                                </button>
                            ))}
                            {cursor && (
                                <button disabled={busy} onClick={() => void loadMore()} className="w-full text-[11px] font-bold text-purple py-3 hover:bg-card-muted disabled:opacity-50">
                                    Load more
                                </button>
                            )}
                        </div>
                    )}
                </div>

                <div className="lg:col-span-3 bg-card border border-border rounded-xl overflow-hidden">
                    {!selected ? (
                        <div className="p-10 text-center">
                            <Shield className="w-8 h-8 text-foreground-muted mx-auto mb-2" />
                            <p className="text-xs text-foreground-muted">Select an alert to view details.</p>
                        </div>
                    ) : (
                        <div className="p-4 space-y-4">
                            <div className="flex items-start justify-between gap-3">
                                <div>
                                    <div className="flex items-center gap-2">
                                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${SEV_STYLE[selected.severity]}`}>{selected.severity}</span>
                                        <span className="text-[10px] font-mono text-foreground-muted">Rule {selected.rule_id ?? '—'} · L{selected.rule_level ?? '—'}</span>
                                    </div>
                                    <h2 className="text-sm font-black text-foreground mt-1.5">{selected.rule_description ?? 'No description'}</h2>
                                </div>
                                <span className={`text-[10px] font-bold px-2 py-0.5 rounded border shrink-0 ${STATUS_STYLE[selected.status]}`}>{STATUS_LABEL[selected.status]}</span>
                            </div>

                            <div className="grid grid-cols-2 gap-3 text-xs">
                                {[
                                    ['Agent', `${selected.agent_name ?? '—'}${selected.agent_id ? ` (${selected.agent_id})` : ''}`],
                                    ['Agent IP', selected.agent_ip ?? '—'],
                                    ['Event time', watTime(selected.event_time)],
                                    ['Received', watTime(selected.received_at)],
                                    ['MITRE', selected.mitre_ids?.length ? selected.mitre_ids.join(', ') : '—'],
                                    ['Wazuh groups', selected.wazuh_groups?.length ? selected.wazuh_groups.join(', ') : '—'],
                                    ['Location', selected.location ?? '—'],
                                    ['Wazuh alert id', selected.wazuh_alert_id],
                                ].map(([k, v]) => (
                                    <div key={k}>
                                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{k}</p>
                                        <p className="text-foreground mt-0.5 break-all">{v}</p>
                                    </div>
                                ))}
                            </div>

                            {selected.raw !== undefined && (
                                <div>
                                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-1.5">
                                        Raw alert{selected.raw_truncated ? ' (truncated to 32 KB)' : ''}
                                    </p>
                                    {/* Untrusted log content: rendered as text only. */}
                                    <pre className="bg-card-muted border border-border rounded-lg p-3 text-[10px] font-mono text-foreground-muted whitespace-pre-wrap break-all max-h-80 overflow-y-auto">
                                        {JSON.stringify(selected.raw, null, 2)}
                                    </pre>
                                </div>
                            )}

                            <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-border">
                                {(['triaged', 'escalated', 'false_positive', 'closed'] as const).map((s) => (
                                    <button key={s} disabled={busy || selected.status === s} onClick={() => void setAlertStatus(selected, s)}
                                        className="text-[11px] font-bold text-foreground border border-border rounded-lg px-3 py-1.5 hover:bg-card-muted disabled:opacity-50">
                                        {STATUS_LABEL[s]}
                                    </button>
                                ))}
                                {actionMsg && <span className={`text-[11px] font-bold ${actionMsg.ok ? 'text-emerald-500' : 'text-red-500'}`}>{actionMsg.text}</span>}
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
