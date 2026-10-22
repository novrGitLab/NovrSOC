'use client';

// Alerts — the stored, org-scoped alert table (GET /api/alerts, phase R2), fed by the SOAR
// forwarder. Replaces the in-memory Wazuh list on this page. Triage writes
// PATCH /api/alerts/:id/status (needs alerts:triage). Phase P3 adds search, assignment to real
// accounts, acknowledgement, a triage note, the alert's history and promote-to-case
// (POST /api/alerts/:id/case, which returns the existing case instead of opening a second one).
// Phase P24 adds the network and firewall fields (source/destination address and port, protocol,
// firewall action, direction, interface), firewall filters, and a refresh every 30 s while the
// tab is visible. Nothing here is sample data: an unavailable store says "not connected", an
// empty one "no data".
//
// mode="client" is the client portal's read-only view of its own organisation
// (GET /api/client/secops/*): no triage, no raw log, no SOC-internal fields.


import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { RefreshCw, Shield, Search } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { getAdminUser } from '@/lib/admin-auth';
import { AiPanel } from '@/components/shared/AiPanel';
import type { Severity } from '@/lib/severity';
import {
    fetchAlertStats, loadJson, watTime, endpoint, STATUS_LABEL, STORED_ALERT_STATUSES, FIREWALL_ACTIONS,
    type AlertStats, type StoredAlert, type StoredAlertStatus, type FirewallAction,
} from '@/lib/alerts';
import { AlertFeedStatus } from '@/components/shared/AlertFeedStatus';
import { usePolling } from '@/lib/usePolling';

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
const ACTION_STYLE: Record<string, string> = {
    block: 'bg-red-500/10 text-red-500 border-red-500/30',
    reject: 'bg-orange/10 text-orange border-orange/30',
    pass: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/30',
};
const actionStyle = (a: string) => ACTION_STYLE[a] ?? 'bg-card-muted text-foreground-muted border-border';

const REFRESH_MS = 30_000;

type Page = { alerts: StoredAlert[]; next_cursor: string | null };
interface AlertEvent { at: string; actor: string; action: string; from_value: string | null; to_value: string | null; details: string | null }
const EVENT_LABEL: Record<string, string> = { status: 'Status', assign: 'Assigned', acknowledge: 'Acknowledged', note: 'Note', case_link: 'Linked to case' };

/** GET /api/client/secops/summary, as far as this page uses it. */
interface ClientSummary {
    alerts_24h: { total: number; by_severity: Record<Severity, number> };
    firewall_7d: Record<FirewallAction, number> | null;
    last_received_at: string | null;
    stale_after_minutes: number;
}

type FirewallFilter = 'all' | 'firewall' | FirewallAction;

export function AlertQueue({ mode = 'staff' }: { mode?: 'staff' | 'client' }) {
    const client = mode === 'client';
    const [severity, setSeverity] = useState<'all' | Severity>('all');
    const [status, setStatus] = useState<'all' | StoredAlertStatus>('all');
    const [firewall, setFirewall] = useState<FirewallFilter>('all');
    const [alerts, setAlerts] = useState<StoredAlert[]>([]);
    const [cursor, setCursor] = useState<string | null>(null);
    const [morePages, setMorePages] = useState(false);
    const [stats, setStats] = useState<AlertStats | null>(null);
    const [summary, setSummary] = useState<ClientSummary | null>(null);
    const [loaded, setLoaded] = useState(false);
    const [loading, setLoading] = useState(true);
    const [notConnected, setNotConnected] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [checkedAt, setCheckedAt] = useState<string | null>(null);
    const [selected, setSelected] = useState<StoredAlert | null>(null);
    const [busy, setBusy] = useState(false);
    const [actionMsg, setActionMsg] = useState<{ ok: boolean; text: string } | null>(null);
    const [reloadKey, setReloadKey] = useState(0);
    const [search, setSearch] = useState('');
    const [text, setText] = useState('');
    const [ipInput, setIpInput] = useState('');
    const [ip, setIp] = useState('');
    const [assigned, setAssigned] = useState<'all' | 'me' | 'unassigned'>('all');
    const [events, setEvents] = useState<AlertEvent[] | null>(null);
    const [note, setNote] = useState('');
    const me = getAdminUser();

    const query = useCallback((after: string | null) => {
        const p = new URLSearchParams({ limit: '50' });
        if (severity !== 'all') p.set('severity', severity);
        if (firewall === 'firewall') p.set('firewall', '1');
        else if (firewall !== 'all') p.set('action', firewall);
        if (after) p.set('cursor', after);
        if (client) return `/api/client/secops/alerts?${p.toString()}`;
        if (status !== 'all') p.set('status', status);
        if (text) p.set('q', text);
        if (ip) p.set('ip', ip);
        if (assigned !== 'all') p.set('assigned', assigned);
        return `/api/alerts?${p.toString()}`;
    }, [client, severity, status, firewall, text, ip, assigned]);

    useEffect(() => {
        let active = true;
        const statsP = client ? loadJson<ClientSummary>('/api/client/secops/summary') : fetchAlertStats('24h');
        void Promise.all([loadJson<Page>(query(null)), statsP]).then(([list, st]) => {
            if (!active) return;
            const failed = !list.ok ? list : !st.ok ? st : null;
            setNotConnected(!!failed && failed.notConnected);
            setError(failed ? failed.error : null);
            setAlerts(list.ok ? list.data.alerts : []);
            setCursor(list.ok ? list.data.next_cursor : null);
            setMorePages(false);
            if (client) setSummary(st.ok ? (st.data as ClientSummary) : null);
            else setStats(st.ok ? (st.data as AlertStats) : null);
            setCheckedAt(new Date().toISOString());
            setLoaded(true);
            setLoading(false);
        });
        return () => { active = false; };
    }, [client, query, reloadKey]);

    const refresh = () => { setLoading(true); setReloadKey((k) => k + 1); };
    // Every 30 s while visible — but not after "Load more", which would throw those pages away.
    usePolling(() => setReloadKey((k) => k + 1), REFRESH_MS, !morePages);

    async function loadMore() {
        if (!cursor) return;
        setBusy(true);
        const r = await loadJson<Page>(query(cursor));
        if (r.ok) {
            setAlerts((prev) => [...prev, ...r.data.alerts]);
            setCursor(r.data.next_cursor);
            setMorePages(true);
        } else {
            setActionMsg({ ok: false, text: r.error });
        }
        setBusy(false);
    }

    async function loadEvents(id: string) {
        const r = await loadJson<{ events: AlertEvent[] }>(`/api/alerts/${id}/events`);
        setEvents(r.ok ? r.data.events : null);
    }

    async function open(a: StoredAlert) {
        setSelected(a);
        setActionMsg(null);
        setEvents(null);
        setNote(a.triage_note ?? '');
        if (client) return; // the list row is the client's whole view of the alert
        const r = await loadJson<{ alert: StoredAlert }>(`/api/alerts/${a.id}`);
        if (r.ok) { setSelected(r.data.alert); setNote(r.data.alert.triage_note ?? ''); }
        void loadEvents(a.id);
    }

    function merge(updated: StoredAlert) {
        setAlerts((prev) => prev.map((x) => (x.id === updated.id ? { ...x, ...updated } : x)));
        setSelected((s) => (s && s.id === updated.id ? { ...s, ...updated } : s));
    }

    async function triage(a: StoredAlert, body: Record<string, unknown>, done: string) {
        setBusy(true);
        setActionMsg(null);
        try {
            const r = await apiFetch(apiUrl(`/api/alerts/${a.id}`), { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
            const d = await r.json().catch(() => null);
            if (!r.ok) { setActionMsg({ ok: false, text: r.status === 403 ? 'You do not have permission to triage alerts.' : d?.error ?? `HTTP ${r.status}` }); return; }
            if (d?.alert) merge(d.alert as StoredAlert);
            setActionMsg({ ok: true, text: done });
            void loadEvents(a.id);
        } catch {
            setActionMsg({ ok: false, text: 'Could not reach the backend' });
        } finally {
            setBusy(false);
        }
    }

    async function promote(a: StoredAlert) {
        setBusy(true);
        setActionMsg(null);
        try {
            const r = await apiFetch(apiUrl(`/api/alerts/${a.id}/case`), { method: 'POST' });
            const d = await r.json().catch(() => null);
            if (!r.ok) { setActionMsg({ ok: false, text: d?.error ?? `HTTP ${r.status}` }); return; }
            merge({ ...a, case_id: d.case.id });
            setActionMsg({ ok: true, text: d.created ? `Case ${d.case.case_number} opened` : d.message ?? `In case ${d.case.case_number}` });
            void loadEvents(a.id);
        } catch {
            setActionMsg({ ok: false, text: 'Could not reach the backend' });
        } finally {
            setBusy(false);
        }
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
            void loadEvents(a.id);
        } catch {
            setActionMsg({ ok: false, text: 'Could not reach the backend' });
        } finally {
            setBusy(false);
        }
    }

    const kpi = (v: number | undefined | null, have: boolean) => (have && v !== undefined && v !== null ? String(v) : '—');
    const kpis = client
        ? [
            { label: 'Alerts (24h)', value: kpi(summary?.alerts_24h.total, !!summary), color: 'text-foreground' },
            { label: 'Critical (24h)', value: kpi(summary?.alerts_24h.by_severity.critical, !!summary), color: 'text-red-500' },
            { label: 'High (24h)', value: kpi(summary?.alerts_24h.by_severity.high, !!summary), color: 'text-orange' },
            { label: 'Medium (24h)', value: kpi(summary?.alerts_24h.by_severity.medium, !!summary), color: 'text-amber' },
            // null firewall counts = the network fields aren't available yet: "—", not 0.
            { label: 'Blocked (7d)', value: kpi(summary?.firewall_7d?.block, !!summary?.firewall_7d), color: 'text-red-500' },
            { label: 'Rejected (7d)', value: kpi(summary?.firewall_7d?.reject, !!summary?.firewall_7d), color: 'text-orange' },
        ]
        : [
            { label: 'Alerts (24h)', value: kpi(stats?.total, !!stats), color: 'text-foreground' },
            { label: 'Critical (24h)', value: kpi(stats?.by_severity.critical, !!stats), color: 'text-red-500' },
            { label: 'High (24h)', value: kpi(stats?.by_severity.high, !!stats), color: 'text-orange' },
            { label: 'Medium (24h)', value: kpi(stats?.by_severity.medium, !!stats), color: 'text-amber' },
            { label: 'New (24h)', value: kpi(stats?.by_status.new, !!stats), color: 'text-red-500' },
            { label: 'Triaged (24h)', value: kpi(stats?.by_status.triaged, !!stats), color: 'text-blue' },
        ];
    const lastReceivedAt = client ? summary?.last_received_at ?? null : stats?.last_received_at ?? null;
    const staleAfter = (client ? summary?.stale_after_minutes : stats?.stale_after_minutes) ?? undefined;
    const filtered = severity !== 'all' || status !== 'all' || firewall !== 'all' || !!ip || !!text || assigned !== 'all';

    return (
        <div className="space-y-5">
            <div className="flex items-center justify-between gap-3">
                <div>
                    <h1 className="text-lg font-black text-foreground">{client ? 'Security Alerts' : 'Alerts'}</h1>
                    <p className="text-xs text-foreground-muted">
                        {client ? 'Wazuh alerts and firewall activity for your organisation' : 'SecOps & Response · Stored Wazuh alerts for your organisation'}
                        {checkedAt ? ` · updated ${watTime(checkedAt)}, refreshes every 30 s` : ''}
                    </p>
                </div>
                <button onClick={refresh} className="flex items-center gap-1.5 text-[11px] font-bold text-foreground-muted hover:text-foreground border border-border rounded-lg px-3 py-1.5">
                    <RefreshCw className="w-3.5 h-3.5" /> Refresh
                </button>
            </div>

            <AlertFeedStatus loaded={loaded} notConnected={notConnected} error={error} lastReceivedAt={lastReceivedAt} staleAfterMinutes={staleAfter} checkedAt={checkedAt} />

            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
                {kpis.map((k) => (
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
                <div className="flex items-center gap-1 bg-card border border-border rounded-lg p-1" role="group" aria-label="Firewall filter">
                    {(['all', 'firewall', ...FIREWALL_ACTIONS] as const).map((f) => (
                        <button key={f} onClick={() => { setLoading(true); setFirewall(f); }}
                            className={`text-[11px] font-bold px-2.5 py-1 rounded-md capitalize transition-colors ${firewall === f ? 'bg-blue text-white' : 'text-foreground-muted hover:text-foreground'}`}>
                            {f === 'all' ? 'All events' : f === 'firewall' ? 'Firewall' : f}
                        </button>
                    ))}
                </div>
                {!client && (
                    <>
                        <div className="flex items-center gap-1 bg-card border border-border rounded-lg p-1">
                            {(['all', ...STORED_ALERT_STATUSES] as const).map((s) => (
                                <button key={s} onClick={() => { setLoading(true); setStatus(s); }}
                                    className={`text-[11px] font-bold px-2.5 py-1 rounded-md transition-colors ${status === s ? 'bg-blue text-white' : 'text-foreground-muted hover:text-foreground'}`}>
                                    {s === 'all' ? 'All Status' : STATUS_LABEL[s]}
                                </button>
                            ))}
                        </div>
                        <div className="flex items-center gap-1 bg-card border border-border rounded-lg p-1">
                            {(['all', 'me', 'unassigned'] as const).map((s) => (
                                <button key={s} onClick={() => { setLoading(true); setAssigned(s); }}
                                    className={`text-[11px] font-bold px-2.5 py-1 rounded-md transition-colors ${assigned === s ? 'bg-blue text-white' : 'text-foreground-muted hover:text-foreground'}`}>
                                    {s === 'all' ? 'Anyone' : s === 'me' ? 'Mine' : 'Unassigned'}
                                </button>
                            ))}
                        </div>
                        <form onSubmit={(e) => { e.preventDefault(); setLoading(true); setText(search.trim()); }} className="flex items-center gap-1 bg-card border border-border rounded-lg px-2 py-1">
                            <Search className="w-3.5 h-3.5 text-foreground-muted" />
                            <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Rule, rule id or agent" aria-label="Search alerts" maxLength={100} className="bg-transparent text-[11px] text-foreground outline-none w-40" />
                        </form>
                        <form onSubmit={(e) => { e.preventDefault(); setLoading(true); setIp(ipInput.trim()); }} className="flex items-center gap-1 bg-card border border-border rounded-lg px-2 py-1">
                            <input value={ipInput} onChange={(e) => setIpInput(e.target.value)} placeholder="Source or destination IP" aria-label="Filter by IP address" maxLength={45} className="bg-transparent text-[11px] font-mono text-foreground outline-none w-40" />
                        </form>
                    </>
                )}
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
                        <p className="text-sm font-bold text-foreground text-center py-10 px-4">No data{filtered ? ' for these filters' : ''}</p>
                    ) : (
                        <div className="max-h-[640px] overflow-y-auto divide-y divide-border">
                            {alerts.map((a) => (
                                <button key={a.id} onClick={() => void open(a)}
                                    className={`w-full text-left p-3 hover:bg-card-muted transition-colors ${selected?.id === a.id ? 'bg-card-muted' : ''}`}>
                                    <div className="flex items-center justify-between gap-2">
                                        <div className="flex items-center gap-1.5">
                                            <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase ${SEV_STYLE[a.severity]}`}>{a.severity}</span>
                                            {a.net_action && <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase ${actionStyle(a.net_action)}`}>{a.net_action}</span>}
                                        </div>
                                        <span className="text-[10px] text-foreground-muted">{watTime(a.event_time)}</span>
                                    </div>
                                    <p className="text-xs font-bold text-foreground mt-1.5 leading-snug">{a.rule_description ?? `Rule ${a.rule_id ?? 'unknown'}`}</p>
                                    {(a.src_ip || a.dst_ip) && (
                                        <p className="text-[10px] font-mono text-foreground-muted mt-1 break-all">
                                            {endpoint(a.src_ip, a.src_port)} → {endpoint(a.dst_ip, a.dst_port)}{a.protocol ? ` · ${a.protocol.toUpperCase()}` : ''}
                                        </p>
                                    )}
                                    <div className="flex items-center justify-between mt-1.5">
                                        <span className="text-[10px] text-foreground-muted font-mono">{a.agent_id === '000' && a.location ? a.location : a.agent_name ?? a.agent_id ?? '—'}</span>
                                        {!client && <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${STATUS_STYLE[a.status]}`}>{STATUS_LABEL[a.status]}</span>}
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
                                {!client && <span className={`text-[10px] font-bold px-2 py-0.5 rounded border shrink-0 ${STATUS_STYLE[selected.status]}`}>{STATUS_LABEL[selected.status]}</span>}
                            </div>

                            <div className="grid grid-cols-2 gap-3 text-xs">
                                {([
                                    ['Agent', selected.agent_id === '000' ? 'Wazuh manager (syslog)' : `${selected.agent_name ?? '—'}${selected.agent_id ? ` (${selected.agent_id})` : ''}`],
                                    ...(client ? [] : [['Agent IP', selected.agent_ip ?? '—']]),
                                    ['Event time', watTime(selected.event_time)],
                                    ['Received', watTime(selected.received_at)],
                                    ['MITRE', selected.mitre_ids?.length ? selected.mitre_ids.join(', ') : '—'],
                                    ...(client ? [] : [['Wazuh groups', selected.wazuh_groups?.length ? selected.wazuh_groups.join(', ') : '—']]),
                                    ['Location', selected.location ?? '—'],
                                    ...(client ? [] : [
                                        ['Wazuh alert id', selected.wazuh_alert_id],
                                        ['Assigned to', selected.assigned_to ?? 'Nobody'],
                                        ['Acknowledged', selected.acknowledged_at ? `${watTime(selected.acknowledged_at)} by ${selected.acknowledged_by ?? '—'}` : 'No'],
                                    ]),
                                ] as [string, string][]).map(([k, v]) => (
                                    <div key={k}>
                                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{k}</p>
                                        <p className="text-foreground mt-0.5 break-all">{v}</p>
                                    </div>
                                ))}
                            </div>

                            {/* Network / firewall (P24). Shown when the alert carries any of it; '—' for a field it lacks. */}
                            {(selected.src_ip || selected.dst_ip || selected.net_action || selected.protocol) && (
                                <div className="border border-border rounded-lg p-3">
                                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">Network</p>
                                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs">
                                        {([
                                            ['Action', selected.net_action ?? '—'],
                                            ['Direction', selected.net_direction ?? '—'],
                                            ['Interface', selected.net_interface ?? '—'],
                                            ['Source', endpoint(selected.src_ip, selected.src_port)],
                                            ['Destination', endpoint(selected.dst_ip, selected.dst_port)],
                                            ['Protocol', selected.protocol?.toUpperCase() ?? '—'],
                                            ['Device', selected.device_hostname ?? selected.location ?? '—'],
                                            ['Decoder', selected.decoder_name ?? '—'],
                                        ] as [string, string][]).map(([k, v]) => (
                                            <div key={k}>
                                                <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{k}</p>
                                                <p className="text-foreground mt-0.5 font-mono break-all">{v}</p>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {!client && selected.raw !== undefined && (
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

                            {!client && (
                                <>
                                    <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-border">
                                        {(['triaged', 'escalated', 'false_positive', 'closed'] as const).map((s) => (
                                            <button key={s} disabled={busy || selected.status === s} onClick={() => void setAlertStatus(selected, s)}
                                                className="text-[11px] font-bold text-foreground border border-border rounded-lg px-3 py-1.5 hover:bg-card-muted disabled:opacity-50">
                                                {STATUS_LABEL[s]}
                                            </button>
                                        ))}
                                    </div>
                                    <div className="flex flex-wrap items-center gap-2">
                                        <button disabled={busy || selected.assigned_to === me.email.toLowerCase()} onClick={() => void triage(selected, { assigned_to: me.email }, 'Assigned to you')}
                                            className="text-[11px] font-bold text-foreground border border-border rounded-lg px-3 py-1.5 hover:bg-card-muted disabled:opacity-50">Assign to me</button>
                                        {selected.assigned_to && (
                                            <button disabled={busy} onClick={() => void triage(selected, { assigned_to: null }, 'Unassigned')}
                                                className="text-[11px] font-bold text-foreground-muted border border-border rounded-lg px-3 py-1.5 hover:bg-card-muted disabled:opacity-50">Unassign</button>
                                        )}
                                        <button disabled={busy || !!selected.acknowledged_at} onClick={() => void triage(selected, { acknowledged: true }, 'Acknowledged')}
                                            className="text-[11px] font-bold text-foreground border border-border rounded-lg px-3 py-1.5 hover:bg-card-muted disabled:opacity-50">{selected.acknowledged_at ? 'Acknowledged' : 'Acknowledge'}</button>
                                        {selected.case_id ? (
                                            <Link href={`/admin/secops/cases?case=${selected.case_id}`} className="text-[11px] font-bold text-purple border border-purple/40 rounded-lg px-3 py-1.5">Open case</Link>
                                        ) : (
                                            <button disabled={busy} onClick={() => void promote(selected)}
                                                className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5 disabled:opacity-50">Promote to case</button>
                                        )}
                                        {actionMsg && <span className={`text-[11px] font-bold ${actionMsg.ok ? 'text-emerald-500' : 'text-red-500'}`}>{actionMsg.text}</span>}
                                    </div>
                                    <div className="space-y-1.5">
                                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">Triage note</p>
                                        <textarea value={note} onChange={(e) => setNote(e.target.value)} maxLength={4000} rows={2} aria-label="Triage note"
                                            className="w-full bg-card-muted border border-border rounded-lg p-2 text-xs text-foreground" />
                                        <button disabled={busy || note === (selected.triage_note ?? '')} onClick={() => void triage(selected, { triage_note: note.trim() || null }, 'Note saved')}
                                            className="text-[11px] font-bold text-foreground border border-border rounded-lg px-3 py-1.5 hover:bg-card-muted disabled:opacity-50">Save note</button>
                                    </div>
                                    <AiPanel key={selected.id} purpose="alert_summary" subjectId={selected.id} title="AI alert summary" />
                                    {events && events.length > 0 && (
                                        <div className="space-y-1">
                                            <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">History</p>
                                            {events.map((e, i) => (
                                                <p key={i} className="text-[11px] text-foreground-muted">
                                                    {watTime(e.at)} · {e.actor} · {EVENT_LABEL[e.action] ?? e.action}
                                                    {e.to_value && e.action !== 'case_link' ? `: ${e.from_value ? `${e.from_value} → ` : ''}${e.to_value}` : ''}
                                                    {e.details ? ` — ${e.details}` : ''}
                                                </p>
                                            ))}
                                        </div>
                                    )}
                                </>
                            )}
                            {client && (
                                <p className="text-[11px] text-foreground-muted border-t border-border pt-3">
                                    Questions about this alert? Contact your SOC team and quote its event time and rule {selected.rule_id ?? ''}.
                                </p>
                            )}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
