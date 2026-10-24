'use client';

// Client portal overview (phase P24): the organisation's own monitoring, from
// GET /api/client/secops/summary and /alerts (org-scoped stored alerts and the organisation's
// Wazuh agents). Refreshes every 60 s while the tab is visible. Every figure is real or shown as
// unavailable ("—" with the reason); nothing is a placeholder or a derived "threat level".

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { getPortalContext } from '@/lib/portal-context';
import { loadJson, watTime, endpoint, type StoredAlert } from '@/lib/alerts';
import { AlertFeedStatus } from '@/components/shared/AlertFeedStatus';
import { usePolling } from '@/lib/usePolling';
import type { Severity } from '@/lib/severity';

interface Summary {
    alerts_24h: { total: number; by_severity: Record<Severity, number> };
    alerts_7d: { total: number; by_severity: Record<Severity, number> };
    firewall_7d: { block: number; reject: number; pass: number } | null;
    last_received_at: string | null;
    stale_after_minutes: number;
    agents: { total: number; active: number; disconnected: number; never_connected: number } | null;
    agents_error: string | null;
}
type Page = { alerts: StoredAlert[]; next_cursor: string | null };

const SEV_BADGE: Record<Severity, string> = {
    critical: 'bg-red-500/10 text-red-500 border-red-500/30',
    high: 'bg-orange/10 text-orange border-orange/30',
    medium: 'bg-amber/10 text-amber border-amber/30',
    low: 'bg-blue/10 text-blue border-blue/30',
};
const ACTION_BADGE: Record<string, string> = {
    block: 'bg-red-500/10 text-red-500 border-red-500/30',
    reject: 'bg-orange/10 text-orange border-orange/30',
    pass: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/30',
};

const REFRESH_MS = 60_000;

function AlertTable({ rows, empty, network }: { rows: StoredAlert[]; empty: string; network?: boolean }) {
    if (rows.length === 0) return <p className="text-xs text-foreground-muted text-center py-8 px-4">{empty}</p>;
    return (
        <div className="overflow-x-auto">
            <table className="w-full text-xs">
                <thead><tr className="border-b border-border">
                    {(network ? ['Action', 'Source', 'Destination', 'Protocol', 'Time'] : ['Severity', 'Alert', 'Asset', 'Time']).map((h) => (
                        <th key={h} className="text-left px-4 py-2 text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{h}</th>
                    ))}
                </tr></thead>
                <tbody>
                    {rows.map((a) => (
                        <tr key={a.id} className="border-b border-border">
                            {network ? (
                                <>
                                    <td className="px-4 py-2"><span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${ACTION_BADGE[a.net_action ?? ''] ?? 'bg-card-muted text-foreground-muted border-border'}`}>{a.net_action ?? '—'}</span></td>
                                    <td className="px-4 py-2 font-mono text-foreground">{endpoint(a.src_ip, a.src_port)}</td>
                                    <td className="px-4 py-2 font-mono text-foreground-muted">{endpoint(a.dst_ip, a.dst_port)}</td>
                                    <td className="px-4 py-2 text-foreground-muted uppercase">{a.protocol ?? '—'}</td>
                                </>
                            ) : (
                                <>
                                    <td className="px-4 py-2"><span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${SEV_BADGE[a.severity]}`}>{a.severity}</span></td>
                                    <td className="px-4 py-2 font-semibold text-foreground">{a.rule_description ?? `Rule ${a.rule_id ?? 'unknown'}`}</td>
                                    <td className="px-4 py-2 font-mono text-foreground-muted">{a.agent_id === '000' ? a.location ?? '—' : a.agent_name ?? '—'}</td>
                                </>
                            )}
                            <td className="px-4 py-2 text-foreground-muted whitespace-nowrap">{watTime(a.event_time)}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

export const PortalDashboard = () => {
    const portal = getPortalContext();
    const [summary, setSummary] = useState<Summary | null>(null);
    const [recent, setRecent] = useState<StoredAlert[]>([]);
    const [firewall, setFirewall] = useState<StoredAlert[]>([]);
    const [state, setState] = useState<{ loaded: boolean; notConnected: boolean; error: string | null; checkedAt: string | null }>({ loaded: false, notConnected: false, error: null, checkedAt: null });

    const load = useCallback(async () => {
        const [s, r, f] = await Promise.all([
            loadJson<Summary>('/api/client/secops/summary'),
            loadJson<Page>('/api/client/secops/alerts?limit=5'),
            loadJson<Page>('/api/client/secops/alerts?limit=5&firewall=1'),
        ]);
        const failed = !s.ok ? s : !r.ok ? r : null;
        setSummary(s.ok ? s.data : null);
        setRecent(r.ok ? r.data.alerts : []);
        // 503 = the firewall fields aren't available yet; shown as such below, not as "no activity".
        setFirewall(f.ok ? f.data.alerts : []);
        setState({ loaded: true, notConnected: !!failed && failed.notConnected, error: failed ? failed.error : null, checkedAt: new Date().toISOString() });
    }, []);
    useEffect(() => {
        const t = setTimeout(() => void load(), 0);
        return () => clearTimeout(t);
    }, [load]);
    usePolling(load, REFRESH_MS);

    const loading = !state.loaded;
    const show = (v: number | null | undefined) => (loading ? '…' : v === null || v === undefined ? '—' : v.toLocaleString());
    const agents = summary?.agents ?? null;

    const kpiCards = [
        { label: 'Monitored Endpoints', value: show(agents?.total), color: 'text-blue', sub: agents ? `${agents.active} active · ${agents.disconnected} disconnected` : summary?.agents_error ? 'Agent inventory unavailable' : undefined },
        { label: 'Alerts (24h)', value: show(summary?.alerts_24h.total), color: 'text-amber', sub: undefined as string | undefined },
        { label: 'Critical + High (7d)', value: show(summary ? summary.alerts_7d.by_severity.critical + summary.alerts_7d.by_severity.high : null), color: 'text-red-500', sub: undefined as string | undefined },
        {
            label: 'Firewall Blocks (7d)',
            value: show(summary?.firewall_7d ? summary.firewall_7d.block + summary.firewall_7d.reject : null),
            color: 'text-blue',
            sub: summary && !summary.firewall_7d ? 'Firewall fields not available yet' : 'Blocked or rejected by your firewall',
        },
    ];

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-lg font-black text-foreground">Welcome, {portal.orgName}</h1>
                <p className="text-xs text-foreground-muted">
                    Your security overview, powered by Cybernovr NovrSOC{state.checkedAt ? ` · updated ${watTime(state.checkedAt)}` : ''}
                </p>
            </div>

            <AlertFeedStatus loaded={state.loaded} notConnected={state.notConnected} error={state.error} lastReceivedAt={summary?.last_received_at ?? null} staleAfterMinutes={summary?.stale_after_minutes} checkedAt={state.checkedAt} />

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {kpiCards.map((k) => (
                    <div key={k.label} className="bg-card border border-border rounded-xl p-4">
                        <div className="h-[3px] bg-blue -mt-4 -mx-4 mb-4 rounded-t-xl" />
                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-1">{k.label}</p>
                        <p className={`text-2xl font-black ${k.color}`}>{k.value}</p>
                        {k.sub && <p className="text-[10px] text-foreground-muted mt-1">{k.sub}</p>}
                    </div>
                ))}
            </div>

            {state.loaded && agents && agents.total === 0 && (
                <div className="bg-card border border-blue/30 rounded-xl p-6">
                    <h3 className="text-sm font-black text-foreground mb-1">No endpoints are reporting yet</h3>
                    <p className="text-xs text-foreground-muted">
                        No Wazuh agents are enrolled for your organisation. Your SOC team provides the agent installer and enrolment details for your environment.
                    </p>
                </div>
            )}

            <div className="bg-card border border-border rounded-xl overflow-hidden">
                <div className="h-[3px] bg-blue" />
                <div className="p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs font-black text-foreground">Firewall Activity</p>
                        <p className="text-[10px] text-foreground-muted">
                            {summary?.firewall_7d
                                ? `Last 7 days: ${summary.firewall_7d.block.toLocaleString()} blocked · ${summary.firewall_7d.reject.toLocaleString()} rejected · ${summary.firewall_7d.pass.toLocaleString()} passed (logged)`
                                : 'Latest firewall events'}
                        </p>
                    </div>
                    <Link href="/client/secops/threats" className="text-[10px] font-bold text-blue hover:underline">View All →</Link>
                </div>
                {loading ? (
                    <div className="p-6 space-y-2">{Array.from({ length: 3 }).map((_, i) => <div key={i} className="h-6 bg-card-muted rounded animate-pulse" />)}</div>
                ) : summary && !summary.firewall_7d ? (
                    <p className="text-xs text-foreground-muted text-center py-8 px-4">Firewall fields are not available yet on this platform.</p>
                ) : (
                    <AlertTable rows={firewall} network empty="No firewall events have been received for your organisation." />
                )}
            </div>

            <div className="bg-card border border-border rounded-xl overflow-hidden">
                <div className="h-[3px] bg-blue" />
                <div className="p-4 flex items-center justify-between">
                    <p className="text-xs font-black text-foreground">Recent Alerts</p>
                    <Link href="/client/secops/threats" className="text-[10px] font-bold text-blue hover:underline">View All →</Link>
                </div>
                {loading ? (
                    <div className="p-6 space-y-2">{Array.from({ length: 3 }).map((_, i) => <div key={i} className="h-6 bg-card-muted rounded animate-pulse" />)}</div>
                ) : (
                    <AlertTable rows={recent} empty={state.error ? 'Alerts unavailable — see above.' : 'No alerts have been received for your organisation.'} />
                )}
            </div>
        </div>
    );
};
