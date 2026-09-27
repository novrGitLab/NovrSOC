'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { RefreshCw, ArrowUp, ArrowRight, ArrowDown, Info } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { SlaTrendChart, type SlaPoint } from './SlaTrendChart';

// Security Assessment — admin view. Posture of every active client organisation, computed from
// the real cases table (GET /api/admin/security-assessment/overview). A figure that can't be
// measured shows "—" with the reason; nothing here is sample data.

export type Posture = 'secure' | 'at_risk' | 'critical';
type Trend = 'improving' | 'stable' | 'declining';

interface ClientRow {
    org_id: string; org_name: string; detection_time_hrs: null; close_time_hrs: number | null; open_cases: number;
    closed_this_month: number; resolved_30d: number; sla_rate: number | null; posture: Posture; trend: Trend | null; last_updated: string | null;
}
interface Overview {
    summary: { active_clients: number; avg_detection_time_hrs: null; avg_close_time_hrs: number | null; open_cases: number; sla_rate: number | null; clients_below_sla: number };
    clients: ClientRow[];
    monthly: SlaPoint[];
    definitions: { sla_target_hours: Record<string, number>; sla_secure_threshold_pct: number; detection_time: string };
    generated_at: string;
}

export const POSTURE_STYLE: Record<Posture, { label: string; cls: string }> = {
    secure: { label: 'Secure', cls: 'bg-green/10 text-green border-green/30' },
    at_risk: { label: 'At Risk', cls: 'bg-amber-500/10 text-amber-600 border-amber-500/30' },
    critical: { label: 'Critical', cls: 'bg-red-500/10 text-red-500 border-red-500/30' },
};

export function TrendMark({ trend }: { trend: Trend | null }) {
    if (!trend) return <span className="text-foreground-muted" title="Needs resolved cases in both this month and last">—</span>;
    const map = {
        improving: { Icon: ArrowUp, text: 'Improving', cls: 'text-green' },
        stable: { Icon: ArrowRight, text: 'Stable', cls: 'text-foreground-muted' },
        declining: { Icon: ArrowDown, text: 'Declining', cls: 'text-red-500' },
    }[trend];
    return <span className={`inline-flex items-center gap-1 text-xs font-bold ${map.cls}`}><map.Icon size={12} /> {map.text}</span>;
}

const fmtHrs = (v: number | null) => (v === null ? '—' : `${v}h`);
const fmtPct = (v: number | null) => (v === null ? '—' : `${v}%`);
const wat = (iso: string | null) => (iso ? new Intl.DateTimeFormat('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }).format(new Date(iso)) + ' WAT' : '—');

export function SecurityAssessmentAdmin({ presence }: { presence?: React.ReactNode }) {
    const [data, setData] = useState<Overview | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [nonce, setNonce] = useState(0);

    useEffect(() => {
        let active = true;
        apiFetch(apiUrl('/api/admin/security-assessment/overview'), { cache: 'no-store' })
            .then(async (r) => {
                const d = await r.json().catch(() => null);
                if (!active) return;
                if (!r.ok || !d) { setError(r.status === 403 ? 'Security Assessment is available to SOC managers and executives.' : d?.error ?? `HTTP ${r.status}`); return; }
                setError(null);
                setData(d as Overview);
            })
            .catch(() => { if (active) setError('Could not reach the backend'); });
        return () => { active = false; };
    }, [nonce]);

    const s = data?.summary;
    const tiles = [
        { label: 'Total Active Clients', value: s ? String(s.active_clients) : '—' },
        { label: 'Avg Detection Time', value: '—', note: 'Not tracked' },
        { label: 'Avg Close Time', value: s ? fmtHrs(s.avg_close_time_hrs) : '—', note: 'Last 30 days' },
        { label: 'Open Cases', value: s ? String(s.open_cases) : '—', note: 'All clients' },
        { label: 'SLA Compliance', value: s ? fmtPct(s.sla_rate) : '—', note: 'Last 30 days' },
        { label: 'Clients Below SLA', value: s ? String(s.clients_below_sla) : '—', note: data ? `Under ${data.definitions.sla_secure_threshold_pct}%` : undefined, alert: (s?.clients_below_sla ?? 0) > 0 },
    ];

    return (
        <div className="space-y-4">
            <div className="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <h1 className="text-lg font-black text-foreground">Security Assessment</h1>
                    <p className="text-xs text-foreground-muted">Posture across every client organisation, from real case data.{data ? ` Updated ${wat(data.generated_at)}.` : ''}</p>
                </div>
                <button onClick={() => { setData(null); setNonce((n) => n + 1); }} className="flex items-center gap-1.5 text-[11px] font-bold text-foreground-muted hover:text-foreground border border-border rounded-lg px-3 py-1.5">
                    <RefreshCw className="w-3.5 h-3.5" /> Refresh
                </button>
            </div>

            {presence}

            {error ? (
                <div role="alert" className="bg-red-500/5 border border-red-500/30 rounded-xl p-6 text-center text-sm font-bold text-red-500">{error}</div>
            ) : (
                <>
                    <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
                        {tiles.map((t) => (
                            <div key={t.label} className="bg-card border border-border rounded-xl p-4">
                                <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{t.label}</p>
                                <p className={`text-2xl font-black mt-1 ${t.alert ? 'text-red-500' : 'text-foreground'}`}>{data ? t.value : <span className="inline-block w-10 h-6 bg-card-muted rounded animate-pulse" />}</p>
                                {t.note && <p className="text-[10px] text-foreground-muted mt-0.5">{t.note}</p>}
                            </div>
                        ))}
                    </div>

                    <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                        <div className="xl:col-span-2 bg-card border border-border rounded-xl overflow-x-auto">
                            <table className="w-full text-xs min-w-[860px]">
                                <thead>
                                    <tr className="text-left text-[10px] uppercase tracking-wider text-foreground-muted border-b border-border">
                                        {['Client', 'Detection Time', 'Close Time', 'Open Cases', 'Closed This Month', 'SLA Rate', 'Posture', 'Trend', 'Last Updated'].map((h) => (
                                            <th key={h} className="px-4 py-2.5 font-bold whitespace-nowrap">{h}</th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody>
                                    {data === null ? (
                                        <tr><td colSpan={9} className="px-4 py-6"><div className="h-8 bg-card-muted rounded animate-pulse" /></td></tr>
                                    ) : data.clients.length === 0 ? (
                                        <tr><td colSpan={9} className="px-4 py-8 text-center text-foreground-muted">No active client organisations.</td></tr>
                                    ) : data.clients.map((c) => (
                                        <tr key={c.org_id} className="border-b border-border/60 last:border-0">
                                            <td className="px-4 py-3">
                                                <Link href={`/admin/secops/security-assessment/report?org=${encodeURIComponent(c.org_id)}`} className="font-bold text-foreground hover:text-purple hover:underline">{c.org_name}</Link>
                                            </td>
                                            <td className="px-4 py-3 text-foreground-muted" title={data.definitions.detection_time}>—</td>
                                            <td className="px-4 py-3 text-foreground">{fmtHrs(c.close_time_hrs)}</td>
                                            <td className="px-4 py-3 text-foreground">{c.open_cases}</td>
                                            <td className="px-4 py-3 text-foreground">{c.closed_this_month}</td>
                                            <td className="px-4 py-3 text-foreground" title={c.sla_rate === null ? 'No worked cases resolved in the last 30 days' : `${c.resolved_30d} resolved in 30 days`}>{fmtPct(c.sla_rate)}</td>
                                            <td className="px-4 py-3"><span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${POSTURE_STYLE[c.posture].cls}`}>{POSTURE_STYLE[c.posture].label}</span></td>
                                            <td className="px-4 py-3"><TrendMark trend={c.trend} /></td>
                                            <td className="px-4 py-3 text-foreground-muted whitespace-nowrap">{wat(c.last_updated)}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>

                        <div className="bg-card border border-border rounded-xl p-4">
                            <h2 className="text-sm font-bold text-foreground">SLA compliance — all clients</h2>
                            <p className="text-[10px] text-foreground-muted mb-3">Share of worked cases resolved within target, by month (WAT)</p>
                            {data ? <SlaTrendChart data={data.monthly} /> : <div className="h-56 bg-card-muted rounded animate-pulse" />}
                        </div>
                    </div>

                    {data && (
                        <div className="flex gap-2 text-[11px] text-foreground-muted bg-card border border-border rounded-xl p-3">
                            <Info size={14} className="shrink-0 mt-px" />
                            <p>
                                SLA targets (time to resolve): {Object.entries(data.definitions.sla_target_hours).map(([k, v]) => `${k} ${v}h`).join(' · ')}.
                                Posture: Secure = SLA over {data.definitions.sla_secure_threshold_pct}% and fewer than 5 open cases; Critical = SLA under 70% or more than 15 open; otherwise At Risk.
                                Auto-closed tier-1 cases are excluded from every figure. Detection time is not tracked: {data.definitions.detection_time.replace(/^Not tracked — /, '')}
                            </p>
                        </div>
                    )}
                </>
            )}
        </div>
    );
}
