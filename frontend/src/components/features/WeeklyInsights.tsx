'use client';

// Weekly insights (phase P8): the counted facts for the period and the one before — alerts, cases,
// response approvals, vulnerabilities, threat-intel matches — with platform health and stated
// limitations, and an AI write-up grounded in exactly these facts.

import { useEffect, useState } from 'react';
import { CalendarRange, AlertTriangle } from 'lucide-react';
import { loadJson } from '@/lib/alerts';
import { fmtWat } from '@/lib/vms';
import { AiPanel } from '@/components/shared/AiPanel';

interface Facts {
    period: { from: string; to: string; days: number; previous_from: string };
    alerts: { total: number; previous_total: number; by_severity: Record<string, number>; previous_by_severity: Record<string, number>; top_rules: { rule_id: string | null; description: string | null; count: number }[]; top_agents: { agent: string; count: number }[] };
    cases: { opened: number; previous_opened: number; resolved: number; open_now: number; overdue_now: number; by_severity_opened: Record<string, number> };
    approvals: Record<string, number>;
    vulnerabilities: { open_now: number; open_by_priority: Record<string, number>; new_p1_p2: number; verified: number; reopened: number; overdue_now: number } | null;
    threat_intel: { new_matches: number; promoted: number } | null;
    health: { name: string; status: string; detail: string }[];
    limitations: string[];
}
const pairs = (o: Record<string, number>) => Object.entries(o).length ? Object.entries(o).map(([k, v]) => `${k} ${v}`).join(' · ') : 'none';
const delta = (now: number, before: number) => (before === 0 ? (now === 0 ? 'no change' : 'none before') : `${now >= before ? '+' : ''}${Math.round(((now - before) / before) * 100)}%`);

function Tile({ label, value, sub }: { label: string; value: number | string; sub?: string }) {
    return (
        <div className="bg-card border border-border rounded-xl p-4">
            <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{label}</p>
            <p className="text-2xl font-black text-foreground mt-1">{value}</p>
            {sub && <p className="text-[10px] text-foreground-muted mt-0.5">{sub}</p>}
        </div>
    );
}

export function WeeklyInsights() {
    const [period, setPeriod] = useState<'7d' | '30d'>('7d');
    const [data, setData] = useState<Facts | null>(null);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        let active = true;
        void loadJson<Facts>(`/api/insights/weekly?days=${period === '7d' ? 7 : 30}`).then((r) => {
            if (!active) return;
            setData(r.ok ? r.data : null);
            setError(r.ok ? null : r.error);
        });
        return () => { active = false; };
    }, [period]);

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between gap-2 flex-wrap">
                <div>
                    <h1 className="text-lg font-black text-foreground flex items-center gap-2"><CalendarRange className="w-5 h-5" /> Weekly Insights</h1>
                    <p className="text-xs text-foreground-muted">Counted from stored records for the period, compared with the period before.</p>
                </div>
                <div className="flex gap-1 bg-card border border-border rounded-lg p-1">{(['7d', '30d'] as const).map((p) => <button key={p} onClick={() => setPeriod(p)} className={`text-[11px] font-bold px-2.5 py-1 rounded-md ${period === p ? 'bg-blue text-white' : 'text-foreground-muted'}`}>Last {p === '7d' ? '7' : '30'} days</button>)}</div>
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {data && (
                <>
                    <p className="text-[11px] text-foreground-muted">{fmtWat(data.period.from)} to {fmtWat(data.period.to)}; compared with {fmtWat(data.period.previous_from)} to {fmtWat(data.period.from)}.</p>
                    {data.limitations.length > 0 && (
                        <div className="rounded-xl p-3 border border-amber/30 bg-amber/10 text-xs text-amber space-y-0.5">
                            <p className="font-bold flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5" /> Read these numbers with care</p>
                            {data.limitations.map((l) => <p key={l}>• {l}</p>)}
                        </div>
                    )}
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                        <Tile label="Alerts" value={data.alerts.total} sub={`${delta(data.alerts.total, data.alerts.previous_total)} vs ${data.alerts.previous_total}`} />
                        <Tile label="Cases opened" value={data.cases.opened} sub={`${delta(data.cases.opened, data.cases.previous_opened)} vs ${data.cases.previous_opened}; ${data.cases.resolved} resolved`} />
                        <Tile label="Open cases now" value={data.cases.open_now} sub={`${data.cases.overdue_now} past deadline`} />
                        <Tile label="Open vulnerabilities" value={data.vulnerabilities?.open_now ?? '—'} sub={data.vulnerabilities ? `${data.vulnerabilities.new_p1_p2} new P1/P2 · ${data.vulnerabilities.overdue_now} overdue` : 'not set up'} />
                    </div>
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs">
                        <div className="bg-card border border-border rounded-xl p-4 space-y-1">
                            <h2 className="text-sm font-black text-foreground">Alerts</h2>
                            <p>By severity: {pairs(data.alerts.by_severity)} (before: {pairs(data.alerts.previous_by_severity)})</p>
                            <p className="text-[10px] font-bold text-foreground-muted uppercase pt-1">Top rules</p>
                            {data.alerts.top_rules.length === 0 ? <p className="text-foreground-muted">None.</p> : data.alerts.top_rules.map((r) => <p key={`${r.rule_id}-${r.description}`}>{r.count} · {r.description ?? `rule ${r.rule_id ?? '?'}`}{r.rule_id ? ` (${r.rule_id})` : ''}</p>)}
                            <p className="text-[10px] font-bold text-foreground-muted uppercase pt-1">Top agents</p>
                            <p>{data.alerts.top_agents.map((a) => `${a.agent} ${a.count}`).join(' · ') || 'none'}</p>
                        </div>
                        <div className="bg-card border border-border rounded-xl p-4 space-y-1">
                            <h2 className="text-sm font-black text-foreground">Response, vulnerabilities, intelligence</h2>
                            <p>Cases opened by severity: {pairs(data.cases.by_severity_opened)}</p>
                            <p>Response approvals: {pairs(data.approvals)}</p>
                            <p>Vulnerabilities: {data.vulnerabilities ? `${pairs(data.vulnerabilities.open_by_priority)} open; ${data.vulnerabilities.verified} verified fixed; ${data.vulnerabilities.reopened} reopened` : 'not set up'}</p>
                            <p>Threat-intel matches: {data.threat_intel ? `${data.threat_intel.new_matches} new, ${data.threat_intel.promoted} opened as cases` : 'not set up'}</p>
                            <p className="text-[10px] font-bold text-foreground-muted uppercase pt-1">Pipelines now</p>
                            {data.health.map((h) => <p key={h.name}><span className={h.status === 'up' ? 'text-green' : h.status === 'off' ? 'text-foreground-muted' : 'text-amber'}>{h.status}</span> · {h.name} — {h.detail}</p>)}
                        </div>
                    </div>
                    <AiPanel key={period} purpose="weekly_insights" subjectId={period} title="AI weekly insights" />
                </>
            )}
        </div>
    );
}
