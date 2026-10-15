'use client';

// Risk trends (phase P7): daily snapshots of open findings by priority, time to remediate, and
// recurring problems. Snapshots start when Release 3 starts; nothing before that is back-filled.

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { TrendingUp } from 'lucide-react';
import { loadJson } from '@/lib/alerts';

interface Snapshot { day: string; open_total: number; open_by_priority: Record<string, number>; overdue: number; kev_open: number; internet_open: number; new_findings: number; verified: number; reopened: number }
interface Trends {
    period: { from: string; to: string; days: number };
    snapshots: Snapshot[];
    time_to_remediate: Record<string, { verified: number; mean_hours: number | null; within_deadline: number }>;
    recurring: { reopened: { id: string; title: string; asset_value: string; times_reopened: number }[]; widespread: { rule_id: string; title: string; open_on_assets: number }[] };
    note: string | null;
}
const BAR: Record<string, string> = { P1: 'bg-red', P2: 'bg-orange', P3: 'bg-amber', P4: 'bg-foreground-muted' };
const hours = (h: number | null) => (h === null ? '—' : h < 48 ? `${h} h` : `${Math.round(h / 24)} days`);

export function VmsTrends() {
    const [data, setData] = useState<Trends | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [days, setDays] = useState(90);

    useEffect(() => {
        let active = true;
        void loadJson<Trends>(`/api/vms/trends?days=${days}`).then((r) => {
            if (!active) return;
            setData(r.ok ? r.data : null);
            setError(r.ok ? null : r.error);
        });
        return () => { active = false; };
    }, [days]);

    const max = Math.max(1, ...(data?.snapshots ?? []).map((s) => s.open_total));
    return (
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between gap-2 flex-wrap">
                <h2 className="text-sm font-black text-foreground flex items-center gap-2"><TrendingUp className="w-4 h-4" /> Risk trend</h2>
                <div className="flex items-center gap-2">
                    <div className="flex gap-1 bg-card-muted rounded-lg p-1">{[30, 90, 365].map((d) => <button key={d} onClick={() => setDays(d)} className={`text-[11px] font-bold px-2 py-0.5 rounded ${days === d ? 'bg-blue text-white' : 'text-foreground-muted'}`}>{d} days</button>)}</div>
                    <Link href="/admin/vms/report" className="text-[11px] font-bold text-purple">Period report →</Link>
                </div>
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {data?.note && <p className="text-xs text-foreground-muted">{data.note}</p>}
            {data && data.snapshots.length > 0 && (
                <div>
                    <div className="flex items-end gap-px h-32" aria-label="Open findings per day, by priority">
                        {data.snapshots.map((s) => (
                            <div key={s.day} title={`${s.day}: ${s.open_total} open (P1 ${s.open_by_priority.P1 ?? 0}, P2 ${s.open_by_priority.P2 ?? 0}, P3 ${s.open_by_priority.P3 ?? 0}, P4 ${s.open_by_priority.P4 ?? 0}); ${s.overdue} overdue`} className="flex-1 min-w-[3px] flex flex-col-reverse">
                                {['P1', 'P2', 'P3', 'P4'].map((p) => <div key={p} className={BAR[p]} style={{ height: `${((s.open_by_priority[p] ?? 0) / max) * 128}px` }} />)}
                            </div>
                        ))}
                    </div>
                    <p className="text-[10px] text-foreground-muted mt-1">{data.snapshots[0].day} → {data.snapshots[data.snapshots.length - 1].day} · open findings per day (P1 red, P2 orange, P3 amber, P4 grey) · latest: {data.snapshots[data.snapshots.length - 1].open_total} open, {data.snapshots[data.snapshots.length - 1].overdue} overdue, {data.snapshots[data.snapshots.length - 1].kev_open} known exploited</p>
                </div>
            )}
            {data && (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 text-xs">
                    <div>
                        <p className="text-[10px] font-bold text-foreground-muted uppercase mb-1">Time to verified fix ({data.period.days} days)</p>
                        {Object.entries(data.time_to_remediate).map(([p, t]) => <p key={p}><span className="font-bold">{p}</span> · {t.verified} verified · mean {hours(t.mean_hours)} · {t.verified ? `${t.within_deadline} within deadline` : '—'}</p>)}
                    </div>
                    <div>
                        <p className="text-[10px] font-bold text-foreground-muted uppercase mb-1">Reopened after a fix</p>
                        {data.recurring.reopened.length === 0 ? <p className="text-foreground-muted">None in the period.</p> : data.recurring.reopened.slice(0, 8).map((f) => <p key={f.id}><Link href={`/admin/vms/findings?id=${f.id}`} className="text-blue">{f.title}</Link> · {f.asset_value} · {f.times_reopened}×</p>)}
                    </div>
                    <div>
                        <p className="text-[10px] font-bold text-foreground-muted uppercase mb-1">Open on 3+ assets</p>
                        {data.recurring.widespread.length === 0 ? <p className="text-foreground-muted">None.</p> : data.recurring.widespread.slice(0, 8).map((r) => <p key={r.rule_id}>{r.title} · {r.open_on_assets} assets</p>)}
                    </div>
                </div>
            )}
        </div>
    );
}
