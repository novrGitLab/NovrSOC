'use client';

// Period report (phase P7): what happened in vulnerability management over a stated period, from
// stored records, with the sources used and what the report cannot see. Printable.

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { FileBarChart, Printer } from 'lucide-react';
import { loadJson } from '@/lib/alerts';
import { fmtWat } from '@/lib/vms';

interface Report {
    period: { from: string; to: string; days: number };
    open_now: { total: number; by_priority: Record<string, number>; overdue: number };
    new_in_period: { total: number; by_priority: Record<string, number>; by_source: Record<string, number> };
    status_changes: Record<string, number>;
    time_to_remediate: Record<string, { verified: number; mean_hours: number | null; within_deadline: number }>;
    scans: Record<string, number>;
    attack_surface_changes: Record<string, number>;
    top_open: { id: string; title: string; asset: string; priority: string; due_at: string | null; status: string }[];
    recurring: { reopened: { id: string; title: string; asset_value: string; times_reopened: number }[]; widespread: { rule_id: string; title: string; open_on_assets: number }[] };
    sources: string[];
    limitations: string[];
}
const pairs = (o: Record<string, number>) => Object.entries(o).length ? Object.entries(o).map(([k, v]) => `${k.replace(/_/g, ' ')} ${v}`).join(' · ') : 'none';

export function VmsReport() {
    const [days, setDays] = useState(30);
    const [data, setData] = useState<Report | null>(null);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        let active = true;
        void loadJson<Report>(`/api/vms/report?days=${days}`).then((r) => {
            if (!active) return;
            setData(r.ok ? r.data : null);
            setError(r.ok ? null : r.error);
        });
        return () => { active = false; };
    }, [days]);

    const section = 'bg-card border border-border rounded-xl p-4 text-xs space-y-1';
    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between gap-2 flex-wrap">
                <h1 className="text-lg font-black text-foreground flex items-center gap-2"><FileBarChart className="w-5 h-5" /> Vulnerability Management report</h1>
                <div className="flex items-center gap-2 print:hidden">
                    <div className="flex gap-1 bg-card border border-border rounded-lg p-1">{[7, 30, 90].map((d) => <button key={d} onClick={() => setDays(d)} className={`text-[11px] font-bold px-2.5 py-1 rounded-md ${days === d ? 'bg-blue text-white' : 'text-foreground-muted'}`}>{d} days</button>)}</div>
                    <button onClick={() => window.print()} className="text-[11px] font-bold border border-border rounded-lg px-3 py-1.5 flex items-center gap-1"><Printer className="w-3.5 h-3.5" /> Print / PDF</button>
                </div>
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {data && (
                <>
                    <p className="text-xs text-foreground-muted">Period: {fmtWat(data.period.from)} to {fmtWat(data.period.to)} ({data.period.days} days). Counted from stored records when this page was opened.</p>
                    <div className={section}>
                        <h2 className="text-sm font-black text-foreground">Position now</h2>
                        <p>{data.open_now.total} open findings ({pairs(data.open_now.by_priority)}); {data.open_now.overdue} past their deadline.</p>
                    </div>
                    <div className={section}>
                        <h2 className="text-sm font-black text-foreground">In the period</h2>
                        <p>New findings: {data.new_in_period.total} ({pairs(data.new_in_period.by_priority)}); by source: {pairs(data.new_in_period.by_source)}.</p>
                        <p>Status changes: {pairs(data.status_changes)}.</p>
                        <p>Scans: {pairs(data.scans)}.</p>
                        <p>Attack surface: {pairs(data.attack_surface_changes)}.</p>
                    </div>
                    <div className={section}>
                        <h2 className="text-sm font-black text-foreground">Time to verified fix</h2>
                        {Object.entries(data.time_to_remediate).map(([p, t]) => <p key={p}>{p}: {t.verified} verified{t.mean_hours !== null ? `, mean ${t.mean_hours} h, ${t.within_deadline} within deadline` : ''}</p>)}
                    </div>
                    <div className={section}>
                        <h2 className="text-sm font-black text-foreground">Open P1 / P2</h2>
                        {data.top_open.length === 0 ? <p className="text-foreground-muted">None.</p> : data.top_open.map((f) => <p key={f.id}><span className="font-bold">{f.priority}</span> <Link href={`/admin/vms/findings?id=${f.id}`} className="text-blue">{f.title}</Link> · {f.asset} · {f.status} · due {fmtWat(f.due_at)}</p>)}
                    </div>
                    <div className={section}>
                        <h2 className="text-sm font-black text-foreground">Recurring</h2>
                        <p>Reopened after a fix: {data.recurring.reopened.length ? data.recurring.reopened.map((f) => `${f.title} on ${f.asset_value} (${f.times_reopened}×)`).join('; ') : 'none'}.</p>
                        <p>Open on 3+ assets: {data.recurring.widespread.length ? data.recurring.widespread.map((r) => `${r.title} (${r.open_on_assets})`).join('; ') : 'none'}.</p>
                    </div>
                    <div className={`${section} border-amber/30`}>
                        <h2 className="text-sm font-black text-foreground">Limitations</h2>
                        {data.limitations.map((l) => <p key={l}>• {l}</p>)}
                        <p className="text-foreground-muted">Sources: {data.sources.join(', ')}.</p>
                    </div>
                </>
            )}
        </div>
    );
}
