'use client';

// Period report (phase P7): what happened in vulnerability management over a stated period, from
// stored records, with the sources used and what the report cannot see. Printable.

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { FileBarChart, Printer } from 'lucide-react';
import { loadJson } from '@/lib/alerts';
import { fmtWat } from '@/lib/vms';
import { ExportButton } from '@/components/shared/ExportButton';
import { PageHeader, Segmented, btn } from './kit';

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
    /** P16: closure by evidence vs claims; what was actually assessed. */
    closure?: { available: false; note: string } | {
        available: true; verified_by_rescan: number; verified_by_wazuh: number; marked_fixed_by_people: number; awaiting_verification_now: number | null;
        verification_inconclusive: number; closed_without_fix: { risk_accepted: number; false_positive: number }; reopened_after_verification: number;
        tasks_completed: { total: number; findings: number; findings_verified: number; findings_not_verified: number };
        verified_examples: { finding_id: string; at: string; how: string; evidence: string | null; title: string | null; asset: string | null; priority: string | null }[];
    };
    coverage?: {
        inventory: { wazuh_endpoints: number; external_assets: number };
        latest_checks: { total: number; reached: number; by_outcome: Record<string, number> };
        full_assessments: { available: false; note: string } | { available: true; total: number; by_status: Record<string, number>; checks_by_status: Record<string, number>; by_trigger: Record<string, number> };
    };
    sources: string[];
    limitations: string[];
}
const pairs = (o: Record<string, number>) => Object.entries(o).length ? Object.entries(o).map(([k, v]) => `${k.replace(/_/g, ' ')} ${v}`).join(' · ') : 'none';

/** endpoint: the report API (the client portal reads /api/client/vms/report); exports: the staff CSV links. */
export function VmsReport({ endpoint = '/api/vms/report', exports = true, findingsPath = '/admin/vms/findings' }: { endpoint?: string; exports?: boolean; findingsPath?: string } = {}) {
    const [days, setDays] = useState(30);
    const [data, setData] = useState<Report | null>(null);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        let active = true;
        void loadJson<Report>(`${endpoint}?days=${days}`).then((r) => {
            if (!active) return;
            setData(r.ok ? r.data : null);
            setError(r.ok ? null : r.error);
        });
        return () => { active = false; };
    }, [days, endpoint]);

    const section = 'bg-card border border-border rounded-2xl p-4 text-xs space-y-1';
    return (
        <div className="space-y-4">
            <PageHeader icon={FileBarChart} title="Reports" description="What happened in vulnerability management over the period, counted from stored records, with the sources used and what the report cannot see."
                actions={<div className="flex flex-wrap items-center gap-2 print:hidden">
                    <Segmented label="Period" value={String(days) as '7' | '30' | '90'} onChange={(v) => setDays(Number(v))} options={[['7', '7 days'], ['30', '30 days'], ['90', '90 days']]} />
                    <ExportButton elementId="vms-report" filename={`vms-report-${days}d-${new Date().toISOString().slice(0, 10)}`} title={`Vulnerability Management report — last ${days} days`} />
                    <button onClick={() => window.print()} className={btn('secondary', 'md')}><Printer className="w-3.5 h-3.5" aria-hidden /> Print</button>
                </div>} />
            {exports && <div className="bg-card border border-border rounded-2xl p-4 text-xs print:hidden">
                <p className="font-bold text-foreground mb-2">Data exports (CSV)</p>
                <p className="text-foreground-muted mb-2">Each list exports exactly the rows its filters show.</p>
                <div className="flex flex-wrap gap-2">
                    {[['/admin/vms/findings', 'Findings'], ['/admin/vms/assets', 'Assets'], ['/admin/vms/remediation?view=table', 'Remediation tasks'], ['/admin/vms/risk', 'Risk queue'], ['/admin/vms/scans/history', 'Scan history'], ['/admin/vms/audit', 'Audit trail']].map(([h, l]) => <Link key={h} href={h} className={btn('secondary')}>{l}</Link>)}
                </div>
            </div>}
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            <div id="vms-report" className="space-y-4">
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
                    {data.closure && (
                        <div className={section}>
                            <h2 className="text-sm font-black text-foreground">Verified closure</h2>
                            {!data.closure.available ? <p className="text-foreground-muted">{data.closure.note}</p> : (
                                <>
                                    <p>Verified fixed by evidence: {data.closure.verified_by_rescan + data.closure.verified_by_wazuh} ({data.closure.verified_by_rescan} by a verification rescan that reached the target, {data.closure.verified_by_wazuh} by a complete Wazuh sync that no longer reports them).</p>
                                    <p>Marked fixed by people: {data.closure.marked_fixed_by_people} — a claim until verified; {data.closure.awaiting_verification_now ?? 'unknown'} awaiting verification now; {data.closure.verification_inconclusive} verification attempt(s) proved nothing (scan failed or did not reach the target).</p>
                                    <p>Remediation tasks completed: {data.closure.tasks_completed.total} on {data.closure.tasks_completed.findings} finding(s), of which {data.closure.tasks_completed.findings_verified} verified and {data.closure.tasks_completed.findings_not_verified} not verified. A completed task is not a verified fix.</p>
                                    <p>Closed without a fix: {data.closure.closed_without_fix.risk_accepted} risk accepted, {data.closure.closed_without_fix.false_positive} false positive. Reopened after verification: {data.closure.reopened_after_verification}.</p>
                                    {data.closure.verified_examples.slice(0, 10).map((e) => <p key={`${e.finding_id}-${e.at}`} className="text-foreground-muted">✓ <Link href={`${findingsPath}?id=${e.finding_id}`} className="text-blue">{e.title ?? e.finding_id}</Link>{e.asset ? ` · ${e.asset}` : ''} · {e.how === 'rescan' ? 'rescan' : e.how === 'wazuh' ? 'Wazuh' : e.how} · {fmtWat(e.at)}{e.evidence ? ` — ${e.evidence}` : ''}</p>)}
                                </>
                            )}
                        </div>
                    )}
                    {data.coverage && (
                        <div className={section}>
                            <h2 className="text-sm font-black text-foreground">Assessment coverage</h2>
                            <p>Inventory now: {data.coverage.inventory.wazuh_endpoints} Wazuh endpoint(s), {data.coverage.inventory.external_assets} external asset(s).</p>
                            <p>Assets whose latest check fell in the period: {data.coverage.latest_checks.total}, of which {data.coverage.latest_checks.reached} reached ({pairs(data.coverage.latest_checks.by_outcome)}). No route and unreachable are not assessments.</p>
                            {data.coverage.full_assessments.available
                                ? <p>Full Assessments: {data.coverage.full_assessments.total} ({pairs(data.coverage.full_assessments.by_status)}); checks: {pairs(data.coverage.full_assessments.checks_by_status)}; started by: {pairs(data.coverage.full_assessments.by_trigger)}.</p>
                                : <p className="text-foreground-muted">{data.coverage.full_assessments.note}</p>}
                        </div>
                    )}
                    <div className={section}>
                        <h2 className="text-sm font-black text-foreground">Open P1 / P2</h2>
                        {data.top_open.length === 0 ? <p className="text-foreground-muted">None.</p> : data.top_open.map((f) => <p key={f.id}><span className="font-bold">{f.priority}</span> <Link href={`${findingsPath}?id=${f.id}`} className="text-blue">{f.title}</Link> · {f.asset} · {f.status} · due {fmtWat(f.due_at)}</p>)}
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
        </div>
    );
}
