'use client';

// Period report (phase P7, extended R3.3A): what happened in vulnerability management over a
// stated period, from stored records, with the sources used and what the report cannot see.
// Printable. Two render modes over the same fetched data: Executive (headline exposure,
// remediation progress, historical trend, key recommendations, compliance context) and
// Technical (the original detailed breakdown, now with CVE/CVSS/KEV on the headline findings).

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { FileBarChart, Printer } from 'lucide-react';
import { loadJson } from '@/lib/alerts';
import { fmtWat } from '@/lib/vms';
import { ExportButton } from '@/components/shared/ExportButton';
import { PageHeader, Segmented, btn, KpiCard, ExportCsvButton, Tag } from './kit';
import { keyRecommendations, type VmsReportForRecommendations } from '@/lib/vmsReportInsights';

interface TopFinding { id: string; title: string; asset: string; priority: string; due_at: string | null; status: string; severity: string | null; cvss: number | null; cve_ids: string[]; known_exploited: boolean }
interface ComplianceFrameworkImpact { failing: number; at_risk: number; controls: { framework: string; control: string; status: 'FAIL' | 'AT RISK'; rationale: string }[] }
interface Compliance { frameworks: Record<string, ComplianceFrameworkImpact>; overall_impact: 'No impact' | 'Low impact' | 'Medium impact' | 'High impact'; unmapped: number; note: string }

interface Report {
    period: { from: string; to: string; days: number };
    open_now: { total: number; by_priority: Record<string, number>; by_severity: Record<string, number>; overdue: number; known_exploited: number; affected_assets: number };
    new_in_period: { total: number; by_priority: Record<string, number>; by_source: Record<string, number> };
    status_changes: Record<string, number>;
    time_to_remediate: Record<string, { verified: number; mean_hours: number | null; within_deadline: number }>;
    scans: Record<string, number>;
    attack_surface_changes: Record<string, number>;
    top_open: TopFinding[];
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
    compliance: Compliance;
    wazuh_freshness?: { last_attempt_at: string | null; last_complete_at: string | null; complete: boolean; problem: string | null };
    sources: string[];
    limitations: string[];
}
interface Trends { period: { from: string; to: string; days: number }; snapshots: { day: string; open_total: number; risk_mean?: number | null; kev_open?: number }[]; note: string | null }

const pairs = (o: Record<string, number>) => Object.entries(o).length ? Object.entries(o).map(([k, v]) => `${k.replace(/_/g, ' ')} ${v}`).join(' · ') : 'none';
const STATUS_COLOR: Record<string, string> = { FAIL: 'text-red font-bold', 'AT RISK': 'text-amber font-bold' };

function ComplianceSection({ compliance }: { compliance: Compliance }) {
    const section = 'bg-card border border-border rounded-2xl p-4 text-xs space-y-2';
    const frameworks = Object.entries(compliance.frameworks);
    return (
        <div className={section}>
            <h2 className="text-sm font-black text-foreground">Compliance Context</h2>
            <p className="text-foreground-muted">Overall impact: <span className="font-bold text-foreground">{compliance.overall_impact}</span>. {compliance.unmapped} open finding(s) below the severity this mapping considers.</p>
            {frameworks.length === 0 ? <p className="text-foreground-muted">No open finding currently maps to a tracked framework control.</p> : (
                <div className="space-y-2">
                    {frameworks.map(([fw, impact]) => (
                        <div key={fw}>
                            <p className="font-bold text-foreground">{fw} — {impact.failing} failing, {impact.at_risk} at risk</p>
                            {impact.controls.map((c) => (
                                <p key={c.control} className="text-foreground-muted ml-2">· <span className={STATUS_COLOR[c.status]}>{c.status}</span> {c.control} — {c.rationale}</p>
                            ))}
                        </div>
                    ))}
                </div>
            )}
            <p className="text-foreground-muted italic border-t border-border pt-2">{compliance.note}</p>
        </div>
    );
}

/** endpoint: the report API (the client portal reads /api/client/vms/report); exports: the staff CSV links. */
export function VmsReport({ endpoint = '/api/vms/report', exports = true, findingsPath = '/admin/vms/findings' }: { endpoint?: string; exports?: boolean; findingsPath?: string } = {}) {
    const [days, setDays] = useState(30);
    const [mode, setMode] = useState<'executive' | 'technical'>('executive');
    const [data, setData] = useState<Report | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [trends, setTrends] = useState<Trends | null>(null);
    const [trendsError, setTrendsError] = useState<string | null>(null);

    useEffect(() => {
        let active = true;
        void loadJson<Report>(`${endpoint}?days=${days}`).then((r) => {
            if (!active) return;
            setData(r.ok ? r.data : null);
            setError(r.ok ? null : r.error);
        });
        // Same daily risk-snapshot trend as /admin/vms/risk's chart, scoped to this org — the
        // client portal reaches its own /api/client/vms/trends (added alongside this report).
        void loadJson<Trends>(`${endpoint.replace('/report', '/trends')}?days=${days}`).then((r) => {
            if (!active) return;
            setTrends(r.ok ? r.data : null);
            setTrendsError(r.ok ? null : r.error);
        });
        return () => { active = false; };
    }, [days, endpoint]);

    const section = 'bg-card border border-border rounded-2xl p-4 text-xs space-y-1';

    const resolvedInPeriod = data?.closure && data.closure.available
        ? data.closure.verified_by_rescan + data.closure.verified_by_wazuh + data.closure.closed_without_fix.risk_accepted + data.closure.closed_without_fix.false_positive
        : null;

    const recommendations = data ? keyRecommendations(data as unknown as VmsReportForRecommendations) : [];

    const trendSummary = (() => {
        if (!trends) return null;
        if (trends.note) return trends.note;
        const first = trends.snapshots[0];
        const last = trends.snapshots[trends.snapshots.length - 1];
        if (!first || !last) return 'No snapshots in this period.';
        const delta = last.open_total - first.open_total;
        const direction = delta > 0 ? `up ${delta}` : delta < 0 ? `down ${Math.abs(delta)}` : 'unchanged';
        return `Open findings ${direction} over the period: ${first.open_total} on ${first.day} → ${last.open_total} on ${last.day} (${trends.snapshots.length} daily snapshot(s)).`;
    })();

    return (
        <div className="space-y-4">
            <PageHeader icon={FileBarChart} title="Reports" description="What happened in vulnerability management over the period, counted from stored records, with the sources used and what the report cannot see."
                actions={<div className="flex flex-wrap items-center gap-2 print:hidden">
                    <Segmented label="View" value={mode} onChange={setMode} options={[['executive', 'Executive'], ['technical', 'Technical']]} />
                    <Segmented label="Period" value={String(days) as '7' | '30' | '90'} onChange={(v) => setDays(Number(v))} options={[['7', '7 days'], ['30', '30 days'], ['90', '90 days']]} />
                    <ExportButton elementId="vms-report" filename={`vms-report-${mode}-${days}d-${new Date().toISOString().slice(0, 10)}`} title={`Vulnerability Management ${mode === 'executive' ? 'Executive' : 'Technical'} report — last ${days} days`} />
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
                    <p className="text-xs text-foreground-muted">Period: {fmtWat(data.period.from)} to {fmtWat(data.period.to)} ({data.period.days} days). Counted from stored records when this page was opened.
                        {data.wazuh_freshness && (data.wazuh_freshness.last_complete_at
                            ? ` Monitoring engine vulnerability data as of ${fmtWat(data.wazuh_freshness.last_complete_at)}.`
                            : ' Monitoring engine vulnerability sync has not completed for this organisation.')}
                    </p>

                    {mode === 'executive' ? (
                        <>
                            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                                <KpiCard label="Open findings" value={data.open_now.total} href={findingsPath} />
                                <KpiCard label="Critical + high (open)" value={(data.open_now.by_severity.critical ?? 0) + (data.open_now.by_severity.high ?? 0)} tone={(data.open_now.by_severity.critical ?? 0) > 0 ? 'critical' : (data.open_now.by_severity.high ?? 0) > 0 ? 'serious' : 'good'} />
                                <KpiCard label="Affected assets" value={data.open_now.affected_assets} />
                                <KpiCard label="Known exploited" value={data.open_now.known_exploited} tone={data.open_now.known_exploited > 0 ? 'critical' : 'good'} />
                                <KpiCard label="Overdue" value={data.open_now.overdue} tone={data.open_now.overdue > 0 ? 'warning' : 'good'} />
                            </div>
                            <div className={section}>
                                <h2 className="text-sm font-black text-foreground">Remediation progress</h2>
                                <p>New findings this period: {data.new_in_period.total}{resolvedInPeriod !== null ? `; resolved (verified or formally closed): ${resolvedInPeriod}` : ''}.</p>
                                {data.closure && data.closure.available && (
                                    <p>Verified fixed by evidence: {data.closure.verified_by_rescan + data.closure.verified_by_wazuh}; {data.closure.awaiting_verification_now ?? 'unknown'} awaiting verification now; {data.closure.closed_without_fix.risk_accepted + data.closure.closed_without_fix.false_positive} closed without a fix (risk accepted or false positive).</p>
                                )}
                                {data.closure && !data.closure.available && <p className="text-foreground-muted">{data.closure.note}</p>}
                            </div>
                            <div className={section}>
                                <h2 className="text-sm font-black text-foreground">Historical risk trend</h2>
                                <p className="text-foreground-muted">{trendsError ? `Trend unavailable — ${trendsError}` : trendSummary ?? 'Loading…'}</p>
                            </div>
                            <div className={`${section} border-blue/30`}>
                                <h2 className="text-sm font-black text-foreground">Key recommendations</h2>
                                {recommendations.map((r) => <p key={r}>• {r}</p>)}
                            </div>
                            <ComplianceSection compliance={data.compliance} />
                        </>
                    ) : (
                        <>
                            <div className={section}>
                                <h2 className="text-sm font-black text-foreground">Position now</h2>
                                <p>{data.open_now.total} open findings ({pairs(data.open_now.by_priority)}); by severity: {pairs(data.open_now.by_severity)}; {data.open_now.overdue} past their deadline; {data.open_now.known_exploited} known exploited (KEV); {data.open_now.affected_assets} affected asset(s).</p>
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
                                            <p>Verified fixed by evidence: {data.closure.verified_by_rescan + data.closure.verified_by_wazuh} ({data.closure.verified_by_rescan} by a verification rescan that reached the target, {data.closure.verified_by_wazuh} by a complete monitoring sync that no longer reports them).</p>
                                            <p>Marked fixed by people: {data.closure.marked_fixed_by_people} — a claim until verified; {data.closure.awaiting_verification_now ?? 'unknown'} awaiting verification now; {data.closure.verification_inconclusive} verification attempt(s) proved nothing (scan failed or did not reach the target).</p>
                                            <p>Remediation tasks completed: {data.closure.tasks_completed.total} on {data.closure.tasks_completed.findings} finding(s), of which {data.closure.tasks_completed.findings_verified} verified and {data.closure.tasks_completed.findings_not_verified} not verified. A completed task is not a verified fix.</p>
                                            <p>Closed without a fix: {data.closure.closed_without_fix.risk_accepted} risk accepted, {data.closure.closed_without_fix.false_positive} false positive. Reopened after verification: {data.closure.reopened_after_verification}.</p>
                                            {data.closure.verified_examples.slice(0, 10).map((e) => <p key={`${e.finding_id}-${e.at}`} className="text-foreground-muted">✓ <Link href={`${findingsPath}?id=${e.finding_id}`} className="text-blue">{e.title ?? e.finding_id}</Link>{e.asset ? ` · ${e.asset}` : ''} · {e.how === 'rescan' ? 'rescan' : e.how === 'wazuh' ? 'monitoring engine' : e.how} · {fmtWat(e.at)}{e.evidence ? ` — ${e.evidence}` : ''}</p>)}
                                        </>
                                    )}
                                </div>
                            )}
                            {data.coverage && (
                                <div className={section}>
                                    <h2 className="text-sm font-black text-foreground">Assessment coverage</h2>
                                    <p>Inventory now: {data.coverage.inventory.wazuh_endpoints} monitored endpoint(s), {data.coverage.inventory.external_assets} external asset(s).</p>
                                    <p>Assets whose latest check fell in the period: {data.coverage.latest_checks.total}, of which {data.coverage.latest_checks.reached} reached ({pairs(data.coverage.latest_checks.by_outcome)}). No route and unreachable are not assessments.</p>
                                    {data.coverage.full_assessments.available
                                        ? <p>Full Assessments: {data.coverage.full_assessments.total} ({pairs(data.coverage.full_assessments.by_status)}); checks: {pairs(data.coverage.full_assessments.checks_by_status)}; started by: {pairs(data.coverage.full_assessments.by_trigger)}.</p>
                                        : <p className="text-foreground-muted">{data.coverage.full_assessments.note}</p>}
                                </div>
                            )}
                            <div className={section}>
                                <div className="flex items-center justify-between flex-wrap gap-2">
                                    <h2 className="text-sm font-black text-foreground">Open P1 / P2</h2>
                                    <div className="print:hidden">
                                        <ExportCsvButton filename={`vms-report-top-open-${days}d.csv`} rows={data.top_open as unknown as Record<string, unknown>[]} label="Export CSV"
                                            columns={[
                                                { key: 'priority', header: 'Priority' }, { key: 'severity', header: 'Severity' }, { key: 'title', header: 'Title' },
                                                { key: 'asset', header: 'Asset' }, { key: 'cve_ids', header: 'CVE IDs' }, { key: 'cvss', header: 'CVSS' },
                                                { key: 'known_exploited', header: 'Known Exploited' }, { key: 'status', header: 'Status' }, { key: 'due_at', header: 'Due' },
                                            ]} />
                                    </div>
                                </div>
                                {data.top_open.length === 0 ? <p className="text-foreground-muted">None.</p> : data.top_open.map((f) => (
                                    <p key={f.id}>
                                        <span className="font-bold">{f.priority}</span> <Link href={`${findingsPath}?id=${f.id}`} className="text-blue">{f.title}</Link> · {f.asset} · {f.status} · due {fmtWat(f.due_at)}
                                        {f.severity && ` · ${f.severity}`}{f.cvss !== null && ` · CVSS ${f.cvss}`}{f.cve_ids.length > 0 && ` · ${f.cve_ids.join(', ')}`}
                                        {f.known_exploited && <> <Tag strong>KEV</Tag></>}
                                    </p>
                                ))}
                            </div>
                            <div className={section}>
                                <h2 className="text-sm font-black text-foreground">Recurring</h2>
                                <p>Reopened after a fix: {data.recurring.reopened.length ? data.recurring.reopened.map((f) => `${f.title} on ${f.asset_value} (${f.times_reopened}×)`).join('; ') : 'none'}.</p>
                                <p>Open on 3+ assets: {data.recurring.widespread.length ? data.recurring.widespread.map((r) => `${r.title} (${r.open_on_assets})`).join('; ') : 'none'}.</p>
                            </div>
                            <ComplianceSection compliance={data.compliance} />
                        </>
                    )}

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
