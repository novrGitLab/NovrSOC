'use client';

// CNII Watch report (R3.3B Stage 6): an Executive and a Technical view over the same
// organisation payload already served by GET /api/cnii/national/orgs/:org (phase P23, extended
// R3.3B with monitoring coverage state, threat intelligence correlation and a historical trend).
// No new backend route — this reuses the organisation drill-down verbatim and the same PDF/CSV
// export mechanics R3.3A built for the VMS report.

import { useState } from 'react';
import Link from 'next/link';
import { FileBarChart, Printer } from 'lucide-react';
import { fmtWat } from '@/lib/vms';
import { SECTOR_BY_ID } from '@/lib/cnii-sectors';
import { keyRecommendations, type CniiReportInput } from '@/lib/cniiReportInsights';
import { ExportButton } from '@/components/shared/ExportButton';
import { PageHeader, Segmented, btn, KpiCard, ExportCsvButton, ErrorState } from '../vms/kit';
import { useVmsData } from '../vms/data';
import type { OrgData } from './CniiNational';

const COVERAGE_LABEL: Record<string, string> = { connected_fresh: 'Connected — receiving telemetry', connected_stale: 'Connected — stale', configured_not_receiving: 'Configured — not yet receiving data', not_connected: 'Not connected', unknown: 'Monitoring status unknown' };
const section = 'bg-card border border-border rounded-2xl p-4 text-xs space-y-1';
const pairs = (o: Record<string, number>) => Object.entries(o).filter(([, v]) => v).length ? Object.entries(o).filter(([, v]) => v).map(([k, v]) => `${k.replace(/_/g, ' ')} ${v}`).join(' · ') : 'none';

export function CniiReport({ org }: { org: string }) {
    const [mode, setMode] = useState<'executive' | 'technical'>('executive');
    const { load, data: d, reload } = useVmsData<OrgData>(`/api/cnii/national/orgs/${encodeURIComponent(org)}`);
    const meta = d ? SECTOR_BY_ID[d.organisation.sector] : undefined;
    const closed = d ? Object.values(d.remediation.findings_closed_by_status).reduce((a, b) => a + b, 0) : 0;
    const openAll = d ? Object.values(d.remediation.findings_open_by_status).reduce((a, b) => a + b, 0) : 0;

    const recommendations = d ? keyRecommendations({
        coverage_state: d.summary.coverage_state as CniiReportInput['coverage_state'],
        critical_high: d.summary.critical_high, kev_open: d.summary.kev_open, assets_requiring_attention: d.summary.assets_requiring_attention,
        threat_intelligence: d.summary.threat_intelligence, remediation_open: openAll, remediation_closed: closed,
    }) : [];

    const trendSummary = (() => {
        if (!d) return null;
        if (d.trend.length < 2) return 'Not enough history yet — a trend needs at least two daily snapshots.';
        const first = d.trend[0], last = d.trend[d.trend.length - 1];
        const delta = last.open_total - first.open_total;
        const direction = delta > 0 ? `up ${delta}` : delta < 0 ? `down ${Math.abs(delta)}` : 'unchanged';
        return `Open findings ${direction} over the period: ${first.open_total} on ${first.day} → ${last.open_total} on ${last.day} (${d.trend.length} daily snapshot(s)).`;
    })();

    return (
        <div className="space-y-4">
            <PageHeader icon={FileBarChart} title={d ? `CNII report — ${d.organisation.name}` : 'CNII report'}
                description="What this organisation's critical-infrastructure monitoring shows, from stored VMS and Threat Intelligence records, with what the report cannot see named explicitly."
                actions={<div className="flex flex-wrap items-center gap-2 print:hidden">
                    <Segmented label="View" value={mode} onChange={setMode} options={[['executive', 'Executive'], ['technical', 'Technical']]} />
                    <ExportButton elementId="cnii-report" filename={`cnii-report-${org}-${mode}-${new Date().toISOString().slice(0, 10)}`} title={`CNII ${mode === 'executive' ? 'Executive' : 'Technical'} report — ${d?.organisation.name ?? org}`} />
                    <button onClick={() => window.print()} className={btn('secondary', 'md')}><Printer className="w-3.5 h-3.5" aria-hidden /> Print</button>
                </div>} />
            {load.state === 'error' && <ErrorState error={load.error} status={load.status} onRetry={reload} />}
            <div id="cnii-report" className="space-y-4">
            {d && (
                <>
                    <p className="text-xs text-foreground-muted">{meta?.label ?? d.organisation.sector}{d.organisation.subfield ? ` · ${d.organisation.subfield}` : ''} · {d.organisation.designation === 'designated' ? 'Designated CNII' : 'Candidate — not yet designated'}. Counted from stored records when this page was opened.</p>

                    {mode === 'executive' ? (
                        <>
                            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                                <KpiCard label="Monitored assets" value={d.summary.assets} />
                                <KpiCard label="Critical + high (open)" value={d.summary.critical_high} tone={d.summary.critical_high ? 'critical' : 'good'} />
                                <KpiCard label="Known exploited" value={d.summary.kev_open} tone={d.summary.kev_open ? 'critical' : 'good'} />
                                <KpiCard label="Verified threat intel" value={d.summary.threat_intelligence.verified} tone={d.summary.threat_intelligence.verified ? 'critical' : 'good'} />
                                <KpiCard label="Monitoring" text={COVERAGE_LABEL[d.summary.coverage_state] ?? d.summary.coverage_state} />
                            </div>
                            <div className={section}>
                                <h2 className="text-sm font-black text-foreground">Remediation progress</h2>
                                <p>{closed} of {closed + openAll} findings closed (verified, risk accepted or false positive){closed + openAll ? ` — ${Math.round((closed / (closed + openAll)) * 100)}%` : ''}; {openAll} open.</p>
                            </div>
                            <div className={section}>
                                <h2 className="text-sm font-black text-foreground">Historical risk trend</h2>
                                <p className="text-foreground-muted">{trendSummary}</p>
                            </div>
                            <div className={`${section} border-blue/30`}>
                                <h2 className="text-sm font-black text-foreground">Key recommendations</h2>
                                {recommendations.map((r) => <p key={r}>• {r}</p>)}
                            </div>
                            <div className={`${section} border-amber/30`}>
                                <h2 className="text-sm font-black text-foreground">Data freshness and limitations</h2>
                                <p>{d.monitoring.last_scan ? `Last scan: ${fmtWat(d.monitoring.last_scan.finished_at)} (${d.monitoring.last_scan.kind}, ${d.monitoring.last_scan.status}).` : 'No scan has been recorded for this organisation.'}</p>
                                <p>Monitoring state: {COVERAGE_LABEL[d.summary.coverage_state] ?? d.summary.coverage_state}. Threat intelligence contextual matches ({d.summary.threat_intelligence.contextual}) are not themselves proof of a targeted attack.</p>
                            </div>
                        </>
                    ) : (
                        <>
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                <KpiCard label="Assets" value={d.summary.assets} sub={`${d.summary.internet_facing} internet-facing`} />
                                <KpiCard label="Open findings" value={d.summary.open_vulnerabilities} sub="Informational excluded" />
                                <KpiCard label="CVEs detected" value={d.cves.length} sub={`${d.cves.filter((c) => c.kev).length} known exploited`} />
                                <KpiCard label="Assets assessed (30d)" value={d.summary.monitoring.assets_assessed_30d} suffix={` / ${d.summary.assets}`} />
                            </div>
                            <div className={section}>
                                <h2 className="text-sm font-black text-foreground">Source integrations</h2>
                                <p>Detection sources: {pairs(d.sources)}.</p>
                                <p>Monitoring: {COVERAGE_LABEL[d.summary.coverage_state] ?? d.summary.coverage_state}{d.summary.monitoring.last_collection ? ` — last passive collection ${fmtWat(d.summary.monitoring.last_collection.at)} (${d.summary.monitoring.last_collection.status})` : ''}.</p>
                            </div>
                            <div className={section}>
                                <div className="flex items-center justify-between flex-wrap gap-2">
                                    <h2 className="text-sm font-black text-foreground">Findings</h2>
                                    <div className="print:hidden">
                                        <ExportCsvButton filename={`cnii-report-${org}-findings.csv`} rows={d.findings as unknown as Record<string, unknown>[]} label="Export CSV"
                                            columns={[{ key: 'priority', header: 'Priority' }, { key: 'severity', header: 'Severity' }, { key: 'title', header: 'Title' }, { key: 'asset_value', header: 'Asset' }, { key: 'cve_ids', header: 'CVE IDs' }, { key: 'scanner_cvss', header: 'CVSS' }, { key: 'kev', header: 'Known Exploited' }, { key: 'status', header: 'Status' }, { key: 'due_at', header: 'Due' }]} />
                                    </div>
                                </div>
                                {d.findings.length === 0 ? <p className="text-foreground-muted">None.</p> : d.findings.slice(0, 50).map((f) => (
                                    <p key={f.id}><span className="font-bold">{f.priority ?? '—'}</span> {f.title} · {f.asset_value}{f.port ? `:${f.port}` : ''} · {f.severity}{f.scanner_cvss !== null ? ` · CVSS ${f.scanner_cvss}` : ''}{f.cve_ids.length ? ` · ${f.cve_ids.join(', ')}` : ''}{f.kev ? ' · KEV' : ''} · {f.status}{f.due_at ? ` · due ${fmtWat(f.due_at)}` : ''}</p>
                                ))}
                                {d.findings.length > 50 && <p className="text-foreground-muted">+{d.findings.length - 50} more — see the CSV export or the organisation page for the full list.</p>}
                            </div>
                            <div className={section}>
                                <h2 className="text-sm font-black text-foreground">Threat intelligence correlation</h2>
                                <p>{d.summary.threat_intelligence.total} match(es) across this organisation&apos;s assets: {d.summary.threat_intelligence.verified} verified, {d.summary.threat_intelligence.contextual} contextual only. Evidence and TLP for each match are on the asset page.</p>
                            </div>
                            <div className={section}>
                                <h2 className="text-sm font-black text-foreground">Remediation status</h2>
                                <p>Open: {pairs(d.remediation.findings_open_by_status)}.</p>
                                <p>Closed: {pairs(d.remediation.findings_closed_by_status)}.</p>
                                <p>Tasks: {pairs(d.remediation.tasks_by_status)}.</p>
                            </div>
                        </>
                    )}
                    <p className="text-[11px] text-foreground-muted">Reporting period: last 90 days of daily snapshots (where recorded) · CNII keeps no asset or finding store of its own — every figure is this organisation&apos;s own VMS and Threat Intelligence record. <Link href={`/admin/cnii/org/${encodeURIComponent(org)}`} className="text-purple dark:text-[var(--vz-prog-4)] font-semibold">Back to organisation →</Link></p>
                </>
            )}
            </div>
        </div>
    );
}
