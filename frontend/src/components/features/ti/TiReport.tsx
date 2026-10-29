'use client';

// Threat Intelligence — Reports (R3.3D, redesigned for professional client delivery). What the
// Threat Information System actually knows about this organisation right now, from stored
// records: indicator and match counts, which matches are worth acting on and why (never an
// invented score), KEV and vulnerability intelligence cross-referenced against open findings,
// threat category distribution, intelligence trends, and what the report cannot see. Executive
// and Technical views over the same fetched data, with the same print/PDF mechanics as the VMS
// and CNII reports (globals.css's @media print block, shared across every report page).

import { useEffect, useState } from 'react';
import { FileBarChart, Printer, ShieldCheck } from 'lucide-react';
import { loadJson } from '@/lib/alerts';
import { fmtWat } from '@/lib/vms';
import { getOrgContext } from '@/lib/orgContext';
import { ExportButton } from '@/components/shared/ExportButton';
import { PageHeader, Segmented, btn, KpiCard, ExportCsvButton } from '@/components/features/vms/kit';
import { BarList, TimeChart } from '@/components/features/vms/charts';
import type { RelevantItem, RelevanceTier } from '@/lib/ti';
import { keyRecommendations, type TiReportForRecommendations } from '@/lib/tiReportInsights';
import { tiReportId, mergeTrend } from './report/reportHelpers';
import { IndicatorMatchesTable } from './report/IndicatorMatchesTable';
import { VulnerabilityIntelTable } from './report/VulnerabilityIntelTable';

interface Report {
    period: { days: number; from: string; to: string };
    indicators: { active: number; new_in_period: number; by_type: Record<string, number> };
    matches: { total: number; by_status: Record<string, number>; verified: number };
    relevant: { by_tier: Record<RelevanceTier, number>; top: RelevantItem[] };
    kev: { new_in_period: number; your_open_findings: number };
    trend: { new_indicators_by_day: { day: string; count: number }[]; new_matches_by_day: { day: string; count: number }[] };
    engine: { correlation_last_run_at: string | null };
    limitations: string[];
    sources: string[];
    generated_at: string;
}
interface OrgRow { name?: string; slug?: string }

const pairs = (o: Record<string, number>) => Object.entries(o).length ? Object.entries(o).map(([k, v]) => `${k.replace(/_/g, ' ')} ${v}`).join(' · ') : 'none';
const TYPE_TOKENS = ['--vz-cat-1', '--vz-cat-3', '--vz-prog-1', '--vz-prog-2', '--vz-prog-3', '--vz-prog-4', '--vz-neutral'] as const;

export function TiReport() {
    const [days, setDays] = useState(30);
    const [mode, setMode] = useState<'executive' | 'technical'>('executive');
    const [data, setData] = useState<Report | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [orgName, setOrgName] = useState<string | null>(null);
    const [generatedAt] = useState(() => new Date());

    useEffect(() => {
        let active = true;
        void loadJson<Report>(`/api/ti/report?days=${days}`).then((r) => {
            if (!active) return;
            setData(r.ok ? r.data : null);
            setError(r.ok ? null : r.error);
        });
        return () => { active = false; };
    }, [days]);

    useEffect(() => {
        let active = true;
        const org = getOrgContext();
        void loadJson<{ organisations: OrgRow[] }>('/api/org-access/mine').then((r) => {
            if (!active || !r.ok) return;
            setOrgName(r.data.organisations.find((o) => o.slug === org)?.name ?? null);
        });
        return () => { active = false; };
    }, []);

    const section = 'bg-card border border-border rounded-2xl p-4 text-xs space-y-1 vms-print-card';
    const chartCard = 'bg-card border border-border rounded-2xl p-4 text-xs space-y-3 vms-print-card';
    const recommendations = data ? keyRecommendations(data as unknown as TiReportForRecommendations) : [];
    const reportId = tiReportId(getOrgContext() || 'org', days, generatedAt);
    const typeItems = data ? Object.entries(data.indicators.by_type).sort((a, b) => b[1] - a[1]).map(([type, value], i) => ({ key: type, label: type, value, token: TYPE_TOKENS[i % TYPE_TOKENS.length] })) : [];
    const trendRows = data ? mergeTrend(data.trend.new_indicators_by_day, data.trend.new_matches_by_day) : [];

    return (
        <div className="space-y-4">
            <PageHeader icon={FileBarChart} title="Reports" description="What the Threat Information System knows about this organisation right now, counted from stored records, with what it cannot see."
                actions={<div className="flex flex-wrap items-center gap-2 print:hidden">
                    <Segmented label="View" value={mode} onChange={setMode} options={[['executive', 'Executive'], ['technical', 'Technical']]} />
                    <Segmented label="Period" value={String(days) as '7' | '30' | '90'} onChange={(v) => setDays(Number(v))} options={[['7', '7 days'], ['30', '30 days'], ['90', '90 days']]} />
                    <ExportButton elementId="ti-report" filename={`ti-report-${mode}-${days}d-${new Date().toISOString().slice(0, 10)}`} title={`Threat Intelligence ${mode === 'executive' ? 'Executive' : 'Technical'} report — last ${days} days`} />
                    <button onClick={() => window.print()} className={btn('secondary', 'md')}><Printer className="w-3.5 h-3.5" aria-hidden /> Print / PDF</button>
                </div>} />
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            <div id="ti-report" className="space-y-4">
            {data && (
                <>
                    <div className="bg-card border border-border rounded-2xl p-5 print:break-after-page vms-print-card">
                        <div className="flex items-start justify-between gap-4 flex-wrap">
                            <div>
                                <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-widest">NovrSOC Threat Intelligence</p>
                                <h1 className="text-xl font-black text-foreground">Threat Intelligence Report</h1>
                                <p className="text-[11px] text-foreground-muted mt-1">Report ID: <span className="font-mono">{reportId}</span></p>
                            </div>
                            <span className="inline-flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wide text-amber bg-amber/10 border border-amber/30 rounded-lg px-2.5 py-1 shrink-0">
                                <ShieldCheck className="w-3.5 h-3.5" aria-hidden /> Confidential — Internal Distribution
                            </span>
                        </div>
                        <dl className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-3 mt-4 text-xs">
                            <div><dt className="text-foreground-muted">Client Organization</dt><dd className="font-bold text-foreground">{orgName ?? getOrgContext() ?? 'My organisation'}</dd></div>
                            <div><dt className="text-foreground-muted">Reporting Period</dt><dd className="font-bold text-foreground">{fmtWat(data.period.from)} – {fmtWat(data.period.to)} ({data.period.days} days)</dd></div>
                            <div><dt className="text-foreground-muted">Report Generated</dt><dd className="font-bold text-foreground">{fmtWat(generatedAt.toISOString())}</dd></div>
                        </dl>
                    </div>

                    {mode === 'executive' ? (
                        <>
                            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                                <KpiCard label="Active indicators" value={data.indicators.active} />
                                <KpiCard label="Critical relevance" value={data.relevant.by_tier.critical} tone={data.relevant.by_tier.critical > 0 ? 'critical' : 'good'} />
                                <KpiCard label="High relevance" value={data.relevant.by_tier.high} tone={data.relevant.by_tier.high > 0 ? 'serious' : 'good'} />
                                <KpiCard label="Verified associations" value={data.matches.verified} />
                                <KpiCard label="New KEV, in period" value={data.kev.new_in_period} tone={data.kev.your_open_findings > 0 ? 'critical' : 'good'} />
                            </div>
                            <div className={section}>
                                <h2 className="text-sm font-black text-foreground">Intelligence summary</h2>
                                <p>{data.relevant.by_tier.critical + data.relevant.by_tier.high} of {data.matches.total} current match{data.matches.total === 1 ? '' : 'es'} rate critical or high relevance ({pairs(data.relevant.by_tier as unknown as Record<string, number>)}).</p>
                                {data.kev.your_open_findings > 0 && <p>{data.kev.your_open_findings} open finding{data.kev.your_open_findings === 1 ? '' : 's'} affected by a newly listed known-exploited vulnerability.</p>}
                            </div>
                            <div className={`${section} border-blue/30`}>
                                <h2 className="text-sm font-black text-foreground">Key recommendations</h2>
                                {recommendations.map((r) => <p key={r}>• {r}</p>)}
                            </div>
                        </>
                    ) : (
                        <div className={section}>
                            <h2 className="text-sm font-black text-foreground">Position now</h2>
                            <p>{data.indicators.active} active indicators ({pairs(data.indicators.by_type)}); {data.indicators.new_in_period} new in the period.</p>
                            <p>{data.matches.total} current match{data.matches.total === 1 ? '' : 'es'} ({pairs(data.matches.by_status)}); {data.matches.verified} verified.</p>
                            <p>Relevance: {pairs(data.relevant.by_tier as unknown as Record<string, number>)}.</p>
                        </div>
                    )}

                    <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                        <div className={chartCard}>
                            <h2 className="text-sm font-black text-foreground">Threat category distribution</h2>
                            {typeItems.length === 0 ? <p className="text-foreground-muted">No active indicators.</p> : <BarList label="Active indicators by type" items={typeItems} />}
                        </div>
                        <div className={chartCard}>
                            <h2 className="text-sm font-black text-foreground">Intelligence trends</h2>
                            {trendRows.length === 0 ? <p className="text-foreground-muted">No new indicators or matches in this period.</p> : (
                                <TimeChart label="New indicators and new matches per day" kind="line" stacked={false} data={trendRows}
                                    series={[{ key: 'indicators', label: 'New indicators', token: '--vz-prog-2' }, { key: 'matches', label: 'New matches', token: '--vz-sev-high' }]} />
                            )}
                        </div>
                    </div>

                    <div className="print:break-before-page space-y-2">
                        <h2 className="text-sm font-black text-foreground">Indicator matches</h2>
                        <IndicatorMatchesTable items={data.relevant.top} />
                    </div>

                    <div className="print:break-before-page space-y-2">
                        <div className="flex items-center justify-between flex-wrap gap-2">
                            <h2 className="text-sm font-black text-foreground">KEV &amp; vulnerability intelligence</h2>
                            {mode === 'technical' && (
                                <div className="print:hidden">
                                    <ExportCsvButton filename={`ti-report-relevant-${days}d.csv`} rows={data.relevant.top as unknown as Record<string, unknown>[]} label="Export matches CSV"
                                        columns={[
                                            { key: 'tier', header: 'Tier' }, { key: 'indicator_type', header: 'Type' }, { key: 'indicator_value', header: 'Value' },
                                            { key: 'entity_type', header: 'Matched' }, { key: 'verified', header: 'Verified' }, { key: 'kev', header: 'KEV' },
                                            { key: 'asset_criticality', header: 'Asset criticality' }, { key: 'confidence', header: 'Confidence' }, { key: 'last_matched_at', header: 'Last matched' },
                                        ]} />
                                </div>
                            )}
                        </div>
                        <VulnerabilityIntelTable days={days} />
                    </div>

                    <div className={`${section} border-amber/30`}>
                        <h2 className="text-sm font-black text-foreground">Methodology, Coverage &amp; Limitations</h2>
                        <p className="text-foreground-muted">This report is generated from live stored intelligence at the time it was opened — not a point-in-time snapshot. Relevance tiers combine real evidence of exposure already in the platform; they are never an invented score.</p>
                        {data.limitations.map((l) => <p key={l}>• {l}</p>)}
                        {!data.engine.correlation_last_run_at && <p>• The correlation engine has not reported a completed run in the process serving this report — see <a href="/admin/ti/sources" className="text-blue hover:underline">Sources &amp; Exchange</a> for current feed freshness.</p>}
                        <p className="text-foreground-muted">Sources: {data.sources.join(', ')}.</p>
                    </div>
                </>
            )}
            </div>
        </div>
    );
}
