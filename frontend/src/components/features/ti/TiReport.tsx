'use client';

// Threat Intelligence — Reports (R3.3D). What the Threat Information System actually knows about
// this organisation right now, from stored records: indicator and match counts, which matches are
// worth acting on and why (never an invented score), KEV cross-referenced against open findings,
// and what the report cannot see. Executive and Technical views over the same fetched data, with
// the same PDF/CSV export mechanics as the VMS and CNII reports.

import { useEffect, useState } from 'react';
import { FileBarChart, Printer } from 'lucide-react';
import { loadJson } from '@/lib/alerts';
import { fmtWat } from '@/lib/vms';
import { ExportButton } from '@/components/shared/ExportButton';
import { PageHeader, Segmented, btn, KpiCard, ExportCsvButton } from '@/components/features/vms/kit';
import { entityHref, TIER_LABEL, TIER_STYLE, type RelevantItem, type RelevanceTier } from '@/lib/ti';
import { keyRecommendations, type TiReportForRecommendations } from '@/lib/tiReportInsights';

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

const pairs = (o: Record<string, number>) => Object.entries(o).length ? Object.entries(o).map(([k, v]) => `${k.replace(/_/g, ' ')} ${v}`).join(' · ') : 'none';

export function TiReport() {
    const [days, setDays] = useState(30);
    const [mode, setMode] = useState<'executive' | 'technical'>('executive');
    const [data, setData] = useState<Report | null>(null);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        let active = true;
        void loadJson<Report>(`/api/ti/report?days=${days}`).then((r) => {
            if (!active) return;
            setData(r.ok ? r.data : null);
            setError(r.ok ? null : r.error);
        });
        return () => { active = false; };
    }, [days]);

    const section = 'bg-card border border-border rounded-2xl p-4 text-xs space-y-1';
    const recommendations = data ? keyRecommendations(data as unknown as TiReportForRecommendations) : [];

    return (
        <div className="space-y-4">
            <PageHeader icon={FileBarChart} title="Reports" description="What the Threat Information System knows about this organisation right now, counted from stored records, with what it cannot see."
                actions={<div className="flex flex-wrap items-center gap-2 print:hidden">
                    <Segmented label="View" value={mode} onChange={setMode} options={[['executive', 'Executive'], ['technical', 'Technical']]} />
                    <Segmented label="Period" value={String(days) as '7' | '30' | '90'} onChange={(v) => setDays(Number(v))} options={[['7', '7 days'], ['30', '30 days'], ['90', '90 days']]} />
                    <ExportButton elementId="ti-report" filename={`ti-report-${mode}-${days}d-${new Date().toISOString().slice(0, 10)}`} title={`Threat Intelligence ${mode === 'executive' ? 'Executive' : 'Technical'} report — last ${days} days`} />
                    <button onClick={() => window.print()} className={btn('secondary', 'md')}><Printer className="w-3.5 h-3.5" aria-hidden /> Print</button>
                </div>} />
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            <div id="ti-report" className="space-y-4">
            {data && (
                <>
                    <p className="text-xs text-foreground-muted">Period: {fmtWat(data.period.from)} to {fmtWat(data.period.to)} ({data.period.days} days). Counted from stored records when this page was opened.</p>

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
                                <h2 className="text-sm font-black text-foreground">Relevant intelligence</h2>
                                <p>{data.relevant.by_tier.critical + data.relevant.by_tier.high} of {data.matches.total} current match{data.matches.total === 1 ? '' : 'es'} rate critical or high relevance ({pairs(data.relevant.by_tier as unknown as Record<string, number>)}).</p>
                                {data.kev.your_open_findings > 0 && <p>{data.kev.your_open_findings} open finding{data.kev.your_open_findings === 1 ? '' : 's'} affected by a newly listed known-exploited vulnerability.</p>}
                            </div>
                            <div className={`${section} border-blue/30`}>
                                <h2 className="text-sm font-black text-foreground">Key recommendations</h2>
                                {recommendations.map((r) => <p key={r}>• {r}</p>)}
                            </div>
                        </>
                    ) : (
                        <>
                            <div className={section}>
                                <h2 className="text-sm font-black text-foreground">Position now</h2>
                                <p>{data.indicators.active} active indicators ({pairs(data.indicators.by_type)}); {data.indicators.new_in_period} new in the period.</p>
                                <p>{data.matches.total} current match{data.matches.total === 1 ? '' : 'es'} ({pairs(data.matches.by_status)}); {data.matches.verified} verified.</p>
                                <p>Relevance: {pairs(data.relevant.by_tier as unknown as Record<string, number>)}.</p>
                            </div>
                            <div className={section}>
                                <h2 className="text-sm font-black text-foreground">In the period</h2>
                                <p>New indicators by day: {data.trend.new_indicators_by_day.length ? data.trend.new_indicators_by_day.map((d) => `${d.day} (${d.count})`).join(', ') : 'none'}.</p>
                                <p>New matches by day: {data.trend.new_matches_by_day.length ? data.trend.new_matches_by_day.map((d) => `${d.day} (${d.count})`).join(', ') : 'none'}.</p>
                            </div>
                            <div className={section}>
                                <div className="flex items-center justify-between flex-wrap gap-2">
                                    <h2 className="text-sm font-black text-foreground">Top relevant matches</h2>
                                    <div className="print:hidden">
                                        <ExportCsvButton filename={`ti-report-relevant-${days}d.csv`} rows={data.relevant.top as unknown as Record<string, unknown>[]} label="Export CSV"
                                            columns={[
                                                { key: 'tier', header: 'Tier' }, { key: 'indicator_type', header: 'Type' }, { key: 'indicator_value', header: 'Value' },
                                                { key: 'entity_type', header: 'Matched' }, { key: 'verified', header: 'Verified' }, { key: 'kev', header: 'KEV' },
                                                { key: 'asset_criticality', header: 'Asset criticality' }, { key: 'confidence', header: 'Confidence' }, { key: 'last_matched_at', header: 'Last matched' },
                                            ]} />
                                    </div>
                                </div>
                                {data.relevant.top.length === 0 ? <p className="text-foreground-muted">None.</p> : data.relevant.top.map((m) => (
                                    <div key={m.match_id} className="border-t border-border pt-1.5 mt-1.5 first:border-0 first:pt-0 first:mt-0">
                                        <p>
                                            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full border uppercase ${TIER_STYLE[m.tier]}`}>{TIER_LABEL[m.tier]}</span>{' '}
                                            <a href={entityHref(m) ?? '#'} className="font-mono text-blue">{m.indicator_type}: {m.indicator_value}</a>{' '}
                                            in {m.entity_type}{m.asset_value ? ` (${m.asset_value})` : ''} · {fmtWat(m.last_matched_at)}
                                            {m.kev && ' · KEV'}{m.asset_criticality && ` · ${m.asset_criticality} criticality`}{m.confidence !== null && ` · confidence ${m.confidence}`}
                                        </p>
                                        <p className="text-foreground-muted">{m.reasons.join('; ')}</p>
                                    </div>
                                ))}
                            </div>
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
