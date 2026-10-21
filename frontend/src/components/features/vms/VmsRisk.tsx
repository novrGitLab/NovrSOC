'use client';

// Risk & Prioritization (redesign, phase P20). Both pages read GET /api/vms/risk, which returns the
// risk model exactly as backend/src/lib/riskScore.ts applies it (weights, thresholds, deadlines),
// counts over the open findings, and the prioritised queue with each finding's stored factors. The
// model is shown as it is — no extra score is computed in the browser.

import { useMemo, useState } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { Gauge, ShieldAlert } from 'lucide-react';
import { fmtWat } from '@/lib/vms';
import { Card, SectionTitle, Tip } from './ui';
import { PageHeader, KpiCard, PriorityBadge, SeverityBadge, RiskScore, Tag, Drawer, ErrorState, ExportCsvButton, Select, Toggle, nf, PRIORITY_META, SEVERITY_META, SEVERITY_KEYS } from './kit';
import { ChartCard, BarList, Donut, TimeChart, Legend, type Series } from './charts';
import { DataTable, type Column } from './table';
import { FindingDetail } from './FindingDetail';
import { useVmsData } from './data';

interface QueueItem {
    id: string; title: string; asset_id: string | null; asset_value: string; severity: string; cvss: number | null; priority: string | null; risk_score: number | null;
    kev: boolean; epss: number | null; exposure: string; criticality: string | null; status: string; due_at: string | null; overdue: boolean; owner: string | null;
    factors: Record<string, { points?: number; basis?: string; weight?: number } | string> | null; evidence_class: string | null;
}
interface Risk {
    model: { weights: Record<string, number>; due_days: Record<string, number>; thresholds: Record<string, string>; components: Record<string, string>; evidence_rule: string; source: string };
    totals: { open: number; with_cve: number; kev: number; overdue: number };
    by_priority: Record<string, number>;
    score_bands: { band: string; count: number }[];
    matrix: Record<string, Record<string, number>>;
    epss: Record<string, number>;
    exposure: Record<string, number>;
    kev_findings: { id: string; title: string; asset_value: string; exposure: string; priority: string | null; cve_ids: string[]; due_at: string | null; overdue: boolean }[];
    queue: QueueItem[];
    trend: { day: string; kev_open: number; internet_open: number; critical_exposures: number | null; risk_mean: number | null; by_priority: Record<string, number> }[];
}

const COMPONENT_LABEL: Record<string, string> = { technical: 'Technical severity', exploitation: 'Exploitation', exposure: 'Exposure', criticality: 'Asset criticality' };
const COMPONENT_TOKEN: Record<string, string> = { technical: '--vz-prog-4', exploitation: '--vz-prog-3', exposure: '--vz-prog-2', criticality: '--vz-prog-1' };
const LIKELIHOOD = [['kev', 'Known exploited (KEV)'], ['epss_high', 'EPSS ≥ 10%'], ['epss_low', 'EPSS < 10%'], ['unknown', 'No exploit data']] as const;

function useOpenFinding() {
    const params = useSearchParams();
    const router = useRouter();
    const pathname = usePathname();
    const id = params.get('id');
    const set = (v: string | null) => { const p = new URLSearchParams(params.toString()); if (v) p.set('id', v); else p.delete('id'); router.replace(`${pathname}${p.toString() ? `?${p.toString()}` : ''}`, { scroll: false }); };
    return [id, set] as const;
}

export function VmsRiskOverview() {
    const { load, data: r, reload } = useVmsData<Risk>('/api/vms/risk');
    const [openId, setOpenId] = useOpenFinding();
    const [prio, setPrio] = useState('');
    const [overdueOnly, setOverdueOnly] = useState(false);
    const loading = load.state === 'loading' && !r;
    const queue = useMemo(() => r?.queue.filter((q) => (!prio || q.priority === prio) && (!overdueOnly || q.overdue)) ?? null, [r, prio, overdueOnly]);
    const columns: Column<QueueItem>[] = [
        { key: 'rank', header: '#', render: (q) => <span className="text-[11px] tabular-nums text-foreground-muted">{(r?.queue.indexOf(q) ?? 0) + 1}</span> },
        { key: 'priority', header: 'Priority', render: (q) => <PriorityBadge priority={q.priority} />, sort: (q) => q.priority ?? 'P9' },
        { key: 'risk', header: 'Risk', render: (q) => <RiskScore score={q.risk_score} />, sort: (q) => q.risk_score },
        { key: 'title', header: 'Finding', className: 'min-w-[220px] max-w-[340px]', render: (q) => <div className="min-w-0"><p className="font-semibold text-foreground truncate">{q.title}</p><p className="text-[11px] font-mono text-foreground-muted truncate">{q.asset_value}</p></div> },
        { key: 'why', header: 'Why', className: 'min-w-[200px]', render: (q) => <Factors q={q} /> },
        { key: 'due', header: 'Due', hideBelow: 'md', sort: (q) => q.due_at ?? '9999', render: (q) => <span className="text-[11px] whitespace-nowrap text-foreground-muted">{q.due_at ? fmtWat(q.due_at).replace(/,? \d\d:\d\d WAT$/, '') : '—'} {q.overdue && <Tag strong>Overdue</Tag>}</span> },
        { key: 'owner', header: 'Owner', hideBelow: 'lg', render: (q) => <span className="text-[11px] text-foreground-muted">{q.owner ?? 'Unassigned'}</span> },
    ];
    return (
        <div className="space-y-5">
            <PageHeader icon={Gauge} title="Risk Overview" description="How open findings are prioritised, and the queue that results. The model below is the one the backend applies; every number is counted from the open findings." />
            {load.state === 'error' && !r && <ErrorState error={load.error} status={load.status} onRetry={reload} />}
            {(r || loading) && <>
            <section className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3" aria-label="Key figures">
                <KpiCard label="Open findings" value={r?.totals.open} reason="Loading" />
                {(['P1', 'P2', 'P3'] as const).map((p) => <KpiCard key={p} label={`${p} — ${PRIORITY_META[p].hint.toLowerCase()}`} value={r ? r.by_priority[p] ?? 0 : undefined} reason="Loading" tone={p === 'P1' && r?.by_priority.P1 ? 'critical' : undefined} />)}
                <KpiCard label="Known exploited (KEV)" value={r?.totals.kev} reason="Loading" tone={r?.totals.kev ? 'critical' : undefined} />
                <KpiCard label="Past deadline" value={r?.totals.overdue} reason="Loading" tone={r?.totals.overdue ? 'warning' : undefined} />
            </section>

            {r && <ModelCard model={r.model} />}

            <section className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <ChartCard title="Open findings by priority" hint="Priority sets the remediation deadline." loading={loading} empty={r && !r.totals.open ? { title: 'No open findings' } : null}>
                    {r && <Donut label="Open findings by priority" centerLabel="open" slices={(['P1', 'P2', 'P3', 'P4'] as const).map((p, i) => ({ key: p, label: `${p} · ${PRIORITY_META[p].hint.toLowerCase()}`, value: r.by_priority[p] ?? 0, token: (['--vz-sev-critical', '--vz-sev-high', '--vz-sev-medium', '--vz-sev-low'] as const)[i], href: `/admin/vms/findings?priority=${p}` }))} />}
                </ChartCard>
                <ChartCard title="Risk score distribution" hint="Open findings by score band (0–100)." loading={loading} empty={r && !r.totals.open ? { title: 'No open findings' } : null}>
                    {r && <BarList label="Findings by risk score band" items={r.score_bands.map((b, i) => ({ key: b.band, label: `Score ${b.band.replace('-', '–')}`, value: b.count, token: (['--vz-sev-critical', '--vz-sev-high', '--vz-sev-medium', '--vz-sev-low'] as const)[i] }))} />}
                </ChartCard>
                <Card className="lg:col-span-2">
                    <SectionTitle title="Likelihood × severity" hint="Open findings by exploitation evidence (rows) and scanner severity (columns)." />
                    {r ? <Matrix matrix={r.matrix} /> : <div className="h-40 rounded-lg bg-card-muted motion-safe:animate-pulse" />}
                </Card>
            </section>

            <Card>
                <SectionTitle title="Prioritised queue" hint="Open findings in the order to fix them: priority, then risk score (top 100)."
                    action={<div className="flex flex-wrap items-center gap-2">
                        <Select label="Priority" value={prio} onChange={setPrio} options={[['', 'Any priority'], ['P1', 'P1'], ['P2', 'P2'], ['P3', 'P3'], ['P4', 'P4']]} />
                        <Toggle on={overdueOnly} onChange={setOverdueOnly}>Overdue</Toggle>
                        <ExportCsvButton filename="vms-risk-queue.csv" rows={queue as unknown as Record<string, unknown>[]} columns={[{ key: 'priority', header: 'Priority' }, { key: 'risk_score', header: 'Risk score' }, { key: 'title', header: 'Finding' }, { key: 'asset_value', header: 'Asset' }, { key: 'severity', header: 'Severity' }, { key: 'cvss', header: 'CVSS' }, { key: 'kev', header: 'KEV' }, { key: 'epss', header: 'EPSS' }, { key: 'exposure', header: 'Exposure' }, { key: 'criticality', header: 'Criticality' }, { key: 'due_at', header: 'Due' }, { key: 'owner', header: 'Owner' }]} />
                    </div>} />
                <div className="-mx-5 -mb-5 [&>div]:rounded-none [&>div]:border-x-0 [&>div]:border-b-0">
                    <DataTable caption="Prioritised remediation queue" rows={queue} columns={columns} rowKey={(q) => q.id} onRowClick={(q) => setOpenId(q.id)} activeKey={openId} pageSize={20} empty="Nothing to prioritise — no open findings match" />
                </div>
            </Card>
            </>}
            <Drawer open={!!openId} onClose={() => setOpenId(null)} title="Finding">{openId && <FindingDetail key={openId} id={openId} onChanged={reload} />}</Drawer>
        </div>
    );
}

function Factors({ q }: { q: QueueItem }) {
    return (
        <div className="flex flex-wrap items-center gap-1.5 text-[10.5px]">
            <SeverityBadge severity={q.severity} />
            {q.cvss !== null && <span className="text-foreground-muted">CVSS {q.cvss}</span>}
            {q.kev ? <Tag strong>KEV</Tag> : q.epss !== null ? <span className="text-foreground-muted">EPSS {(q.epss * 100).toFixed(q.epss < 0.01 ? 2 : 1)}%</span> : null}
            {q.exposure === 'internet' && <Tag>Internet</Tag>}
            {q.criticality && <span className="text-foreground-muted">{q.criticality} asset</span>}
            {(q.evidence_class === 'version_match' || q.evidence_class === 'intelligence') && <Tip label="Not confirmed by a scanner, so capped at P3"><Tag>Unconfirmed</Tag></Tip>}
        </div>
    );
}

function ModelCard({ model }: { model: Risk['model'] }) {
    const parts = Object.entries(model.weights);
    return (
        <Card>
            <SectionTitle title="How risk is calculated" hint={`The backend's model (${model.source}). Each open finding gets a 0–100 score and a priority.`} />
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="space-y-3">
                    <div className="flex h-8 w-full gap-[2px] rounded-lg overflow-hidden" role="img" aria-label={`Score weights: ${parts.map(([k, w]) => `${COMPONENT_LABEL[k] ?? k} ${Math.round(w * 100)}%`).join(', ')}`}>
                        {parts.map(([k, w]) => <div key={k} className="flex items-center justify-center text-[10.5px] font-bold text-white" style={{ flexGrow: w, flexBasis: 0, background: `var(${COMPONENT_TOKEN[k] ?? '--vz-neutral'})` }}>{Math.round(w * 100)}%</div>)}
                    </div>
                    <dl className="space-y-2">
                        {parts.map(([k, w]) => (
                            <div key={k} className="flex gap-3">
                                <dt className="w-36 shrink-0 text-xs font-semibold text-foreground flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-sm" style={{ background: `var(${COMPONENT_TOKEN[k]})` }} aria-hidden />{COMPONENT_LABEL[k] ?? k} · {Math.round(w * 100)}%</dt>
                                <dd className="text-xs text-foreground-muted">{model.components[k]}</dd>
                            </div>
                        ))}
                    </dl>
                </div>
                <div className="space-y-3">
                    <table className="w-full text-xs">
                        <thead><tr className="text-left text-[10.5px] uppercase tracking-wide text-foreground-muted"><th className="pb-1.5">Priority</th><th className="pb-1.5">When</th><th className="pb-1.5 text-right">Deadline</th></tr></thead>
                        <tbody>
                            {Object.entries(model.thresholds).map(([p, rule]) => (
                                <tr key={p} className="border-t border-border"><td className="py-1.5"><PriorityBadge priority={p} /></td><td className="py-1.5 text-foreground">{rule}</td><td className="py-1.5 text-right tabular-nums text-foreground">{model.due_days[p]} days</td></tr>
                            ))}
                        </tbody>
                    </table>
                    <p className="text-[11px] text-foreground-muted flex gap-1.5"><ShieldAlert className="w-3.5 h-3.5 shrink-0 mt-px" aria-hidden />{model.evidence_rule}.</p>
                </div>
            </div>
        </Card>
    );
}

function Matrix({ matrix }: { matrix: Risk['matrix'] }) {
    const max = Math.max(1, ...Object.values(matrix).flatMap((r) => Object.values(r)));
    return (
        <div className="overflow-x-auto">
            <table className="w-full text-[11px] border-separate border-spacing-[3px]">
                <thead><tr><th className="sr-only">Likelihood</th>{SEVERITY_KEYS.map((s) => <th key={s} scope="col" className="font-semibold text-foreground-muted pb-1">{SEVERITY_META[s].label}</th>)}</tr></thead>
                <tbody>
                    {LIKELIHOOD.map(([k, label]) => (
                        <tr key={k}>
                            <th scope="row" className="text-left font-semibold text-foreground pr-2 whitespace-nowrap">{label}</th>
                            {SEVERITY_KEYS.map((s) => {
                                const n = matrix[k]?.[s] ?? 0;
                                return (
                                    <td key={s} className="text-center rounded-md h-9 min-w-[40px] tabular-nums font-bold" title={`${label}, ${SEVERITY_META[s].label}: ${n}`}
                                        style={n ? { background: `color-mix(in srgb, var(--vz-prog-4) ${Math.round(15 + (n / max) * 75)}%, transparent)`, color: n / max > 0.45 ? '#fff' : 'var(--foreground)' } : { background: 'var(--card-muted)', color: 'var(--foreground-muted)' }}>{n || '·'}</td>
                                );
                            })}
                        </tr>
                    ))}
                </tbody>
            </table>
            <p className="text-[10.5px] text-foreground-muted mt-2">Darker = more findings. Top-left is the most urgent combination.</p>
        </div>
    );
}

const EXPOSURE_SERIES: Series[] = [
    { key: 'kev_open', label: 'Known exploited (KEV)', token: '--vz-sev-critical' },
    { key: 'critical_exposures', label: 'Critical exposures', token: '--vz-sev-high' },
    { key: 'internet_open', label: 'On internet-facing assets', token: '--vz-cat-1' },
];

export function VmsExposure() {
    const { load, data: r, reload } = useVmsData<Risk>('/api/vms/risk');
    const [openId, setOpenId] = useOpenFinding();
    const loading = load.state === 'loading' && !r;
    const epssHigh = r ? (r.epss['10–50%'] ?? 0) + (r.epss['≥50%'] ?? 0) : undefined;
    const kevCols: Column<Risk['kev_findings'][number]>[] = [
        { key: 'priority', header: 'Priority', render: (k) => <PriorityBadge priority={k.priority} />, sort: (k) => k.priority ?? 'P9' },
        { key: 'title', header: 'Finding', className: 'min-w-[220px]', render: (k) => <span className="font-semibold text-foreground">{k.title}</span> },
        { key: 'cve', header: 'CVE', render: (k) => <span className="text-[11px] font-mono">{k.cve_ids.join(', ')}</span> },
        { key: 'asset', header: 'Asset', hideBelow: 'md', render: (k) => <span className="font-mono text-[11px]">{k.asset_value}</span> },
        { key: 'exposure', header: 'Exposure', render: (k) => k.exposure === 'internet' ? <Tag strong>Internet</Tag> : <span className="text-[11px] text-foreground-muted">{k.exposure}</span> },
        { key: 'due', header: 'Due', hideBelow: 'md', sort: (k) => k.due_at ?? '9999', render: (k) => <span className="text-[11px] whitespace-nowrap">{k.due_at ? fmtWat(k.due_at).replace(/,? \d\d:\d\d WAT$/, '') : '—'} {k.overdue && <Tag strong>Overdue</Tag>}</span> },
    ];
    return (
        <div className="space-y-5">
            <PageHeader icon={ShieldAlert} title="Exposure & Threat Context" description="Which open findings are reachable from the internet and which have exploitation evidence: CISA KEV (exploited in the wild) and EPSS (probability of exploitation in the next 30 days)." />
            {load.state === 'error' && !r && <ErrorState error={load.error} status={load.status} onRetry={reload} />}
            {(r || loading) && <>
            <section className="grid grid-cols-2 md:grid-cols-4 gap-3" aria-label="Key figures">
                <KpiCard label="Known exploited (KEV)" value={r?.totals.kev} reason="Loading" tone={r?.totals.kev ? 'critical' : undefined} sub="Open findings whose CVE is in CISA KEV" />
                <KpiCard label="EPSS ≥ 10%" value={epssHigh} reason="Loading" tone={epssHigh ? 'serious' : undefined} sub="Likely to be exploited soon" />
                <KpiCard label="On internet-facing assets" value={r ? r.exposure.internet ?? 0 : undefined} reason="Loading" sub="Open findings, any severity" />
                <KpiCard label="With a CVE" value={r?.totals.with_cve} reason="Loading" sub={r ? `of ${nf.format(r.totals.open)} open; others have no exploit data` : undefined} />
            </section>
            <section className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                <ChartCard title="Exploitation probability (EPSS)" hint="Open findings by the highest EPSS of their CVEs." loading={loading} empty={r && !r.totals.open ? { title: 'No open findings' } : null}>
                    {r && <BarList label="Findings by EPSS band" items={[['≥50%', '≥ 50%', '--vz-sev-critical'], ['10–50%', '10–50%', '--vz-sev-high'], ['1–10%', '1–10%', '--vz-sev-medium'], ['<1%', '< 1%', '--vz-sev-low'], ['unknown', 'CVE not scored by EPSS yet', '--vz-neutral'], ['no_cve', 'No CVE', '--vz-neutral']].map(([key, label, token]) => ({ key, label, value: r.epss[key] ?? 0, token: token as Series['token'] }))} />}
                </ChartCard>
                <ChartCard title="Where open findings are" hint="Exposure of the asset each open finding is on." loading={loading} empty={r && !r.totals.open ? { title: 'No open findings' } : null}>
                    {r && <Donut label="Open findings by asset exposure" centerLabel="open" slices={[['internet', 'Internet-facing', '--vz-sev-high'], ['internal', 'Internal', '--vz-prog-2'], ['unknown', 'Exposure unknown', '--vz-neutral']].map(([key, label, token]) => ({ key, label, value: r.exposure[key] ?? 0, token: token as Series['token'] }))} />}
                </ChartCard>
                <ChartCard title="Exposure over time" hint="Daily snapshots. Critical exposures are recorded from the P20 update onward." loading={loading} empty={r && r.trend.length < 2 ? { title: 'Not enough history yet', body: 'A trend needs at least two daily snapshots.' } : null}>
                    {r && <><TimeChart kind="line" label="Exposure over time" data={r.trend} series={EXPOSURE_SERIES} stacked={false} height={180} /><Legend series={EXPOSURE_SERIES} /></>}
                </ChartCard>
            </section>
            <Card>
                <SectionTitle title="Known exploited vulnerabilities" hint="Open findings whose CVE CISA lists as exploited in the wild. KEV on an internet-facing asset is always P1." action={<ExportCsvButton filename="vms-kev-findings.csv" rows={r?.kev_findings as unknown as Record<string, unknown>[]} columns={[{ key: 'priority', header: 'Priority' }, { key: 'title', header: 'Finding' }, { key: 'cve_ids', header: 'CVEs' }, { key: 'asset_value', header: 'Asset' }, { key: 'exposure', header: 'Exposure' }, { key: 'due_at', header: 'Due' }, { key: 'overdue', header: 'Overdue' }]} />} />
                <div className="-mx-5 -mb-5 [&>div]:rounded-none [&>div]:border-x-0 [&>div]:border-b-0">
                    <DataTable caption="Known exploited findings" rows={r?.kev_findings ?? null} columns={kevCols} rowKey={(k) => k.id} onRowClick={(k) => setOpenId(k.id)} pageSize={15} empty="No open finding has a CVE in CISA KEV" />
                </div>
            </Card>
            </>}
            <Drawer open={!!openId} onClose={() => setOpenId(null)} title="Finding">{openId && <FindingDetail key={openId} id={openId} onChanged={reload} />}</Drawer>
        </div>
    );
}
