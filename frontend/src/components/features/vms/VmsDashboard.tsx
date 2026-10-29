'use client';

// VMS Dashboard (redesign, phase P20). One read of GET /api/vms/dashboard: every KPI, chart and
// list below is counted from stored records for the organisation being viewed. A figure that could
// not be read is "Unavailable" (never 0); a chart without history says so (the risk-score history
// starts with the first P20 snapshot and is never back-filled).

import { useState } from 'react';
import Link from 'next/link';
import {
    Radar, Plus, ScanSearch, AlertOctagon, FileBarChart, Server, Bug, ShieldAlert, Globe, Clock, Activity, Gauge, CheckCircle2, ArrowRight, RefreshCw,
} from 'lucide-react';
import { fmtWat, SCAN_KIND_LABEL, ENGINE_STATE_LABEL, EVENT_LABEL, scanProgress, type EngineState, type VmsScan } from '@/lib/vms';
import { Card, SectionTitle, StatusPill, type Tone } from './ui';
import { PageHeader, KpiCard, SeverityBadge, PriorityBadge, RiskScore, Segmented, ErrorState, EmptyState, Tag, btn, relTime, nf } from './kit';
import { ChartCard, TimeChart, Donut, BarList, Legend, type Series } from './charts';
import { useVmsData, useVmsCan } from './data';

interface Dashboard {
    period: { days: number; from: string; to: string };
    kpis: {
        total_assets: number; internet_facing_assets: number; open_findings: number; open_vulnerabilities: number; critical_open: number; critical_exposures: number;
        overdue_tasks: number; overdue_findings: number; active_scans: number; new_findings: number; verified_in_period: number; remediation_rate: number | null;
        risk_mean: number | null; risk_max: number | null; engines_available: number; engines_total: number;
    };
    definitions: Record<string, string>;
    charts: {
        severity: Record<string, number>; status: Record<string, number>; assets_by_criticality: Record<string, number>; assets_by_exposure: Record<string, number>;
        new_findings: Record<string, number | string>[]; scan_activity: Record<string, number | string>[];
        risk: { day: string; risk_mean: number; risk_max: number | null }[];
        exposure: { day: string; critical_exposures: number | null; internet_open: number; kev_open: number }[];
        tasks: Record<string, number>;
    };
    lists: {
        recent_critical: { id: string; title: string; asset_id: string | null; asset_value: string; severity: string; priority: string | null; risk_score: number | null; first_seen: string; internet: boolean }[];
        highest_risk_assets: { asset_id: string; value: string; open: number; by_severity: Record<string, number>; max_risk: number; exposure: string | null; criticality: string | null; asset_type: string | null }[];
        active_scans: (Pick<VmsScan, 'id' | 'kind' | 'status' | 'targets' | 'progress' | 'requested_at' | 'started_at' | 'heartbeat_at' | 'worker_id'> & { purpose?: string })[];
        overdue_tasks: { id: string; title: string; owner: string | null; due_at: string; status: string; finding: { id: string; title: string; asset_value: string; priority: string | null } | null }[];
        activity: { at: string; kind: 'asset' | 'finding'; event: string; subject: string | null; subject_id: string; details: Record<string, unknown> | null }[];
    };
    engines: { id: string; label: string; kind: string; state: EngineState; note: string; versions: string[] }[];
    worker_presence: { state: 'online' | 'offline' | 'never'; online_workers: number; last_seen_at: string | null };
}

const SEV_SERIES: Series[] = [
    { key: 'critical', label: 'Critical', token: '--vz-sev-critical' }, { key: 'high', label: 'High', token: '--vz-sev-high' },
    { key: 'medium', label: 'Medium', token: '--vz-sev-medium' }, { key: 'low', label: 'Low', token: '--vz-sev-low' },
];
const SCAN_SERIES: Series[] = [
    { key: 'assessed', label: 'Assessed', token: '--vz-good' }, { key: 'inconclusive', label: 'Inconclusive (no host reached)', token: '--vz-warning' },
    { key: 'failed', label: 'Failed', token: '--vz-critical' }, { key: 'cancelled', label: 'Cancelled', token: '--vz-neutral' }, { key: 'in_progress', label: 'Queued / running', token: '--vz-cat-1' },
];
const RISK_SERIES: Series[] = [{ key: 'risk_mean', label: 'Mean risk score', token: '--vz-prog-3' }, { key: 'risk_max', label: 'Highest risk score', token: '--vz-sev-high' }];
const EXPOSURE_SERIES: Series[] = [
    { key: 'critical_exposures', label: 'Critical exposures', token: '--vz-sev-critical' }, { key: 'kev_open', label: 'Known exploited (KEV)', token: '--vz-sev-medium' },
    { key: 'internet_open', label: 'On internet-facing assets', token: '--vz-cat-1' },
];
const STATUS_SLICES = [
    ['open', 'Open', '--vz-sev-high'], ['reopened', 'Reopened', '--vz-sev-critical'], ['acknowledged', 'Triaged', '--vz-prog-1'], ['in_progress', 'In progress', '--vz-prog-2'],
    ['fixed_pending_verification', 'Awaiting verification', '--vz-prog-3'], ['verified', 'Resolved (verified)', '--vz-good'], ['risk_accepted', 'Risk accepted', '--vz-neutral'], ['false_positive', 'False positive', '--vz-sev-info'],
] as const;
const ENGINE_TONE: Record<EngineState, Tone> = { available: 'good', offline: 'warning', not_enabled: 'neutral', not_installed: 'critical', no_worker: 'critical' };
const CRIT = ['critical', 'high', 'medium', 'low'] as const;

export function VmsDashboard() {
    const [days, setDays] = useState<'7' | '30' | '90'>('30');
    const { load, data: d, reload, at } = useVmsData<Dashboard>(`/api/vms/dashboard?days=${days}`);
    const can = useVmsCan();
    const loading = load.state === 'loading' && !d;
    const k = d?.kpis;
    const now = at ?? 0;

    return (
        <div className="space-y-5">
            <PageHeader
                icon={Radar} title="VMS Dashboard"
                description="Exposure, vulnerabilities, remediation and scanning for this organisation — every figure is counted from stored records; nothing is estimated."
                actions={<>
                    <Segmented label="Period" value={days} onChange={setDays} options={[['7', '7 days'], ['30', '30 days'], ['90', '90 days']]} />
                    <button onClick={reload} className={btn('secondary')} aria-label="Refresh"><RefreshCw className={`w-3.5 h-3.5 ${load.state === 'loading' ? 'motion-safe:animate-spin' : ''}`} aria-hidden /></button>
                </>}
            />
            {/* Quick actions: each goes to the working flow; the backend checks the permission there. */}
            <div className="flex flex-wrap gap-2">
                <Link href="/admin/vms/discovery" className={btn('secondary', 'md')}><Plus className="w-4 h-4" aria-hidden /> Add asset</Link>
                <Link href="/admin/vms/scans" className={btn('primary', 'md')}><ScanSearch className="w-4 h-4" aria-hidden /> Start authorised scan</Link>
                <Link href="/admin/vms/findings?severity=critical" className={btn('secondary', 'md')}><AlertOctagon className="w-4 h-4" aria-hidden /> View critical findings</Link>
                <Link href="/admin/vms/report" className={btn('secondary', 'md')}><FileBarChart className="w-4 h-4" aria-hidden /> Generate report</Link>
                {can.readOnly && <span className="self-center text-[11px] text-foreground-muted">Scans and changes need an analyst or manager role.</span>}
            </div>
            {load.state === 'error' && <ErrorState error={load.error} status={load.status} onRetry={reload} />}
            {/* Nothing below renders after a failed load: an empty list would read as "nothing to do". */}
            {(d || loading) && <>

            {/* KPIs */}
            <section aria-label="Key figures" className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-3">
                {loading ? Array.from({ length: 10 }, (_, i) => <div key={i} className="h-[104px] rounded-2xl bg-card border border-border motion-safe:animate-pulse" />) : k && <>
                    <KpiCard label="Total assets" value={k.total_assets} icon={Server} href="/admin/vms/assets" sub={`${nf.format(k.internet_facing_assets)} internet-facing`} />
                    <KpiCard label="Open vulnerabilities" value={k.open_vulnerabilities} icon={Bug} href="/admin/vms/findings" hint={d.definitions.open_vulnerabilities} sub={`${nf.format(k.open_findings - k.open_vulnerabilities)} informational not counted`} />
                    <KpiCard label="Critical vulnerabilities" value={k.critical_open} tone={k.critical_open ? 'critical' : 'good'} href="/admin/vms/findings?severity=critical" sub="Open, scanner severity critical" />
                    <KpiCard label="Critical exposures" value={k.critical_exposures} tone={k.critical_exposures ? 'serious' : 'good'} href="/admin/vms/risk/exposure" hint={d.definitions.critical_exposures} sub="Critical/high on internet-facing assets" />
                    <KpiCard label="Overdue remediation tasks" value={k.overdue_tasks} tone={k.overdue_tasks ? 'warning' : 'good'} href="/admin/vms/remediation?view=table&overdue=1" hint={d.definitions.overdue_tasks} sub={`${nf.format(k.overdue_findings)} findings past their deadline`} />
                    <KpiCard label="Active scans" value={k.active_scans} icon={Activity} href="/admin/vms/scans" sub="Queued or running now" />
                    <KpiCard label={`New vulnerabilities (${days}d)`} value={k.new_findings} icon={Clock} href="/admin/vms/findings" sub="First seen in the period" />
                    <KpiCard label="Remediation completion" value={k.remediation_rate} suffix="%" reason="No findings verified or open in this period" hint={d.definitions.remediation_rate} sub={`${nf.format(k.verified_in_period)} verified fixed in ${days} days`} icon={CheckCircle2} />
                    <KpiCard label="Overall risk score" value={k.risk_mean === null ? null : Math.round(k.risk_mean)} reason="No open scored findings" hint={d.definitions.risk_mean} href="/admin/vms/risk" sub={k.risk_max !== null ? `Mean of open findings, 0–100 · highest ${k.risk_max}` : 'Mean of open findings, 0–100'} icon={Gauge} />
                    <KpiCard label="Scanner availability" value={k.engines_available} suffix={` / ${k.engines_total}`} tone={k.engines_available === k.engines_total ? 'good' : k.engines_available ? 'warning' : 'critical'} sub={`Engines with a connected worker · ${d.worker_presence.online_workers} worker(s) online`} />
                </>}
            </section>

            {/* Charts */}
            <section aria-label="Charts" className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                <ChartCard title="Open findings by severity" hint="Scanner severity of everything not yet resolved." loading={loading} empty={k && !k.open_findings ? { title: 'No open findings' } : null}>
                    {d && <Donut label="Open findings by severity" centerLabel="open" slices={[...SEV_SERIES, { key: 'info', label: 'Informational', token: '--vz-sev-info' as const }].map((s) => ({ key: s.key, label: s.label, token: s.token, value: d.charts.severity[s.key] ?? 0, href: `/admin/vms/findings?severity=${s.key}` }))} />}
                </ChartCard>
                <ChartCard className="xl:col-span-2" title="Risk score over time" hint="Daily snapshot of the mean and highest risk score of open findings."
                    loading={loading} empty={d && d.charts.risk.length === 0 ? { title: 'No risk history yet', body: 'Risk scores are recorded in the daily snapshot from the P20 update onward. Earlier days are not reconstructed, so the line starts with the first recorded day.' } : null}>
                    {d && <><TimeChart kind="line" label="Risk score over time" data={d.charts.risk} series={RISK_SERIES} yMax={100} stacked={false} /><Legend series={RISK_SERIES} /></>}
                </ChartCard>
                <ChartCard className="xl:col-span-2" title="New vulnerabilities" hint={`First seen per day, by severity, last ${days} days.`} loading={loading} empty={k && !k.new_findings ? { title: 'No new vulnerabilities in this period' } : null}>
                    {d && <><TimeChart kind="area" label="New vulnerabilities per day" data={d.charts.new_findings} series={SEV_SERIES} /><Legend series={SEV_SERIES} /></>}
                </ChartCard>
                <ChartCard title="Remediation progress" hint="Remediation tasks by state. A finding closes only when a rescan or the monitoring engine verifies it." loading={loading}
                    empty={d && !Object.values(d.charts.tasks).some(Boolean) ? { title: 'No remediation tasks yet', body: 'Tasks are added from a finding or from an AI plan a person accepted.' } : null}>
                    {d && <BarList label="Remediation tasks by state" items={[['todo', 'To do', '--vz-prog-1'], ['doing', 'In progress', '--vz-prog-3'], ['done', 'Done', '--vz-good'], ['cancelled', 'Cancelled', '--vz-neutral']].map(([key, label, token]) => ({ key, label, value: d.charts.tasks[key] ?? 0, token: token as Series['token'], href: '/admin/vms/remediation?view=table' }))} />}
                </ChartCard>
                <ChartCard title="Assets by business criticality" hint="Active assets; criticality is set by people on each asset." loading={loading} empty={k && !k.total_assets ? { title: 'No assets yet', body: 'Add an authorised scope and run discovery, or map monitoring groups.' } : null}>
                    {d && <BarList label="Assets by criticality" items={CRIT.map((c, i) => ({ key: c, label: c[0].toUpperCase() + c.slice(1), value: d.charts.assets_by_criticality[c] ?? 0, token: (['--vz-prog-4', '--vz-prog-3', '--vz-prog-2', '--vz-prog-1'] as const)[i], href: `/admin/vms/assets?criticality=${c}` }))} />}
                </ChartCard>
                <ChartCard title="Finding status" hint="Every finding on record, by lifecycle state." loading={loading} empty={d && !Object.values(d.charts.status).some(Boolean) ? { title: 'No findings on record' } : null}>
                    {d && <Donut label="Findings by status" centerLabel="findings" size={150} slices={STATUS_SLICES.map(([key, label, token]) => ({ key, label, token, value: d.charts.status[key] ?? 0 }))} />}
                </ChartCard>
                <ChartCard title="Critical exposure trend" hint="Daily snapshots of open findings that matter most from outside." loading={loading}
                    empty={d && d.charts.exposure.length < 2 ? { title: 'Not enough history yet', body: 'A trend needs at least two daily snapshots; one is taken each day. Critical exposures are recorded from the P20 update onward.' } : null}>
                    {d && <><TimeChart kind="line" label="Exposure trend" data={d.charts.exposure} series={EXPOSURE_SERIES} stacked={false} height={200} /><Legend series={EXPOSURE_SERIES} /></>}
                </ChartCard>
                <ChartCard className="xl:col-span-3" title="Scan activity and outcomes" hint="Scans requested per day. A scan that reached no host is inconclusive — never counted as assessed." loading={loading}
                    empty={d && !d.charts.scan_activity.some((r) => SCAN_SERIES.some((s) => Number(r[s.key]))) ? { title: 'No scans in this period' } : null}>
                    {d && <><TimeChart kind="bar" label="Scans per day by outcome" data={d.charts.scan_activity} series={SCAN_SERIES} /><Legend series={SCAN_SERIES} /></>}
                </ChartCard>
            </section>

            {/* Lists */}
            <section aria-label="Work lists" className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
                <ListCard title="Recent critical findings" hint="Open critical and high, newest first." href="/admin/vms/findings?severity=critical" loading={loading} empty={!d?.lists.recent_critical.length ? 'No open critical or high findings' : null}>
                    {d?.lists.recent_critical.map((f) => (
                        <Link key={f.id} href={`/admin/vms/findings?id=${f.id}`} className="flex items-start gap-3 py-2.5 hover:bg-card-muted/60 -mx-2 px-2 rounded-lg">
                            <PriorityBadge priority={f.priority} />
                            <span className="flex-1 min-w-0">
                                <span className="block text-xs font-semibold text-foreground truncate">{f.title}</span>
                                <span className="block text-[11px] text-foreground-muted truncate"><SeverityBadge severity={f.severity} /> · <span className="font-mono">{f.asset_value}</span>{f.internet ? ' · internet-facing' : ''} · {relTime(f.first_seen, now)}</span>
                            </span>
                            <RiskScore score={f.risk_score} />
                        </Link>
                    ))}
                </ListCard>
                <ListCard title="Highest-risk assets" hint="Ranked by open severity, then highest risk score." href="/admin/vms/assets" loading={loading} empty={!d?.lists.highest_risk_assets.length ? 'No asset has open findings' : null}>
                    {d?.lists.highest_risk_assets.map((a) => (
                        <Link key={a.asset_id} href={`/admin/vms/assets/${a.asset_id}`} className="flex items-center gap-3 py-2.5 hover:bg-card-muted/60 -mx-2 px-2 rounded-lg">
                            <span className="flex-1 min-w-0">
                                <span className="block text-xs font-semibold font-mono text-foreground break-all">{a.value}</span>
                                <span className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-foreground-muted">{a.open} open · {['critical', 'high', 'medium', 'low'].filter((s) => a.by_severity[s]).map((s) => `${a.by_severity[s]} ${s}`).join(' · ')}{a.exposure === 'internet' && <Tag><Globe className="w-3 h-3" aria-hidden />Internet</Tag>}</span>
                            </span>
                            <RiskScore score={a.max_risk} />
                        </Link>
                    ))}
                </ListCard>
                <ListCard title="Active scans" hint="Queued or running now." href="/admin/vms/scans" loading={loading} empty={!d?.lists.active_scans.length ? 'No scans queued or running' : null}>
                    {d?.lists.active_scans.map((s) => (
                        <div key={s.id} className="py-2.5">
                            <div className="flex items-center justify-between gap-2">
                                <span className="text-xs font-semibold text-foreground truncate">{SCAN_KIND_LABEL[s.kind] ?? s.kind}</span>
                                <StatusPill tone={s.status === 'running' ? 'good' : 'neutral'} label={s.status === 'running' ? 'Running' : 'Queued'} />
                            </div>
                            <p className="text-[11px] text-foreground-muted truncate font-mono">{s.targets.slice(0, 3).join(', ')}{s.targets.length > 3 ? ` +${s.targets.length - 3}` : ''}</p>
                            <p className="text-[11px] text-foreground-muted">{scanProgress(s.progress) || `requested ${relTime(s.requested_at, now)}`}</p>
                        </div>
                    ))}
                </ListCard>
                <ListCard title="Overdue remediation tasks" hint="Not done, past their due date." href="/admin/vms/remediation?view=table&overdue=1" loading={loading} empty={!d?.lists.overdue_tasks.length ? 'No overdue tasks' : null}>
                    {d?.lists.overdue_tasks.map((t) => (
                        <Link key={t.id} href={t.finding ? `/admin/vms/findings?id=${t.finding.id}` : '/admin/vms/remediation?view=table'} className="flex items-start gap-3 py-2.5 hover:bg-card-muted/60 -mx-2 px-2 rounded-lg">
                            <PriorityBadge priority={t.finding?.priority} />
                            <span className="flex-1 min-w-0">
                                <span className="block text-xs font-semibold text-foreground truncate">{t.title}</span>
                                <span className="block text-[11px] text-foreground-muted truncate">{t.owner ?? 'Unassigned'} · due {relTime(t.due_at, now)}{t.finding ? ` · ${t.finding.asset_value}` : ''}</span>
                            </span>
                        </Link>
                    ))}
                </ListCard>
                <ListCard title="Recent activity" hint="Asset changes and finding history." href="/admin/vms/monitoring/changes" loading={loading} empty={!d?.lists.activity.length ? 'No recorded activity' : null}>
                    {d?.lists.activity.slice(0, 8).map((a, i) => (
                        <div key={`${a.at}-${i}`} className="py-2">
                            <p className="text-xs text-foreground"><span className="font-semibold">{a.kind === 'asset' ? EVENT_LABEL[a.event] ?? a.event : activityLabel(a.event, a.details)}</span>{a.subject ? <> · <span className={a.kind === 'asset' ? 'font-mono' : ''}>{a.subject}</span></> : null}</p>
                            <p className="text-[11px] text-foreground-muted">{relTime(a.at, now)}{a.kind === 'finding' && a.details?.actor ? ` · ${String(a.details.actor)}` : ''}</p>
                        </div>
                    ))}
                </ListCard>
                <ListCard title="Scanner health" hint={d ? `Workers: ${d.worker_presence.state === 'online' ? `${d.worker_presence.online_workers} online` : d.worker_presence.state === 'never' ? 'none has connected' : `offline, last seen ${fmtWat(d.worker_presence.last_seen_at)}`}` : undefined} href={can.scope ? '/admin/vms/operations/workers' : undefined} loading={loading} empty={!d?.engines.length ? 'No scan engines known' : null}>
                    {d?.engines.map((e) => (
                        <div key={e.id} className="flex items-start justify-between gap-3 py-2.5">
                            <span className="min-w-0"><span className="block text-xs font-semibold text-foreground">{e.label}</span><span className="block text-[11px] text-foreground-muted">{e.note}{e.versions.length ? ` · ${e.versions.join(', ')}` : ''}</span></span>
                            <StatusPill tone={ENGINE_TONE[e.state]} label={ENGINE_STATE_LABEL[e.state]} />
                        </div>
                    ))}
                </ListCard>
            </section>
            </>}
        </div>
    );
}

function activityLabel(action: string, details: Record<string, unknown> | null): string {
    const to = details?.to ? String(details.to).replace(/_/g, ' ') : '';
    switch (action) {
        case 'detected': return 'Finding detected';
        case 'status': return `Status → ${to}`;
        case 'owner': return `Owner → ${to || 'none'}`;
        case 'due': return 'Deadline changed';
        case 'note': return 'Note added';
        case 'verified': return 'Verified fixed';
        case 'reopened': return 'Reopened';
        case 'verification_queued': return 'Verification scan queued';
        case 'case_link': return 'Promoted to case';
        case 'risk': return 'Risk re-scored';
        default: return action.replace(/_/g, ' ');
    }
}

function ListCard({ title, hint, href, loading, empty, children }: { title: string; hint?: string; href?: string; loading: boolean; empty: string | null; children: React.ReactNode }) {
    return (
        <Card className="flex flex-col">
            <SectionTitle title={title} hint={hint} action={href ? <Link href={href} className="text-[11px] font-semibold text-purple dark:text-[var(--vz-prog-4)] inline-flex items-center gap-0.5 whitespace-nowrap">View all <ArrowRight className="w-3 h-3" aria-hidden /></Link> : undefined} />
            {loading ? <div className="space-y-3">{Array.from({ length: 4 }, (_, i) => <div key={i} className="h-9 rounded-lg bg-card-muted motion-safe:animate-pulse" />)}</div>
                : empty ? <EmptyState compact icon={ShieldAlert} title={empty} />
                : <div className="divide-y divide-border -my-1">{children}</div>}
        </Card>
    );
}
