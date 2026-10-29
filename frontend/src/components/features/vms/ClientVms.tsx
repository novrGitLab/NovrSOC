'use client';

// Client VMS portal (phase P21): a client's own organisation — overview, assets, vulnerabilities,
// remediation and reports — read from /api/client/vms with the client's own NovrSOC session. The
// backend fixes the organisation from the token and confines the session to /api/client/; these
// pages hold no organisation choice and show nothing about the SOC's scanners or staff.

import { useMemo, useState } from 'react';
import { useRouter, useSearchParams, usePathname } from 'next/navigation';
import Link from 'next/link';
import { ShieldCheck, Boxes, Bug, Wrench, Globe } from 'lucide-react';
import { fmtWat } from '@/lib/vms';
import { Card, SectionTitle, StatusPill } from './ui';
import { PageHeader, KpiCard, SeverityBadge, PriorityBadge, RiskScore, Segmented, Select, Drawer, ErrorState, EmptyState, ExportCsvButton, Tag, relTime, SEVERITY_META, SEVERITY_KEYS } from './kit';
import { ChartCard, Donut, BarList } from './charts';
import { DataTable, type Column } from './table';
import { VmsReport } from './VmsReport';
import { useVmsData } from './data';

interface Summary {
    kpis: { assets: number; internet_facing: number; open_vulnerabilities: number; critical: number; known_exploited: number; overdue: number; resolved_30_days: number; risk_mean: number | null; open_tasks: number };
    severity: Record<string, number>;
    by_status: Record<string, number>;
    top_findings: { id: string; title: string; asset_value: string; severity: string; priority: string | null; risk_score: number | null; due_at: string | null; known_exploited: boolean; internet: boolean }[];
    top_assets: { asset_id: string; value: string; open: number; by_severity: Record<string, number>; max_risk: number }[];
}
interface CFinding { id: string; asset_id: string | null; asset_value: string; port: number | null; title: string; cve_ids: string[]; scanner_severity: string; scanner_cvss: number | null; risk_score: number | null; priority: string | null; status: string; status_label: string; due_at: string | null; first_seen: string; last_seen: string; verified_at: string | null }
interface CDetail {
    finding: CFinding & { description: string | null; remediation: string | null; references_urls: string[] | null };
    scanner_cvss?: { score: number | null; version: string | null; vector: string | null };
    cve_intel: { cve_id: string; description: string | null; cvss_score: number | null; epss_score: number | null; kev: boolean; kev_date_added: string | null; kev_required_action: string | null }[];
    tasks: { id: string; title: string; status: string; owner: string | null; due_at: string | null; completed_at: string | null }[];
    history: { at: string; action: string; from: string | null; to: string | null }[];
}
interface CAsset { id: string; value: string; asset_type: string; exposure: string; criticality: string; hostnames: string[]; ips: string[]; last_seen: string; findings: { open: number; by_severity: Record<string, number>; max_risk: number | null } }
interface CTask { id: string; finding_id: string; title: string; status: string; owner: string | null; due_at: string | null; completed_at: string | null; created_at: string; overdue: boolean; finding: { id: string; title: string; asset_value: string; scanner_severity: string; priority: string | null; status_label: string } | null }
const TASK_LABEL: Record<string, string> = { todo: 'To do', doing: 'In progress', done: 'Done' };
const STATUS_ORDER = ['open', 'reopened', 'acknowledged', 'in_progress', 'fixed_pending_verification'] as const;
const STATUS_TEXT: Record<string, string> = { open: 'Open', reopened: 'Reopened', acknowledged: 'Confirmed', in_progress: 'Being fixed', fixed_pending_verification: 'Fix awaiting verification' };

export function ClientVmsOverview() {
    const { load, data: d, reload, at } = useVmsData<Summary>('/api/client/vms/summary');
    const now = at ?? 0;
    const k = d?.kpis;
    return (
        <div className="space-y-5">
            <PageHeader icon={ShieldCheck} title="Vulnerability overview" description="Your organisation's exposure and vulnerabilities, as found by NovrSOC's authorised scanning and your endpoint agents. Counted from stored records; nothing is estimated." />
            {load.state === 'error' && <ErrorState error={load.error} status={load.status} onRetry={reload} />}
            {(d || load.state === 'loading') && <>
                <section className="grid grid-cols-2 md:grid-cols-4 gap-3" aria-label="Key figures">
                    <KpiCard label="Assets monitored" value={k?.assets} reason="Loading" href="/client/vms/assets" sub={k ? `${k.internet_facing} internet-facing` : undefined} />
                    <KpiCard label="Open vulnerabilities" value={k?.open_vulnerabilities} reason="Loading" href="/client/vms/findings" />
                    <KpiCard label="Critical" value={k?.critical} reason="Loading" tone={k?.critical ? 'critical' : k ? 'good' : undefined} href="/client/vms/findings?severity=critical" />
                    <KpiCard label="Known exploited (CISA KEV)" value={k?.known_exploited} reason="Loading" tone={k?.known_exploited ? 'critical' : undefined} />
                    <KpiCard label="Past their fix deadline" value={k?.overdue} reason="Loading" tone={k?.overdue ? 'warning' : undefined} />
                    <KpiCard label="Resolved in 30 days" value={k?.resolved_30_days} reason="Loading" tone={k?.resolved_30_days ? 'good' : undefined} sub="Verified fixed by a rescan or agent" />
                    <KpiCard label="Average risk score" value={k ? (k.risk_mean === null ? null : Math.round(k.risk_mean)) : undefined} reason={k ? 'No open scored vulnerabilities' : 'Loading'} sub="0–100, open vulnerabilities" />
                    <KpiCard label="Open remediation tasks" value={k?.open_tasks} reason="Loading" href="/client/vms/remediation" />
                </section>
                <section className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                    <ChartCard title="Open vulnerabilities by severity" loading={!d} empty={d && !Object.values(d.severity).some(Boolean) ? { title: 'No open vulnerabilities' } : null}>
                        {d && <Donut label="Open vulnerabilities by severity" centerLabel="open" slices={SEVERITY_KEYS.map((s) => ({ key: s, label: SEVERITY_META[s].label, value: d.severity[s] ?? 0, token: `--vz-sev-${s}` as const, href: `/client/vms/findings?severity=${s}` }))} />}
                    </ChartCard>
                    <ChartCard title="Where fixes stand" hint="Open vulnerabilities by remediation stage." loading={!d} empty={d && !Object.values(d.by_status).some(Boolean) ? { title: 'Nothing open' } : null}>
                        {d && <BarList label="Open vulnerabilities by stage" items={STATUS_ORDER.map((s, i) => ({ key: s, label: STATUS_TEXT[s], value: d.by_status[s] ?? 0, token: (['--vz-sev-high', '--vz-sev-critical', '--vz-prog-1', '--vz-prog-2', '--vz-prog-3'] as const)[i] }))} />}
                    </ChartCard>
                    <Card>
                        <SectionTitle title="Most exposed assets" hint="Ranked by open severity, then risk." action={<Link href="/client/vms/assets" className="text-[11px] font-semibold text-purple dark:text-[var(--vz-prog-4)]">All assets →</Link>} />
                        {!d ? <div className="h-40 rounded-lg bg-card-muted motion-safe:animate-pulse" /> : d.top_assets.length === 0 ? <EmptyState compact title="No asset has open vulnerabilities" /> : (
                            <ul className="divide-y divide-border">
                                {d.top_assets.map((a) => (
                                    <li key={a.asset_id}><Link href={`/client/vms/findings?asset_id=${a.asset_id}`} className="flex items-center gap-3 py-2 hover:bg-card-muted/60 -mx-2 px-2 rounded-lg">
                                        <span className="flex-1 min-w-0"><span className="block text-xs font-semibold font-mono text-foreground break-all">{a.value}</span><span className="block text-[11px] text-foreground-muted">{a.open} open · {SEVERITY_KEYS.filter((s) => a.by_severity[s]).map((s) => `${a.by_severity[s]} ${s}`).join(' · ')}</span></span>
                                        <RiskScore score={a.max_risk} />
                                    </Link></li>
                                ))}
                            </ul>
                        )}
                    </Card>
                </section>
                <Card>
                    <SectionTitle title="Fix these first" hint="Your highest-risk open vulnerabilities." action={<Link href="/client/vms/findings" className="text-[11px] font-semibold text-purple dark:text-[var(--vz-prog-4)]">All vulnerabilities →</Link>} />
                    {!d ? <div className="h-32 rounded-lg bg-card-muted motion-safe:animate-pulse" /> : d.top_findings.length === 0 ? <EmptyState compact title="No open vulnerabilities" /> : (
                        <ul className="divide-y divide-border">
                            {d.top_findings.map((f) => (
                                <li key={f.id}><Link href={`/client/vms/findings?id=${f.id}`} className="flex items-start gap-3 py-2.5 hover:bg-card-muted/60 -mx-2 px-2 rounded-lg">
                                    <PriorityBadge priority={f.priority} />
                                    <span className="flex-1 min-w-0"><span className="block text-xs font-semibold text-foreground">{f.title}</span><span className="flex flex-wrap items-center gap-2 text-[11px] text-foreground-muted"><SeverityBadge severity={f.severity} /><span className="font-mono">{f.asset_value}</span>{f.internet && <Tag><Globe className="w-3 h-3" aria-hidden />Internet</Tag>}{f.known_exploited && <Tag strong>Known exploited</Tag>}{f.due_at && <span>due {relTime(f.due_at, now)}</span>}</span></span>
                                    <RiskScore score={f.risk_score} />
                                </Link></li>
                            ))}
                        </ul>
                    )}
                </Card>
            </>}
        </div>
    );
}

export function ClientVmsAssets() {
    const router = useRouter();
    const { load, data, reload } = useVmsData<{ assets: CAsset[] }>('/api/client/vms/assets');
    const [exposure, setExposure] = useState('');
    const rows = useMemo(() => data?.assets.filter((a) => !exposure || a.exposure === exposure) ?? null, [data, exposure]);
    const columns: Column<CAsset>[] = [
        { key: 'value', header: 'Asset', sort: (a) => a.value, render: (a) => <div><p className="font-mono font-semibold text-foreground break-all">{a.value}</p><p className="text-[10.5px] text-foreground-muted">{a.asset_type}{a.ips.length && a.asset_type !== 'ip' ? ` · ${a.ips.slice(0, 2).join(', ')}` : ''}</p></div> },
        { key: 'exposure', header: 'Exposure', sort: (a) => a.exposure, render: (a) => a.exposure === 'internet' ? <Tag><Globe className="w-3 h-3" aria-hidden />Internet</Tag> : <span className="text-[11px] text-foreground-muted capitalize">{a.exposure}</span> },
        { key: 'criticality', header: 'Criticality', hideBelow: 'md', render: (a) => <span className="text-[11px] capitalize">{a.criticality}</span> },
        { key: 'open', header: 'Open vulnerabilities', sort: (a) => a.findings.open, render: (a) => a.findings.open ? <span className="text-[11px]"><b className="text-foreground">{a.findings.open}</b> · {SEVERITY_KEYS.filter((s) => a.findings.by_severity[s]).map((s) => `${a.findings.by_severity[s]} ${s}`).join(' · ')}</span> : <span className="text-[11px] text-foreground-muted">None</span> },
        { key: 'risk', header: 'Highest risk', sort: (a) => a.findings.max_risk ?? -1, render: (a) => <RiskScore score={a.findings.max_risk} /> },
        { key: 'seen', header: 'Last seen', hideBelow: 'lg', sort: (a) => a.last_seen, render: (a) => <span className="text-[11px] text-foreground-muted">{fmtWat(a.last_seen)}</span> },
    ];
    return (
        <div className="space-y-5">
            <PageHeader icon={Boxes} title="Your assets" description="The hosts, domains and addresses of your organisation that NovrSOC monitors, with their open vulnerabilities." actions={<ExportCsvButton filename="assets.csv" rows={rows?.map((a) => ({ ...a, open: a.findings.open, max_risk: a.findings.max_risk }))} columns={[{ key: 'value', header: 'Asset' }, { key: 'asset_type', header: 'Type' }, { key: 'exposure', header: 'Exposure' }, { key: 'criticality', header: 'Criticality' }, { key: 'open', header: 'Open vulnerabilities' }, { key: 'max_risk', header: 'Highest risk' }, { key: 'last_seen', header: 'Last seen' }]} />} />
            <Select label="Exposure" value={exposure} onChange={setExposure} options={[['', 'Any exposure'], ['internet', 'Internet-facing'], ['internal', 'Internal'], ['unknown', 'Unknown']]} />
            {load.state === 'error' ? <ErrorState error={load.error} status={load.status} onRetry={reload} />
                : <DataTable caption="Your assets" rows={rows} columns={columns} rowKey={(a) => a.id} onRowClick={(a) => router.push(`/client/vms/findings?asset_id=${a.id}`)} initialSort={{ key: 'open', dir: 'desc' }} empty="No assets recorded yet" />}
        </div>
    );
}

export function ClientVmsFindings() {
    const params = useSearchParams();
    const router = useRouter();
    const pathname = usePathname();
    const [status, setStatus] = useState<'open' | 'resolved' | 'all'>('open');
    const [severity, setSeverity] = useState(params.get('severity') ?? '');
    const assetId = params.get('asset_id');
    const openId = params.get('id');
    const path = `/api/client/vms/findings?status=${status}${severity ? `&severity=${severity}` : ''}${assetId ? `&asset_id=${assetId}` : ''}`;
    const { load, data, reload } = useVmsData<{ findings: CFinding[] }>(path);
    const setOpen = (id: string | null) => { const p = new URLSearchParams(params.toString()); if (id) p.set('id', id); else p.delete('id'); router.replace(`${pathname}${p.toString() ? `?${p.toString()}` : ''}`, { scroll: false }); };
    const columns: Column<CFinding>[] = [
        { key: 'priority', header: 'Priority', sort: (f) => f.priority ?? 'P9', render: (f) => <PriorityBadge priority={f.priority} /> },
        { key: 'title', header: 'Vulnerability', className: 'min-w-[220px]', render: (f) => <div><p className="font-semibold text-foreground">{f.title}</p><p className="text-[10.5px] text-foreground-muted">{f.cve_ids.slice(0, 2).join(', ')}</p></div> },
        { key: 'severity', header: 'Severity', sort: (f) => SEVERITY_META[f.scanner_severity]?.rank ?? 9, render: (f) => <SeverityBadge severity={f.scanner_severity} /> },
        { key: 'risk', header: 'Risk', sort: (f) => f.risk_score, render: (f) => <RiskScore score={f.risk_score} /> },
        { key: 'asset', header: 'Asset', hideBelow: 'md', render: (f) => <span className="font-mono text-[11px] break-all">{f.asset_value}{f.port ? `:${f.port}` : ''}</span> },
        { key: 'status', header: 'Status', render: (f) => <span className="text-[11px] font-semibold">{f.status_label}</span> },
        { key: 'due', header: 'Fix by', hideBelow: 'md', sort: (f) => f.due_at ?? '9999', render: (f) => <span className="text-[11px] text-foreground-muted whitespace-nowrap">{f.due_at ? fmtWat(f.due_at).replace(/,? \d\d:\d\d WAT$/, '') : '—'}</span> },
    ];
    return (
        <div className="space-y-5">
            <PageHeader icon={Bug} title="Vulnerabilities" description="Vulnerabilities found on your assets, ranked by risk. A vulnerability is resolved only when a rescan or your endpoint agent confirms it is gone."
                actions={<ExportCsvButton filename="vulnerabilities.csv" rows={data?.findings as unknown as Record<string, unknown>[]} columns={[{ key: 'priority', header: 'Priority' }, { key: 'risk_score', header: 'Risk' }, { key: 'scanner_severity', header: 'Severity' }, { key: 'title', header: 'Vulnerability' }, { key: 'cve_ids', header: 'CVEs' }, { key: 'asset_value', header: 'Asset' }, { key: 'status_label', header: 'Status' }, { key: 'due_at', header: 'Fix by' }, { key: 'first_seen', header: 'First seen' }]} />} />
            <div className="flex flex-wrap items-center gap-2">
                <Segmented label="Status" value={status} onChange={setStatus} options={[['open', 'Open'], ['resolved', 'Resolved'], ['all', 'All']]} />
                <Select label="Severity" value={severity} onChange={setSeverity} options={[['', 'Any severity'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['info', 'Info']]} />
                {assetId && <Link href="/client/vms/findings" className="text-xs font-semibold text-purple dark:text-[var(--vz-prog-4)]">Showing one asset — show all</Link>}
            </div>
            {load.state === 'error' ? <ErrorState error={load.error} status={load.status} onRetry={reload} />
                : <DataTable caption="Vulnerabilities" rows={data?.findings ?? null} columns={columns} rowKey={(f) => f.id} onRowClick={(f) => setOpen(f.id)} activeKey={openId} initialSort={{ key: 'risk', dir: 'desc' }} empty={status === 'open' ? 'No open vulnerabilities' : 'Nothing in this view'} />}
            <Drawer open={!!openId} onClose={() => setOpen(null)} title="Vulnerability">{openId && <ClientFinding id={openId} />}</Drawer>
        </div>
    );
}

function ClientFinding({ id }: { id: string }) {
    const { load, data } = useVmsData<CDetail>(`/api/client/vms/findings/${id}`);
    if (load.state === 'error') return <ErrorState error={load.error} status={load.status} />;
    if (!data) return <div className="h-40 rounded-xl bg-card-muted motion-safe:animate-pulse" />;
    const f = data.finding;
    return (
        <div className="space-y-5 text-xs">
            <div className="space-y-2">
                <div className="flex flex-wrap items-center gap-2"><PriorityBadge priority={f.priority} /><SeverityBadge severity={f.scanner_severity} /><RiskScore score={f.risk_score} wide />{data.cve_intel.some((c) => c.kev) && <Tag strong>Known exploited</Tag>}<span className="ml-auto font-semibold text-foreground">{f.status_label}</span></div>
                <p className="text-base font-black text-foreground">{f.title}</p>
                <p className="text-foreground-muted">Scanner CVSS: <b className="text-foreground">{data.scanner_cvss?.score ?? 'not reported'}</b>{data.scanner_cvss?.version ? ` (CVSS v${data.scanner_cvss.version})` : ''} · NovrSOC risk score <b className="text-foreground">{f.risk_score ?? '—'}</b> / 100, which also weighs exploitation evidence, exposure and asset criticality.</p>
                <p className="text-foreground-muted"><span className="font-mono">{f.asset_value}{f.port ? `:${f.port}` : ''}</span> · first seen {fmtWat(f.first_seen)} · last seen {fmtWat(f.last_seen)}{f.due_at ? ` · fix by ${fmtWat(f.due_at)}` : ''}</p>
            </div>
            {f.description && <section><h3 className="text-[11px] font-bold uppercase tracking-wide text-foreground-muted mb-1">What it is</h3><p className="whitespace-pre-wrap leading-relaxed text-foreground">{f.description}</p></section>}
            {f.remediation && <section><h3 className="text-[11px] font-bold uppercase tracking-wide text-foreground-muted mb-1">How to fix it</h3><p className="whitespace-pre-wrap leading-relaxed text-foreground">{f.remediation}</p></section>}
            {data.cve_intel.length > 0 && (
                <section><h3 className="text-[11px] font-bold uppercase tracking-wide text-foreground-muted mb-1">Threat context</h3>
                    {data.cve_intel.map((c) => <div key={c.cve_id} className="border border-border rounded-xl p-3 mb-2 bg-card"><p className="font-bold">{c.cve_id}{c.kev ? ' · listed by CISA as exploited in the wild' : ''}</p><p className="text-foreground-muted">CVSS {c.cvss_score ?? 'unknown'} · EPSS {c.epss_score !== null ? `${(c.epss_score * 100).toFixed(1)}%` : 'unknown'}</p>{c.kev_required_action && <p>Required action: {c.kev_required_action}</p>}</div>)}
                </section>
            )}
            <section><h3 className="text-[11px] font-bold uppercase tracking-wide text-foreground-muted mb-1">Remediation tasks</h3>
                {data.tasks.length === 0 ? <p className="text-foreground-muted">No tasks yet.</p> : data.tasks.map((t) => <div key={t.id} className="flex items-center gap-2 border-t border-border first:border-0 py-1.5"><span className="flex-1">{t.title}</span><span className="text-foreground-muted">{t.owner ?? ''}{t.due_at ? ` · due ${fmtWat(t.due_at)}` : ''}</span><StatusPill tone={t.status === 'done' ? 'good' : 'neutral'} label={TASK_LABEL[t.status] ?? t.status} /></div>)}
            </section>
            <section><h3 className="text-[11px] font-bold uppercase tracking-wide text-foreground-muted mb-1">Status history</h3>
                {data.history.length === 0 ? <p className="text-foreground-muted">No changes yet.</p> : data.history.map((h, i) => <p key={i} className="text-foreground-muted">{fmtWat(h.at)} · {h.action === 'detected' ? 'Detected' : h.action === 'verified' ? 'Verified fixed' : h.action === 'reopened' ? 'Found again on rescan' : `${h.from ?? '—'} → ${h.to}`}</p>)}
            </section>
        </div>
    );
}

export function ClientVmsRemediation() {
    const router = useRouter();
    const { load, data, reload, at } = useVmsData<{ tasks: CTask[] }>('/api/client/vms/tasks');
    const [view, setView] = useState<'open' | 'done' | 'all'>('open');
    const now = at ?? 0;
    const rows = useMemo(() => data?.tasks.filter((t) => view === 'all' || (view === 'open' ? t.status !== 'done' : t.status === 'done')) ?? null, [data, view]);
    const columns: Column<CTask>[] = [
        { key: 'title', header: 'Task', className: 'min-w-[180px]', render: (t) => <span className="font-semibold text-foreground">{t.title}</span> },
        { key: 'finding', header: 'Vulnerability', hideBelow: 'md', render: (t) => t.finding ? <span className="flex items-center gap-2"><PriorityBadge priority={t.finding.priority} /><span className="text-[11px]">{t.finding.title}<span className="block font-mono text-foreground-muted">{t.finding.asset_value}</span></span></span> : '—' },
        { key: 'owner', header: 'Owner', render: (t) => <span className="text-[11px]">{t.owner ?? '—'}</span> },
        { key: 'due', header: 'Due', sort: (t) => t.due_at ?? '9999', render: (t) => <span className="text-[11px] whitespace-nowrap">{t.due_at ? relTime(t.due_at, now) : '—'} {t.overdue && <Tag strong>Overdue</Tag>}</span> },
        { key: 'status', header: 'Status', sort: (t) => t.status, render: (t) => <StatusPill tone={t.status === 'done' ? 'good' : t.overdue ? 'warning' : 'neutral'} label={TASK_LABEL[t.status] ?? t.status} /> },
    ];
    return (
        <div className="space-y-5">
            <PageHeader icon={Wrench} title="Remediation" description="The remediation work agreed for your vulnerabilities and where each task stands. Finishing a task does not close the vulnerability: a rescan or your endpoint agent has to confirm the fix." />
            <Segmented label="Tasks" value={view} onChange={setView} options={[['open', 'Open'], ['done', 'Done'], ['all', 'All']]} />
            {load.state === 'error' ? <ErrorState error={load.error} status={load.status} onRetry={reload} />
                : <DataTable caption="Remediation tasks" rows={rows} columns={columns} rowKey={(t) => t.id} onRowClick={(t) => router.push(`/client/vms/findings?id=${t.finding_id}`)} initialSort={{ key: 'due', dir: 'asc' }} empty="No remediation tasks" />}
        </div>
    );
}

export function ClientVmsReports() {
    // richDetail off: the client portal's findings endpoint has a different shape than the staff
    // one the new sections need (see VmsReport.tsx's file header) — unchanged existing behaviour.
    return <VmsReport endpoint="/api/client/vms/report" exports={false} findingsPath="/client/vms/findings" richDetail={false} />;
}
