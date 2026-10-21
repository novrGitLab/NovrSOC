'use client';

// Asset Management (redesign, phase P20): Asset Inventory, the asset page, Asset Discovery and Attack
// Surface. Assets are what scans found inside authorised scope plus the Wazuh-managed endpoints —
// one record set (GET /api/vms/assets, with each asset's open findings and highest risk). Owner and
// criticality are set by people (PATCH /api/vms/assets/:id, vms:manage); everything else is observed.

import { useEffect, useMemo, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { Boxes, Globe, Radar, ArrowLeft, Server, ShieldCheck, Plus } from 'lucide-react';
import {
    fmtWat, EVENT_LABEL, describeEvent, OUTCOME_LABEL, portStates, ELIGIBILITY_LABEL, PROFILE_LABEL, ASSESSMENT_STATUS_LABEL, SCAN_KIND_LABEL,
    type VmsAsset, type VmsService, type VmsTech, type VmsEvent, type VmsAssessment, type VmsScan,
} from '@/lib/vms';
import { AiPanel } from '@/components/shared/AiPanel';
import { Card, SectionTitle, StatusPill, SegmentBar } from './ui';
import { PageHeader, KpiCard, RiskScore, PriorityBadge, SeverityBadge, Segmented, Select, SearchBox, ErrorState, Notice, EmptyState, ExportCsvButton, ConfirmDialog, Timeline, Tag, btn, relTime, nf, type Msg, SEVERITY_META } from './kit';
import { ChartCard, BarList, Donut } from './charts';
import { DataTable, type Column } from './table';
import { AttackSurfaceMap } from './AttackSurfaceMap';
import { VmsEndpoints } from './VmsEndpoints';
import { VmsScope } from './VmsScope';
import { ScanResult } from './VmsRemediationPlus';
import { STATUS_LABEL, type Finding } from './FindingDetail';
import { useVmsData, useVmsCan, vmsSend } from './data';

type Asset = VmsAsset & { findings?: { open: number; by_severity: Record<string, number>; max_risk: number | null } };
interface AssetDetail { asset: VmsAsset; services: VmsService[]; technologies: VmsTech[]; events: VmsEvent[]; linked?: { id: string; asset_type: string; value: string; exposure: string; relation: string; services: VmsService[] }[] }
interface Overview { assets: { active: number; internet_facing: number; gone: number; open_services: number }; last_7_days: { new_assets: number; changed_assets: number; gone_assets: number; new_services: number }; active_scopes: number }

const SEV4 = ['critical', 'high', 'medium', 'low'] as const;
const TYPE_LABEL: Record<string, string> = { domain: 'Domain', host: 'Host', ip: 'IP address', endpoint: 'Wazuh endpoint', asn: 'ASN', cidr: 'Network' };
const EXPOSURE_LABEL: Record<string, string> = { internet: 'Internet-facing', internal: 'Internal', unknown: 'Unknown' };

function SevBar({ by }: { by: Record<string, number> }) {
    return <div className="w-24"><SegmentBar height="h-2" label="Open findings by severity" segments={SEV4.map((s) => ({ key: s, label: SEVERITY_META[s].label, value: by[s] ?? 0, color: SEVERITY_META[s].color }))} /></div>;
}
function Outcome({ a }: { a: VmsAsset }) {
    if (!a.last_assessed_at) return <span className="text-[11px] text-foreground-muted">Not assessed</span>;
    const o = a.last_assessment?.outcome ?? '';
    return <span className="text-[11px] text-foreground-muted">{/^reachable/.test(o) ? 'Assessed' : OUTCOME_LABEL[o] ?? 'No result'} · {fmtWat(a.last_assessed_at).replace(/,? \d\d:\d\d WAT$/, '')}</span>;
}

// ── Asset Inventory ────────────────────────────────────────────────────────────────────────────
export function VmsAssetInventory() {
    const params = useSearchParams();
    const router = useRouter();
    // Old links: ?id= opened an asset in the list; it has its own page now.
    const legacyId = params.get('id');
    useEffect(() => { if (legacyId) router.replace(`/admin/vms/assets/${legacyId}`); }, [legacyId, router]);
    const [view, setView] = useState<'all' | 'endpoints'>(params.get('view') === 'endpoints' || params.get('source') === 'wazuh' ? 'endpoints' : 'all');
    const [exposure, setExposure] = useState(params.get('exposure') ?? '');
    const [status, setStatus] = useState<'active' | 'gone' | 'all'>('active');
    const [type, setType] = useState(params.get('source') === 'external' ? 'external' : '');
    const [criticality, setCriticality] = useState(params.get('criticality') ?? '');
    const [q, setQ] = useState('');
    const path = useMemo(() => {
        const p = new URLSearchParams();
        if (exposure) p.set('exposure', exposure);
        if (status !== 'all') p.set('status', status);
        if (q) p.set('q', q);
        return `/api/vms/assets?${p.toString()}`;
    }, [exposure, status, q]);
    const { load, data, reload } = useVmsData<{ assets: Asset[] }>(view === 'all' ? path : null);
    const rows = useMemo(() => data?.assets.filter((a) => (!type || (type === 'external' ? a.asset_type !== 'endpoint' : a.asset_type === type)) && (!criticality || a.criticality === criticality)) ?? null, [data, type, criticality]);
    const columns: Column<Asset>[] = [
        { key: 'value', header: 'Asset', className: 'min-w-[200px]', sort: (a) => a.value, render: (a) => <div><p className="font-mono font-semibold text-foreground break-all">{a.value}</p><p className="text-[10.5px] text-foreground-muted">{TYPE_LABEL[a.asset_type] ?? a.asset_type}{a.ips.length && a.asset_type !== 'ip' ? ` · ${a.ips.slice(0, 2).join(', ')}` : ''}{a.status === 'gone' ? ' · gone' : ''}</p></div> },
        { key: 'exposure', header: 'Exposure', sort: (a) => a.exposure, render: (a) => a.exposure === 'internet' ? <Tag><Globe className="w-3 h-3" aria-hidden />Internet</Tag> : <span className="text-[11px] text-foreground-muted">{EXPOSURE_LABEL[a.exposure] ?? a.exposure}</span> },
        { key: 'criticality', header: 'Criticality', sort: (a) => ['critical', 'high', 'medium', 'low'].indexOf(a.criticality), render: (a) => <span className="text-[11px] font-semibold capitalize">{a.criticality}</span> },
        { key: 'findings', header: 'Open findings', sort: (a) => a.findings?.open ?? 0, render: (a) => a.findings?.open ? <div className="flex items-center gap-2"><span className="tabular-nums font-bold w-6 text-right">{a.findings.open}</span><SevBar by={a.findings.by_severity} /></div> : <span className="text-[11px] text-foreground-muted">None</span> },
        { key: 'risk', header: 'Max risk', sort: (a) => a.findings?.max_risk ?? -1, render: (a) => <RiskScore score={a.findings?.max_risk} /> },
        { key: 'assessed', header: 'Last assessment', hideBelow: 'lg', sort: (a) => a.last_assessed_at ?? '', render: (a) => <Outcome a={a} /> },
        { key: 'owner', header: 'Owner', hideBelow: 'lg', sort: (a) => a.owner ?? '~', render: (a) => <span className="text-[11px] text-foreground-muted">{a.owner ?? '—'}</span> },
        { key: 'seen', header: 'Last seen', hideBelow: 'md', sort: (a) => a.last_seen, render: (a) => <span className="text-[11px] text-foreground-muted whitespace-nowrap">{fmtWat(a.last_seen).replace(/ WAT$/, '')}</span> },
    ];
    return (
        <div className="space-y-5">
            <PageHeader icon={Boxes} title="Asset Inventory" description="Every host, domain and IP found inside authorised scope, and every Wazuh-managed endpoint — one inventory, with each asset's open findings and highest risk."
                actions={<>
                    <Segmented label="View" value={view} onChange={setView} options={[['all', 'All assets'], ['endpoints', 'Managed endpoints (Wazuh)']]} />
                    <Link href="/admin/vms/discovery" className={btn('secondary')}><Plus className="w-3.5 h-3.5" aria-hidden /> Add asset</Link>
                </>} />
            {view === 'endpoints' ? <VmsEndpoints /> : (
                <>
                    <div className="flex flex-wrap items-center gap-2">
                        <Select label="Type" value={type} onChange={setType} options={[['', 'Any type'], ['external', 'Found by scans'], ['endpoint', 'Wazuh endpoints'], ['domain', 'Domains'], ['host', 'Hosts'], ['ip', 'IP addresses']]} />
                        <Select label="Exposure" value={exposure} onChange={setExposure} options={[['', 'Any exposure'], ['internet', 'Internet-facing'], ['internal', 'Internal'], ['unknown', 'Unknown']]} />
                        <Select label="Criticality" value={criticality} onChange={setCriticality} options={[['', 'Any criticality'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']]} />
                        <Segmented label="Status" value={status} onChange={setStatus} options={[['active', 'Active'], ['gone', 'Gone'], ['all', 'All']]} />
                        <SearchBox value={q} onSubmit={setQ} placeholder="Hostname or IP" label="Search assets" />
                        <div className="ml-auto"><ExportCsvButton filename="vms-assets.csv" rows={rows?.map((a) => ({ ...a, open_findings: a.findings?.open ?? 0, max_risk: a.findings?.max_risk ?? '' }))} columns={[{ key: 'value', header: 'Asset' }, { key: 'asset_type', header: 'Type' }, { key: 'exposure', header: 'Exposure' }, { key: 'criticality', header: 'Criticality' }, { key: 'owner', header: 'Owner' }, { key: 'ips', header: 'IPs' }, { key: 'open_findings', header: 'Open findings' }, { key: 'max_risk', header: 'Max risk' }, { key: 'status', header: 'Status' }, { key: 'first_seen', header: 'First seen' }, { key: 'last_seen', header: 'Last seen' }, { key: 'last_assessed_at', header: 'Last assessed' }]} /></div>
                    </div>
                    {load.state === 'error' ? <ErrorState error={load.error} status={load.status} onRetry={reload} />
                        : <DataTable caption="Asset inventory" rows={rows} columns={columns} rowKey={(a) => a.id} onRowClick={(a) => router.push(`/admin/vms/assets/${a.id}`)} initialSort={{ key: 'findings', dir: 'desc' }}
                            empty={<EmptyState icon={Boxes} title={data?.assets.length ? 'No assets match these filters' : 'No assets yet'} body={data?.assets.length ? undefined : 'Add an authorised scope and run discovery, or map Wazuh agent groups to this organisation.'} action={data?.assets.length ? undefined : <Link href="/admin/vms/discovery" className={btn('primary', 'md')}>Go to Asset Discovery</Link>} />} />}
                    {data && data.assets.length >= 1000 && <p className="text-[11px] text-foreground-muted">Showing the 1000 most recently seen assets. Use the filters or search to find others.</p>}
                </>
            )}
        </div>
    );
}

// ── Asset page ─────────────────────────────────────────────────────────────────────────────────
export function VmsAssetPage({ id }: { id: string }) {
    const can = useVmsCan();
    const router = useRouter();
    const { load, data, reload, at } = useVmsData<AssetDetail>(`/api/vms/assets/${id}`);
    const findings = useVmsData<{ findings: Finding[] }>(`/api/vms/findings?status=all&asset_id=${id}`);
    const assessments = useVmsData<{ assessments: VmsAssessment[] }>(`/api/vms/assessments?asset_id=${id}`);
    const [tab, setTab] = useState<'overview' | 'findings' | 'services' | 'assessments' | 'history'>('overview');
    const [msg, setMsg] = useState<Msg>(null);
    const [assess, setAssess] = useState(false);
    const now = at ?? 0;
    if (load.state === 'error') return <div className="space-y-4"><Link href="/admin/vms/assets" className={btn('ghost')}><ArrowLeft className="w-3.5 h-3.5" aria-hidden /> Asset Inventory</Link><ErrorState error={load.error} status={load.status} onRetry={reload} /></div>;
    if (!data) return <div className="space-y-4"><div className="h-16 rounded-2xl bg-card-muted motion-safe:animate-pulse" /><div className="h-64 rounded-2xl bg-card-muted motion-safe:animate-pulse" /></div>;
    const a = data.asset;
    const open = findings.data?.findings.filter((f) => !['verified', 'risk_accepted', 'false_positive'].includes(f.status)) ?? [];
    const bySev = Object.fromEntries(SEV4.map((s) => [s, open.filter((f) => f.scanner_severity === s).length]));
    async function patch(body: Record<string, unknown>) {
        const r = await vmsSend('PATCH', `/api/vms/assets/${a.id}`, body);
        setMsg(r.ok ? { ok: true, text: 'Saved' } : { ok: false, text: r.error });
        if (r.ok) reload();
    }
    const findingCols: Column<Finding>[] = [
        { key: 'priority', header: 'Priority', sort: (f) => f.priority ?? 'P9', render: (f) => <PriorityBadge priority={f.priority} /> },
        { key: 'title', header: 'Finding', className: 'min-w-[220px]', render: (f) => <div><p className="font-semibold text-foreground">{f.title}</p><p className="text-[10.5px] text-foreground-muted">{f.cve_ids.slice(0, 2).join(', ') || f.rule_id}{f.port ? ` · port ${f.port}` : ''}</p></div> },
        { key: 'severity', header: 'Severity', render: (f) => <SeverityBadge severity={f.scanner_severity} /> },
        { key: 'risk', header: 'Risk', sort: (f) => f.risk_score, render: (f) => <RiskScore score={f.risk_score} /> },
        { key: 'status', header: 'Status', sort: (f) => f.status, render: (f) => <span className="text-[11px] font-semibold">{STATUS_LABEL[f.status] ?? f.status}</span> },
    ];
    return (
        <div className="space-y-5">
            <Link href="/admin/vms/assets" className={btn('ghost')}><ArrowLeft className="w-3.5 h-3.5" aria-hidden /> Asset Inventory</Link>
            <PageHeader icon={a.asset_type === 'endpoint' ? Server : Globe} title={a.value}
                description={<>{TYPE_LABEL[a.asset_type] ?? a.asset_type} · {EXPOSURE_LABEL[a.exposure] ?? a.exposure} · first seen {fmtWat(a.first_seen)} · last seen {relTime(a.last_seen, now)} · found by {a.discovery_sources.join(', ') || '—'}{a.status === 'gone' ? ' · no longer seen' : ''}</>}
                actions={can.scan ? <button onClick={() => setAssess(true)} className={btn('primary', 'md')}><Radar className="w-4 h-4" aria-hidden /> Run assessment</button> : undefined} />
            <Notice msg={msg} />
            <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <KpiCard label="Open findings" value={findings.data ? open.length : undefined} reason="Loading" sub={findings.data ? SEV4.filter((s) => bySev[s]).map((s) => `${bySev[s]} ${s}`).join(' · ') || 'None open' : undefined} />
                <KpiCard label="Highest risk" value={open.length ? Math.max(...open.map((f) => f.risk_score ?? 0)) : findings.data ? 0 : undefined} reason="Loading" sub="0–100, open findings" />
                <KpiCard label="Open services" value={data.services.filter((s) => s.status !== 'gone').length} sub={`${data.technologies.length} technologies seen`} />
                <KpiCard label="Assessments" value={assessments.data?.assessments.length} reason="Loading" sub={a.last_assessed_at ? `last ${relTime(a.last_assessed_at, now)}` : 'Never assessed'} />
            </section>
            <Segmented label="Asset sections" value={tab} onChange={setTab} options={[['overview', 'Overview'], ['findings', `Findings (${findings.data?.findings.length ?? '…'})`], ['services', `Services (${data.services.length})`], ['assessments', 'Assessments'], ['history', 'History']]} />

            {tab === 'overview' && (
                <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                    <Card className="xl:col-span-2 space-y-4">
                        <SectionTitle title="Details" />
                        <dl className="grid grid-cols-2 md:grid-cols-3 gap-x-4 gap-y-3 text-xs">
                            <D k="IP addresses" v={<span className="font-mono">{a.ips.join(', ') || '—'}</span>} />
                            <D k="Hostnames" v={<span className="font-mono">{a.hostnames.join(', ') || '—'}</span>} />
                            <D k="CNAME" v={<span className="font-mono">{a.dns?.cname?.join(', ') || '—'}</span>} />
                            <D k="Web" v={a.http ? `${a.http.status ?? '—'} · ${a.http.title ?? 'no title'} · ${a.http.webserver ?? 'server unknown'}${a.http.cdn ? ` · CDN ${a.http.cdn}` : ''}` : 'No web service seen'} />
                            {a.asset_type === 'endpoint' && <D k="Wazuh agent" v={`${a.wazuh_agent_id ?? '—'} · ${a.os ?? 'OS not reported'} · ${a.agent_status ?? 'status unknown'}`} />}
                            {a.asset_type === 'endpoint' && <D k="Scan eligibility" v={a.scan_eligibility ? `${ELIGIBILITY_LABEL[a.scan_eligibility.status]} — ${a.scan_eligibility.reason}` : 'Not evaluated yet'} />}
                            {a.next_scan_at !== undefined && <D k="Next automatic assessment" v={a.next_scan_at ? fmtWat(a.next_scan_at) : 'Not planned by an enabled policy'} />}
                        </dl>
                        <div className="flex flex-wrap gap-4 items-end pt-1">
                            <label className="text-[11px] font-semibold text-foreground-muted">Owner
                                {can.manage ? <input key={`${a.id}-${a.owner}`} defaultValue={a.owner ?? ''} maxLength={200} placeholder="team or person" onBlur={(e) => { const v = e.target.value.trim(); if (v !== (a.owner ?? '')) void patch({ owner: v || null }); }} className="block mt-1 bg-card border border-border rounded-lg px-2 py-1.5 text-xs text-foreground" /> : <span className="block mt-1 text-xs text-foreground">{a.owner ?? '—'}</span>}
                            </label>
                            <label className="text-[11px] font-semibold text-foreground-muted">Business criticality
                                {can.manage ? <select value={a.criticality} onChange={(e) => void patch({ criticality: e.target.value })} className="block mt-1 bg-card border border-border rounded-lg px-2 py-1.5 text-xs text-foreground">{['low', 'medium', 'high', 'critical'].map((c) => <option key={c} value={c}>{c}</option>)}</select> : <span className="block mt-1 text-xs text-foreground capitalize">{a.criticality}</span>}
                            </label>
                            <p className="text-[11px] text-foreground-muted max-w-xs">Criticality feeds the risk score (10%) of this asset&apos;s findings.</p>
                        </div>
                        {a.last_assessment && (
                            <div className="border border-border rounded-xl p-3 space-y-1">
                                <p className="text-[11px] font-semibold text-foreground-muted">Last reachability check · {a.last_assessment.method} · {fmtWat(a.last_assessed_at ?? null)}</p>
                                <StatusPill tone={/^reachable/.test(a.last_assessment.outcome) ? 'good' : 'warning'} label={OUTCOME_LABEL[a.last_assessment.outcome] ?? a.last_assessment.outcome} />
                                <p className="text-xs text-foreground">{a.last_assessment.reason}</p>
                                {a.last_assessment.ports_scanned ? <p className="text-[11px] text-foreground-muted">{a.last_assessment.ports_scanned} port(s) scanned: {portStates(a.last_assessment.port_states)}</p> : null}
                            </div>
                        )}
                        {(data.linked ?? []).length > 0 && (
                            <div><p className="text-[11px] font-semibold text-foreground-muted mb-1">Linked records</p>
                                {data.linked!.map((l) => <p key={l.id} className="text-xs"><Link href={`/admin/vms/assets/${l.id}`} className="font-mono font-semibold text-purple dark:text-[var(--vz-prog-4)]">{l.value}</Link> <span className="text-foreground-muted">({l.asset_type === 'endpoint' ? 'Wazuh endpoint' : 'scanned address'} · {l.relation})</span></p>)}
                            </div>
                        )}
                    </Card>
                    <Card>
                        <SectionTitle title="Open findings by severity" />
                        <BarList label="Open findings by severity" items={SEV4.map((s) => ({ key: s, label: SEVERITY_META[s].label, value: bySev[s], token: `--vz-sev-${s}` as const, href: `/admin/vms/findings?asset_id=${a.id}` }))} />
                        <Link href={`/admin/vms/findings?asset_id=${a.id}`} className="block mt-3 text-[11px] font-semibold text-purple dark:text-[var(--vz-prog-4)]">Open in Vulnerability Findings →</Link>
                    </Card>
                    <Card className="xl:col-span-2"><SectionTitle title="Attack-surface map" hint="Relationships from stored records, each labelled confirmed, observed or inferred." /><AttackSurfaceMap assetId={a.id} onOpenAsset={(x) => router.push(`/admin/vms/assets/${x}`)} /></Card>
                    <div><AiPanel key={a.id} purpose="asset_assessment" subjectId={a.id} title="AI exposure assessment (draft — review before acting)" /></div>
                </div>
            )}
            {tab === 'findings' && findings.load.state === 'error' && <ErrorState error={findings.load.error} status={findings.load.status} onRetry={findings.reload} />}
            {tab === 'findings' && findings.load.state !== 'error' && <DataTable caption="Findings on this asset" rows={findings.data?.findings ?? null} columns={findingCols} rowKey={(f) => f.id} onRowClick={(f) => router.push(`/admin/vms/findings?id=${f.id}&asset_id=${a.id}`)} initialSort={{ key: 'risk', dir: 'desc' }} empty="No findings recorded on this asset" />}
            {tab === 'services' && (
                <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                    <div className="xl:col-span-2"><DataTable caption="Services" rows={data.services} rowKey={(s) => s.id} initialSort={{ key: 'port', dir: 'asc' }} empty="No services recorded (port scans need port-scan authorisation)" columns={[
                        { key: 'port', header: 'Port', sort: (s) => s.port, render: (s) => <span className="font-mono">{s.port}/{s.protocol}</span> },
                        { key: 'service', header: 'Service', render: (s) => s.service ?? '—' },
                        { key: 'product', header: 'Product', render: (s) => [s.product, s.version].filter(Boolean).join(' ') || '—' },
                        { key: 'status', header: 'State', render: (s) => <StatusPill tone={s.status === 'gone' ? 'neutral' : 'good'} label={s.status === 'gone' ? 'No longer open' : 'Open'} /> },
                        { key: 'seen', header: 'Last seen', hideBelow: 'md', render: (s) => <span className="text-[11px] text-foreground-muted">{fmtWat(s.last_seen)}</span> },
                    ]} /></div>
                    <Card><SectionTitle title="Technologies" />{data.technologies.length ? <ul className="space-y-1.5">{data.technologies.map((t) => <li key={t.id} className="text-xs flex justify-between gap-2"><span className="text-foreground">{t.name}{t.version ? ` ${t.version}` : ''}</span><span className="text-foreground-muted text-[10.5px]">{t.source}</span></li>)}</ul> : <p className="text-xs text-foreground-muted">None detected.</p>}</Card>
                </div>
            )}
            {tab === 'assessments' && <DataTable caption="Assessments of this asset" rows={assessments.data?.assessments ?? null} rowKey={(x) => x.id} onRowClick={(x) => router.push(`/admin/vms/scans?id=${x.id}`)} empty="Not assessed yet" columns={[
                { key: 'when', header: 'Requested', render: (x) => fmtWat(x.requested_at) },
                { key: 'profile', header: 'Profile', render: (x) => PROFILE_LABEL[x.profile] ?? x.profile },
                { key: 'status', header: 'Status', render: (x) => <span className="font-semibold">{ASSESSMENT_STATUS_LABEL[x.status]} · {x.progress.finished}/{x.progress.total}</span> },
                { key: 'by', header: 'By', hideBelow: 'md', render: (x) => <span className="text-[11px] text-foreground-muted">{x.requested_by}</span> },
            ]} />}
            {tab === 'history' && <Card><SectionTitle title="Change history" hint="What scans and Wazuh observed changing on this asset." /><Timeline empty="No changes recorded." items={data.events.slice(0, 60).map((e) => ({ id: e.id, at: e.at, title: EVENT_LABEL[e.event] ?? e.event, meta: fmtWat(e.at), body: describeEvent(e) || null, tone: e.event.endsWith('_gone') ? 'neutral' : e.event.endsWith('_new') ? 'warning' : undefined }))} /></Card>}

            <ConfirmDialog open={assess} title="Run an assessment of this asset?" body={<>Plans the <b>Full Assessment</b> checks for <span className="font-mono">{a.value}</span> that its authorised scope allows and a connected worker can run. Checks that cannot run are recorded as not attempted, with the reason.</>}
                confirmLabel="Start assessment" onCancel={() => setAssess(false)}
                onConfirm={async () => { setAssess(false); const r = await vmsSend<{ existing: boolean; assessment: { id: string } }>('POST', '/api/vms/assessments', { asset_id: a.id }); setMsg(r.ok ? { ok: true, text: r.data.existing ? 'An assessment of this asset is already in progress.' : 'Assessment planned — follow it in Scan Management.' } : { ok: false, text: r.error }); assessments.reload(); }} />
        </div>
    );
}
function D({ k, v }: { k: string; v: React.ReactNode }) {
    return <div className="min-w-0"><dt className="text-[10px] font-semibold uppercase tracking-wide text-foreground-muted">{k}</dt><dd className="text-xs text-foreground mt-0.5 break-words">{v}</dd></div>;
}

// ── Asset Discovery ────────────────────────────────────────────────────────────────────────────
export function VmsDiscovery() {
    const router = useRouter();
    const scans = useVmsData<{ scans: VmsScan[] }>('/api/vms/scans?limit=300');
    const events = useVmsData<{ events: VmsEvent[] }>('/api/vms/events?days=30');
    const [tab, setTab] = useState<'scope' | 'jobs' | 'new'>('scope');
    const now = scans.at ?? 0;
    const jobs = useMemo(() => scans.data?.scans.filter((s) => s.kind === 'discovery' || (s.kind as string) === 'passive_osint') ?? null, [scans.data]);
    const found = useMemo(() => events.data?.events.filter((e) => e.event === 'asset_new') ?? null, [events.data]);
    return (
        <div className="space-y-5">
            <PageHeader icon={Radar} title="Asset Discovery" description="Assets enter the inventory in two ways: discovery scans inside an authorised scope (subdomains, DNS, HTTP), and Wazuh agents of the organisation's mapped groups. Nothing outside authorised scope is ever scanned."
                actions={<Link href="/admin/vms/scans" className={btn('primary', 'md')}><Radar className="w-4 h-4" aria-hidden /> Run discovery</Link>} />
            <section className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <Step n={1} title="Authorise the scope" body="A manager records the domains, IPs or networks the organisation authorised, with the agreement reference, exclusions and what may run (discovery, port scans, vulnerability scans)." />
                <Step n={2} title="Run discovery" body="Discovery finds subdomains, resolves DNS and probes HTTP inside that scope. Each new host becomes an asset with its source." />
                <Step n={3} title="Review and classify" body="Set an owner and business criticality on each asset — criticality feeds the risk score of its findings." />
            </section>
            <Segmented label="Discovery sections" value={tab} onChange={setTab} options={[['scope', 'Authorised scope'], ['jobs', `Discovery jobs${jobs ? ` (${jobs.length})` : ''}`], ['new', `Newly discovered (30 days)${found ? ` (${found.length})` : ''}`]]} />
            {tab === 'scope' && <VmsScope />}
            {tab === 'jobs' && (scans.load.state === 'error' ? <ErrorState error={scans.load.error} status={scans.load.status} onRetry={scans.reload} />
                : <DataTable caption="Discovery jobs" rows={jobs} rowKey={(s) => s.id} initialSort={{ key: 'when', dir: 'desc' }} onRowClick={(s) => router.push(`/admin/vms/scans/history?scan=${s.id}`)}
                    empty={<EmptyState title="No discovery jobs yet" body="Run discovery from Scan Management once a scope is authorised." />} columns={[
                        { key: 'when', header: 'Requested', sort: (s) => s.requested_at, render: (s) => <span className="text-[11px] whitespace-nowrap">{fmtWat(s.requested_at)}</span> },
                        { key: 'kind', header: 'Type', render: (s) => <span className="text-[11px]">{(s.kind as string) === 'passive_osint' ? 'Passive (third-party sources, no traffic to the target)' : SCAN_KIND_LABEL[s.kind]}</span> },
                        { key: 'targets', header: 'Scope', render: (s) => <span className="text-[11px] font-mono">{s.targets.join(', ')}</span> },
                        { key: 'result', header: 'Result', render: (s) => <ScanResult s={s} /> },
                        { key: 'summary', header: 'Found', hideBelow: 'md', render: (s) => <span className="text-[11px] text-foreground-muted">{s.summary ? Object.entries(s.summary).filter(([k, v]) => typeof v === 'number' && k !== 'outcome').map(([k, v]) => `${String(v)} ${k.replace(/_/g, ' ')}`).slice(0, 3).join(' · ') || '—' : '—'}</span> },
                    ]} />)}
            {tab === 'new' && (events.load.state === 'error' ? <ErrorState error={events.load.error} status={events.load.status} onRetry={events.reload} />
                : <DataTable caption="Newly discovered assets" rows={found} rowKey={(e) => e.id} onRowClick={(e) => { if (e.asset_id) router.push(`/admin/vms/assets/${e.asset_id}`); }} empty="No new assets in the last 30 days" columns={[
                    { key: 'at', header: 'Discovered', sort: (e) => e.at, render: (e) => <span className="text-[11px] whitespace-nowrap">{relTime(e.at, now)}</span> },
                    { key: 'asset', header: 'Asset', render: (e) => <span className="font-mono font-semibold">{e.vms_assets?.value ?? String(e.details?.value ?? '—')}</span> },
                    { key: 'type', header: 'Type', render: (e) => <span className="text-[11px]">{TYPE_LABEL[e.vms_assets?.asset_type ?? ''] ?? e.vms_assets?.asset_type ?? '—'}</span> },
                    { key: 'source', header: 'Source', hideBelow: 'md', render: (e) => <span className="text-[11px] text-foreground-muted">{String(e.details?.source ?? e.details?.discovery_source ?? '—')}</span> },
                ]} />)}
        </div>
    );
}
function Step({ n, title, body }: { n: number; title: string; body: string }) {
    return <Card><div className="flex gap-3"><span className="w-7 h-7 shrink-0 rounded-full bg-purple text-white text-xs font-black flex items-center justify-center">{n}</span><div><p className="text-xs font-bold text-foreground">{title}</p><p className="text-[11px] text-foreground-muted mt-1 leading-relaxed">{body}</p></div></div></Card>;
}

// ── Attack Surface ─────────────────────────────────────────────────────────────────────────────
interface Svc { id: string; port: number; protocol: string; service: string | null; product: string | null; version: string | null; asset: { id: string; value: string; exposure: string } | null; open_findings: { count: number } }
export function VmsAttackSurface() {
    const router = useRouter();
    const ov = useVmsData<Overview>('/api/vms/overview');
    const assets = useVmsData<{ assets: Asset[] }>('/api/vms/assets?status=active&exposure=internet');
    const all = useVmsData<{ assets: Asset[] }>('/api/vms/assets?status=active');
    const svc = useVmsData<{ services: Svc[] }>('/api/vms/services');
    const events = useVmsData<{ events: VmsEvent[] }>('/api/vms/events?days=7');
    const loading = !ov.data && ov.load.state === 'loading';
    const extSvc = useMemo(() => svc.data?.services.filter((s) => s.asset?.exposure === 'internet') ?? null, [svc.data]);
    const topPorts = useMemo(() => {
        const m = new Map<string, number>();
        for (const s of extSvc ?? []) { const k = `${s.port}/${s.protocol}${s.service ? ` ${s.service}` : ''}`; m.set(k, (m.get(k) ?? 0) + 1); }
        return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
    }, [extSvc]);
    const exposureCounts = useMemo(() => { const m: Record<string, number> = {}; for (const a of all.data?.assets ?? []) m[a.exposure] = (m[a.exposure] ?? 0) + 1; return m; }, [all.data]);
    const ext = assets.data?.assets ?? null;
    const withFindings = ext?.filter((a) => a.findings?.open).length;
    return (
        <div className="space-y-5">
            <PageHeader icon={Globe} title="Attack Surface" description="What the organisation exposes to the internet: internet-facing assets, the services they answer on, their open findings, and what changed this week. Exposure comes from what scans observed." />
            {ov.load.state === 'error' && <ErrorState error={ov.load.error} status={ov.load.status} onRetry={ov.reload} />}
            <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <KpiCard label="Internet-facing assets" value={ov.data?.assets.internet_facing} reason="Loading" icon={Globe} sub={ov.data ? `of ${nf.format(ov.data.assets.active)} active assets` : undefined} />
                <KpiCard label="Exposed services" value={extSvc?.length} reason="Loading" sub="Open ports on internet-facing assets" />
                <KpiCard label="Exposed assets with open findings" value={withFindings} reason="Loading" tone={withFindings ? 'serious' : undefined} />
                <KpiCard label="Changes this week" value={ov.data ? ov.data.last_7_days.new_assets + ov.data.last_7_days.changed_assets + ov.data.last_7_days.gone_assets + ov.data.last_7_days.new_services : undefined} reason="Loading" href="/admin/vms/monitoring/changes"
                    sub={ov.data ? `${ov.data.last_7_days.new_assets} new · ${ov.data.last_7_days.new_services} new services · ${ov.data.last_7_days.gone_assets} gone` : undefined} />
            </section>
            <section className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                <ChartCard title="Assets by exposure" hint="Active assets." loading={loading || !all.data} empty={all.data && !all.data.assets.length ? { title: 'No assets yet' } : null}>
                    <Donut label="Assets by exposure" centerLabel="assets" slices={[['internet', 'Internet-facing', '--vz-sev-high'], ['internal', 'Internal', '--vz-prog-2'], ['unknown', 'Unknown', '--vz-neutral']].map(([k, l, t]) => ({ key: k, label: l, value: exposureCounts[k] ?? 0, token: t as '--vz-neutral', href: `/admin/vms/assets?exposure=${k}` }))} />
                </ChartCard>
                <ChartCard title="Most exposed services" hint="Ports open on internet-facing assets, by how many assets expose them." loading={!svc.data && svc.load.state === 'loading'} empty={extSvc && !extSvc.length ? { title: 'No exposed services recorded', body: 'Port scans need port-scan authorisation in the scope.' } : null}>
                    <BarList label="Most exposed services" items={topPorts.map(([k, n]) => ({ key: k, label: <span className="font-mono">{k}</span>, value: n, token: '--vz-cat-1' }))} />
                </ChartCard>
                <Card>
                    <SectionTitle title="This week" hint="Changes observed in the last 7 days." action={<Link href="/admin/vms/monitoring/changes" className="text-[11px] font-semibold text-purple dark:text-[var(--vz-prog-4)]">All changes →</Link>} />
                    {events.data && events.data.events.length === 0 ? <EmptyState compact title="No changes this week" /> : (
                        <ul className="space-y-2">
                            {(events.data?.events ?? []).slice(0, 8).map((e) => <li key={e.id} className="text-xs"><span className="font-semibold text-foreground">{EVENT_LABEL[e.event] ?? e.event}</span> · <span className="font-mono">{e.vms_assets?.value ?? '—'}</span> <span className="text-foreground-muted">{describeEvent(e)}</span></li>)}
                        </ul>
                    )}
                </Card>
            </section>
            <Card>
                <SectionTitle title="Internet-facing assets" hint="Ranked by open findings; open one for services, history and its attack-surface map." />
                <div className="-mx-5 -mb-5 [&>div]:rounded-none [&>div]:border-x-0 [&>div]:border-b-0">
                    {assets.load.state === 'error' ? <div className="p-5"><ErrorState error={assets.load.error} status={assets.load.status} onRetry={assets.reload} /></div>
                        : <DataTable caption="Internet-facing assets" rows={ext} rowKey={(a) => a.id} onRowClick={(a) => router.push(`/admin/vms/assets/${a.id}`)} initialSort={{ key: 'findings', dir: 'desc' }} pageSize={15}
                            empty={<EmptyState icon={ShieldCheck} title="No internet-facing assets recorded" body="Exposure is set when a scan observes an asset answering from the internet." />} columns={[
                                { key: 'value', header: 'Asset', render: (a) => <span className="font-mono font-semibold">{a.value}</span>, sort: (a) => a.value },
                                { key: 'web', header: 'Web', hideBelow: 'md', render: (a) => <span className="text-[11px] text-foreground-muted">{a.http ? `${a.http.status ?? '—'} · ${a.http.webserver ?? 'server unknown'}` : '—'}</span> },
                                { key: 'services', header: 'Services', sort: (a) => extSvc?.filter((s) => s.asset?.id === a.id).length ?? 0, render: (a) => <span className="text-[11px] font-mono">{extSvc?.filter((s) => s.asset?.id === a.id).map((s) => s.port).slice(0, 6).join(', ') || '—'}</span> },
                                { key: 'findings', header: 'Open findings', sort: (a) => a.findings?.open ?? 0, render: (a) => a.findings?.open ? <div className="flex items-center gap-2"><span className="font-bold tabular-nums w-6 text-right">{a.findings.open}</span><SevBar by={a.findings.by_severity} /></div> : <span className="text-[11px] text-foreground-muted">None</span> },
                                { key: 'risk', header: 'Max risk', sort: (a) => a.findings?.max_risk ?? -1, render: (a) => <RiskScore score={a.findings?.max_risk} /> },
                                { key: 'crit', header: 'Criticality', hideBelow: 'lg', render: (a) => <span className="text-[11px] capitalize">{a.criticality}</span> },
                            ]} />}
                </div>
            </Card>
        </div>
    );
}
