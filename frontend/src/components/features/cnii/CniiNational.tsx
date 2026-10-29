'use client';

// CNII Watch — national critical-infrastructure intelligence (phase P23):
//   Overview → Sector → Organisation → Asset → Finding.
// Every figure comes from GET /api/cnii/national (read-only). An organisation is CNII only through
// its recorded CNII profile; its assets and findings are its own VMS records. The backend counts
// only organisations the caller may view. "Infrastructure risk" is the mean NovrSOC contextual
// risk score, defined on screen — never an average of CVSS, which is shown separately.

import { useMemo, useState, type ReactNode } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { ShieldAlert, ChevronRight, Building2, Server, Globe, Radar, Info } from 'lucide-react';
import { fmtWat } from '@/lib/vms';
import { CNII_SECTORS, SECTOR_BY_ID } from '@/lib/cnii-sectors';
import { Card, SectionTitle, StatusPill, Tip, type Tone } from '../vms/ui';
import { PageHeader, KpiCard, SeverityBadge, PriorityBadge, RiskScore, Tag, Toggle, SearchBox, Select, ErrorState, EmptyState, relTime, nf, SEVERITY_META, SEVERITY_KEYS, riskColor } from '../vms/kit';
import { ChartCard, Donut, BarList, TimeChart, Legend, type Series } from '../vms/charts';
import { DataTable, type Column } from '../vms/table';
import { useVmsData } from '../vms/data';

export type Sev = Record<string, number>;
export type Risk = { mean: number | null; max: number | null; scored: number };
// R3.3B Stage 2: the five real monitoring states (lib/cniiCoverage.ts on the backend) — never
// collapsed back down to a binary "monitored"/"not monitored" pill in this file.
export type CoverageState = 'connected_fresh' | 'connected_stale' | 'configured_not_receiving' | 'not_connected' | 'unknown';
type CoverageTally = Record<CoverageState, number>;
export interface TiSum { total: number; verified: number; contextual: number }
interface OrgSum {
    slug: string; name: string; sector?: string; subfield: string | null; designation: string;
    assets: number; internet_facing: number; open_findings: number; open_vulnerabilities: number; severity: Sev; priority: Sev; critical_high: number; kev_open: number;
    risk: Risk; assets_requiring_attention: number; monitoring: { active_scopes: number; assets_assessed_30d: number; last_collection: { at: string; status: string } | null };
    coverage_state: CoverageState; threat_intelligence: TiSum;
}
interface TopAsset { asset_id: string; org_id: string; organisation: string; value: string; open: number; severity: Sev; max_risk: number; kev: number; asset_type: string | null; exposure: string | null; criticality: string | null }
interface National {
    visibility: { mode: 'all' | 'assigned'; organisations: number; designated_only: boolean };
    definitions: Record<string, string>;
    kpis: { sectors_configured: number; sectors_monitored: number; organisations: number; designated: number; assets: number; open_vulnerabilities: number; critical: number; high: number; kev_open: number; risk: Risk; assets_requiring_attention: number; coverage: { organisations_scoped: number; organisations: number; pct: number | null; by_state: CoverageTally } };
    severity: Sev; priority: Sev; sources: Sev;
    trend: { day: string; open_total: number; kev_open: number; internet_open: number; organisations: number }[];
    sectors: { id: string; organisations: number; designated: number; candidates: number; assets: number; open_vulnerabilities: number; critical_high: number; severity: Sev; priority: Sev; risk: Risk; coverage: { by_state: CoverageTally; total: number; connected_pct: number | null }; threat_intelligence: TiSum }[];
    organisations: OrgSum[];
    top_assets: TopAsset[];
}
interface SectorData {
    sector: string; visibility: { mode: string; organisations: number }; definitions: Record<string, string>;
    kpis: { organisations: number; designated: number; assets: number; internet_facing: number; open_vulnerabilities: number; kev_open: number; risk: Risk; assets_requiring_attention: number; coverage: { organisations_scoped: number; assets_assessed_30d: number; by_state: CoverageTally } };
    severity: Sev; priority: Sev; sources: Sev; organisations: OrgSum[]; top_assets: TopAsset[];
}
export interface OrgData {
    organisation: { slug: string; name: string; sector: string; subfield: string | null; designation: string; designation_reference: string | null; profile_updated_at: string | null };
    definitions: Record<string, string>;
    summary: Omit<OrgSum, 'slug' | 'name' | 'subfield' | 'designation'>;
    monitoring: { active_scopes: number; last_scan: { kind: string; status: string; finished_at: string } | null };
    remediation: { findings_open_by_status: Sev; findings_closed_by_status: Sev; tasks_by_status: Sev };
    sources: Sev;
    cves: { cve_id: string; kev: boolean; findings: number }[];
    assets: { id: string; value: string; asset_type: string; exposure: string; criticality: string; last_seen: string; last_assessed_at: string | null; findings: { open: number; severity: Sev; max_risk: number | null }; threat_intelligence: TiSum }[];
    findings: { id: string; asset_id: string | null; asset_value: string; port: number | null; title: string; rule_id: string; cve_ids: string[]; scanner_cvss: number | null; risk_score: number | null; priority: string | null; severity: string; status: string; detected_by: string[]; kev: boolean; first_seen: string; last_seen: string; due_at: string | null; evidence_class: string | null }[];
    trend: { day: string; open_total: number; kev_open: number; internet_open: number; risk_mean: number | null; critical_exposures: number }[];
}
interface AssetData {
    organisation: { slug: string; name: string; sector: string; designation: string };
    asset: { id: string; value: string; asset_type: string; exposure: string; criticality: string; hostnames: string[]; ips: string[]; discovery_sources: string[]; first_seen: string; last_seen: string; last_assessed_at: string | null; last_assessment: { outcome?: string; reason?: string } | null };
    findings: {
        id: string; title: string; rule_id: string; port: number | null; status: string; severity: string; priority: string | null; risk_score: number | null;
        cvss: { score: number | null; version: string | null; vector: string | null }; cves: { cve_id: string; kev: boolean; epss: number | null }[];
        detected_by: string[]; evidence_class: string | null; first_seen: string; last_seen: string; verified_at: string | null; due_at: string | null;
        remediation: string | null; description: string | null;
        evidence: { detections: number; last_observed_at: string | null; sources: string[]; locations: string[] };
        history: { at: string; action: string; from: string | null; to: string | null }[];
        tasks: { title: string; status: string; due_at: string | null }[];
    }[];
    // R3.3B Stage 4: each row keeps its own verified-vs-contextual verdict and TLP — never folded
    // into a single "threat matches" count, and never presented as proof of an attack on its own.
    threat_intelligence: { indicator_type: string | null; indicator_value: string | null; confidence: number | null; malware_families: string[]; threat_types: string[]; verified: boolean; status: string; case_id: string | null; tlp: string }[];
}

const SEV_TOKENS = { critical: '--vz-sev-critical', high: '--vz-sev-high', medium: '--vz-sev-medium', low: '--vz-sev-low', info: '--vz-sev-info' } as const;
const PRIO_SERIES: Series[] = [{ key: 'P1', label: 'P1', token: '--vz-sev-critical' }, { key: 'P2', label: 'P2', token: '--vz-sev-high' }, { key: 'P3', label: 'P3', token: '--vz-sev-medium' }, { key: 'P4', label: 'P4', token: '--vz-sev-low' }];
const STATUS_TEXT: Record<string, string> = { open: 'Open', reopened: 'Reopened', acknowledged: 'Triaged', in_progress: 'In progress', fixed_pending_verification: 'Awaiting verification', verified: 'Verified fixed', risk_accepted: 'Risk accepted', false_positive: 'False positive' };
const SOURCE_LABEL: Record<string, string> = { nuclei: 'Vulnerability Scanning Engine', openvas: 'Extended Vulnerability Scanning', wazuh: 'Monitoring agent', unknown: 'Not recorded' };
const sectorLabel = (id: string) => SECTOR_BY_ID[id]?.label ?? id;
const designationTag = (d: string) => d === 'designated' ? <StatusPill tone="good" label="Designated CNII" /> : <StatusPill tone="warning" label="Candidate — not yet designated" />;

// R3.3B Stage 2: five real states, not a binary "has a scope" pill — a scope with no recorded
// collection, or one that stopped reporting, must never read the same as fresh telemetry.
const COVERAGE_TONE: Record<CoverageState, Tone> = { connected_fresh: 'good', connected_stale: 'warning', configured_not_receiving: 'warning', not_connected: 'critical', unknown: 'neutral' };
// CNII Watch has no continuous endpoint agent of its own: "connected" means a recent authorised
// *passive collection* (a point-in-time external scan), never continuous Wazuh/EDR telemetry.
const COVERAGE_LABEL: Record<CoverageState, string> = { connected_fresh: 'Recent authorised passive collection', connected_stale: 'Passive collection has run, but not recently', configured_not_receiving: 'Authorised, but no passive collection has run yet', not_connected: 'No active authorised scope — not connected', unknown: 'Monitoring status unknown' };
function CoverageBadge({ state, detail }: { state: CoverageState; detail?: string }) {
    return <StatusPill tone={COVERAGE_TONE[state]} label={detail ? `${COVERAGE_LABEL[state]} · ${detail}` : COVERAGE_LABEL[state]} />;
}
function ThreatIntelSummary({ ti }: { ti: TiSum }) {
    if (ti.total === 0) return <span className="text-[11px] text-foreground-muted">No indicator matches</span>;
    return <span className="text-[11px]"><b className="tabular-nums">{ti.total}</b> indicator match{ti.total === 1 ? '' : 'es'}{ti.verified > 0 ? <> · <span className="font-semibold" style={{ color: 'var(--vz-sev-critical)' }}>{ti.verified} verified</span></> : ''}{ti.contextual > 0 ? ` · ${ti.contextual} contextual` : ''}</span>;
}

function Crumbs({ items }: { items: { label: string; href?: string }[] }) {
    return (
        <nav aria-label="Breadcrumb" className="flex flex-wrap items-center gap-1 text-[11px] text-foreground-muted">
            {items.map((c, i) => (
                <span key={i} className="inline-flex items-center gap-1">
                    {i > 0 && <ChevronRight className="w-3 h-3" aria-hidden />}
                    {c.href ? <Link href={c.href} className="hover:text-foreground hover:underline">{c.label}</Link> : <span className="font-semibold text-foreground">{c.label}</span>}
                </span>
            ))}
        </nav>
    );
}
function RiskKpi({ risk, definition, href }: { risk: Risk | undefined; definition?: string; href?: string }) {
    return <KpiCard label="Infrastructure risk (contextual)" value={risk ? (risk.mean === null ? null : Math.round(risk.mean)) : undefined} reason={risk ? 'No open scored findings' : 'Loading'} hint={definition} href={href}
        sub={risk && risk.mean !== null ? <>Mean NovrSOC risk of {nf.format(risk.scored)} open finding(s) · highest {risk.max} <Tip label={definition ?? ''}><Info className="inline w-3 h-3" aria-label="How this is calculated" tabIndex={0} /></Tip></> : 'NovrSOC risk score, 0–100 — not CVSS'} />;
}
function Note({ children }: { children: ReactNode }) {
    return <p className="flex items-start gap-1.5 text-[11px] text-foreground-muted"><Info className="w-3.5 h-3.5 mt-px shrink-0" aria-hidden /><span>{children}</span></p>;
}
const sevSlices = (s: Sev, href?: (k: string) => string) => SEVERITY_KEYS.map((k) => ({ key: k, label: SEVERITY_META[k].label, value: s[k] ?? 0, token: SEV_TOKENS[k], href: href?.(k) }));
const sourceItems = (s: Sev) => Object.entries(s).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ key: k, label: SOURCE_LABEL[k] ?? k, value: v, token: '--vz-cat-1' as const }));

// ── National overview ─────────────────────────────────────────────────────────────────────────
export function CniiNationalOverview() {
    const [designatedOnly, setDesignatedOnly] = useState(false);
    const { load, data: d, reload } = useVmsData<National>(`/api/cnii/national${designatedOnly ? '?designated=1' : ''}`);
    const [q, setQ] = useState('');
    const loading = load.state === 'loading' && !d;
    const k = d?.kpis;
    const sectors = useMemo(() => {
        if (!d) return null;
        const byId = new Map(d.sectors.map((s) => [s.id, s]));
        return CNII_SECTORS.map((meta) => ({ meta, s: byId.get(meta.id)! })).filter(({ meta }) => !q || meta.label.toLowerCase().includes(q.toLowerCase()))
            .sort((a, b) => (b.s.risk.mean ?? -1) - (a.s.risk.mean ?? -1) || b.s.organisations - a.s.organisations);
    }, [d, q]);
    return (
        <div className="space-y-5">
            <Crumbs items={[{ label: 'CNII Watch' }, { label: 'National overview' }]} />
            <PageHeader icon={Radar} title="CNII national overview"
                description="Critical national information infrastructure by sector, from the organisations NovrSOC monitors and their own vulnerability records. Nothing here is estimated: a sector without monitored organisations says so."
                actions={<><Toggle on={designatedOnly} onChange={setDesignatedOnly}>Designated only</Toggle><Link href="/admin/cnii/manage" className="text-[11px] font-semibold text-purple dark:text-[var(--vz-prog-4)] px-2">Classification & intake →</Link></>} />
            {load.state === 'error' && <ErrorState error={load.error} status={load.status} onRetry={reload} />}
            {d && <Note>{d.definitions.organisations} {d.visibility.mode === 'assigned' ? 'You see the organisations you are assigned to.' : 'You see every profiled organisation.'}</Note>}
            {(d || loading) && <>
                <section className="grid grid-cols-2 md:grid-cols-4 gap-3" aria-label="National figures">
                    <KpiCard label="Monitored sectors" value={k?.sectors_monitored} suffix={k ? ` / ${k.sectors_configured}` : ''} reason="Loading" icon={Radar} sub="Sectors with at least one profiled organisation" />
                    <KpiCard label="Monitored organisations" value={k?.organisations} reason="Loading" icon={Building2} sub={k ? `${k.designated} designated · ${k.organisations - k.designated} candidate` : undefined} />
                    <KpiCard label="Monitored assets" value={k?.assets} reason="Loading" icon={Server} sub="Active assets of those organisations" />
                    <KpiCard label="Active vulnerabilities" value={k?.open_vulnerabilities} reason="Loading" icon={ShieldAlert} sub="Open, informational excluded" />
                    <KpiCard label="Critical & high" value={k ? k.critical + k.high : undefined} reason="Loading" tone={k && k.critical + k.high ? 'critical' : k ? 'good' : undefined} sub={k ? `${k.critical} critical · ${k.high} high${k.kev_open ? ` · ${k.kev_open} known exploited` : ''}` : undefined} />
                    <RiskKpi risk={k?.risk} definition={d?.definitions.infrastructure_risk} />
                    <KpiCard label="Assets requiring attention" value={k?.assets_requiring_attention} reason="Loading" tone={k?.assets_requiring_attention ? 'warning' : k ? 'good' : undefined} hint={d?.definitions.assets_requiring_attention} sub="Critical/high, P1/P2 or known-exploited findings" />
                    <KpiCard label="Monitoring coverage" value={k ? k.coverage.pct : undefined} suffix="%" reason={k ? 'No organisations' : 'Loading'} hint={d?.definitions.monitoring_coverage}
                        sub={k ? <>{k.coverage.organisations_scoped} of {k.coverage.organisations} receiving telemetry{k.coverage.by_state.connected_stale ? ` · ${k.coverage.by_state.connected_stale} stale` : ''}{k.coverage.by_state.configured_not_receiving ? ` · ${k.coverage.by_state.configured_not_receiving} never collected` : ''}</> : undefined} />
                </section>

                <section className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                    <ChartCard title="Vulnerabilities by severity" hint="Scanner (CVSS) severity of open findings." loading={loading} empty={d && !Object.values(d.severity).some(Boolean) ? { title: 'No open findings in monitored infrastructure' } : null}>
                        {d && <Donut label="Open findings by severity" centerLabel="open" slices={sevSlices(d.severity)} />}
                    </ChartCard>
                    <ChartCard title="Top sectors by risk" hint="Mean NovrSOC contextual risk of each sector's open findings." loading={loading} empty={d && !d.sectors.some((s) => s.risk.mean !== null) ? { title: 'No sector has scored findings yet' } : null}>
                        {d && <BarList label="Sectors by contextual risk" max={100} items={d.sectors.filter((s) => s.risk.mean !== null).sort((a, b) => (b.risk.mean ?? 0) - (a.risk.mean ?? 0)).slice(0, 6).map((s) => ({ key: s.id, label: sectorLabel(s.id), value: Math.round(s.risk.mean!), token: '--vz-sev-high' as const, href: `/admin/cnii/${s.id}`, note: `Mean risk ${s.risk.mean} · highest ${s.risk.max} · ${s.open_vulnerabilities} open` }))} />}
                    </ChartCard>
                    <ChartCard title="Detection sources" hint="Which scanner or agent reported each open finding." loading={loading} empty={d && !Object.keys(d.sources).length ? { title: 'No findings recorded' } : null}>
                        {d && <BarList label="Findings by detection source" items={sourceItems(d.sources)} />}
                    </ChartCard>
                    <ChartCard className="xl:col-span-2" title="Risk distribution by sector" hint="Open findings by NovrSOC priority, per monitored sector." loading={loading} empty={d && !d.sectors.some((s) => s.organisations) ? { title: 'No monitored sectors' } : null}>
                        {d && (
                            <div className="space-y-3">
                                {d.sectors.filter((s) => s.organisations).map((s) => {
                                    const total = Object.values(s.priority).reduce((a, b) => a + b, 0);
                                    return (
                                        <Link key={s.id} href={`/admin/cnii/${s.id}`} className="block group">
                                            <div className="flex justify-between text-xs mb-1"><span className="font-semibold text-foreground group-hover:underline">{sectorLabel(s.id)}</span><span className="text-foreground-muted tabular-nums">{total} open</span></div>
                                            <div className="flex h-3 w-full gap-[2px] rounded-full overflow-hidden bg-card-muted">{PRIO_SERIES.map((p) => s.priority[p.key] ? <div key={p.key} title={`${p.label}: ${s.priority[p.key]}`} style={{ flexGrow: s.priority[p.key], background: `var(${p.token})` }} /> : null)}</div>
                                        </Link>
                                    );
                                })}
                                <Legend series={PRIO_SERIES} />
                            </div>
                        )}
                    </ChartCard>
                    <ChartCard title="Organisations and assets by sector" loading={loading} empty={d && !d.sectors.some((s) => s.organisations) ? { title: 'No monitored sectors' } : null}>
                        {d && <BarList label="Assets by sector" items={d.sectors.filter((s) => s.organisations).map((s) => ({ key: s.id, label: <span>{sectorLabel(s.id)} <span className="text-foreground-muted">· {s.organisations} org</span></span>, value: s.assets, token: '--vz-prog-3' as const, href: `/admin/cnii/${s.id}` }))} />}
                    </ChartCard>
                    <ChartCard className="xl:col-span-3" title="Open findings over time" hint="Daily risk snapshots of the monitored organisations, summed. Days without a snapshot are absent, not filled." loading={loading}
                        empty={d && d.trend.length < 2 ? { title: 'Not enough history yet', body: 'A trend needs at least two daily snapshots.' } : null}>
                        {d && <><TimeChart kind="line" stacked={false} label="Open findings over time" data={d.trend} series={[{ key: 'open_total', label: 'Open findings', token: '--vz-prog-3' }, { key: 'internet_open', label: 'On internet-facing assets', token: '--vz-cat-1' }, { key: 'kev_open', label: 'Known exploited', token: '--vz-sev-critical' }]} height={200} /><Legend series={[{ key: 'open_total', label: 'Open findings', token: '--vz-prog-3' }, { key: 'internet_open', label: 'On internet-facing assets', token: '--vz-cat-1' }, { key: 'kev_open', label: 'Known exploited', token: '--vz-sev-critical' }]} /></>}
                    </ChartCard>
                </section>

                <section aria-label="Sectors" className="space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                        <h2 className="text-sm font-black text-foreground">Sectors ({CNII_SECTORS.length})</h2>
                        <SearchBox value={q} onSubmit={setQ} placeholder="Find a sector" label="Find a sector" />
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
                        {loading && Array.from({ length: 8 }, (_, i) => <div key={i} className="h-40 rounded-2xl bg-card border border-border motion-safe:animate-pulse" />)}
                        {sectors?.map(({ meta, s }) => {
                            const Icon = meta.icon;
                            const monitored = s.organisations > 0;
                            return (
                                <Link key={meta.id} href={`/admin/cnii/${meta.id}`} className={`group relative block bg-card border border-border rounded-2xl p-4 overflow-hidden transition-colors hover:border-purple/40 focus-visible:ring-2 focus-visible:ring-purple/60 outline-none ${monitored ? '' : 'opacity-80'}`}>
                                    <span className="absolute inset-x-0 top-0 h-1" style={{ background: meta.color }} aria-hidden />
                                    <div className="flex items-start justify-between gap-2">
                                        <span className="flex items-center gap-2 min-w-0"><span className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0" style={{ background: `${meta.color}22`, color: meta.color }}><Icon className="w-4 h-4" aria-hidden /></span>
                                            <span className="min-w-0"><span className="block text-sm font-bold text-foreground leading-tight">{meta.label}</span>{!monitored && <span className="block mt-1"><Tag>Not monitored</Tag></span>}</span></span>
                                        {monitored && <RiskBadge risk={s.risk} />}
                                    </div>
                                    {monitored ? (
                                        <dl className="grid grid-cols-3 gap-2 mt-4 text-center">
                                            <div><dt className="text-[10px] text-foreground-muted">Organisations</dt><dd className="text-lg font-black tabular-nums text-foreground">{s.organisations}</dd></div>
                                            <div><dt className="text-[10px] text-foreground-muted">Assets</dt><dd className="text-lg font-black tabular-nums text-foreground">{nf.format(s.assets)}</dd></div>
                                            <div><dt className="text-[10px] text-foreground-muted">Crit / high</dt><dd className="text-lg font-black tabular-nums" style={{ color: s.critical_high ? 'var(--vz-sev-critical)' : undefined }}>{s.critical_high}</dd></div>
                                        </dl>
                                    ) : <p className="text-[11px] text-foreground-muted mt-4 leading-relaxed">No organisation in this sector has a CNII profile yet{designatedOnly ? ' (designated only)' : ''}. Classify one from Classification & intake.</p>}
                                    {monitored && <p className="mt-3 text-[10.5px] text-foreground-muted">{s.designated} designated · {s.candidates} candidate · {s.coverage.by_state.connected_fresh + s.coverage.by_state.connected_stale}/{s.organisations} receiving telemetry</p>}
                                </Link>
                            );
                        })}
                    </div>
                </section>

                <section className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                    <Card>
                        <SectionTitle title="Monitored organisations" hint="Ranked by contextual risk." />
                        {!d ? <div className="h-32 rounded-lg bg-card-muted motion-safe:animate-pulse" /> : d.organisations.length === 0 ? <EmptyState compact title="No organisation has a CNII profile" body="Set a sector on an organisation in Classification & intake." /> : (
                            <ul className="divide-y divide-border">
                                {[...d.organisations].sort((a, b) => (b.risk.mean ?? -1) - (a.risk.mean ?? -1)).slice(0, 10).map((o) => (
                                    <li key={o.slug}><Link href={`/admin/cnii/org/${encodeURIComponent(o.slug)}`} className="flex items-center gap-3 py-2.5 hover:bg-card-muted/60 -mx-2 px-2 rounded-lg">
                                        <span className="flex-1 min-w-0"><span className="block text-xs font-semibold text-foreground truncate">{o.name}</span><span className="block text-[11px] text-foreground-muted">{sectorLabel(o.sector ?? '')}{o.subfield ? ` · ${o.subfield}` : ''} · {o.assets} assets · {o.critical_high} critical/high</span></span>
                                        {o.designation !== 'designated' && <Tag>Candidate</Tag>}
                                        <RiskScore score={o.risk.mean} />
                                    </Link></li>
                                ))}
                            </ul>
                        )}
                    </Card>
                    <TopAssets rows={d?.top_assets ?? null} />
                </section>
            </>}
        </div>
    );
}

function RiskBadge({ risk }: { risk: Risk }) {
    if (risk.mean === null) return <Tip label="No open scored findings"><span className="text-[10px] font-semibold text-foreground-muted">Risk —</span></Tip>;
    return <Tip label={`Mean NovrSOC risk ${risk.mean} (highest ${risk.max})`}><span className="text-[11px] font-black px-2 py-0.5 rounded-md text-white tabular-nums" style={{ background: riskColor(risk.mean) }}>{Math.round(risk.mean)}</span></Tip>;
}

function TopAssets({ rows }: { rows: TopAsset[] | null }) {
    return (
        <Card>
            <SectionTitle title="Most vulnerable assets" hint="By highest contextual risk, then open severity." />
            {!rows ? <div className="h-32 rounded-lg bg-card-muted motion-safe:animate-pulse" /> : rows.length === 0 ? <EmptyState compact title="No asset has open findings" /> : (
                <ul className="divide-y divide-border">
                    {rows.map((a) => (
                        <li key={a.asset_id}><Link href={`/admin/cnii/org/${encodeURIComponent(a.org_id)}/asset/${a.asset_id}`} className="flex items-center gap-3 py-2.5 hover:bg-card-muted/60 -mx-2 px-2 rounded-lg">
                            <span className="flex-1 min-w-0"><span className="block text-xs font-semibold font-mono text-foreground break-all">{a.value}</span><span className="block text-[11px] text-foreground-muted">{a.organisation} · {a.open} open · {SEVERITY_KEYS.filter((s) => a.severity[s]).map((s) => `${a.severity[s]} ${s}`).join(' · ')}</span></span>
                            {a.exposure === 'internet' && <Tag><Globe className="w-3 h-3" aria-hidden />Internet</Tag>}
                            {a.kev > 0 && <Tag strong>KEV</Tag>}
                            <RiskScore score={a.max_risk} />
                        </Link></li>
                    ))}
                </ul>
            )}
        </Card>
    );
}

// ── Sector ────────────────────────────────────────────────────────────────────────────────────
export function CniiNationalSector({ sectorId }: { sectorId: string }) {
    const meta = SECTOR_BY_ID[sectorId];
    const router = useRouter();
    const { load, data: d, reload } = useVmsData<SectorData>(meta ? `/api/cnii/national/sectors/${encodeURIComponent(sectorId)}` : null);
    const [q, setQ] = useState('');
    const loading = load.state === 'loading' && !d;
    if (!meta) return <EmptyState title="Unknown sector" action={<Link href="/admin/cnii" className="text-xs font-semibold underline">Back to the national overview</Link>} />;
    const Icon = meta.icon;
    const k = d?.kpis;
    const orgs = d?.organisations.filter((o) => !q || o.name.toLowerCase().includes(q.toLowerCase()) || o.slug.includes(q.toLowerCase())) ?? null;
    const cols: Column<OrgSum>[] = [
        { key: 'name', header: 'Organisation', sort: (o) => o.name, render: (o) => <div><p className="font-semibold text-foreground">{o.name}</p><p className="text-[10.5px] text-foreground-muted">{o.subfield ?? 'No sub-field'} · {o.slug}</p></div> },
        { key: 'designation', header: 'Designation', render: (o) => designationTag(o.designation) },
        { key: 'assets', header: 'Assets', sort: (o) => o.assets, render: (o) => <span className="tabular-nums">{nf.format(o.assets)}</span> },
        { key: 'open', header: 'Open findings', sort: (o) => o.open_vulnerabilities, render: (o) => <span className="text-[11px]"><b className="tabular-nums">{o.open_vulnerabilities}</b> · {SEVERITY_KEYS.filter((s) => s !== 'info' && o.severity[s]).map((s) => `${o.severity[s]} ${s}`).join(' · ') || 'none'}</span> },
        { key: 'risk', header: 'Contextual risk', sort: (o) => o.risk.mean ?? -1, render: (o) => <RiskScore score={o.risk.mean} wide /> },
        { key: 'coverage', header: 'Monitoring', hideBelow: 'lg', render: (o) => <CoverageBadge state={o.coverage_state} /> },
        { key: 'ti', header: 'Threat intel', hideBelow: 'lg', sort: (o) => o.threat_intelligence.total, render: (o) => <ThreatIntelSummary ti={o.threat_intelligence} /> },
    ];
    return (
        <div className="space-y-5">
            <Crumbs items={[{ label: 'CNII Watch', href: '/admin/cnii' }, { label: meta.label }]} />
            <div className="relative overflow-hidden rounded-2xl border border-border bg-card p-5">
                <span className="absolute inset-y-0 left-0 w-1.5" style={{ background: meta.color }} aria-hidden />
                <div className="flex flex-wrap items-start gap-4">
                    <span className="w-12 h-12 rounded-xl flex items-center justify-center shrink-0" style={{ background: `${meta.color}22`, color: meta.color }}><Icon className="w-6 h-6" aria-hidden /></span>
                    <div className="flex-1 min-w-[200px]">
                        <h1 className="text-xl font-black text-foreground">{meta.label}</h1>
                        <p className="text-xs text-foreground-muted mt-1 max-w-3xl">{meta.description}</p>
                        <p className="text-[11px] text-foreground-muted mt-2">Frameworks: {meta.compliance.join(' · ')} · Sub-fields: {meta.subfields.join(', ')}</p>
                    </div>
                    {k && <RiskBadge risk={k.risk} />}
                </div>
            </div>
            {load.state === 'error' && <ErrorState error={load.error} status={load.status} onRetry={reload} />}
            {(d || loading) && <>
                <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <KpiCard label="Organisations" value={k?.organisations} reason="Loading" icon={Building2} sub={k ? `${k.designated} designated · ${k.organisations - k.designated} candidate` : undefined} />
                    <KpiCard label="Assets" value={k?.assets} reason="Loading" icon={Server} sub={k ? `${k.internet_facing} internet-facing` : undefined} />
                    <KpiCard label="Active vulnerabilities" value={k?.open_vulnerabilities} reason="Loading" sub={d ? `${d.severity.critical ?? 0} critical · ${d.severity.high ?? 0} high · ${d.severity.medium ?? 0} medium · ${d.severity.low ?? 0} low` : undefined} tone={d && (d.severity.critical || d.severity.high) ? 'critical' : undefined} />
                    <RiskKpi risk={k?.risk} definition={d?.definitions.infrastructure_risk} />
                    <KpiCard label="Assets requiring attention" value={k?.assets_requiring_attention} reason="Loading" hint={d?.definitions.assets_requiring_attention} tone={k?.assets_requiring_attention ? 'warning' : undefined} />
                    <KpiCard label="Known exploited (KEV)" value={k?.kev_open} reason="Loading" tone={k?.kev_open ? 'critical' : undefined} />
                    <KpiCard label="Organisations with authorised scope" value={k?.coverage.organisations_scoped} suffix={k ? ` / ${k.organisations}` : ''} reason="Loading" />
                    <KpiCard label="Assets assessed (30 days)" value={k?.coverage.assets_assessed_30d} suffix={k ? ` / ${k.assets}` : ''} reason="Loading" sub="Reached by a scan in the last 30 days" />
                </section>
                {d && d.organisations.length === 0 ? <Card><EmptyState icon={Building2} title={`No ${meta.label} organisation is monitored yet`} body="No organisation in this sector has a CNII profile that you may view. Nothing is shown rather than an estimate." action={<Link href="/admin/cnii/manage" className="text-xs font-semibold underline">Classification & intake</Link>} /></Card> : <>
                    <section className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                        <ChartCard title="Vulnerability severity" hint="Scanner (CVSS) severity of open findings." loading={loading} empty={d && !Object.values(d.severity).some(Boolean) ? { title: 'No open findings' } : null}>
                            {d && <Donut label="Sector findings by severity" centerLabel="open" slices={sevSlices(d.severity)} />}
                        </ChartCard>
                        <ChartCard title="Risk distribution" hint="Open findings by NovrSOC priority (contextual risk)." loading={loading} empty={d && !Object.values(d.priority).some(Boolean) ? { title: 'No open findings' } : null}>
                            {d && <BarList label="Findings by priority" items={PRIO_SERIES.map((p) => ({ key: p.key, label: p.label, value: d.priority[p.key] ?? 0, token: p.token }))} />}
                        </ChartCard>
                        <ChartCard title="Top affected organisations" hint="By open critical and high findings." loading={loading} empty={d && !d.organisations.some((o) => o.open_findings) ? { title: 'No organisation has open findings' } : null}>
                            {d && <BarList label="Organisations by critical/high findings" items={[...d.organisations].sort((a, b) => b.critical_high - a.critical_high || b.open_vulnerabilities - a.open_vulnerabilities).slice(0, 6).map((o) => ({ key: o.slug, label: o.name, value: o.critical_high, token: '--vz-sev-critical' as const, href: `/admin/cnii/org/${encodeURIComponent(o.slug)}`, note: `${o.open_vulnerabilities} open, ${o.critical_high} critical/high` }))} />}
                        </ChartCard>
                    </section>
                    <Card>
                        <SectionTitle title="Organisation directory" hint="Every organisation with a CNII profile in this sector that you may view." action={<SearchBox value={q} onSubmit={setQ} placeholder="Find an organisation" label="Find an organisation" />} />
                        <div className="-mx-5 -mb-5 [&>div]:rounded-none [&>div]:border-x-0 [&>div]:border-b-0">
                            <DataTable caption="Sector organisations" rows={orgs} columns={cols} rowKey={(o) => o.slug} onRowClick={(o) => router.push(`/admin/cnii/org/${encodeURIComponent(o.slug)}`)} initialSort={{ key: 'risk', dir: 'desc' }} empty="No organisation matches" />
                        </div>
                    </Card>
                    <TopAssets rows={d?.top_assets ?? null} />
                </>}
            </>}
        </div>
    );
}

// ── Organisation ──────────────────────────────────────────────────────────────────────────────
export function CniiNationalOrg({ org }: { org: string }) {
    const router = useRouter();
    const { load, data: d, reload, at } = useVmsData<OrgData>(`/api/cnii/national/orgs/${encodeURIComponent(org)}`);
    const [tab, setTab] = useState<'findings' | 'assets' | 'cves'>('findings');
    const [sev, setSev] = useState('');
    const [q, setQ] = useState('');
    const s = d?.summary;
    const loading = load.state === 'loading' && !d;
    const findings = useMemo(() => d?.findings.filter((f) => (!sev || f.severity === sev) && (!q || `${f.title} ${f.cve_ids.join(' ')} ${f.asset_value}`.toLowerCase().includes(q.toLowerCase()))) ?? null, [d, sev, q]);
    const meta = d ? SECTOR_BY_ID[d.organisation.sector] : undefined;
    const fCols: Column<OrgData['findings'][number]>[] = [
        { key: 'priority', header: 'Priority', sort: (f) => f.priority ?? 'P9', render: (f) => <PriorityBadge priority={f.priority} /> },
        { key: 'title', header: 'Vulnerability', className: 'min-w-[220px]', render: (f) => <div><p className="font-semibold text-foreground">{f.title}</p><p className="text-[10.5px] font-mono text-foreground-muted truncate max-w-[300px]">{f.rule_id}</p></div> },
        { key: 'cve', header: 'CVE', render: (f) => f.cve_ids.length ? <span className="text-[11px] font-mono">{f.cve_ids.slice(0, 2).join(', ')}{f.cve_ids.length > 2 ? ` +${f.cve_ids.length - 2}` : ''}{f.kev && <> <Tag strong>KEV</Tag></>}</span> : <span className="text-[11px] text-foreground-muted">—</span> },
        { key: 'cvss', header: 'CVSS', sort: (f) => f.scanner_cvss, render: (f) => <span className="tabular-nums text-[11px]">{f.scanner_cvss ?? '—'}</span> },
        { key: 'severity', header: 'Severity', sort: (f) => -(SEVERITY_META[f.severity]?.rank ?? 9), render: (f) => <SeverityBadge severity={f.severity} /> },
        { key: 'risk', header: 'Contextual risk', sort: (f) => f.risk_score, render: (f) => <RiskScore score={f.risk_score} /> },
        { key: 'asset', header: 'Asset', hideBelow: 'md', render: (f) => <span className="font-mono text-[11px] break-all">{f.asset_value}{f.port ? `:${f.port}` : ''}</span> },
        { key: 'source', header: 'Source', hideBelow: 'lg', render: (f) => <span className="text-[11px] text-foreground-muted">{f.detected_by.map((x) => SOURCE_LABEL[x] ?? x).join(', ')}</span> },
        { key: 'status', header: 'Status', hideBelow: 'lg', render: (f) => <span className="text-[11px]">{STATUS_TEXT[f.status] ?? f.status}</span> },
    ];
    const aCols: Column<OrgData['assets'][number]>[] = [
        { key: 'value', header: 'Asset', sort: (a) => a.value, render: (a) => <div><p className="font-mono font-semibold text-foreground break-all">{a.value}</p><p className="text-[10.5px] text-foreground-muted">{a.asset_type} · {a.criticality} criticality</p></div> },
        { key: 'exposure', header: 'Exposure', render: (a) => a.exposure === 'internet' ? <Tag><Globe className="w-3 h-3" aria-hidden />Internet</Tag> : <span className="text-[11px] text-foreground-muted">{a.exposure}</span> },
        { key: 'open', header: 'Open findings', sort: (a) => a.findings.open, render: (a) => a.findings.open ? <span className="text-[11px]"><b>{a.findings.open}</b> · {SEVERITY_KEYS.filter((x) => a.findings.severity[x]).map((x) => `${a.findings.severity[x]} ${x}`).join(' · ')}</span> : <span className="text-[11px] text-foreground-muted">None</span> },
        { key: 'risk', header: 'Highest risk', sort: (a) => a.findings.max_risk ?? -1, render: (a) => <RiskScore score={a.findings.max_risk} /> },
        { key: 'seen', header: 'Last seen', hideBelow: 'md', sort: (a) => a.last_seen, render: (a) => <span className="text-[11px] text-foreground-muted">{fmtWat(a.last_seen)}</span> },
    ];
    if (load.state === 'error') return <div className="space-y-4"><Crumbs items={[{ label: 'CNII Watch', href: '/admin/cnii' }, { label: org }]} /><ErrorState error={load.error} status={load.status} onRetry={reload} /></div>;
    const rem = d?.remediation;
    const closed = rem ? Object.values(rem.findings_closed_by_status).reduce((a, b) => a + b, 0) : 0;
    const openAll = rem ? Object.values(rem.findings_open_by_status).reduce((a, b) => a + b, 0) : 0;
    return (
        <div className="space-y-5">
            <Crumbs items={[{ label: 'CNII Watch', href: '/admin/cnii' }, ...(d ? [{ label: meta?.label ?? d.organisation.sector, href: `/admin/cnii/${d.organisation.sector}` }] : []), { label: d?.organisation.name ?? org }]} />
            {!d ? <div className="h-24 rounded-2xl bg-card-muted motion-safe:animate-pulse" /> : (
                <div className="rounded-2xl border border-border bg-card p-5 flex flex-wrap items-start gap-4">
                    <span className="w-12 h-12 rounded-xl flex items-center justify-center bg-purple/10 text-purple dark:text-[var(--vz-prog-4)]"><Building2 className="w-6 h-6" aria-hidden /></span>
                    <div className="flex-1 min-w-[220px] space-y-1">
                        <h1 className="text-xl font-black text-foreground">{d.organisation.name}</h1>
                        <p className="text-xs text-foreground-muted">{meta?.label ?? d.organisation.sector}{d.organisation.subfield ? ` · ${d.organisation.subfield}` : ''} · {d.organisation.slug}</p>
                        <div className="flex flex-wrap items-center gap-3 pt-1">
                            {designationTag(d.organisation.designation)}
                            <CoverageBadge state={d.summary.coverage_state} detail={d.monitoring.active_scopes ? `${d.monitoring.active_scopes} authorised scope(s)` : undefined} />
                            {d.monitoring.last_scan && <span className="text-[11px] text-foreground-muted">Last scan {relTime(d.monitoring.last_scan.finished_at, at ?? 0)} ({d.monitoring.last_scan.kind}, {d.monitoring.last_scan.status})</span>}
                        </div>
                    </div>
                    <div className="flex items-center gap-2"><RiskBadge risk={d.summary.risk} /><Link href={`/admin/cnii/org/${encodeURIComponent(org)}/report`} className="text-[11px] font-semibold text-purple dark:text-[var(--vz-prog-4)]">Report →</Link><Link href={`/admin/cnii/org/${encodeURIComponent(org)}/manage`} className="text-[11px] font-semibold text-purple dark:text-[var(--vz-prog-4)]">Profile & inventory →</Link></div>
                </div>
            )}
            {(d || loading) && <>
                <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <RiskKpi risk={s?.risk} definition={d?.definitions.infrastructure_risk} />
                    <KpiCard label="Assets" value={s?.assets} reason="Loading" sub={s ? `${s.internet_facing} internet-facing` : undefined} icon={Server} />
                    <KpiCard label="Open findings" value={s?.open_vulnerabilities} reason="Loading" sub="Informational excluded" />
                    <KpiCard label="Critical & high" value={s?.critical_high} reason="Loading" tone={s?.critical_high ? 'critical' : s ? 'good' : undefined} />
                    <KpiCard label="CVEs detected" value={d?.cves.length} reason="Loading" sub={d ? `${d.cves.filter((c) => c.kev).length} known exploited` : undefined} />
                    <KpiCard label="Assets requiring attention" value={s?.assets_requiring_attention} reason="Loading" hint={d?.definitions.assets_requiring_attention} tone={s?.assets_requiring_attention ? 'warning' : undefined} />
                    <KpiCard label="Remediation progress" value={d ? (openAll + closed ? Math.round((closed / (openAll + closed)) * 100) : null) : undefined} suffix="%" reason={d ? 'No findings on record' : 'Loading'} sub={d ? `${closed} closed (verified, accepted or false positive) · ${openAll} open` : undefined} />
                    <KpiCard label="Assets assessed (30 days)" value={s?.monitoring.assets_assessed_30d} suffix={s ? ` / ${s.assets}` : ''} reason="Loading" />
                    <KpiCard label="Threat intelligence matches" value={s?.threat_intelligence.total} reason="Loading" tone={s && s.threat_intelligence.verified > 0 ? 'critical' : s ? 'good' : undefined}
                        hint={d?.definitions.threat_intelligence}
                        sub={s ? (s.threat_intelligence.total ? `${s.threat_intelligence.verified} verified association(s) · ${s.threat_intelligence.contextual} contextual only — not a confirmed attack or compromise` : 'No indicator matches') : undefined} />
                </section>
                <section className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                    <ChartCard title="Severity (CVSS)" loading={loading} empty={d && !Object.values(d.summary.severity).some(Boolean) ? { title: 'No open findings' } : null}>{d && <Donut label="Findings by severity" centerLabel="open" slices={sevSlices(d.summary.severity)} />}</ChartCard>
                    <ChartCard title="Contextual risk (priority)" loading={loading} empty={d && !Object.values(d.summary.priority).some(Boolean) ? { title: 'No open findings' } : null}>{d && <BarList label="Findings by priority" items={PRIO_SERIES.map((p) => ({ key: p.key, label: p.label, value: d.summary.priority[p.key] ?? 0, token: p.token }))} />}</ChartCard>
                    <ChartCard title="Remediation" hint="Where each open finding stands." loading={loading} empty={d && !openAll ? { title: 'Nothing open' } : null}>{d && <BarList label="Open findings by remediation stage" items={['open', 'reopened', 'acknowledged', 'in_progress', 'fixed_pending_verification'].map((k, i) => ({ key: k, label: STATUS_TEXT[k], value: d.remediation.findings_open_by_status[k] ?? 0, token: (['--vz-sev-high', '--vz-sev-critical', '--vz-prog-1', '--vz-prog-2', '--vz-prog-3'] as const)[i] }))} />}</ChartCard>
                </section>
                <Card>
                    <SectionTitle title={tab === 'findings' ? 'Findings' : tab === 'assets' ? 'Asset inventory' : 'CVEs detected'} action={
                        <div className="flex flex-wrap items-center gap-2">
                            {tab === 'findings' && <><Select label="Severity" value={sev} onChange={setSev} options={[['', 'Any severity'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['info', 'Info']]} /><SearchBox value={q} onSubmit={setQ} placeholder="Title, CVE or asset" label="Search findings" /></>}
                            <div className="inline-flex gap-0.5 bg-card-muted rounded-lg p-0.5" role="tablist">{(['findings', 'assets', 'cves'] as const).map((t) => <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)} className={`text-[11px] font-semibold px-2.5 py-1 rounded-md ${tab === t ? 'bg-card text-foreground shadow-sm' : 'text-foreground-muted'}`}>{t === 'findings' ? `Findings (${d?.findings.length ?? '…'})` : t === 'assets' ? `Assets (${d?.assets.length ?? '…'})` : `CVEs (${d?.cves.length ?? '…'})`}</button>)}</div>
                        </div>} />
                    <div className="-mx-5 -mb-5 [&>div]:rounded-none [&>div]:border-x-0 [&>div]:border-b-0">
                        {tab === 'findings' && <DataTable caption="Organisation findings" rows={findings} columns={fCols} rowKey={(f) => f.id} onRowClick={(f) => f.asset_id ? router.push(`/admin/cnii/org/${encodeURIComponent(org)}/asset/${f.asset_id}#f-${f.id}`) : undefined} initialSort={{ key: 'risk', dir: 'desc' }} empty="No open findings" />}
                        {tab === 'assets' && <DataTable caption="Organisation assets" rows={d?.assets ?? null} columns={aCols} rowKey={(a) => a.id} onRowClick={(a) => router.push(`/admin/cnii/org/${encodeURIComponent(org)}/asset/${a.id}`)} initialSort={{ key: 'open', dir: 'desc' }} empty="No assets recorded" />}
                        {tab === 'cves' && <DataTable caption="CVEs" rows={d?.cves ?? null} rowKey={(c) => c.cve_id} empty="No CVE identified in open findings" columns={[
                            { key: 'cve', header: 'CVE', sort: (c) => c.cve_id, render: (c) => <span className="font-mono font-semibold">{c.cve_id}</span> },
                            { key: 'kev', header: 'CISA KEV', render: (c) => c.kev ? <Tag strong>Known exploited</Tag> : <span className="text-[11px] text-foreground-muted">No</span> },
                            { key: 'n', header: 'Open findings', sort: (c) => c.findings, render: (c) => c.findings },
                        ]} />}
                    </div>
                </Card>
            </>}
        </div>
    );
}

// ── Asset ─────────────────────────────────────────────────────────────────────────────────────
export function CniiNationalAsset({ org, id }: { org: string; id: string }) {
    const { load, data: d, reload } = useVmsData<AssetData>(`/api/cnii/national/orgs/${encodeURIComponent(org)}/assets/${encodeURIComponent(id)}`);
    const [show, setShow] = useState<'open' | 'all'>('open');
    if (load.state === 'error') return <div className="space-y-4"><Crumbs items={[{ label: 'CNII Watch', href: '/admin/cnii' }, { label: org, href: `/admin/cnii/org/${encodeURIComponent(org)}` }, { label: 'Asset' }]} /><ErrorState error={load.error} status={load.status} onRetry={reload} /></div>;
    if (!d) return <div className="space-y-4"><div className="h-6 w-80 rounded bg-card-muted motion-safe:animate-pulse" /><div className="h-32 rounded-2xl bg-card-muted motion-safe:animate-pulse" /><div className="h-64 rounded-2xl bg-card-muted motion-safe:animate-pulse" /></div>;
    const a = d.asset;
    const meta = SECTOR_BY_ID[d.organisation.sector];
    const closedStates = ['verified', 'risk_accepted', 'false_positive'];
    const fs = d.findings.filter((f) => show === 'all' || !closedStates.includes(f.status));
    const open = d.findings.filter((f) => !closedStates.includes(f.status));
    const sev = Object.fromEntries(SEVERITY_KEYS.map((k) => [k, open.filter((f) => f.severity === k).length]));
    const maxRisk = open.length ? Math.max(...open.map((f) => f.risk_score ?? 0)) : null;
    return (
        <div className="space-y-5">
            <Crumbs items={[{ label: 'CNII Watch', href: '/admin/cnii' }, { label: meta?.label ?? d.organisation.sector, href: `/admin/cnii/${d.organisation.sector}` }, { label: d.organisation.name, href: `/admin/cnii/org/${encodeURIComponent(org)}` }, { label: a.value }]} />
            <div className="rounded-2xl border border-border bg-card p-5 flex flex-wrap items-start gap-4">
                <span className="w-12 h-12 rounded-xl flex items-center justify-center bg-purple/10 text-purple dark:text-[var(--vz-prog-4)]"><Server className="w-6 h-6" aria-hidden /></span>
                <div className="flex-1 min-w-[220px] space-y-1">
                    <h1 className="text-xl font-black font-mono text-foreground break-all">{a.value}</h1>
                    <p className="text-xs text-foreground-muted">{a.asset_type} · {a.exposure === 'internet' ? 'internet-facing' : a.exposure} · {a.criticality} criticality · {d.organisation.name} · {meta?.label}</p>
                    <p className="text-[11px] text-foreground-muted">First seen {fmtWat(a.first_seen)} · last seen {fmtWat(a.last_seen)} · {a.last_assessed_at ? `last assessed ${fmtWat(a.last_assessed_at)}` : 'not assessed yet'} · found by {a.discovery_sources.join(', ') || '—'}</p>
                    {(a.ips.length > 0 || a.hostnames.length > 0) && <p className="text-[11px] font-mono text-foreground-muted break-all">{[...a.hostnames, ...a.ips].slice(0, 8).join(' · ')}</p>}
                </div>
                <Link href={`/admin/vms/assets/${a.id}`} className="text-[11px] font-semibold text-purple dark:text-[var(--vz-prog-4)]">Open in VMS →</Link>
            </div>
            <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <KpiCard label="Open findings" value={open.filter((f) => f.severity !== 'info').length} sub="Informational excluded" />
                <KpiCard label="Critical & high" value={(sev.critical ?? 0) + (sev.high ?? 0)} tone={(sev.critical ?? 0) + (sev.high ?? 0) ? 'critical' : 'good'} />
                <KpiCard label="Highest contextual risk" value={maxRisk} reason="No open findings" sub="NovrSOC risk, 0–100 — not CVSS" />
                <KpiCard label="CVEs" value={new Set(open.flatMap((f) => f.cves.map((c) => c.cve_id))).size} sub={`${open.filter((f) => f.cves.some((c) => c.kev)).length} with a known-exploited CVE`} />
            </section>
            {d.threat_intelligence.length > 0 && (
                <Card>
                    <SectionTitle title="Threat intelligence" hint="Verified means an analyst promoted this match or linked it to a case — a confirmed indicator-to-asset association, not a confirmed attack, compromise or breach. Contextual is an unreviewed, shared indicator or CVE appearing — never proof of anything on its own." />
                    <ul className="divide-y divide-border">
                        {d.threat_intelligence.map((m, i) => (
                            <li key={i} className="py-2.5 flex flex-wrap items-center gap-2">
                                <StatusPill tone={m.verified ? 'critical' : 'neutral'} label={m.verified ? 'Verified association — not a confirmed attack' : 'Contextual only — not yet confirmed'} />
                                <span className="text-xs font-mono text-foreground">{m.indicator_type}: {m.indicator_value}</span>
                                {m.malware_families.length > 0 && <Tag>{m.malware_families.join(', ')}</Tag>}
                                {m.threat_types.length > 0 && <span className="text-[11px] text-foreground-muted">{m.threat_types.join(', ')}</span>}
                                {m.confidence !== null && <span className="text-[11px] text-foreground-muted">confidence {m.confidence}</span>}
                                <Tag strong={m.tlp === 'red' || m.tlp === 'amber+strict'}>TLP:{m.tlp.toUpperCase()}</Tag>
                                {m.case_id && <Link href={`/admin/secops/cases?id=${m.case_id}`} className="text-[11px] font-semibold text-purple dark:text-[var(--vz-prog-4)]">Case →</Link>}
                            </li>
                        ))}
                    </ul>
                </Card>
            )}
            <div className="flex items-center justify-between gap-2 flex-wrap">
                <h2 className="text-sm font-black text-foreground">Vulnerability findings</h2>
                <div className="inline-flex gap-0.5 bg-card border border-border rounded-lg p-0.5">{(['open', 'all'] as const).map((t) => <button key={t} aria-pressed={show === t} onClick={() => setShow(t)} className={`text-[11px] font-semibold px-2.5 py-1 rounded-md ${show === t ? 'bg-purple text-white' : 'text-foreground-muted'}`}>{t === 'open' ? `Open (${open.length})` : `All, incl. history (${d.findings.length})`}</button>)}</div>
            </div>
            {fs.length === 0 ? <Card><EmptyState title="No findings on this asset" body="Nothing has been reported for it by the scanners or agents that cover it." /></Card> : (
                <div className="space-y-3">
                    {fs.map((f) => (
                        <Card key={f.id} as="div" className="space-y-3">
                            <div id={`f-${f.id}`} className="flex flex-wrap items-start gap-2 scroll-mt-20">
                                <PriorityBadge priority={f.priority} /><SeverityBadge severity={f.severity} />
                                <span className="flex-1 min-w-[200px] text-sm font-bold text-foreground">{f.title}{f.port ? <span className="text-foreground-muted font-normal"> · port {f.port}</span> : null}</span>
                                <span className="text-[11px] font-semibold text-foreground">{STATUS_TEXT[f.status] ?? f.status}</span>
                            </div>
                            <dl className="grid grid-cols-2 lg:grid-cols-5 gap-3 text-xs">
                                <div><dt className="text-[10px] uppercase tracking-wide text-foreground-muted">CVSS (scanner)</dt><dd className="font-semibold">{f.cvss.score ?? 'Not reported'}{f.cvss.version ? ` · v${f.cvss.version}` : ''}</dd>{f.cvss.vector && <dd className="font-mono text-[10px] text-foreground-muted break-all">{f.cvss.vector}</dd>}</div>
                                <div><dt className="text-[10px] uppercase tracking-wide text-foreground-muted">NovrSOC risk (contextual)</dt><dd><RiskScore score={f.risk_score} wide /></dd></div>
                                <div><dt className="text-[10px] uppercase tracking-wide text-foreground-muted">CVE</dt><dd className="font-mono text-[11px]">{f.cves.length ? f.cves.map((c) => <span key={c.cve_id} className="block">{c.cve_id}{c.kev ? ' · KEV' : ''}{c.epss !== null ? ` · EPSS ${(Number(c.epss) * 100).toFixed(1)}%` : ''}</span>) : '—'}</dd></div>
                                <div><dt className="text-[10px] uppercase tracking-wide text-foreground-muted">Detected by</dt><dd>{f.detected_by.map((x) => SOURCE_LABEL[x] ?? x).join(', ') || '—'}{f.evidence_class && f.evidence_class !== 'scanner_check' ? <span className="block text-[10.5px] text-foreground-muted">{f.evidence_class.replace(/_/g, ' ')}</span> : null}</dd></div>
                                <div><dt className="text-[10px] uppercase tracking-wide text-foreground-muted">Verification</dt><dd>{f.verified_at ? `Verified fixed ${fmtWat(f.verified_at)}` : f.status === 'fixed_pending_verification' ? 'Fixed — awaiting a rescan' : 'Not verified'}</dd>{f.due_at && !f.verified_at && <dd className="text-[10.5px] text-foreground-muted">Fix by {fmtWat(f.due_at)}</dd>}</div>
                            </dl>
                            <p className="text-[11px] text-foreground-muted">Evidence: {f.evidence.detections} detection(s){f.evidence.last_observed_at ? `, last ${fmtWat(f.evidence.last_observed_at)}` : ''}{f.evidence.sources.length ? ` · ${f.evidence.sources.map((x) => SOURCE_LABEL[x] ?? x).join(', ')}` : ''}{f.evidence.locations.length ? ` · at ${f.evidence.locations.join(', ')}` : ''} · first seen {fmtWat(f.first_seen)}</p>
                            {f.remediation && <div><p className="text-[10px] uppercase tracking-wide text-foreground-muted">Remediation guidance</p><p className="text-xs whitespace-pre-wrap leading-relaxed text-foreground">{f.remediation}</p></div>}
                            {f.tasks.length > 0 && <p className="text-[11px] text-foreground-muted">Tasks: {f.tasks.map((t) => `${t.title} (${t.status})`).join(' · ')}</p>}
                            {f.history.length > 0 && <details><summary className="text-[11px] font-semibold text-foreground-muted cursor-pointer">History ({f.history.length})</summary><ul className="mt-1 space-y-0.5">{f.history.map((h, i) => <li key={i} className="text-[11px] text-foreground-muted">{fmtWat(h.at)} · {h.action === 'status' ? `${STATUS_TEXT[h.from ?? ''] ?? h.from ?? '—'} → ${STATUS_TEXT[h.to ?? ''] ?? h.to}` : h.action.replace(/_/g, ' ')}</li>)}</ul></details>}
                            <Link href={`/admin/vms/findings?id=${f.id}`} className="inline-block text-[11px] font-semibold text-purple dark:text-[var(--vz-prog-4)]">Open finding in VMS →</Link>
                        </Card>
                    ))}
                </div>
            )}
        </div>
    );
}
