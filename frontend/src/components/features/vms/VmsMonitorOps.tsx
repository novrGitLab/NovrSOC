'use client';

// Continuous Monitoring and Scanner Operations (redesign, phase P20).
//   Monitoring Rules — automatic assessment policies (GET /api/vms/admin/status, vms:scope). Created
//     disabled; turning one on is confirmed and audited; each run is limited by scope, exclusions,
//     cooldown and per-run caps exactly like a manual assessment.
//   Changes & Alerts — asset and service changes, labelled by how they were observed: an active
//     scan of ours, a passive source (no traffic to the target), or the Wazuh agent sync.
//   Scanner Integrations / Worker Health / Scan Policies & Configuration — for managers; the data
//     comes from /api/vms/admin/status, which the backend refuses below soc_manager. No secret,
//     token or password is ever sent to the browser: integrations show configured / not configured.

import { useMemo, useState } from 'react';
import Link from 'next/link';
import { Activity, Bell, CalendarClock, Cog, Cpu, Play, Plug, ShieldCheck, SlidersHorizontal, RotateCcw } from 'lucide-react';
import { fmtWat, fmtDuration, PROFILE_LABEL, ELIGIBILITY_LABEL, EVENT_LABEL, describeEvent, ENGINE_STATE_LABEL, SCAN_KIND_LABEL, type EligibilityStatus, type VmsEvent, type VmsScan, type VmsOperations, type VmsProfile, type EngineState } from '@/lib/vms';
import { Card, SectionTitle, StatusPill, ToneIcon, type Tone } from './ui';
import { PageHeader, KpiCard, PriorityBadge, Segmented, Select, ConfirmDialog, ErrorState, Notice, EmptyState, ExportCsvButton, Tag, btn, relTime, type Msg } from './kit';
import { DataTable, type Column } from './table';
import { VmsSchedules } from './VmsSchedules';
import { STATUS_LABEL, type Finding } from './FindingDetail';
import { useVmsData, useVmsCan, vmsSend } from './data';

interface Policy {
    id: string; name: string; enabled: boolean; asset_source: 'wazuh' | 'external' | 'any'; profile?: string; cooldown_hours: number; max_per_run: number; last_run_at: string | null;
    last_result: { queued?: number; existing?: number; skipped_cooldown?: number; blocked?: { asset: string; reason: string }[]; blocked_total?: number; not_evaluated?: number; event_triggered?: number; ineligible?: Record<string, number> } | null;
}
interface AdminStatus {
    deployed_version: string | null;
    workers: { source: string; online: number; window_seconds: number; list: { worker_id: string; online: boolean; version: string | null; kinds: string[]; tools: Record<string, boolean>; tool_versions: Record<string, string>; networks: string[]; features: string[]; last_seen_at: string; last_heartbeat_at?: string | null; last_claim_at?: string | null; last_job_at: string | null }[] };
    scheduler: { last_run_at: string | null; policies: { at?: string } | null };
    wazuh: { available: boolean; freshness?: { last_attempt_at: string | null; last_complete_at: string | null; complete: boolean | null; problem: string | null }; note?: string | null };
    cve_intel: { tracked: number; kev_checked_at: string | null; epss_fetched_at: string | null; nvd_fetched_at: string | null; osv?: { available: boolean; fetched_at?: string | null; note?: string } };
    ai: { configured: boolean; model: string };
    evidence: { available: boolean; retention_days?: number; items?: number; next_expiry?: string | null };
    scopes: { active: number; expired_or_revoked: number; with_exclusions: number; passive_only: number; vuln_allowed: number };
    policies: { available: boolean; note?: string; list?: Policy[] };
}
type Part = { ok: boolean; error?: string } & Record<string, unknown>;
interface WazuhCheck { checked_at: string; verdict: 'working' | 'reachable_not_synced' | 'not_working' | 'not_configured'; manager: Part & { api_version?: string | null }; agents: Part & { count?: number; active?: number; groups?: string[] }; vulnerabilities: Part & { records_for_org?: number } }
const SOURCE_LABEL = { wazuh: 'Wazuh endpoints', external: 'External hosts and IPs', any: 'All assets' } as const;
const VERDICT: Record<WazuhCheck['verdict'], { label: string; tone: Tone }> = { working: { label: 'Working', tone: 'good' }, reachable_not_synced: { label: 'Reachable, not yet synced completely', tone: 'warning' }, not_working: { label: 'Not working', tone: 'critical' }, not_configured: { label: 'Not configured', tone: 'neutral' } };
const ENGINE_TONE: Record<EngineState, Tone> = { available: 'good', offline: 'warning', not_enabled: 'neutral', not_installed: 'critical', no_worker: 'critical' };
const freshTone = (iso: string | null | undefined, hours: number, now: number): Tone => (!iso ? 'critical' : now - Date.parse(iso) > hours * 3_600_000 ? 'warning' : 'good');

function useAdminStatus() { return useVmsData<AdminStatus>('/api/vms/admin/status'); }

// ── Monitoring Rules ───────────────────────────────────────────────────────────────────────────
export function VmsMonitoringRules() {
    const can = useVmsCan();
    const { load, data: s, reload } = useAdminStatus();
    const [msg, setMsg] = useState<Msg>(null);
    const [form, setForm] = useState({ name: '', asset_source: 'external' as Policy['asset_source'], profile: 'standard' as 'discovery' | 'standard' | 'full', cooldown_hours: 168, max_per_run: 5 });
    const [toggle, setToggle] = useState<Policy | null>(null);
    const [run, setRun] = useState<Policy | null>(null);
    const input = 'block mt-1 bg-card border border-border rounded-lg px-2 py-1.5 text-xs text-foreground';
    return (
        <div className="space-y-5">
            <PageHeader icon={ShieldCheck} title="Monitoring Rules" description="Automatic assessment policies. A policy never authorises anything a manual assessment could not: every asset is checked against authorised scope, exclusions, worker capabilities and routes on every run. New policies are created disabled." />
            {load.state === 'error' && <ErrorState error={load.status === 403 ? 'Monitoring rules are managed by SOC managers and super admins; the backend refuses this request for other roles. Schedules and changes are available to you.' : load.error} status={load.status} onRetry={reload} />}
            <Notice msg={msg} />
            {s && !s.policies.available && <ErrorState error={s.policies.note ?? 'Policies are not set up'} status={503} />}
            {s?.policies.available && (
                <>
                    <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <KpiCard label="Policies" value={s.policies.list?.length ?? 0} />
                        <KpiCard label="Enabled" value={s.policies.list?.filter((p) => p.enabled).length ?? 0} tone={s.policies.list?.some((p) => p.enabled) ? 'warning' : 'good'} sub="Automatic scanning is on while any is enabled" />
                        <KpiCard label="Last policy run" text={s.scheduler.policies?.at ? fmtWat(s.scheduler.policies.at).replace(/ WAT$/, '') : 'Never'} sub="Policies are evaluated hourly" />
                        <KpiCard label="Active scope entries" value={s.scopes.active} sub={`${s.scopes.vuln_allowed} allow vulnerability scans`} href="/admin/vms/discovery" />
                    </section>
                    {can.scope && (
                        <Card>
                            <SectionTitle title="New policy" hint="Created disabled. Review it, then turn it on." />
                            <form onSubmit={async (e) => { e.preventDefault(); const r = await vmsSend('POST', '/api/vms/admin/policies', form); setMsg(r.ok ? { ok: true, text: 'Policy created — disabled until you turn it on.' } : { ok: false, text: r.error }); if (r.ok) { setForm({ ...form, name: '' }); reload(); } }} className="grid grid-cols-2 md:grid-cols-6 gap-3 items-end">
                                <label className="col-span-2 text-[11px] font-semibold text-foreground-muted">Name<input className={`${input} w-full`} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="External hosts weekly" maxLength={120} /></label>
                                <label className="text-[11px] font-semibold text-foreground-muted">Assets<select className={`${input} w-full`} value={form.asset_source} onChange={(e) => setForm({ ...form, asset_source: e.target.value as Policy['asset_source'] })}><option value="external">External hosts and IPs</option><option value="wazuh">Wazuh endpoints</option><option value="any">All assets</option></select></label>
                                <label className="text-[11px] font-semibold text-foreground-muted">Profile<select className={`${input} w-full`} value={form.profile} onChange={(e) => setForm({ ...form, profile: e.target.value as typeof form.profile })}>{(['discovery', 'standard', 'full'] as const).map((x) => <option key={x} value={x}>{PROFILE_LABEL[x]}</option>)}</select></label>
                                <label className="text-[11px] font-semibold text-foreground-muted">At most every (hours)<input type="number" min={24} max={2160} className={`${input} w-full`} value={form.cooldown_hours} onChange={(e) => setForm({ ...form, cooldown_hours: Number(e.target.value) })} /></label>
                                <label className="text-[11px] font-semibold text-foreground-muted">Assets per run<input type="number" min={1} max={50} className={`${input} w-full`} value={form.max_per_run} onChange={(e) => setForm({ ...form, max_per_run: Number(e.target.value) })} /></label>
                                <div className="col-span-2 md:col-span-6"><button className={btn('primary', 'md')} disabled={form.name.trim().length < 3}>Create (disabled)</button></div>
                            </form>
                        </Card>
                    )}
                    {(s.policies.list ?? []).length === 0 ? <Card><EmptyState title="No monitoring rules" body="Assessments run only when someone starts them or a schedule queues a scan." /></Card> : (
                        <div className="space-y-3">
                            {s.policies.list!.map((p) => (
                                <Card key={p.id} className="space-y-2">
                                    <div className="flex flex-wrap items-start justify-between gap-2">
                                        <div>
                                            <p className="text-sm font-bold text-foreground">{p.name}</p>
                                            <p className="text-[11px] text-foreground-muted">{SOURCE_LABEL[p.asset_source]} · {PROFILE_LABEL[p.profile ?? 'full'] ?? p.profile} profile · at most every {p.cooldown_hours} h per asset · up to {p.max_per_run} per hourly run</p>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <StatusPill tone={p.enabled ? 'warning' : 'neutral'} label={p.enabled ? 'Enabled — scanning automatically' : 'Disabled'} />
                                            {can.scope && <button onClick={() => setToggle(p)} className={btn('secondary')}>{p.enabled ? 'Disable' : 'Enable…'}</button>}
                                            {can.scope && <button onClick={() => setRun(p)} className={btn('secondary')}><Play className="w-3 h-3" aria-hidden /> Run now</button>}
                                        </div>
                                    </div>
                                    <p className="text-[11px] text-foreground-muted">Last run {p.last_run_at ? fmtWat(p.last_run_at) : 'never'}{p.last_result ? `: ${p.last_result.queued ?? 0} queued, ${p.last_result.existing ?? 0} already in progress, ${p.last_result.skipped_cooldown ?? 0} in cooldown, ${p.last_result.blocked_total ?? (p.last_result.blocked ?? []).length} blocked${p.last_result.not_evaluated ? `, ${p.last_result.not_evaluated} left for the next run` : ''}${p.last_result.event_triggered ? `, ${p.last_result.event_triggered} early because an address changed` : ''}` : ''}</p>
                                    {p.last_result?.ineligible && Object.keys(p.last_result.ineligible).length > 0 && <p className="text-[11px] text-foreground-muted">Not eligible: {Object.entries(p.last_result.ineligible).map(([k, n]) => `${n} ${ELIGIBILITY_LABEL[k as EligibilityStatus] ?? k}`).join(', ')} — <Link href="/admin/vms/assets?view=endpoints" className="underline">Managed endpoints</Link></p>}
                                    {(p.last_result?.blocked ?? []).slice(0, 5).map((b, i) => <p key={i} className="text-[11px] text-foreground"><span className="font-mono">{b.asset}</span>: {b.reason}</p>)}
                                </Card>
                            ))}
                        </div>
                    )}
                </>
            )}
            <ConfirmDialog open={!!toggle} tone={toggle?.enabled ? 'primary' : 'danger'} title={toggle?.enabled ? `Disable “${toggle?.name}”?` : `Enable automatic scanning for “${toggle?.name}”?`}
                body={toggle && !toggle.enabled ? <>Every hour, up to {toggle.max_per_run} {SOURCE_LABEL[toggle.asset_source].toLowerCase()} will get a <b>{PROFILE_LABEL[toggle.profile ?? 'full']}</b> assessment — only the checks their authorised scope and the connected workers allow. Make sure the targets&apos; owners authorised this. The change is audited.</> : 'No new assessments will be started by this policy. Scans already queued are not cancelled.'}
                confirmLabel={toggle?.enabled ? 'Disable' : 'Enable automatic scanning'} onCancel={() => setToggle(null)}
                onConfirm={async () => { const p = toggle!; setToggle(null); const r = await vmsSend('PATCH', `/api/vms/admin/policies/${p.id}`, { enabled: !p.enabled }); setMsg(r.ok ? { ok: true, text: `Policy ${!p.enabled ? 'enabled' : 'disabled'}` } : { ok: false, text: r.error }); reload(); }} />
            <ConfirmDialog open={!!run} title={`Run “${run?.name}” now?`} body="Evaluates the policy once now, with the same scope, cooldown and per-run limits as the hourly run. Assets it selects get assessments queued." confirmLabel="Run now" onCancel={() => setRun(null)}
                onConfirm={async () => { const p = run!; setRun(null); const r = await vmsSend<{ run: { queued: number; existing: number; skipped_cooldown: number; blocked: unknown[]; blocked_total?: number; not_evaluated?: number } }>('POST', `/api/vms/admin/policies/${p.id}/run`); setMsg(r.ok ? { ok: true, text: `Run: ${r.data.run.queued} queued, ${r.data.run.existing} already in progress, ${r.data.run.skipped_cooldown} in cooldown, ${r.data.run.blocked_total ?? r.data.run.blocked.length} blocked` } : { ok: false, text: r.error }); reload(); }} />
        </div>
    );
}

export function VmsSchedulesPage() {
    return (
        <div className="space-y-5">
            <PageHeader icon={CalendarClock} title="Scan Schedules" description="Recurring scans of an authorised scope. A schedule queues a scan only while its scope is active and allows that scan kind; when the scope expires or is revoked, the schedule stops." />
            <VmsSchedules />
        </div>
    );
}

// ── Changes & Alerts ───────────────────────────────────────────────────────────────────────────
type Observed = 'active' | 'passive' | 'wazuh' | 'unknown';
const OBSERVED: Record<Observed, { label: string; hint: string }> = {
    active: { label: 'Active scan', hint: 'Our scanner sent traffic to the target inside authorised scope' },
    passive: { label: 'Passive source', hint: 'Third-party data; no traffic was sent to the target' },
    wazuh: { label: 'Wazuh agent', hint: 'Reported by the endpoint agent' },
    unknown: { label: 'Not recorded', hint: 'The change has no source job recorded' },
};
export function VmsChanges() {
    const [days, setDays] = useState<'7' | '30' | '90'>('30');
    const [tab, setTab] = useState<'changes' | 'alerts'>('changes');
    const [observed, setObserved] = useState<'' | Observed>('');
    const [kind, setKind] = useState('');
    const events = useVmsData<{ events: (VmsEvent & { job_id?: string | null })[] }>(`/api/vms/events?days=${days}`);
    const scans = useVmsData<{ scans: VmsScan[] }>('/api/vms/scans?limit=500');
    const high = useVmsData<{ findings: Finding[] }>('/api/vms/findings?status=all&priority=P1,P2');
    const reopened = useVmsData<{ findings: Finding[] }>('/api/vms/findings?status=reopened');
    const notif = useVmsData<{ enabled: boolean; state: { last_run_at?: string | null; last_result?: Record<string, unknown> | null } | null }>('/api/vms/notifications');
    const now = events.at ?? 0;
    const jobKind = useMemo(() => new Map((scans.data?.scans ?? []).map((s) => [s.id, s.kind as string])), [scans.data]);
    const observedOf = (e: VmsEvent & { job_id?: string | null }): Observed => {
        if (e.job_id) { const k = jobKind.get(e.job_id); return k === 'passive_osint' ? 'passive' : k ? 'active' : 'unknown'; }
        const src = String(e.details?.source ?? e.details?.discovery_source ?? '');
        return src === 'wazuh' || e.vms_assets?.asset_type === 'endpoint' ? 'wazuh' : src ? 'passive' : 'unknown';
    };
    const rows = useMemo(() => events.data?.events.filter((e) => (!observed || observedOf(e) === observed) && (!kind || e.event === kind)) ?? null,
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [events.data, observed, kind, jobKind]);
    const sinceMs = now - Number(days) * 86_400_000;
    const alerts = useMemo(() => {
        const out: { id: string; at: string; title: string; detail: string; tone: Tone; href: string; priority?: string | null }[] = [];
        for (const f of high.data?.findings ?? []) if (Date.parse(f.first_seen) >= sinceMs) out.push({ id: `f${f.id}`, at: f.first_seen, title: `New ${f.priority} finding: ${f.title}`, detail: `${f.asset_value} · ${STATUS_LABEL[f.status] ?? f.status}`, tone: f.priority === 'P1' ? 'critical' : 'serious', href: `/admin/vms/findings?id=${f.id}`, priority: f.priority });
        for (const f of reopened.data?.findings ?? []) out.push({ id: `r${f.id}`, at: f.last_seen, title: `Reopened: ${f.title}`, detail: `${f.asset_value} — still present when rescanned`, tone: 'critical', href: `/admin/vms/findings?id=${f.id}`, priority: f.priority });
        for (const e of events.data?.events ?? []) if ((e.event === 'asset_new' || e.event === 'service_new') && (e.vms_assets as { exposure?: string } | null | undefined)?.exposure === 'internet') out.push({ id: `e${e.id}`, at: e.at, title: e.event === 'asset_new' ? `New internet-facing asset: ${e.vms_assets?.value}` : `New service on ${e.vms_assets?.value}`, detail: describeEvent(e), tone: 'warning', href: e.asset_id ? `/admin/vms/assets/${e.asset_id}` : '/admin/vms/attack-surface' });
        return out.sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
    }, [high.data, reopened.data, events.data, sinceMs]);
    const columns: Column<VmsEvent & { job_id?: string | null }>[] = [
        { key: 'at', header: 'When', sort: (e) => e.at, render: (e) => <span className="text-[11px] whitespace-nowrap" title={fmtWat(e.at)}>{relTime(e.at, now)}</span> },
        { key: 'event', header: 'Change', sort: (e) => e.event, render: (e) => <span className="font-semibold text-foreground">{EVENT_LABEL[e.event] ?? e.event}</span> },
        { key: 'asset', header: 'Asset', render: (e) => e.asset_id ? <Link href={`/admin/vms/assets/${e.asset_id}`} onClick={(x) => x.stopPropagation()} className="font-mono text-[11px] text-purple dark:text-[var(--vz-prog-4)] hover:underline">{e.vms_assets?.value ?? '—'}</Link> : <span className="font-mono text-[11px]">—</span> },
        { key: 'detail', header: 'Detail', className: 'max-w-[300px]', render: (e) => <span className="text-[11px] text-foreground-muted break-words">{describeEvent(e) || '—'}</span> },
        { key: 'observed', header: 'Observed by', sort: (e) => observedOf(e), render: (e) => { const o = OBSERVED[observedOf(e)]; return <span title={o.hint}><Tag>{o.label}</Tag></span>; } },
    ];
    return (
        <div className="space-y-5">
            <PageHeader icon={Activity} title="Changes & Alerts" description="What changed on the attack surface and what needs attention. Each change says how it was observed — an active scan of ours, a passive third-party source that sent no traffic to the target, or the Wazuh agent."
                actions={<Segmented label="Period" value={days} onChange={setDays} options={[['7', '7 days'], ['30', '30 days'], ['90', '90 days']]} />} />
            <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <KpiCard label="Changes" value={events.data?.events.length} reason="Loading" sub={`Last ${days} days (up to 500)`} />
                <KpiCard label="From active scans" value={events.data && scans.data ? events.data.events.filter((e) => observedOf(e) === 'active').length : undefined} reason="Loading" />
                <KpiCard label="From passive sources / Wazuh" value={events.data && scans.data ? events.data.events.filter((e) => observedOf(e) === 'passive' || observedOf(e) === 'wazuh').length : undefined} reason="Loading" />
                <KpiCard label="Alerts" value={high.data && reopened.data && events.data ? alerts.length : undefined} reason="Loading" tone={alerts.length ? 'warning' : undefined} sub={notif.data ? (notif.data.enabled ? `Email alerts on · last sent check ${notif.data.state?.last_run_at ? relTime(notif.data.state.last_run_at, now) : 'never'}` : 'Email alerts are not configured') : undefined} icon={Bell} />
            </section>
            <Segmented label="List" value={tab} onChange={setTab} options={[['changes', 'Changes'], ['alerts', `Alerts${high.data && reopened.data ? ` (${alerts.length})` : ''}`]]} />
            {tab === 'changes' ? (
                <>
                    <div className="flex flex-wrap items-center gap-2">
                        <Select label="Observed by" value={observed} onChange={setObserved} options={[['', 'Any source'], ['active', 'Active scans'], ['passive', 'Passive sources'], ['wazuh', 'Wazuh agent'], ['unknown', 'Not recorded']]} />
                        <Select label="Change" value={kind} onChange={setKind} options={[['', 'Any change'], ...Object.entries(EVENT_LABEL)] as [string, string][]} />
                        <div className="ml-auto"><ExportCsvButton filename="vms-changes.csv" rows={rows?.map((e) => ({ at: e.at, change: EVENT_LABEL[e.event] ?? e.event, asset: e.vms_assets?.value, detail: describeEvent(e), observed_by: OBSERVED[observedOf(e)].label }))} columns={[{ key: 'at', header: 'When' }, { key: 'change', header: 'Change' }, { key: 'asset', header: 'Asset' }, { key: 'detail', header: 'Detail' }, { key: 'observed_by', header: 'Observed by' }]} /></div>
                    </div>
                    {events.load.state === 'error' ? <ErrorState error={events.load.error} status={events.load.status} onRetry={events.reload} />
                        : <DataTable caption="Attack-surface changes" rows={rows} columns={columns} rowKey={(e) => e.id} initialSort={{ key: 'at', dir: 'desc' }} empty={`No changes recorded in the last ${days} days`} />}
                </>
            ) : (
                <Card>
                    <SectionTitle title="Alerts" hint="New P1/P2 findings, findings reopened by a rescan, and new internet-facing assets or services in the period." />
                    {!high.data || !reopened.data ? <div className="h-32 rounded-lg bg-card-muted motion-safe:animate-pulse" /> : alerts.length === 0 ? <EmptyState compact title="No alerts in this period" /> : (
                        <ul className="divide-y divide-border">
                            {alerts.slice(0, 100).map((a) => (
                                <li key={a.id}><Link href={a.href} className="flex items-start gap-3 py-2.5 hover:bg-card-muted/60 -mx-2 px-2 rounded-lg">
                                    <ToneIcon tone={a.tone} className="w-4 h-4 mt-0.5" />{a.priority && <PriorityBadge priority={a.priority} />}
                                    <span className="flex-1 min-w-0"><span className="block text-xs font-semibold text-foreground">{a.title}</span><span className="block text-[11px] text-foreground-muted">{a.detail}</span></span>
                                    <span className="text-[11px] text-foreground-muted whitespace-nowrap">{relTime(a.at, now)}</span>
                                </Link></li>
                            ))}
                        </ul>
                    )}
                </Card>
            )}
        </div>
    );
}

// ── Scanner Integrations ───────────────────────────────────────────────────────────────────────
export function VmsScannerIntegrations() {
    const { load, data: s, reload, at } = useAdminStatus();
    const ops = useVmsData<VmsOperations>('/api/vms/operations');
    const [check, setCheck] = useState<WazuhCheck | null>(null);
    const [checking, setChecking] = useState(false);
    const [msg, setMsg] = useState<Msg>(null);
    const now = at ?? 0;
    if (load.state === 'error') return <div className="space-y-5"><PageHeader icon={Plug} title="Scanner Integrations" /><ErrorState error={load.error} status={load.status} onRetry={reload} /></div>;
    const rows: { name: string; state: Tone; label: string; detail: string }[] = s ? [
        { name: 'Wazuh (agents and vulnerabilities)', state: !s.wazuh.available ? 'neutral' : s.wazuh.freshness?.complete === false ? 'warning' : freshTone(s.wazuh.freshness?.last_complete_at, 3, now), label: !s.wazuh.available ? 'Not set up' : s.wazuh.freshness?.last_complete_at ? `Synced ${relTime(s.wazuh.freshness.last_complete_at, now)}` : 'Never synced', detail: s.wazuh.freshness?.problem ?? s.wazuh.note ?? 'Hourly sync of agents and their vulnerabilities for this organisation' },
        { name: 'CISA KEV catalogue', state: freshTone(s.cve_intel.kev_checked_at, 48, now), label: s.cve_intel.kev_checked_at ? `Checked ${relTime(s.cve_intel.kev_checked_at, now)}` : 'Never checked', detail: `${s.cve_intel.tracked} CVEs tracked` },
        { name: 'FIRST EPSS', state: freshTone(s.cve_intel.epss_fetched_at, 48, now), label: s.cve_intel.epss_fetched_at ? `Fetched ${relTime(s.cve_intel.epss_fetched_at, now)}` : 'Never fetched', detail: 'Exploitation probability for each CVE' },
        { name: 'NVD', state: freshTone(s.cve_intel.nvd_fetched_at, 72, now), label: s.cve_intel.nvd_fetched_at ? `Fetched ${relTime(s.cve_intel.nvd_fetched_at, now)}` : 'Never fetched', detail: 'CVSS and descriptions' },
        { name: 'OSV', state: !s.cve_intel.osv?.available ? 'neutral' : freshTone(s.cve_intel.osv.fetched_at, 72, now), label: !s.cve_intel.osv?.available ? 'Not set up' : s.cve_intel.osv.fetched_at ? `Fetched ${relTime(s.cve_intel.osv.fetched_at, now)}` : 'Never fetched', detail: s.cve_intel.osv?.note ?? 'Fixed versions by package ecosystem' },
        { name: 'AI service', state: s.ai.configured ? 'good' : 'neutral', label: s.ai.configured ? 'Configured' : 'Not configured', detail: s.ai.configured ? `Model ${s.ai.model}. Drafts explanations and plans; never changes records.` : 'AI panels say AI is unavailable; nothing is generated in its place' },
        { name: 'Raw evidence store', state: s.evidence.available ? 'good' : 'neutral', label: s.evidence.available ? `${s.evidence.items} item(s)` : 'Not set up', detail: s.evidence.available ? `Redacted tool output kept ${s.evidence.retention_days} days; next expiry ${fmtWat(s.evidence.next_expiry ?? null)}` : 'Raw scan output is not kept' },
        { name: 'Scheduler', state: freshTone(s.scheduler.last_run_at, 2, now), label: s.scheduler.last_run_at ? `Ran ${relTime(s.scheduler.last_run_at, now)}` : 'Not run since start', detail: `Hourly: schedules, policies, snapshots. Last policy run ${fmtWat(s.scheduler.policies?.at ?? null)}` },
    ] : [];
    return (
        <div className="space-y-5">
            <PageHeader icon={Plug} title="Scanner Integrations" description="Every integration the VMS depends on and whether it is working, from what each last did. Only configured / not configured and timestamps are shown — no credential, token or password reaches the browser."
                actions={<button disabled={checking} onClick={async () => { setChecking(true); const r = await vmsSend<WazuhCheck>('POST', '/api/vms/admin/wazuh/check'); setChecking(false); if (r.ok) setCheck(r.data); else setMsg({ ok: false, text: r.error }); }} className={btn('secondary', 'md')}>{checking ? 'Checking Wazuh…' : 'Check Wazuh connection'}</button>} />
            <Notice msg={msg} />
            {check && (
                <Card className="space-y-1 text-xs">
                    <div className="flex items-center gap-2"><StatusPill tone={VERDICT[check.verdict].tone} label={`Wazuh: ${VERDICT[check.verdict].label}`} /><span className="text-foreground-muted">checked {fmtWat(check.checked_at)}</span></div>
                    <p>Manager API: {check.manager.ok ? `Wazuh ${check.manager.api_version ?? 'version not reported'}` : check.manager.error}</p>
                    <p>Agents: {check.agents.ok ? `${check.agents.count} in ${(check.agents.groups ?? []).join(', ') || 'no mapped group'} (${check.agents.active} active)` : check.agents.error}</p>
                    <p>Vulnerability index: {check.vulnerabilities.ok ? `${check.vulnerabilities.records_for_org} record(s) for this organisation` : check.vulnerabilities.error}</p>
                </Card>
            )}
            <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <KpiCard label="Scan engines available" value={ops.data ? ops.data.engines.filter((e) => e.state === 'available').length : undefined} suffix={ops.data ? ` / ${ops.data.engines.length}` : ''} reason="Loading" href="/admin/vms/operations/workers" />
                <KpiCard label="Workers online" value={s?.workers.online} reason="Loading" tone={s ? (s.workers.online ? 'good' : 'critical') : undefined} href="/admin/vms/operations/workers" />
                <KpiCard label="Backend version" text={s ? s.deployed_version ?? 'Not reported' : '…'} />
                <KpiCard label="Active scope entries" value={s?.scopes.active} reason="Loading" href="/admin/vms/discovery" />
            </section>
            <Card>
                <SectionTitle title="Integrations" />
                {!s ? <div className="h-48 rounded-lg bg-card-muted motion-safe:animate-pulse" /> : (
                    <ul className="divide-y divide-border">
                        {rows.map((r) => <li key={r.name} className="flex flex-wrap items-center gap-3 py-3"><span className="w-56 text-xs font-semibold text-foreground">{r.name}</span><span className="w-48"><StatusPill tone={r.state} label={r.label} /></span><span className="flex-1 min-w-[200px] text-[11px] text-foreground-muted">{r.detail}</span></li>)}
                    </ul>
                )}
            </Card>
            <Card>
                <SectionTitle title="Scan engines" hint="Available only when a connected worker runs the engine with its tools installed." />
                {ops.data ? (
                    <ul className="divide-y divide-border">
                        {ops.data.engines.map((e) => <li key={e.id} className="flex flex-wrap items-center gap-3 py-3"><span className="w-56 text-xs font-semibold text-foreground">{e.label}</span><span className="w-48"><StatusPill tone={ENGINE_TONE[e.state]} label={ENGINE_STATE_LABEL[e.state]} /></span><span className="flex-1 text-[11px] text-foreground-muted">{e.note}{e.versions.length ? ` · ${e.versions.join(', ')}` : ''}</span></li>)}
                    </ul>
                ) : <div className="h-32 rounded-lg bg-card-muted motion-safe:animate-pulse" />}
            </Card>
        </div>
    );
}

// ── Worker Health ──────────────────────────────────────────────────────────────────────────────
export function VmsWorkerHealth() {
    const can = useVmsCan();
    const { load, data: s, reload, at } = useAdminStatus();
    const ops = useVmsData<VmsOperations>('/api/vms/operations');
    const [retry, setRetry] = useState<VmsScan | null>(null);
    const [msg, setMsg] = useState<Msg>(null);
    const now = at ?? 0;
    if (load.state === 'error') return <div className="space-y-5"><PageHeader icon={Cpu} title="Worker Health" /><ErrorState error={load.error} status={load.status} onRetry={reload} /></div>;
    const kinds = Object.entries(ops.data?.last_7_days ?? {});
    return (
        <div className="space-y-5">
            <PageHeader icon={Cpu} title="Worker Health" description="The scanner workers this backend knows, what each can run, when it was last heard from, and how scans have gone in the last 7 days. A worker is online only if it called in recently." />
            <Notice msg={msg} />
            <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <KpiCard label="Workers online" value={s?.workers.online} reason="Loading" tone={s ? (s.workers.online ? 'good' : 'critical') : undefined} sub={s ? `of ${s.workers.list.length} known · online = heard from in ${Math.round(s.workers.window_seconds / 60)} min` : undefined} />
                <KpiCard label="Queued" value={ops.data?.queue.queued} reason="Loading" sub={ops.data?.queue.oldest_queued_at ? `oldest ${relTime(ops.data.queue.oldest_queued_at, now)}` : 'Nothing waiting'} />
                <KpiCard label="Running" value={ops.data?.queue.running} reason="Loading" />
                <KpiCard label="Failed (7 days)" value={ops.data ? kinds.reduce((n, [, v]) => n + v.failed, 0) : undefined} reason="Loading" tone={ops.data && kinds.some(([, v]) => v.failed) ? 'critical' : undefined} />
            </section>
            <Card>
                <SectionTitle title="Workers" />
                {!s ? <div className="h-32 rounded-lg bg-card-muted motion-safe:animate-pulse" /> : s.workers.list.length === 0 ? <EmptyState compact title="No scanner worker has connected" body="Deploy the VMS worker (runbook: deploy-vms-worker) with its own token; it appears here once it calls in." /> : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-xs">
                            <thead><tr className="text-left text-[10.5px] uppercase tracking-wide text-foreground-muted border-b border-border"><th className="py-2 pr-3">Worker</th><th className="pr-3">Status</th><th className="pr-3">Runs</th><th className="pr-3">Tools</th><th className="pr-3">Networks</th><th>Safeguards</th></tr></thead>
                            <tbody>
                                {s.workers.list.map((w) => (
                                    <tr key={w.worker_id} className="border-b border-border last:border-0 align-top">
                                        <td className="py-2.5 pr-3"><p className="font-mono font-semibold">{w.worker_id}</p><p className="text-[10.5px] text-foreground-muted">v{w.version ?? '?'}</p></td>
                                        <td className="pr-3"><StatusPill tone={w.online ? 'good' : 'warning'} label={w.online ? 'Online' : 'Not heard from'} /><p className="text-[10.5px] text-foreground-muted mt-0.5">seen {relTime(w.last_seen_at, now)}{w.last_job_at ? ` · last job ${relTime(w.last_job_at, now)}` : ''}</p></td>
                                        <td className="pr-3">{w.kinds.map((k) => <span key={k} className="block">{SCAN_KIND_LABEL[k as VmsScan['kind']] ?? k}</span>)}</td>
                                        <td className="pr-3">{Object.entries(w.tools).map(([t, ok]) => <span key={t} className={`block ${ok ? '' : 'text-foreground-muted line-through'}`}>{t}{ok && w.tool_versions[t] ? ` ${w.tool_versions[t]}` : ''}</span>)}</td>
                                        <td className="pr-3">{w.networks.join(', ') || 'Public internet only'}</td>
                                        <td>{w.features.map((f) => <span key={f} className="block">{f.replace(/_/g, ' ')}</span>)}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </Card>
            <Card>
                <SectionTitle title="Last 7 days by scan kind" hint="Inconclusive = the scan completed without reaching any host; it is not counted as succeeded." />
                {!ops.data ? <div className="h-32 rounded-lg bg-card-muted motion-safe:animate-pulse" /> : kinds.length === 0 ? <EmptyState compact title="No scans in the last 7 days" /> : (
                    <div className="overflow-x-auto"><table className="w-full text-xs">
                        <thead><tr className="text-left text-[10.5px] uppercase tracking-wide text-foreground-muted border-b border-border"><th className="py-2 pr-3">Scan</th><th className="pr-3 text-right">Succeeded</th><th className="pr-3 text-right">Inconclusive</th><th className="pr-3 text-right">Failed</th><th className="pr-3 text-right">Cancelled</th><th className="pr-3 text-right">Queued / running</th><th className="text-right">Median time</th></tr></thead>
                        <tbody>{kinds.map(([k, v]) => <tr key={k} className="border-b border-border last:border-0"><td className="py-2 pr-3 font-semibold">{SCAN_KIND_LABEL[k as VmsScan['kind']] ?? k}</td><td className="pr-3 text-right tabular-nums">{v.succeeded}</td><td className="pr-3 text-right tabular-nums">{v.inconclusive}</td><td className="pr-3 text-right tabular-nums">{v.failed}</td><td className="pr-3 text-right tabular-nums">{v.cancelled}</td><td className="pr-3 text-right tabular-nums">{v.queued + v.running}</td><td className="text-right">{fmtDuration(v.median_duration_s)}</td></tr>)}</tbody>
                    </table></div>
                )}
            </Card>
            <Card>
                <SectionTitle title="Recent failures" hint="Failed scans in the last 7 days." />
                <div className="-mx-5 -mb-5 [&>div]:rounded-none [&>div]:border-x-0 [&>div]:border-b-0">
                    <DataTable caption="Recent scan failures" rows={ops.data?.recent_failures ?? null} rowKey={(j) => j.id} pageSize={10} empty="No failed scans in the last 7 days" columns={[
                        { key: 'when', header: 'Requested', render: (j) => <span className="text-[11px] whitespace-nowrap">{fmtWat(j.requested_at)}</span> },
                        { key: 'kind', header: 'Scan', render: (j) => SCAN_KIND_LABEL[j.kind] ?? j.kind },
                        { key: 'targets', header: 'Targets', render: (j) => <span className="font-mono text-[11px]">{j.targets.join(', ')}</span> },
                        { key: 'error', header: 'Error', className: 'max-w-[320px]', render: (j) => <span className="text-[11px] text-foreground break-words">{j.error ?? '—'}</span> },
                        ...(can.scan ? [{ key: 'act', header: '', render: (j: VmsScan & { assessment_id?: string | null }) => !j.assessment_id ? <button onClick={() => setRetry(j)} className={btn('secondary')}><RotateCcw className="w-3 h-3" aria-hidden /> Retry</button> : <Link href={`/admin/vms/scans?id=${j.assessment_id}`} className="text-[11px] font-semibold underline">Assessment</Link> }] : []),
                    ]} />
                </div>
            </Card>
            <ConfirmDialog open={!!retry} title="Retry this scan?" body="It is queued again through the same scope checks as a new request." confirmLabel="Retry" onCancel={() => setRetry(null)}
                onConfirm={async () => { const j = retry!; setRetry(null); const r = await vmsSend<{ message?: string }>('POST', `/api/vms/scans/${j.id}/retry`); setMsg(r.ok ? { ok: true, text: r.data.message ?? 'Queued again' } : { ok: false, text: r.error }); ops.reload(); }} />
        </div>
    );
}

// ── Scan Policies & Configuration ──────────────────────────────────────────────────────────────
export function VmsScanConfig() {
    const { load, data: s, reload } = useAdminStatus();
    const profiles = useVmsData<{ profiles: VmsProfile[] }>('/api/vms/profiles');
    if (load.state === 'error') return <div className="space-y-5"><PageHeader icon={SlidersHorizontal} title="Scan Policies & Configuration" /><ErrorState error={load.error} status={load.status} onRetry={reload} /></div>;
    return (
        <div className="space-y-5">
            <PageHeader icon={SlidersHorizontal} title="Scan Policies & Configuration" description="What each scan profile runs, the safeguards every scan passes through, and how automation is configured. Scanner credentials and worker tokens live on the server and the worker host only." />
            <Card>
                <SectionTitle title="Scan profiles" hint="A profile runs only the steps its authorised scope allows and a connected worker can perform." />
                {!profiles.data ? <div className="h-40 rounded-lg bg-card-muted motion-safe:animate-pulse" /> : (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                        {profiles.data.profiles.map((p) => (
                            <div key={p.id} className="border border-border rounded-xl p-4 space-y-1.5">
                                <div className="flex items-center justify-between gap-2"><p className="text-sm font-bold text-foreground">{p.label}</p><StatusPill tone={!p.runnable ? 'neutral' : p.available === false ? 'warning' : 'good'} label={!p.runnable ? 'Not startable manually' : p.available === false ? 'Engines unavailable' : 'Available'} /></div>
                                <p className="text-[11px] text-foreground-muted">{p.description}</p>
                                <p className="text-[11px] text-foreground"><b>Steps:</b> {p.steps.join(' → ') || '—'}</p>
                                <p className="text-[11px] text-foreground"><b>Ports:</b> {p.ports} · <b>Engines:</b> {p.engines.join(', ') || '—'}</p>
                                {p.availability_note && <p className="text-[11px] text-foreground-muted">{p.availability_note}</p>}
                                {p.not_covered.length > 0 && <p className="text-[11px] text-foreground-muted">Not covered: {p.not_covered.join('; ')}</p>}
                            </div>
                        ))}
                    </div>
                )}
            </Card>
            <section className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <Card>
                    <SectionTitle title="Safeguards on every scan" />
                    <ul className="space-y-2 text-xs text-foreground list-disc pl-4">
                        <li>Targets must be inside an active, unexpired authorised scope with an authorisation reference; exclusions are never touched.</li>
                        <li>Each scope says what may run: discovery, port scans, vulnerability scans — separately.</li>
                        <li>Workers authenticate with their own token, re-check scope before running, and report results that the backend validates again.</li>
                        <li>Scan requests, scope changes, policy changes and cross-organisation access are written to the audit log.</li>
                        <li>A scan that reaches no host is recorded as inconclusive, never as assessed.</li>
                    </ul>
                </Card>
                <Card>
                    <SectionTitle title="Current configuration" />
                    {!s ? <div className="h-32 rounded-lg bg-card-muted motion-safe:animate-pulse" /> : (
                        <dl className="grid grid-cols-2 gap-3 text-xs">
                            <div><dt className="text-[10.5px] uppercase text-foreground-muted">Active scope entries</dt><dd className="font-semibold">{s.scopes.active} ({s.scopes.passive_only} passive only)</dd></div>
                            <div><dt className="text-[10.5px] uppercase text-foreground-muted">Allow vulnerability scans</dt><dd className="font-semibold">{s.scopes.vuln_allowed}</dd></div>
                            <div><dt className="text-[10.5px] uppercase text-foreground-muted">With exclusions</dt><dd className="font-semibold">{s.scopes.with_exclusions}</dd></div>
                            <div><dt className="text-[10.5px] uppercase text-foreground-muted">Expired or revoked</dt><dd className="font-semibold">{s.scopes.expired_or_revoked}</dd></div>
                            <div><dt className="text-[10.5px] uppercase text-foreground-muted">Monitoring rules enabled</dt><dd className="font-semibold">{s.policies.available ? `${s.policies.list?.filter((p) => p.enabled).length ?? 0} of ${s.policies.list?.length ?? 0}` : 'Not set up'}</dd></div>
                            <div><dt className="text-[10.5px] uppercase text-foreground-muted">Evidence retention</dt><dd className="font-semibold">{s.evidence.available ? `${s.evidence.retention_days} days` : 'Not set up'}</dd></div>
                        </dl>
                    )}
                    <div className="flex flex-wrap gap-2 mt-4">
                        <Link href="/admin/vms/monitoring" className={btn('secondary')}><Cog className="w-3.5 h-3.5" aria-hidden /> Monitoring rules</Link>
                        <Link href="/admin/vms/monitoring/schedules" className={btn('secondary')}><CalendarClock className="w-3.5 h-3.5" aria-hidden /> Scan schedules</Link>
                        <Link href="/admin/vms/discovery" className={btn('secondary')}><ShieldCheck className="w-3.5 h-3.5" aria-hidden /> Authorised scope</Link>
                    </div>
                </Card>
            </section>
        </div>
    );
}
