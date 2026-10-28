'use client';

// Reporting Center (phase P30, R3.3E): schedule and recipient administration, generate-now,
// history/downloads and delivery status for VMS, CNII Watch, Threat Intelligence and the unified
// Executive Summary. Reads real data from /api/reports/* — see backend/src/routes/reports.ts.
//
// reports:read (analyst, executive and above) sees everything here except schedule/recipient
// administration and "generate & deliver" — those need reports:manage (not executive: adding a
// recipient can add an external email address, the same staff-only line every other :manage
// permission in this app draws). Scheduler health is staff-only (super_admin/soc_manager), since
// it is platform-wide, not scoped to one organisation.

import { useCallback, useEffect, useState } from 'react';
import { FileBarChart, Calendar, Users, History as HistoryIcon, Activity, Download, RefreshCw, ShieldCheck, AlertTriangle, Trash2, Plus } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { loadJson } from '@/lib/alerts';
import { getAdminUser } from '@/lib/admin-auth';
import { Donut, type Slice } from '@/components/features/vms/charts';

type ReportType = 'vms' | 'cnii' | 'threat_intel' | 'executive_summary';
type ReportFormat = 'executive' | 'technical';

interface TypeInfo { report_type: ReportType; label: string; available: boolean; module: string | null }
interface Schedule {
    id: string; report_type: ReportType; format: ReportFormat; cadence: 'weekly' | 'monthly';
    day_of_week: number | null; day_of_month: number | null; hour_local: number; timezone: string;
    enabled: boolean; next_run_at: string | null; last_success_at: string | null; last_failure_at: string | null; last_error: string | null;
}
interface Recipient {
    id: string; kind: 'portal_user' | 'external_email'; email: string; display_name: string | null;
    report_types: ReportType[]; enabled: boolean; external_authorised_by: string | null; added_by: string; added_at: string;
}
interface Delivery { report_job_id: string; status: string; recipient_email: string; error: string | null; id?: string }
interface Job {
    id: string; report_type: ReportType; format: ReportFormat; status: string; trigger: 'scheduled' | 'manual';
    requested_at: string; finished_at: string | null; last_error: string | null; deliveries: Delivery[];
}
interface OpsHealth {
    scheduler: { at: string | null; enqueued: number; processed: number; last_error: string | null };
    queue: { queued: number; running: number };
    stuck_jobs: { id: string; org_id: string; report_type: string; claimed_at: string; worker_id: string }[];
    recent_failures: { id: string; org_id: string; report_type: string; last_error: string | null; finished_at: string }[];
}

const TYPE_LABEL: Record<ReportType, string> = { vms: 'Vulnerability & Exposure', cnii: 'CNII Watch', threat_intel: 'Threat Intelligence', executive_summary: 'Unified Executive Summary' };
const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const fmt = (iso: string | null) => (iso ? new Intl.DateTimeFormat('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', year: '2-digit', hour: '2-digit', minute: '2-digit' }).format(new Date(iso)) + ' WAT' : '—');
const STATUS_STYLE: Record<string, string> = {
    completed: 'bg-green/10 text-green', sent: 'bg-green/10 text-green', partial: 'bg-amber/10 text-amber',
    queued: 'bg-card-muted text-foreground-muted', running: 'bg-blue/10 text-blue', failed: 'bg-red/10 text-red',
};
const Badge = ({ s }: { s: string }) => <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${STATUS_STYLE[s] ?? 'bg-card-muted text-foreground-muted'}`}>{s}</span>;

async function downloadArtifact(jobId: string, format: 'pdf' | 'csv') {
    const r = await apiFetch(apiUrl(`/api/reports/${jobId}/download?format=${format}`));
    if (!r.ok) { window.alert(`Could not download: HTTP ${r.status}`); return; }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `report-${jobId}.${format}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

export function ReportingCenter() {
    const me = getAdminUser();
    const canManage = me.role === 'super_admin' || me.role === 'soc_manager' || me.role === 'analyst';
    const isStaff = me.role === 'super_admin' || me.role === 'soc_manager';
    const [tab, setTab] = useState<'generate' | 'schedules' | 'recipients' | 'history' | 'ops'>('generate');
    const [types, setTypes] = useState<TypeInfo[] | null>(null);
    const [schedules, setSchedules] = useState<Schedule[] | null>(null);
    const [recipients, setRecipients] = useState<Recipient[] | null>(null);
    const [jobs, setJobs] = useState<Job[] | null>(null);
    const [ops, setOps] = useState<OpsHealth | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [msg, setMsg] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);
    const [reloadKey, setReloadKey] = useState(0);
    const reload = useCallback(() => setReloadKey((k) => k + 1), []);

    useEffect(() => {
        let active = true;
        void loadJson<{ types: TypeInfo[] }>('/api/reports/types').then((r) => { if (active) setTypes(r.ok ? r.data.types : null); });
        void loadJson<{ schedules: Schedule[] }>('/api/reports/schedules').then((r) => { if (active) setSchedules(r.ok ? r.data.schedules : null); });
        void loadJson<{ recipients: Recipient[] }>('/api/reports/recipients').then((r) => { if (active) setRecipients(r.ok ? r.data.recipients : null); });
        void loadJson<{ jobs: Job[] }>('/api/reports/history').then((r) => { if (active) setJobs(r.ok ? r.data.jobs : null); else setError(r.ok ? null : r.error); });
        if (isStaff) void loadJson<OpsHealth>('/api/reports/ops/health').then((r) => { if (active) setOps(r.ok ? r.data : null); });
        return () => { active = false; };
    }, [reloadKey, isStaff]);

    const post = async (path: string, body?: unknown, method = 'POST') => {
        setBusy(true); setError(null); setMsg(null);
        try {
            const r = await apiFetch(apiUrl(path), { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
            const d = await r.json().catch(() => null);
            if (!r.ok) { setError(d?.error ?? `HTTP ${r.status}`); return null; }
            reload();
            return d;
        } catch {
            setError('Could not reach the backend');
            return null;
        } finally {
            setBusy(false);
        }
    };

    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground flex items-center gap-2"><FileBarChart className="w-5 h-5" /> Reporting Center</h1>
                <p className="text-xs text-foreground-muted">Scheduled and on-demand client reporting across VMS, CNII Watch and Threat Intelligence.</p>
            </div>
            <div className="flex gap-1 bg-card border border-border rounded-lg p-1 flex-wrap">
                {([['generate', 'Generate', FileBarChart], ['schedules', 'Schedules', Calendar], ['recipients', 'Recipients', Users], ['history', 'History', HistoryIcon], ...(isStaff ? [['ops', 'Scheduler Health', Activity] as const] : [])] as [typeof tab, string, typeof FileBarChart][]).map(([k, label, Icon]) => (
                    <button key={k} onClick={() => setTab(k)} className={`text-[11px] font-bold px-2.5 py-1.5 rounded-md flex items-center gap-1 ${tab === k ? 'bg-blue text-white' : 'text-foreground-muted'}`}><Icon className="w-3.5 h-3.5" /> {label}</button>
                ))}
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {msg && <p role="status" className="text-xs text-green font-semibold">{msg}</p>}

            {tab === 'generate' && (
                <GeneratePanel types={types} canManage={canManage} busy={busy}
                    onGenerate={async (body) => {
                        const d = await post('/api/reports/generate', body);
                        if (d) { setMsg(`Report generated (${d.status}).${d.warnings?.length ? ` Limitations: ${d.warnings.join('; ')}` : ''}`); setTab('history'); }
                    }} />
            )}

            {tab === 'schedules' && (
                <SchedulesPanel schedules={schedules} types={types} canManage={canManage} busy={busy}
                    onCreate={(body) => post('/api/reports/schedules', body)}
                    onToggle={(id, enabled) => post(`/api/reports/schedules/${id}`, { enabled }, 'PATCH')}
                    onDelete={(id) => post(`/api/reports/schedules/${id}`, undefined, 'DELETE')} />
            )}

            {tab === 'recipients' && (
                <RecipientsPanel recipients={recipients} canManage={canManage} busy={busy}
                    onCreate={(body) => post('/api/reports/recipients', body)}
                    onToggle={(id, enabled) => post(`/api/reports/recipients/${id}`, { enabled }, 'PATCH')}
                    onAuthorise={(id) => post(`/api/reports/recipients/${id}/authorise`)}
                    onDelete={(id) => post(`/api/reports/recipients/${id}`, undefined, 'DELETE')} />
            )}

            {tab === 'history' && <HistoryPanel jobs={jobs} canManage={canManage} busy={busy} onRetry={(id) => post(`/api/reports/deliveries/${id}/retry`)} />}

            {tab === 'ops' && isStaff && <OpsPanel ops={ops} />}
        </div>
    );
}

function GeneratePanel({ types, canManage, busy, onGenerate }: { types: TypeInfo[] | null; canManage: boolean; busy: boolean; onGenerate: (b: Record<string, unknown>) => void }) {
    const [reportType, setReportType] = useState<ReportType>('vms');
    const [format, setFormat] = useState<ReportFormat>('executive');
    const [periodDays, setPeriodDays] = useState(30);
    const [deliver, setDeliver] = useState(false);
    const info = types?.find((t) => t.report_type === reportType);
    return (
        <div className="bg-card border border-border rounded-xl p-4 space-y-3 max-w-xl">
            <h2 className="text-sm font-black text-foreground">Generate a report now</h2>
            <div className="grid grid-cols-2 gap-3">
                <label className="text-xs space-y-1">
                    <span className="text-foreground-muted font-semibold">Report type</span>
                    <select value={reportType} onChange={(e) => setReportType(e.target.value as ReportType)} className="w-full bg-background border border-border rounded-lg px-2 py-1.5">
                        {(types ?? Object.keys(TYPE_LABEL).map((k) => ({ report_type: k as ReportType, label: TYPE_LABEL[k as ReportType], available: true, module: null }))).map((t) => (
                            <option key={t.report_type} value={t.report_type} disabled={!t.available}>{t.label}{!t.available ? ' (module not enabled)' : ''}</option>
                        ))}
                    </select>
                </label>
                <label className="text-xs space-y-1">
                    <span className="text-foreground-muted font-semibold">Format</span>
                    <select value={format} onChange={(e) => setFormat(e.target.value as ReportFormat)} className="w-full bg-background border border-border rounded-lg px-2 py-1.5">
                        <option value="executive">Executive</option>
                        <option value="technical">Technical</option>
                    </select>
                </label>
                <label className="text-xs space-y-1">
                    <span className="text-foreground-muted font-semibold">Period (days)</span>
                    <input type="number" min={1} max={365} value={periodDays} onChange={(e) => setPeriodDays(Number(e.target.value))} className="w-full bg-background border border-border rounded-lg px-2 py-1.5" />
                </label>
                {canManage && (
                    <label className="text-xs space-y-1 flex flex-col justify-end">
                        <span className="flex items-center gap-2"><input type="checkbox" checked={deliver} onChange={(e) => setDeliver(e.target.checked)} /> <span className="font-semibold">Also deliver to configured recipients</span></span>
                    </label>
                )}
            </div>
            {info && !info.available && <p className="text-xs text-amber flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5" /> {info.module} is not enabled for this organisation.</p>}
            <button disabled={busy || (info && !info.available)} onClick={() => onGenerate({ report_type: reportType, format, period_days: periodDays, deliver })} className="text-xs font-bold bg-blue text-white px-3 py-1.5 rounded-lg disabled:opacity-50">
                {deliver ? 'Generate & deliver' : 'Generate (view only)'}
            </button>
            <p className="text-[10px] text-foreground-muted">Scheduled and emailed reports always generate at a conservative client data-sensitivity ceiling, regardless of who signed in — an email leaves the platform&apos;s access controls the moment it is sent.</p>
        </div>
    );
}

function SchedulesPanel({ schedules, types, canManage, busy, onCreate, onToggle, onDelete }: {
    schedules: Schedule[] | null; types: TypeInfo[] | null; canManage: boolean; busy: boolean;
    onCreate: (b: Record<string, unknown>) => void; onToggle: (id: string, enabled: boolean) => void; onDelete: (id: string) => void;
}) {
    const [open, setOpen] = useState(false);
    const [reportType, setReportType] = useState<ReportType>('vms');
    const [cadence, setCadence] = useState<'weekly' | 'monthly'>('weekly');
    const [dayOfWeek, setDayOfWeek] = useState(1);
    const [dayOfMonth, setDayOfMonth] = useState(1);
    const [hourLocal, setHourLocal] = useState(8);
    return (
        <div className="space-y-3">
            {canManage && (
                <div className="bg-card border border-border rounded-xl p-4 space-y-3">
                    <button onClick={() => setOpen((o) => !o)} className="text-xs font-bold text-blue flex items-center gap-1"><Plus className="w-3.5 h-3.5" /> New schedule</button>
                    {open && (
                        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 text-xs">
                            <label className="space-y-1"><span className="text-foreground-muted font-semibold">Report type</span>
                                <select value={reportType} onChange={(e) => setReportType(e.target.value as ReportType)} className="w-full bg-background border border-border rounded-lg px-2 py-1.5">
                                    {(types ?? []).map((t) => <option key={t.report_type} value={t.report_type} disabled={!t.available}>{t.label}</option>)}
                                </select>
                            </label>
                            <label className="space-y-1"><span className="text-foreground-muted font-semibold">Cadence</span>
                                <select value={cadence} onChange={(e) => setCadence(e.target.value as 'weekly' | 'monthly')} className="w-full bg-background border border-border rounded-lg px-2 py-1.5">
                                    <option value="weekly">Weekly</option><option value="monthly">Monthly</option>
                                </select>
                            </label>
                            {cadence === 'weekly'
                                ? <label className="space-y-1"><span className="text-foreground-muted font-semibold">Day</span>
                                    <select value={dayOfWeek} onChange={(e) => setDayOfWeek(Number(e.target.value))} className="w-full bg-background border border-border rounded-lg px-2 py-1.5">
                                        {DAYS.map((d, i) => <option key={d} value={i}>{d}</option>)}
                                    </select>
                                </label>
                                : <label className="space-y-1"><span className="text-foreground-muted font-semibold">Day of month</span>
                                    <input type="number" min={1} max={28} value={dayOfMonth} onChange={(e) => setDayOfMonth(Number(e.target.value))} className="w-full bg-background border border-border rounded-lg px-2 py-1.5" />
                                </label>}
                            <label className="space-y-1"><span className="text-foreground-muted font-semibold">Hour (Africa/Lagos)</span>
                                <input type="number" min={0} max={23} value={hourLocal} onChange={(e) => setHourLocal(Number(e.target.value))} className="w-full bg-background border border-border rounded-lg px-2 py-1.5" />
                            </label>
                            <div className="flex items-end">
                                <button disabled={busy} onClick={() => onCreate({ report_type: reportType, cadence, day_of_week: cadence === 'weekly' ? dayOfWeek : undefined, day_of_month: cadence === 'monthly' ? dayOfMonth : undefined, hour_local: hourLocal, enabled: true })} className="text-xs font-bold bg-blue text-white px-3 py-1.5 rounded-lg disabled:opacity-50">Create</button>
                            </div>
                        </div>
                    )}
                </div>
            )}
            {schedules === null ? <p className="text-xs text-foreground-muted">Not connected.</p> : schedules.length === 0 ? <p className="text-xs text-foreground-muted">No schedules yet.</p> : (
                <div className="bg-card border border-border rounded-xl divide-y divide-border">
                    {schedules.map((s) => (
                        <div key={s.id} className="p-3 flex items-center justify-between gap-2 flex-wrap text-xs">
                            <div>
                                <p className="font-bold text-foreground">{TYPE_LABEL[s.report_type]} · {s.format}</p>
                                <p className="text-foreground-muted">{s.cadence === 'weekly' ? DAYS[s.day_of_week ?? 0] : `Day ${s.day_of_month} of the month`} at {String(s.hour_local).padStart(2, '0')}:00 {s.timezone} · next run {fmt(s.next_run_at)}</p>
                                {s.last_error && <p className="text-amber">{s.last_error}</p>}
                            </div>
                            {canManage && (
                                <div className="flex items-center gap-2">
                                    <button disabled={busy} onClick={() => onToggle(s.id, !s.enabled)} className={`font-bold px-2 py-1 rounded-md ${s.enabled ? 'bg-green/10 text-green' : 'bg-card-muted text-foreground-muted'}`}>{s.enabled ? 'Enabled' : 'Disabled'}</button>
                                    <button disabled={busy} onClick={() => onDelete(s.id)} className="text-red"><Trash2 className="w-4 h-4" /></button>
                                </div>
                            )}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

function RecipientsPanel({ recipients, canManage, busy, onCreate, onToggle, onAuthorise, onDelete }: {
    recipients: Recipient[] | null; canManage: boolean; busy: boolean;
    onCreate: (b: Record<string, unknown>) => void; onToggle: (id: string, enabled: boolean) => void; onAuthorise: (id: string) => void; onDelete: (id: string) => void;
}) {
    const [open, setOpen] = useState(false);
    const [kind, setKind] = useState<'portal_user' | 'external_email'>('portal_user');
    const [email, setEmail] = useState('');
    return (
        <div className="space-y-3">
            {canManage && (
                <div className="bg-card border border-border rounded-xl p-4 space-y-3">
                    <button onClick={() => setOpen((o) => !o)} className="text-xs font-bold text-blue flex items-center gap-1"><Plus className="w-3.5 h-3.5" /> Add recipient</button>
                    {open && (
                        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                            <label className="space-y-1"><span className="text-foreground-muted font-semibold">Kind</span>
                                <select value={kind} onChange={(e) => setKind(e.target.value as 'portal_user' | 'external_email')} className="w-full bg-background border border-border rounded-lg px-2 py-1.5">
                                    <option value="portal_user">Existing NovrSOC account</option>
                                    <option value="external_email">External email address</option>
                                </select>
                            </label>
                            <label className="space-y-1 lg:col-span-2"><span className="text-foreground-muted font-semibold">Email</span>
                                <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="name@example.com" className="w-full bg-background border border-border rounded-lg px-2 py-1.5" />
                            </label>
                            <div className="flex items-end">
                                <button disabled={busy || !email} onClick={() => { onCreate({ kind, email }); setEmail(''); }} className="text-xs font-bold bg-blue text-white px-3 py-1.5 rounded-lg disabled:opacity-50">Add</button>
                            </div>
                            {kind === 'external_email' && <p className="col-span-full text-amber text-[10px] flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> An external address must be explicitly authorised below before any report is sent to it.</p>}
                        </div>
                    )}
                </div>
            )}
            {recipients === null ? <p className="text-xs text-foreground-muted">Not connected.</p> : recipients.length === 0 ? <p className="text-xs text-foreground-muted">No recipients yet.</p> : (
                <div className="bg-card border border-border rounded-xl divide-y divide-border">
                    {recipients.map((r) => {
                        const needsAuth = r.kind === 'external_email' && !r.external_authorised_by;
                        return (
                            <div key={r.id} className="p-3 flex items-center justify-between gap-2 flex-wrap text-xs">
                                <div>
                                    <p className="font-bold text-foreground">{r.email} <span className="text-foreground-muted font-normal">({r.kind === 'portal_user' ? 'NovrSOC account' : 'external'})</span></p>
                                    <p className="text-foreground-muted">{r.report_types.length === 0 ? 'All report types' : r.report_types.map((t) => TYPE_LABEL[t]).join(', ')}{needsAuth ? ' · awaiting authorisation' : ''}</p>
                                </div>
                                {canManage && (
                                    <div className="flex items-center gap-2">
                                        {needsAuth && <button disabled={busy} onClick={() => onAuthorise(r.id)} className="font-bold px-2 py-1 rounded-md bg-amber/10 text-amber flex items-center gap-1"><ShieldCheck className="w-3.5 h-3.5" /> Authorise</button>}
                                        <button disabled={busy} onClick={() => onToggle(r.id, !r.enabled)} className={`font-bold px-2 py-1 rounded-md ${r.enabled ? 'bg-green/10 text-green' : 'bg-card-muted text-foreground-muted'}`}>{r.enabled ? 'Enabled' : 'Disabled'}</button>
                                        <button disabled={busy} onClick={() => onDelete(r.id)} className="text-red"><Trash2 className="w-4 h-4" /></button>
                                    </div>
                                )}
                            </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
}

const JOB_STATUS_TOKEN = { completed: '--vz-good', partial: '--vz-warning', failed: '--vz-critical', running: '--vz-prog-2', queued: '--vz-neutral' } as const;
const JOB_STATUS_LABEL: Record<keyof typeof JOB_STATUS_TOKEN, string> = { completed: 'Completed', partial: 'Partial', failed: 'Failed', running: 'Running', queued: 'Queued' };

function HistoryPanel({ jobs, canManage, busy, onRetry }: { jobs: Job[] | null; canManage: boolean; busy: boolean; onRetry: (deliveryId: string) => void }) {
    if (jobs === null) return <p className="text-xs text-foreground-muted">Not connected.</p>;
    if (jobs.length === 0) return <p className="text-xs text-foreground-muted">No reports generated yet.</p>;
    const counts: Record<string, number> = {};
    for (const j of jobs) counts[j.status] = (counts[j.status] ?? 0) + 1;
    const slices: Slice[] = (Object.keys(JOB_STATUS_TOKEN) as (keyof typeof JOB_STATUS_TOKEN)[]).filter((s) => counts[s]).map((s) => ({ key: s, label: JOB_STATUS_LABEL[s], value: counts[s], token: JOB_STATUS_TOKEN[s] }));
    return (
        <div className="space-y-3">
            {slices.length > 0 && (
                <div className="bg-card border border-border rounded-xl p-4">
                    <p className="text-xs font-black text-foreground mb-3">Report runs by outcome</p>
                    <Donut slices={slices} centerLabel={`${jobs.length} runs`} label="Report runs by outcome" size={140} />
                </div>
            )}
            <div className="bg-card border border-border rounded-xl divide-y divide-border">
            {jobs.map((j) => (
                <div key={j.id} className="p-3 space-y-2 text-xs">
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                        <div>
                            <p className="font-bold text-foreground">{TYPE_LABEL[j.report_type]} · {j.format} · <Badge s={j.status} /></p>
                            <p className="text-foreground-muted">{j.trigger === 'manual' ? 'Manual' : 'Scheduled'} · requested {fmt(j.requested_at)}{j.finished_at ? ` · finished ${fmt(j.finished_at)}` : ''}</p>
                            {j.last_error && <p className="text-amber">{j.last_error}</p>}
                        </div>
                        <div className="flex gap-2">
                            <button onClick={() => downloadArtifact(j.id, 'pdf')} className="font-bold px-2 py-1 rounded-md bg-card-muted text-foreground flex items-center gap-1"><Download className="w-3.5 h-3.5" /> PDF</button>
                            <button onClick={() => downloadArtifact(j.id, 'csv')} className="font-bold px-2 py-1 rounded-md bg-card-muted text-foreground flex items-center gap-1"><Download className="w-3.5 h-3.5" /> CSV</button>
                        </div>
                    </div>
                    {j.deliveries.length > 0 && (
                        <div className="pl-2 border-l-2 border-border space-y-1">
                            {j.deliveries.map((d, i) => (
                                <div key={`${d.recipient_email}-${i}`} className="flex items-center gap-2">
                                    <Badge s={d.status} /> <span>{d.recipient_email}</span>
                                    {d.error && <span className="text-red">{d.error}</span>}
                                    {canManage && d.status === 'failed' && d.id && <button disabled={busy} onClick={() => onRetry(d.id!)} className="text-blue font-bold flex items-center gap-1"><RefreshCw className="w-3 h-3" /> Retry</button>}
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            ))}
            </div>
        </div>
    );
}

function OpsPanel({ ops }: { ops: OpsHealth | null }) {
    if (ops === null) return <p className="text-xs text-foreground-muted">Not connected.</p>;
    return (
        <div className="space-y-3">
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                <div className="bg-card border border-border rounded-xl p-4"><p className="text-[10px] font-bold text-foreground-muted uppercase">Last scheduler tick</p><p className="text-sm font-black text-foreground">{fmt(ops.scheduler.at)}</p></div>
                <div className="bg-card border border-border rounded-xl p-4"><p className="text-[10px] font-bold text-foreground-muted uppercase">Queued jobs</p><p className="text-2xl font-black text-foreground">{ops.queue.queued}</p></div>
                <div className="bg-card border border-border rounded-xl p-4"><p className="text-[10px] font-bold text-foreground-muted uppercase">Running jobs</p><p className="text-2xl font-black text-foreground">{ops.queue.running}</p></div>
                <div className="bg-card border border-border rounded-xl p-4"><p className="text-[10px] font-bold text-foreground-muted uppercase">Stuck (&gt;30m)</p><p className="text-2xl font-black text-foreground">{ops.stuck_jobs.length}</p></div>
            </div>
            {ops.scheduler.last_error && <p className="text-xs text-red">{ops.scheduler.last_error}</p>}
            {ops.stuck_jobs.length > 0 && (
                <div className="bg-card border border-border rounded-xl p-4 text-xs space-y-1">
                    <h2 className="font-black text-foreground">Stuck jobs</h2>
                    {ops.stuck_jobs.map((j) => <p key={j.id}>{j.org_id} · {TYPE_LABEL[j.report_type as ReportType] ?? j.report_type} · claimed by {j.worker_id} at {fmt(j.claimed_at)}</p>)}
                </div>
            )}
            <div className="bg-card border border-border rounded-xl p-4 text-xs space-y-1">
                <h2 className="font-black text-foreground">Recent failures (7 days)</h2>
                {ops.recent_failures.length === 0 ? <p className="text-foreground-muted">None.</p> : ops.recent_failures.map((f) => <p key={f.id}>{f.org_id} · {TYPE_LABEL[f.report_type as ReportType] ?? f.report_type} · {fmt(f.finished_at)} — {f.last_error}</p>)}
            </div>
        </div>
    );
}
