'use client';

// Vulnerability Detection — Scan Management and Scan Results & History (redesign, phase P20).
// Starting a scan goes through the existing endpoints (POST /api/vms/assessments, POST /api/vms/scans),
// which check authorised scope, exclusions, the scan kinds the scope allows and the caller's
// permission; the form only offers what the scope allows and says which engines a connected worker
// can actually run. A scan that "succeeded" without reaching any host is shown as inconclusive.

import { useEffect, useMemo, useState } from 'react';
import { useRouter, useSearchParams, usePathname } from 'next/navigation';
import Link from 'next/link';
import { ScanSearch, History, Download, RefreshCw, Play, XCircle, RotateCcw } from 'lucide-react';
import { apiFetch, apiUrl } from '@/lib/api';
import {
    fmtWat, fmtDuration, scanProgress, SCAN_KIND_LABEL, PROFILE_LABEL, TRIGGER_LABEL, OUTCOME_LABEL, STEP_STATUS_LABEL, ASSESSMENT_STATUS_LABEL, RETRYABLE_STEPS, ENGINE_STATE_LABEL,
    type VmsScan, type VmsScope, type VmsAssessment, type VmsProfile, type VmsEvidence, type StepStatus, type AssessmentStatus, type VmsOperations,
} from '@/lib/vms';
import { Card, SectionTitle, StatusPill, type Tone } from './ui';
import { PageHeader, KpiCard, PriorityBadge, Segmented, Select, Drawer, ConfirmDialog, ErrorState, Notice, EmptyState, EvidenceViewer, ExportCsvButton, Tag, btn, relTime, type Msg } from './kit';
import { DataTable, type Column } from './table';
import { ScanResult } from './VmsRemediationPlus';
import { useVmsData, useVmsCan, vmsSend } from './data';

type Scan = VmsScan & { findings_count?: number; attempts?: number; assessment_id?: string | null };
interface AssessmentDetail { assessment: VmsAssessment; findings: { id: string; title: string; priority: string | null; status: string; evidence_class: string; port: number | null }[]; evidence: (Omit<VmsEvidence, 'content'> & { job_id: string })[] }

const STEP_TONE: Record<StepStatus, Tone> = { pending: 'neutral', running: 'neutral', completed: 'good', findings_detected: 'serious', inconclusive: 'warning', failed: 'critical', not_attempted: 'warning', unsupported: 'warning' };
const ASSESS_TONE: Record<AssessmentStatus, Tone> = { in_progress: 'neutral', completed: 'good', partial: 'warning', inconclusive: 'warning', failed: 'critical', not_attempted: 'warning', cancelled: 'neutral' };
const ENGINE_FOR: Record<string, string> = { discovery: 'discovery', ports: 'nmap', vuln_nuclei: 'nuclei', vuln_openvas: 'openvas' };

function useParam(key: string) {
    const params = useSearchParams();
    const router = useRouter();
    const pathname = usePathname();
    const v = params.get(key);
    const set = (x: string | null) => { const p = new URLSearchParams(params.toString()); if (x) p.set(key, x); else p.delete(key); router.replace(`${pathname}${p.toString() ? `?${p.toString()}` : ''}`, { scroll: false }); };
    return [v, set] as const;
}

// ── Scan Management ────────────────────────────────────────────────────────────────────────────
export function VmsScanManagement() {
    const can = useVmsCan();
    const scans = useVmsData<{ scans: Scan[] }>('/api/vms/scans?limit=100');
    const assessments = useVmsData<{ assessments: VmsAssessment[] }>('/api/vms/assessments');
    const [assessmentId, setAssessmentId] = useParam('id');
    const [scanId, setScanId] = useParam('scan');
    const [msg, setMsg] = useState<Msg>(null);
    const [cancel, setCancel] = useState<Scan | null>(null);
    const active = useMemo(() => scans.data?.scans.filter((s) => s.status === 'queued' || s.status === 'running') ?? null, [scans.data]);
    const now = scans.at ?? 0;
    const live = !!active?.length || !!assessments.data?.assessments.some((a) => a.status === 'in_progress');
    const { reload: reloadScans } = scans;
    const { reload: reloadAssessments } = assessments;
    useEffect(() => {
        if (!live) return;
        const t = setInterval(() => { reloadScans(); reloadAssessments(); }, 15_000);
        return () => clearInterval(t);
    }, [live, reloadScans, reloadAssessments]);

    const activeCols: Column<Scan>[] = [
        { key: 'kind', header: 'Scan', render: (s) => <div><p className="font-semibold text-foreground">{SCAN_KIND_LABEL[s.kind] ?? s.kind}</p><p className="text-[10.5px] text-foreground-muted">{s.purpose === 'verification' ? 'Verification' : s.assessment_id ? 'Part of an assessment' : 'Single scan'}</p></div> },
        { key: 'targets', header: 'Targets', className: 'max-w-[260px]', render: (s) => <span className="text-[11px] font-mono break-all">{s.targets.slice(0, 3).join(', ')}{s.targets.length > 3 ? ` +${s.targets.length - 3}` : ''}</span> },
        { key: 'state', header: 'State', render: (s) => <div className="space-y-0.5"><StatusPill tone="neutral" label={s.status === 'running' ? (s.cancel_requested ? 'Stopping' : 'Running') : 'Queued'} />{s.attention && <p className="text-[10.5px] text-foreground max-w-[260px]">{s.attention}</p>}</div> },
        { key: 'progress', header: 'Progress', hideBelow: 'md', render: (s) => <span className="text-[11px] text-foreground-muted">{scanProgress(s.progress) || '—'}{s.heartbeat_at ? ` · heartbeat ${relTime(s.heartbeat_at, now)}` : ''}</span> },
        { key: 'when', header: 'Requested', hideBelow: 'lg', render: (s) => <span className="text-[11px] text-foreground-muted whitespace-nowrap">{relTime(s.requested_at, now)} · {s.requested_by}</span> },
        ...(can.scan ? [{ key: 'act', header: '', render: (s: Scan) => !s.cancel_requested ? <button onClick={(e) => { e.stopPropagation(); setCancel(s); }} className={btn('ghost')}><XCircle className="w-3.5 h-3.5" aria-hidden /> Cancel</button> : null }] : []),
    ];
    const assessCols: Column<VmsAssessment>[] = [
        { key: 'target', header: 'Target', render: (a) => <span className="font-mono font-semibold text-foreground break-all">{a.target}</span>, sort: (a) => a.target },
        { key: 'profile', header: 'Profile', render: (a) => <span className="text-[11px]">{PROFILE_LABEL[a.profile] ?? a.profile}{a.trigger && a.trigger !== 'manual' ? <span className="block text-[10.5px] text-foreground-muted">{TRIGGER_LABEL[a.trigger] ?? a.trigger}</span> : null}</span> },
        { key: 'status', header: 'Status', render: (a) => <StatusPill tone={ASSESS_TONE[a.status]} label={`${ASSESSMENT_STATUS_LABEL[a.status]} · ${a.progress.finished}/${a.progress.total}`} />, sort: (a) => a.status },
        { key: 'steps', header: 'Checks', hideBelow: 'lg', render: (a) => <div className="flex flex-wrap gap-1">{a.steps.map((s) => <span key={s.kind} title={s.detail} className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-card-muted text-foreground-muted">{s.label}: {STEP_STATUS_LABEL[s.status]}</span>)}</div> },
        { key: 'when', header: 'Requested', sort: (a) => a.requested_at, render: (a) => <span className="text-[11px] text-foreground-muted whitespace-nowrap">{relTime(a.requested_at, now)}</span> },
    ];

    return (
        <div className="space-y-5">
            <PageHeader icon={ScanSearch} title="Scan Management" description="Start authorised scans and follow them. Only targets inside active authorised scope can be scanned; exclusions are honoured, and checks that cannot run are reported as not attempted — never as done."
                actions={<><Link href="/admin/vms/scans/history" className={btn('secondary')}><History className="w-3.5 h-3.5" aria-hidden /> Results & history</Link><button onClick={() => { scans.reload(); assessments.reload(); }} className={btn('secondary')} aria-label="Refresh"><RefreshCw className="w-3.5 h-3.5" aria-hidden /></button></>} />
            {can.scan ? <StartScan onDone={(m, id) => { setMsg(m); scans.reload(); assessments.reload(); if (id) setAssessmentId(id); }} /> : <p className="text-xs text-foreground-muted">Starting scans needs an analyst or manager role.</p>}
            <Notice msg={msg} />
            <Card>
                <SectionTitle title="Active scans" hint="Queued or running now; refreshes every 15 seconds while anything is active." />
                <div className="-mx-5 -mb-5 [&>div]:rounded-none [&>div]:border-x-0 [&>div]:border-b-0">
                    {scans.load.state === 'error' ? <div className="p-5"><ErrorState error={scans.load.error} status={scans.load.status} onRetry={scans.reload} /></div>
                        : <DataTable caption="Active scans" rows={active} columns={activeCols} rowKey={(s) => s.id} onRowClick={(s) => setScanId(s.id)} empty="No scans queued or running" pageSize={10} />}
                </div>
            </Card>
            <Card>
                <SectionTitle title="Assessments" hint="Each assessment runs its profile's checks on one target and records which ran, which did not, and why." />
                <div className="-mx-5 -mb-5 [&>div]:rounded-none [&>div]:border-x-0 [&>div]:border-b-0">
                    {assessments.load.state === 'error' ? <div className="p-5"><ErrorState error={assessments.load.error} status={assessments.load.status} onRetry={assessments.reload} /></div>
                        : <DataTable caption="Assessments" rows={assessments.data?.assessments ?? null} columns={assessCols} rowKey={(a) => a.id} onRowClick={(a) => setAssessmentId(a.id)} activeKey={assessmentId} initialSort={{ key: 'when', dir: 'desc' }} pageSize={15}
                            empty={<EmptyState title="No assessments yet" body="Start one above, or from an asset's page." />} />}
                </div>
            </Card>
            <Drawer open={!!assessmentId} onClose={() => setAssessmentId(null)} title="Assessment">{assessmentId && <AssessmentPanel key={assessmentId} id={assessmentId} onChanged={() => { assessments.reload(); scans.reload(); }} />}</Drawer>
            <Drawer open={!!scanId} onClose={() => setScanId(null)} title="Scan">{scanId && <ScanPanel key={scanId} scan={scans.data?.scans.find((s) => s.id === scanId) ?? null} onChanged={scans.reload} />}</Drawer>
            <ConfirmDialog open={!!cancel} title="Cancel this scan?" tone="danger" body="A queued scan is cancelled; a running one is asked to stop at its next checkpoint." confirmLabel="Cancel scan" onCancel={() => setCancel(null)}
                onConfirm={async () => { const s = cancel!; setCancel(null); const r = await vmsSend<{ message?: string }>('POST', `/api/vms/scans/${s.id}/cancel`); setMsg(r.ok ? { ok: true, text: r.data.message ?? 'Cancelled' } : { ok: false, text: r.error }); scans.reload(); }} />
        </div>
    );
}

function StartScan({ onDone }: { onDone: (m: Msg, assessmentId?: string) => void }) {
    const [mode, setMode] = useState<'assessment' | 'single'>('assessment');
    const profiles = useVmsData<{ profiles: VmsProfile[] }>('/api/vms/profiles');
    const scopes = useVmsData<{ scopes: VmsScope[] }>('/api/vms/scopes');
    const ops = useVmsData<VmsOperations>('/api/vms/operations');
    const [target, setTarget] = useState('');
    const [profile, setProfile] = useState('standard');
    const [form, setForm] = useState({ scope_id: '', kind: 'discovery' as VmsScan['kind'], targets: '', ports: 'top-1000' });
    const [confirm, setConfirm] = useState(false);
    const now = scopes.at ?? 0;
    const live = scopes.data?.scopes.filter((s) => s.status === 'active' && Date.parse(s.expires_at) > now) ?? [];
    const scope = live.find((s) => s.id === form.scope_id);
    const engine = (kind: string) => ops.data?.engines.find((e) => e.id === ENGINE_FOR[kind]);
    const runnable = profiles.data?.profiles.filter((p) => p.runnable) ?? [];
    const chosen = runnable.find((p) => p.id === profile);
    const input = 'block mt-1 w-full bg-card border border-border rounded-lg px-2.5 py-2 text-xs text-foreground outline-none focus:ring-2 focus:ring-purple/40';

    async function submit() {
        setConfirm(false);
        if (mode === 'assessment') {
            const r = await vmsSend<{ assessment: { id: string }; existing: boolean }>('POST', '/api/vms/assessments', { target: target.trim(), profile });
            if (!r.ok) { onDone({ ok: false, text: r.error }); return; }
            setTarget('');
            onDone({ ok: true, text: r.data.existing ? 'An assessment of this target is already in progress; showing it.' : `${PROFILE_LABEL[profile] ?? profile} assessment planned.` }, r.data.assessment.id);
        } else {
            const targets = form.targets.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean);
            const r = await vmsSend<{ existing?: boolean; warning?: string }>('POST', '/api/vms/scans', { scope_id: form.scope_id, kind: form.kind, ...(targets.length ? { targets } : {}), ...(form.kind === 'ports' ? { ports: form.ports } : {}) });
            onDone(r.ok ? { ok: true, text: `${r.data.existing ? 'That scan is already queued or running.' : 'Scan queued.'}${r.data.warning ? ` Note: ${r.data.warning}` : ''}` } : { ok: false, text: r.error });
        }
    }
    const kindAllowed = (k: VmsScan['kind']) => !scope || (k === 'discovery' ? scope.allow_discovery !== false : k === 'ports' ? scope.allow_port_scan : scope.allow_vuln_scan);
    return (
        <Card>
            <SectionTitle title="Start an authorised scan" hint="The backend checks scope, exclusions and your role before anything is queued." action={<Segmented label="Scan type" value={mode} onChange={setMode} options={[['assessment', 'Asset assessment'], ['single', 'Single scan']]} />} />
            {mode === 'assessment' ? (
                <form className="grid grid-cols-1 md:grid-cols-[2fr_1fr_auto] gap-3 items-end" onSubmit={(e) => { e.preventDefault(); if (target.trim()) setConfirm(true); }}>
                    <label className="text-[11px] font-semibold text-foreground-muted">Target (host or IP inside authorised scope)
                        <input className={input} value={target} onChange={(e) => setTarget(e.target.value)} placeholder="e.g. app.example.com" maxLength={253} />
                    </label>
                    <label className="text-[11px] font-semibold text-foreground-muted">Profile
                        <select className={input} value={profile} onChange={(e) => setProfile(e.target.value)}>
                            {(runnable.length ? runnable : [{ id: 'standard', label: 'Standard' } as VmsProfile]).map((p) => <option key={p.id} value={p.id}>{p.label}{p.available === false ? ' — engines unavailable' : ''}</option>)}
                        </select>
                    </label>
                    <button type="submit" disabled={!target.trim()} className={btn('primary', 'md')}><Play className="w-3.5 h-3.5" aria-hidden /> Start assessment</button>
                    {chosen && (
                        <div className="md:col-span-3 text-[11px] text-foreground-muted space-y-0.5">
                            <p>{chosen.description} Ports: {chosen.ports}. Engines: {chosen.engines.join(', ') || '—'}.</p>
                            {chosen.availability_note && <p className="text-foreground">{chosen.availability_note}</p>}
                            {chosen.not_covered.length > 0 && <p>Not covered: {chosen.not_covered.join('; ')}.</p>}
                        </div>
                    )}
                </form>
            ) : (
                <form className="grid grid-cols-1 md:grid-cols-4 gap-3 items-end" onSubmit={(e) => { e.preventDefault(); if (form.scope_id) setConfirm(true); }}>
                    <label className="text-[11px] font-semibold text-foreground-muted">Authorised scope
                        <select className={input} value={form.scope_id} onChange={(e) => setForm({ ...form, scope_id: e.target.value })}>
                            <option value="">Choose…</option>
                            {live.map((s) => <option key={s.id} value={s.id}>{s.value}</option>)}
                        </select>
                    </label>
                    <label className="text-[11px] font-semibold text-foreground-muted">Scan
                        <select className={input} value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value as VmsScan['kind'] })}>
                            {(['discovery', 'ports', 'vuln_nuclei', 'vuln_openvas'] as const).map((k) => {
                                const e = engine(k);
                                const off = !kindAllowed(k) || (e ? e.state !== 'available' : false);
                                return <option key={k} value={k} disabled={off}>{SCAN_KIND_LABEL[k]}{!kindAllowed(k) ? ' — not authorised for this scope' : e && e.state !== 'available' ? ` — ${ENGINE_STATE_LABEL[e.state].toLowerCase()}` : ''}</option>;
                            })}
                        </select>
                    </label>
                    <label className="text-[11px] font-semibold text-foreground-muted">Targets (optional)
                        <input className={input} value={form.targets} onChange={(e) => setForm({ ...form, targets: e.target.value })} placeholder={scope ? `Default: ${scope.value}` : 'host or IP, comma-separated'} />
                    </label>
                    <div className="flex gap-2 items-end">
                        {form.kind === 'ports' && <label className="text-[11px] font-semibold text-foreground-muted">Ports<input className={`${input} w-28`} value={form.ports} onChange={(e) => setForm({ ...form, ports: e.target.value })} title="top-100, top-1000, 1-65535 or a list like 22,80,443" /></label>}
                        <button type="submit" disabled={!form.scope_id} className={btn('primary', 'md')}><Play className="w-3.5 h-3.5" aria-hidden /> Queue scan</button>
                    </div>
                    {scopes.data && live.length === 0 && <p className="md:col-span-4 text-[11px] text-foreground">No active authorised scope. <Link href="/admin/vms/discovery" className="font-semibold underline">Add one in Asset Discovery</Link> (managers).</p>}
                </form>
            )}
            <ConfirmDialog open={confirm} title={mode === 'assessment' ? 'Start this assessment?' : 'Queue this scan?'}
                body={mode === 'assessment'
                    ? <>Runs the <b>{PROFILE_LABEL[profile] ?? profile}</b> checks against <span className="font-mono">{target.trim()}</span>, only where an active authorised scope covers it. The request is recorded in the audit log.</>
                    : <>Queues <b>{SCAN_KIND_LABEL[form.kind]}</b> against <span className="font-mono">{form.targets.trim() || scope?.value}</span> under the scope <span className="font-mono">{scope?.value}</span> ({scope?.authorization_reference}). The request is recorded in the audit log.</>}
                confirmLabel={mode === 'assessment' ? 'Start assessment' : 'Queue scan'} onCancel={() => setConfirm(false)} onConfirm={submit} />
        </Card>
    );
}

function AssessmentPanel({ id, onChanged }: { id: string; onChanged: () => void }) {
    const can = useVmsCan();
    const { load, data, reload } = useVmsData<AssessmentDetail>(`/api/vms/assessments/${id}`);
    const [msg, setMsg] = useState<Msg>(null);
    const [content, setContent] = useState<Record<string, string>>({});
    const [cancel, setCancel] = useState(false);
    if (load.state === 'error') return <ErrorState error={load.error} status={load.status} onRetry={reload} />;
    if (!data) return <div className="h-40 rounded-xl bg-card-muted motion-safe:animate-pulse" />;
    const a = data.assessment;
    async function act(kind: 'retry' | 'cancel') {
        const r = await vmsSend<{ nothing_to_retry?: boolean }>('POST', `/api/vms/assessments/${a.id}/${kind}`);
        setMsg(r.ok ? { ok: true, text: kind === 'retry' ? (r.data.nothing_to_retry ? 'Nothing to retry: every step completed or is still running.' : 'Steps that did not complete were planned again.') : 'Cancelled.' } : { ok: false, text: r.error });
        reload();
        onChanged();
    }
    async function report() {
        const r = await apiFetch(apiUrl(`/api/vms/assessments/${a.id}/report`));
        if (!r.ok) { setMsg({ ok: false, text: `Report not available (HTTP ${r.status})` }); return; }
        const blob = await r.blob();
        const name = /filename="([^"]+)"/.exec(r.headers.get('Content-Disposition') ?? '')?.[1] ?? 'assessment-report.md';
        const link = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: name });
        link.click();
        URL.revokeObjectURL(link.href);
    }
    async function showEvidence(jobId: string, eid: string) {
        if (content[eid] !== undefined) { setContent((c) => Object.fromEntries(Object.entries(c).filter(([k]) => k !== eid))); return; }
        const r = await jobEvidence(jobId);
        setContent((c) => ({ ...c, [eid]: r.find((x) => x.id === eid)?.content ?? 'Not available (expired or removed).' }));
    }
    return (
        <div className="space-y-5 text-xs">
            <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                    <p className="text-base font-black font-mono text-foreground break-all">{a.target}</p>
                    <p className="text-foreground-muted">{PROFILE_LABEL[a.profile] ?? a.profile} · {a.trigger && a.trigger !== 'manual' ? `${TRIGGER_LABEL[a.trigger] ?? a.trigger} · ` : ''}requested by {a.requested_by} · {fmtWat(a.requested_at)}</p>
                </div>
                <StatusPill tone={ASSESS_TONE[a.status]} label={`${ASSESSMENT_STATUS_LABEL[a.status]} · ${a.progress.finished}/${a.progress.total}`} />
            </div>
            <div className="flex flex-wrap gap-2">
                <button onClick={() => void report()} className={btn('secondary')}><Download className="w-3.5 h-3.5" aria-hidden /> Management report</button>
                {can.scan && a.status !== 'cancelled' && a.steps.some((s) => RETRYABLE_STEPS.includes(s.status)) && <button onClick={() => void act('retry')} className={btn('primary')}><RotateCcw className="w-3.5 h-3.5" aria-hidden /> Retry incomplete checks</button>}
                {can.scan && a.status === 'in_progress' && <button onClick={() => setCancel(true)} className={btn('secondary')}>Cancel</button>}
            </div>
            <Notice msg={msg} />
            <section>
                <h3 className="text-[11px] font-bold uppercase tracking-wide text-foreground-muted mb-2">Checks</h3>
                <div className="space-y-2">
                    {a.steps.map((s) => (
                        <div key={s.kind} className="border border-border rounded-xl p-3 bg-card">
                            <div className="flex items-center justify-between gap-2"><span className="font-semibold text-foreground">{s.label}</span><StatusPill tone={STEP_TONE[s.status]} label={STEP_STATUS_LABEL[s.status]} /></div>
                            <p className="text-foreground-muted mt-1">{s.detail}</p>
                            {s.job?.target_outcomes && Object.entries(s.job.target_outcomes).map(([t, o]) => <p key={t} className="text-foreground-muted"><span className="font-mono">{t}</span>: {OUTCOME_LABEL[o.outcome] ?? o.outcome} — {o.reason}</p>)}
                        </div>
                    ))}
                </div>
            </section>
            <section>
                <h3 className="text-[11px] font-bold uppercase tracking-wide text-foreground-muted mb-2">Findings ({data.findings.length})</h3>
                {data.findings.length === 0 ? <p className="text-foreground-muted">None recorded by the checks that ran. Checks that did not run give no assurance.</p>
                    : data.findings.map((f) => <Link key={f.id} href={`/admin/vms/findings?id=${f.id}`} className="flex items-center gap-2 border-t border-border first:border-0 py-1.5 hover:underline"><PriorityBadge priority={f.priority} /><span className="flex-1 text-foreground">{f.title}{f.port ? ` (port ${f.port})` : ''}</span>{(f.evidence_class === 'version_match' || f.evidence_class === 'intelligence') && <Tag>Unconfirmed</Tag>}</Link>)}
            </section>
            <section>
                <h3 className="text-[11px] font-bold uppercase tracking-wide text-foreground-muted mb-2">Raw tool output (kept 30 days)</h3>
                {data.evidence.length === 0 ? <p className="text-foreground-muted">None held for this assessment.</p> : data.evidence.map((e) => (
                    <div key={e.id} className="border border-border rounded-xl p-2 mb-1.5 bg-card">
                        <button onClick={() => void showEvidence(e.job_id, e.id)} className="text-left text-foreground w-full">{e.tool} · <span className="font-mono">{e.target}</span> · {Math.round(e.bytes / 1024)} KB{e.truncated ? ' (cut)' : ''} · {fmtWat(e.created_at)} · SHA-256 {e.sha256.slice(0, 12)}…</button>
                        {content[e.id] !== undefined && <pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap break-all text-[10.5px] font-mono text-foreground bg-card-muted rounded-lg p-2">{content[e.id]}</pre>}
                    </div>
                ))}
            </section>
            <ConfirmDialog open={cancel} tone="danger" title="Cancel this assessment?" body="Queued scans are cancelled and running ones stopped." confirmLabel="Cancel assessment" onCancel={() => setCancel(false)} onConfirm={async () => { setCancel(false); await act('cancel'); }} />
        </div>
    );
}
async function jobEvidence(jobId: string): Promise<VmsEvidence[]> {
    const r = await apiFetch(apiUrl(`/api/vms/scans/${jobId}/evidence`));
    const d = await r.json().catch(() => null);
    return r.ok && d?.evidence ? d.evidence : [];
}

/** One scan: outcome per target, summary, error, raw tool output and retry. */
function ScanPanel({ scan: s, onChanged }: { scan: Scan | null; onChanged: () => void }) {
    const can = useVmsCan();
    const ev = useVmsData<{ available: boolean; evidence: VmsEvidence[]; note?: string }>(s && (s.status === 'succeeded' || s.status === 'failed') ? `/api/vms/scans/${s.id}/evidence` : null);
    const [msg, setMsg] = useState<Msg>(null);
    const [retry, setRetry] = useState(false);
    if (!s) return <EmptyState title="Scan not in the loaded list" body="It may be older than the most recent scans shown." />;
    const outcomes = (s.summary?.target_outcomes ?? {}) as Record<string, { outcome: string; reason: string }>;
    const duration = s.started_at && s.finished_at ? (Date.parse(s.finished_at) - Date.parse(s.started_at)) / 1000 : null;
    return (
        <div className="space-y-5 text-xs">
            <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                    <p className="text-base font-black text-foreground">{SCAN_KIND_LABEL[s.kind] ?? s.kind}</p>
                    <p className="text-foreground-muted">{s.purpose === 'verification' ? 'Verification · ' : ''}requested by {s.requested_by} · {fmtWat(s.requested_at)}{duration !== null ? ` · took ${fmtDuration(duration)}` : ''}</p>
                </div>
                <ScanResult s={s} />
            </div>
            <p className="font-mono break-all text-foreground">{s.targets.join(', ')}</p>
            {s.attention && <p className="text-foreground"><b>Waiting:</b> {s.attention}</p>}
            {s.error && <p className="text-foreground"><b>Error:</b> {s.error}</p>}
            {Object.keys(outcomes).length > 0 && (
                <section><h3 className="text-[11px] font-bold uppercase tracking-wide text-foreground-muted mb-2">Per target</h3>
                    {Object.entries(outcomes).map(([t, o]) => <p key={t} className="border-t border-border first:border-0 py-1.5"><span className="font-mono">{t}</span> — <b>{OUTCOME_LABEL[o.outcome] ?? o.outcome}</b>: <span className="text-foreground-muted">{o.reason}</span></p>)}
                </section>
            )}
            {s.summary && Object.keys(s.summary).filter((k) => k !== 'outcome' && k !== 'target_outcomes').length > 0 && (
                <section><h3 className="text-[11px] font-bold uppercase tracking-wide text-foreground-muted mb-2">Summary</h3>
                    <dl className="grid grid-cols-2 gap-2">{Object.entries(s.summary).filter(([k]) => k !== 'outcome' && k !== 'target_outcomes').map(([k, v]) => <div key={k}><dt className="text-[10px] uppercase text-foreground-muted">{k.replace(/_/g, ' ')}</dt><dd className="text-foreground break-words">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</dd></div>)}</dl>
                </section>
            )}
            <p className="text-foreground-muted">Findings with evidence from this scan: <b className="text-foreground">{s.findings_count ?? 0}</b></p>
            {can.scan && s.status === 'failed' && !s.assessment_id && <button onClick={() => setRetry(true)} className={btn('primary')}><RotateCcw className="w-3.5 h-3.5" aria-hidden /> Retry scan</button>}
            <Notice msg={msg} />
            {(s.status === 'succeeded' || s.status === 'failed') && (
                <section><h3 className="text-[11px] font-bold uppercase tracking-wide text-foreground-muted mb-2">Raw tool output (redacted, kept 30 days)</h3>
                    {ev.load.state === 'error' ? <p className="text-foreground-muted">{ev.load.error}</p> : ev.data?.note ? <p className="text-foreground-muted">{ev.data.note}</p>
                        : <EvidenceViewer items={(ev.data?.evidence ?? []).map((e) => ({ id: e.id, title: `${e.tool} · ${e.target}`, meta: `${Math.round(e.bytes / 1024)} KB · SHA-256 ${e.sha256.slice(0, 12)}…`, content: e.content, truncated: e.truncated }))} empty={ev.data ? 'No raw output kept for this scan (kept 30 days).' : 'Loading…'} />}
                </section>
            )}
            <ConfirmDialog open={retry} title="Retry this scan?" body="The scan is queued again through the same scope checks as a new request." confirmLabel="Retry" onCancel={() => setRetry(false)}
                onConfirm={async () => { setRetry(false); const r = await vmsSend<{ message?: string }>('POST', `/api/vms/scans/${s.id}/retry`); setMsg(r.ok ? { ok: true, text: r.data.message ?? 'Queued again' } : { ok: false, text: r.error }); onChanged(); }} />
        </div>
    );
}

// ── Scan Results & History ─────────────────────────────────────────────────────────────────────
const RESULT_OF = (s: Scan): 'assessed' | 'inconclusive' | 'failed' | 'cancelled' | 'active' => {
    if (s.status === 'queued' || s.status === 'running') return 'active';
    if (s.status === 'failed') return 'failed';
    if (s.status === 'cancelled') return 'cancelled';
    const o = String((s.summary as { outcome?: string } | null)?.outcome ?? '');
    return ['unreachable', 'insufficient_evidence', 'no_route'].includes(o) ? 'inconclusive' : 'assessed';
};

export function VmsScanHistory() {
    const { load, data, reload, at } = useVmsData<{ scans: Scan[] }>('/api/vms/scans?limit=500');
    const [scanId, setScanId] = useParam('scan');
    const [result, setResult] = useState<'' | 'assessed' | 'inconclusive' | 'failed' | 'cancelled' | 'active'>('');
    const [kind, setKind] = useState('');
    const [purpose, setPurpose] = useState('');
    const now = at ?? 0;
    const rows = useMemo(() => data?.scans.filter((s) => (!result || RESULT_OF(s) === result) && (!kind || s.kind === kind) && (!purpose || (purpose === 'verification' ? s.purpose === 'verification' : s.purpose !== 'verification'))) ?? null, [data, result, kind, purpose]);
    const count = (r: ReturnType<typeof RESULT_OF>) => data?.scans.filter((s) => RESULT_OF(s) === r).length;
    const columns: Column<Scan>[] = [
        { key: 'when', header: 'Requested', sort: (s) => s.requested_at, render: (s) => <span className="text-[11px] whitespace-nowrap">{fmtWat(s.requested_at).replace(/ WAT$/, '')}</span> },
        { key: 'kind', header: 'Scan', sort: (s) => s.kind, render: (s) => <div><p className="font-semibold text-foreground">{SCAN_KIND_LABEL[s.kind] ?? s.kind}</p><p className="text-[10.5px] text-foreground-muted">{s.purpose === 'verification' ? 'Verification' : s.assessment_id ? 'Assessment step' : 'Single scan'}</p></div> },
        { key: 'targets', header: 'Targets', className: 'max-w-[240px]', render: (s) => <span className="text-[11px] font-mono break-all">{s.targets.slice(0, 2).join(', ')}{s.targets.length > 2 ? ` +${s.targets.length - 2}` : ''}</span> },
        { key: 'result', header: 'Result', sort: (s) => RESULT_OF(s), render: (s) => <ScanResult s={s} /> },
        { key: 'findings', header: 'Findings', sort: (s) => s.findings_count ?? 0, render: (s) => <span className="tabular-nums font-semibold">{s.findings_count ?? 0}</span> },
        { key: 'duration', header: 'Duration', hideBelow: 'md', sort: (s) => (s.started_at && s.finished_at ? Date.parse(s.finished_at) - Date.parse(s.started_at) : null), render: (s) => <span className="text-[11px] text-foreground-muted">{s.started_at && s.finished_at ? fmtDuration((Date.parse(s.finished_at) - Date.parse(s.started_at)) / 1000) : '—'}</span> },
        { key: 'by', header: 'By', hideBelow: 'lg', render: (s) => <span className="text-[11px] text-foreground-muted">{s.requested_by}</span> },
    ];
    return (
        <div className="space-y-5">
            <PageHeader icon={History} title="Scan Results & History" description="Every scan requested for this organisation (latest 500) and what it actually established. A scan that reached no host, or could not route to it, is inconclusive — it is never counted as a successful assessment."
                actions={<ExportCsvButton filename="vms-scan-history.csv" rows={rows?.map((s) => ({ ...s, result: RESULT_OF(s), outcome: (s.summary as { outcome?: string } | null)?.outcome ?? '' }))} columns={[{ key: 'requested_at', header: 'Requested' }, { key: 'kind', header: 'Kind' }, { key: 'purpose', header: 'Purpose' }, { key: 'targets', header: 'Targets' }, { key: 'status', header: 'Status' }, { key: 'result', header: 'Result' }, { key: 'outcome', header: 'Outcome' }, { key: 'findings_count', header: 'Findings' }, { key: 'started_at', header: 'Started' }, { key: 'finished_at', header: 'Finished' }, { key: 'requested_by', header: 'Requested by' }, { key: 'error', header: 'Error' }]} />} />
            <section className="grid grid-cols-2 md:grid-cols-4 gap-3" aria-label="Results">
                <KpiCard label="Assessed" value={count('assessed')} reason="Loading" tone={count('assessed') ? 'good' : undefined} sub="Reached the target and completed" />
                <KpiCard label="Inconclusive" value={count('inconclusive')} reason="Loading" tone={count('inconclusive') ? 'warning' : undefined} sub="Completed without reaching a host" />
                <KpiCard label="Failed" value={count('failed')} reason="Loading" tone={count('failed') ? 'critical' : undefined} />
                <KpiCard label="Queued or running" value={count('active')} reason="Loading" />
            </section>
            <div className="flex flex-wrap items-center gap-2">
                <Segmented label="Result" value={result} onChange={setResult} options={[['', 'All'], ['assessed', 'Assessed'], ['inconclusive', 'Inconclusive'], ['failed', 'Failed'], ['cancelled', 'Cancelled'], ['active', 'Active']]} />
                <Select label="Scan" value={kind} onChange={setKind} options={[['', 'Any scan'], ['discovery', 'Discovery'], ['ports', 'Ports'], ['vuln_nuclei', 'Nuclei'], ['vuln_openvas', 'OpenVAS'], ['passive_osint', 'Passive OSINT']]} />
                <Select label="Purpose" value={purpose} onChange={setPurpose} options={[['', 'Any purpose'], ['verification', 'Verification'], ['other', 'Discovery & assessment']]} />
            </div>
            {load.state === 'error' ? <ErrorState error={load.error} status={load.status} onRetry={reload} />
                : <DataTable caption="Scan history" rows={rows} columns={columns} rowKey={(s) => s.id} onRowClick={(s) => setScanId(s.id)} activeKey={scanId} initialSort={{ key: 'when', dir: 'desc' }} empty={data?.scans.length ? 'No scans match these filters' : 'No scans have been requested yet'} />}
            <Drawer open={!!scanId} onClose={() => setScanId(null)} title="Scan" subtitle={scanId ? relTime(data?.scans.find((s) => s.id === scanId)?.requested_at, now) : null}>{scanId && <ScanPanel key={scanId} scan={data?.scans.find((s) => s.id === scanId) ?? null} onChanged={reload} />}</Drawer>
        </div>
    );
}
