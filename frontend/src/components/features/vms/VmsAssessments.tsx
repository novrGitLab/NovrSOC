'use client';

// Full Assessments (phase P13): every applicable scan for one authorised target, grouped. The backend
// plans each step before dispatch — queued, not attempted or unsupported, with the reason — and the
// status shown is derived from the scan jobs, so a scan that never ran is never shown as done.
// Includes progress, the findings the assessment produced, the raw tool output kept for 30 days and
// a downloadable management report. All data from /api/vms/assessments.

import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { ClipboardCheck, Download, RefreshCw } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { loadJson } from '@/lib/alerts';
import { getAdminUser } from '@/lib/admin-auth';
import { fmtWat, OUTCOME_LABEL, STEP_STATUS_LABEL, STEP_STATUS_STYLE, ASSESSMENT_STATUS_LABEL, ASSESSMENT_STATUS_STYLE, type VmsAssessment, type VmsEvidence } from '@/lib/vms';

interface Finding { id: string; title: string; priority: string | null; status: string; evidence_class: string; port: number | null; cve_ids: string[] }
interface Detail { assessment: VmsAssessment; findings: Finding[]; evidence: (Omit<VmsEvidence, 'content'> & { job_id: string })[] }

export function VmsAssessments() {
    const params = useSearchParams();
    const role = getAdminUser().role;
    const canRun = ['super_admin', 'soc_manager', 'analyst'].includes(role);
    const [list, setList] = useState<VmsAssessment[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [selected, setSelected] = useState<string | null>(params.get('id'));
    const [detail, setDetail] = useState<Detail | null>(null);
    const [target, setTarget] = useState('');
    const [msg, setMsg] = useState<string | null>(null);
    const [content, setContent] = useState<Record<string, string>>({});
    const [tick, setTick] = useState(0);
    const reload = useCallback(() => setTick((t) => t + 1), []);

    useEffect(() => {
        let active = true;
        void loadJson<{ assessments: VmsAssessment[] }>('/api/vms/assessments').then((r) => {
            if (!active) return;
            setList(r.ok ? r.data.assessments : null);
            setError(r.ok ? null : r.error);
        });
        return () => { active = false; };
    }, [tick]);

    useEffect(() => {
        if (!selected) return;
        let active = true;
        void loadJson<Detail>(`/api/vms/assessments/${selected}`).then((r) => { if (active) setDetail(r.ok ? r.data : null); });
        return () => { active = false; };
    }, [selected, tick]);

    // While anything is in progress, refresh every 15 s.
    const running = !!list?.some((a) => a.status === 'in_progress');
    useEffect(() => {
        if (!running) return;
        const t = setInterval(reload, 15_000);
        return () => clearInterval(t);
    }, [running, reload]);

    async function send(path: string, body?: unknown) {
        const r = await apiFetch(apiUrl(path), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
        const d = await r.json().catch(() => null);
        return { ok: r.ok, data: d, error: d?.error ?? `HTTP ${r.status}` };
    }
    async function start() {
        setMsg(null);
        const r = await send('/api/vms/assessments', { target: target.trim() });
        if (!r.ok) { setMsg(r.error); return; }
        setMsg(r.data.existing ? 'An assessment of this target is already in progress; showing it.' : 'Full assessment planned.');
        setSelected(r.data.assessment.id);
        setTarget('');
        reload();
    }
    async function act(kind: 'retry' | 'cancel') {
        if (!detail) return;
        if (kind === 'cancel' && !window.confirm('Cancel this assessment? Queued scans are cancelled and running ones stopped.')) return;
        const r = await send(`/api/vms/assessments/${detail.assessment.id}/${kind}`);
        setMsg(r.ok ? (kind === 'retry' ? (r.data.nothing_to_retry ? 'Nothing to retry: every step completed or is still running.' : 'Steps that did not complete were planned again.') : 'Cancelled.') : r.error);
        reload();
    }
    async function download() {
        if (!detail) return;
        const r = await apiFetch(apiUrl(`/api/vms/assessments/${detail.assessment.id}/report`));
        if (!r.ok) { setMsg(`Report not available (HTTP ${r.status})`); return; }
        const blob = await r.blob();
        const name = /filename="([^"]+)"/.exec(r.headers.get('Content-Disposition') ?? '')?.[1] ?? 'assessment-report.md';
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = name;
        a.click();
        URL.revokeObjectURL(a.href);
    }
    async function viewEvidence(jobId: string, id: string) {
        if (content[id] !== undefined) { setContent({ ...content, [id]: undefined as unknown as string }); return; }
        const r = await loadJson<{ evidence: VmsEvidence[] }>(`/api/vms/scans/${jobId}/evidence`);
        const e = r.ok ? r.data.evidence.find((x) => x.id === id) : undefined;
        setContent({ ...content, [id]: e?.content ?? 'Not available (expired or removed).' });
    }

    const a = detail?.assessment;
    const byPriority = (p: string) => detail?.findings.filter((f) => f.priority === p).length ?? 0;
    const unconfirmed = detail?.findings.filter((f) => f.evidence_class === 'version_match' || f.evidence_class === 'intelligence').length ?? 0;
    const input = 'bg-card-muted border border-border rounded-lg px-3 py-2 text-xs text-foreground';
    return (
        <div className="space-y-4">
            <div className="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <h1 className="text-lg font-black text-foreground flex items-center gap-2"><ClipboardCheck className="w-5 h-5" /> Assessments</h1>
                    <p className="text-xs text-foreground-muted max-w-3xl">A full assessment runs every check the authorised scope allows and a connected worker can perform, for one host or IP. Checks that cannot run are listed as not attempted or unsupported, with the reason — never as done.</p>
                </div>
                {canRun && (
                    <form onSubmit={(e) => { e.preventDefault(); if (target.trim()) void start(); }} className="flex gap-2">
                        <input className={input} placeholder="Host or IP inside authorised scope" value={target} onChange={(e) => setTarget(e.target.value)} aria-label="Target to assess" />
                        <button className="text-[11px] font-bold text-white bg-purple rounded-lg px-3">Start full assessment</button>
                    </form>
                )}
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {msg && <p role="status" className="text-xs text-foreground font-semibold">{msg}</p>}

            <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
                <div className="lg:col-span-2 bg-card border border-border rounded-xl divide-y divide-border">
                    {list && list.length === 0 && <p className="text-xs text-foreground-muted p-6 text-center">No assessments yet. Start one above, or from an asset on Attack Surface.</p>}
                    {(list ?? []).map((x) => (
                        <button key={x.id} onClick={() => setSelected(x.id)} className={`w-full text-left p-3 text-xs ${selected === x.id ? 'bg-card-muted' : ''}`}>
                            <div className="flex items-center justify-between gap-2">
                                <span className="font-mono font-bold text-foreground break-all">{x.target}</span>
                                <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${ASSESSMENT_STATUS_STYLE[x.status]}`}>{ASSESSMENT_STATUS_LABEL[x.status]}</span>
                            </div>
                            <p className="text-foreground-muted mt-1">{x.progress.finished}/{x.progress.total} checks finished · {fmtWat(x.requested_at)}</p>
                            <div className="flex flex-wrap gap-1 mt-1">{x.steps.map((s) => <span key={s.kind} className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${STEP_STATUS_STYLE[s.status]}`}>{s.label}: {STEP_STATUS_LABEL[s.status]}</span>)}</div>
                        </button>
                    ))}
                </div>

                <div className="lg:col-span-3 bg-card border border-border rounded-xl p-4 text-xs space-y-4">
                    {!a ? <p className="text-foreground-muted text-center py-10">Select an assessment.</p> : (
                        <>
                            <div className="flex items-start justify-between gap-2 flex-wrap">
                                <div>
                                    <h2 className="text-sm font-black font-mono text-foreground">{a.target}</h2>
                                    <p className="text-foreground-muted">Requested by {a.requested_by} · {fmtWat(a.requested_at)}{a.retried_at ? ` · retried ${fmtWat(a.retried_at)}` : ''}</p>
                                </div>
                                <div className="flex gap-2">
                                    <button onClick={() => void download()} className="flex items-center gap-1 text-[11px] font-bold border border-border rounded-lg px-3 py-1.5"><Download className="w-3.5 h-3.5" /> Report</button>
                                    {canRun && a.steps.some((s) => ['failed', 'not_attempted', 'unsupported'].includes(s.status)) && a.status !== 'cancelled' && <button onClick={() => void act('retry')} className="flex items-center gap-1 text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5"><RefreshCw className="w-3.5 h-3.5" /> Retry incomplete</button>}
                                    {canRun && a.status === 'in_progress' && <button onClick={() => void act('cancel')} className="text-[11px] font-bold text-red border border-border rounded-lg px-3 py-1.5">Cancel</button>}
                                </div>
                            </div>
                            <span className={`inline-block text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${ASSESSMENT_STATUS_STYLE[a.status]}`}>{ASSESSMENT_STATUS_LABEL[a.status]} · {a.progress.finished}/{a.progress.total}</span>

                            <div>
                                <p className="text-[10px] font-bold text-foreground-muted uppercase mb-1">Checks</p>
                                <table className="w-full">
                                    <tbody>
                                        {a.steps.map((s) => (
                                            <tr key={s.kind} className="border-t border-border align-top">
                                                <td className="py-1.5 pr-2 font-semibold text-foreground">{s.label}</td>
                                                <td className="pr-2"><span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${STEP_STATUS_STYLE[s.status]}`}>{STEP_STATUS_LABEL[s.status]}</span></td>
                                                <td className="text-foreground-muted">
                                                    {s.detail}
                                                    {s.job?.target_outcomes && Object.entries(s.job.target_outcomes).map(([t, o]) => <p key={t}><span className="font-mono">{t}</span>: {OUTCOME_LABEL[o.outcome] ?? o.outcome} — {o.reason}</p>)}
                                                    {(s.previous_job_ids ?? []).length > 0 && <p>{s.previous_job_ids.length} earlier attempt(s) kept</p>}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>

                            <div>
                                <p className="text-[10px] font-bold text-foreground-muted uppercase mb-1">Findings</p>
                                {!detail!.findings.length ? <p className="text-foreground-muted">None recorded by the checks that ran. Checks that did not run give no assurance.</p> : (
                                    <>
                                        <p className="text-foreground mb-1">P1 {byPriority('P1')} · P2 {byPriority('P2')} · P3 {byPriority('P3')} · P4 {byPriority('P4')}{unconfirmed ? <span className="text-amber"> · {unconfirmed} unconfirmed</span> : null}</p>
                                        <ul className="space-y-0.5">{detail!.findings.map((f) => <li key={f.id}><span className="font-bold">{f.priority ?? '—'}</span> {f.title}{f.port ? ` (port ${f.port})` : ''} · {f.evidence_class.replace(/_/g, ' ')} · {f.status.replace(/_/g, ' ')}</li>)}</ul>
                                    </>
                                )}
                            </div>

                            <div>
                                <p className="text-[10px] font-bold text-foreground-muted uppercase mb-1">Evidence (raw tool output, kept 30 days)</p>
                                {!detail!.evidence.length ? <p className="text-foreground-muted">None held for this assessment.</p> : detail!.evidence.map((e) => (
                                    <div key={e.id} className="border border-border rounded-lg p-2 mb-1">
                                        <button onClick={() => void viewEvidence(e.job_id, e.id)} className="text-left text-foreground">{e.tool} · <span className="font-mono">{e.target}</span> · {Math.round(e.bytes / 1024)} KB{e.truncated ? ' (cut)' : ''} · {fmtWat(e.created_at)} · SHA-256 {e.sha256.slice(0, 12)}…</button>
                                        {content[e.id] !== undefined && <pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap break-all text-[10px] text-foreground-muted">{content[e.id]}</pre>}
                                    </div>
                                ))}
                            </div>
                        </>
                    )}
                </div>
            </div>
        </div>
    );
}
