'use client';

// One finding, in full (redesign, phase P20): risk explanation, threat context (CVSS, EPSS, KEV,
// OSV), evidence, correlations, AI analysis, remediation tasks, comments and history. Changes go
// through the existing endpoints, which check the permission and organisation and record each one
// in the finding's history. Verified and reopened are never set here — only scans or Wazuh do that.

import { useState } from 'react';
import Link from 'next/link';
import { ShieldAlert, ScanSearch, Briefcase, Plus, MessageSquare } from 'lucide-react';
import { fmtWat } from '@/lib/vms';
import { AiPanel } from '@/components/shared/AiPanel';
import { Skeleton } from './ui';
import { SeverityBadge, PriorityBadge, RiskScore, Tag, ErrorState, Notice, ConfirmDialog, EvidenceViewer, Timeline, btn, type Msg } from './kit';
import { useVmsData, useVmsCan, vmsSend } from './data';

export interface Finding {
    id: string; asset_id: string | null; asset_value: string; port: number | null; protocol: string | null; source_class: 'active_scan' | 'wazuh'; detected_by: string[];
    rule_id: string; title: string; finding_type: string; cve_ids: string[]; scanner_severity: string; scanner_cvss: number | null; risk_score: number | null;
    priority: 'P1' | 'P2' | 'P3' | 'P4' | null; status: string; owner: string | null; due_at: string | null; first_seen: string; last_seen: string; verified_at: string | null; case_id: string | null;
    description?: string | null; remediation?: string | null; references_urls?: string[]; risk_factors?: Record<string, { points?: number; basis?: string; weight?: number } | string> | null;
    evidence_class?: string | null; correlated?: number; correlated_confirmed?: number;
}
interface Detail {
    finding: Finding;
    /** The scanner's own CVSS (P22): score, version and vector as reported. Not the NovrSOC risk score. */
    scanner_cvss?: { score: number | null; version: string | null; vector: string | null; source: string | null; observed_at: string | null } | null;
    evidence: { id: string; source: string; observed_at: string; matched_at: string | null; evidence: unknown; job_id: string | null }[];
    events: { id: string; at: string; actor: string; action: string; from_value: string | null; to_value: string | null; details: string | null }[];
    cve_intel: { cve_id: string; description: string | null; cvss_score: number | null; cvss_vector: string | null; epss_score: number | null; epss_percentile: number | null; kev: boolean; kev_checked_at: string | null; kev_date_added: string | null; kev_required_action: string | null; kev_ransomware: string | null; osv_status?: 'found' | 'not_found' | null; osv_ids?: string[] | null; osv_fetched_at?: string | null; osv_affected?: { ecosystem: string | null; name: string | null; repo: string | null; fixed: string[] }[] | null }[];
    correlated?: { cves: string[]; relation: string; basis: 'confirmed' | 'inferred'; explanation: string; other: { id: string; asset_value: string; source_class: string; detected_by: string[]; status: string } }[];
    correlation_error?: string | null;
    asset: { id: string; value: string; exposure: string; criticality: string; owner: string | null } | null;
    tasks: { id: string; title: string; status: string; owner: string | null; due_at: string | null; details?: string | null; ai_artifact_id?: string | null }[];
}

export const STATUS_LABEL: Record<string, string> = {
    open: 'Open', acknowledged: 'Triaged', in_progress: 'In progress', fixed_pending_verification: 'Awaiting verification', verified: 'Resolved (verified)',
    reopened: 'Reopened', risk_accepted: 'Risk accepted', false_positive: 'False positive',
};
/** Transitions a person may make (the backend allows these; verified/reopened come only from scans). */
export const NEXT: Record<string, string[]> = {
    open: ['acknowledged', 'in_progress', 'fixed_pending_verification', 'risk_accepted', 'false_positive'],
    reopened: ['acknowledged', 'in_progress', 'fixed_pending_verification', 'risk_accepted', 'false_positive'],
    acknowledged: ['in_progress', 'fixed_pending_verification', 'risk_accepted', 'false_positive', 'open'],
    in_progress: ['fixed_pending_verification', 'acknowledged', 'risk_accepted', 'false_positive', 'open'],
    fixed_pending_verification: ['in_progress', 'open'], verified: [], risk_accepted: ['open'], false_positive: ['open'],
};
export const CLOSED = ['verified', 'risk_accepted', 'false_positive'];
export const isOverdue = (f: Pick<Finding, 'due_at' | 'status'>, now: number) => !!f.due_at && Date.parse(f.due_at) < now && !CLOSED.includes(f.status);
const FACTOR_LABEL: Record<string, string> = { technical: 'Technical severity', exploitation: 'Exploitation likelihood', exposure: 'Exposure', criticality: 'Asset criticality' };
const TASK_LABEL: Record<string, string> = { todo: 'To do', doing: 'In progress', done: 'Done', cancelled: 'Cancelled' };

type Pending = { kind: 'status'; to: string } | { kind: 'verify' } | { kind: 'case' } | null;

export function FindingDetail({ id, onChanged }: { id: string; onChanged?: () => void }) {
    const { load, data, reload, at } = useVmsData<Detail>(`/api/vms/findings/${id}`);
    const can = useVmsCan();
    const [msg, setMsg] = useState<Msg>(null);
    const [pending, setPending] = useState<Pending>(null);
    const [task, setTask] = useState({ title: '', owner: '', due: '' });
    const [note, setNote] = useState('');
    const now = at ?? 0;

    if (load.state === 'error') return <ErrorState error={load.error} status={load.status} onRetry={reload} />;
    if (!data) return <div className="space-y-3"><Skeleton className="h-6 w-2/3" /><Skeleton className="h-24" /><Skeleton className="h-40" /></div>;
    const f = data.finding;
    const kev = data.cve_intel.some((c) => c.kev);

    async function run(method: 'POST' | 'PATCH', path: string, body: unknown, done: string) {
        setMsg(null);
        const r = await vmsSend<{ message?: string }>(method, path, body);
        setMsg(r.ok ? { ok: true, text: r.data.message ?? done } : { ok: false, text: r.error });
        if (r.ok) { reload(); onChanged?.(); }
        return r.ok;
    }

    return (
        <div className="space-y-5 text-xs">
            {/* Summary */}
            <div className="space-y-2">
                <div className="flex flex-wrap items-center gap-2">
                    <PriorityBadge priority={f.priority} />
                    <SeverityBadge severity={f.scanner_severity} />
                    <RiskScore score={f.risk_score} wide />
                    {kev && <Tag strong title="Listed in the CISA Known Exploited Vulnerabilities catalogue">Known exploited</Tag>}
                    {isOverdue(f, now) && <Tag title="Past its remediation deadline">Overdue</Tag>}
                    <span className="ml-auto text-[11px] font-semibold text-foreground">{STATUS_LABEL[f.status] ?? f.status}</span>
                </div>
                <dl className="grid grid-cols-2 sm:grid-cols-3 gap-x-4 gap-y-2 bg-card border border-border rounded-xl p-3">
                    <Fact k="Asset" v={f.asset_id ? <Link className="font-mono font-semibold text-purple dark:text-[var(--vz-prog-4)] hover:underline break-all" href={`/admin/vms/assets/${f.asset_id}`}>{f.asset_value}{f.port ? `:${f.port}` : ''}</Link> : <span className="font-mono break-all">{f.asset_value}</span>} />
                    <Fact k="Source" v={f.source_class === 'wazuh' ? 'Wazuh agent' : (f.detected_by.join(', ') || 'Active scan')} />
                    <Fact k="Evidence" v={f.evidence_class ? f.evidence_class.replace(/_/g, ' ') : '—'} />
                    <Fact k="Scanner CVSS (severity)" v={data.scanner_cvss?.score !== null && data.scanner_cvss?.score !== undefined
                        ? <span title={data.scanner_cvss.vector ?? undefined}>{data.scanner_cvss.score}{data.scanner_cvss.version ? ` · CVSS v${data.scanner_cvss.version}` : ' · version not reported'}{data.scanner_cvss.source ? ` · ${data.scanner_cvss.source}` : ''}{data.scanner_cvss.vector && <span className="block font-mono text-[10px] text-foreground-muted break-all">{data.scanner_cvss.vector}</span>}</span>
                        : f.scanner_cvss ?? 'Not reported'} />
                    <Fact k="NovrSOC risk (contextual)" v={f.risk_score !== null ? `${f.risk_score} / 100 · ${f.priority ?? '—'}` : '—'} />
                    <Fact k="CVE" v={f.cve_ids.length ? f.cve_ids.join(', ') : '—'} />
                    <Fact k="Rule" v={<span className="font-mono break-all">{f.rule_id}</span>} />
                    <Fact k="First seen" v={fmtWat(f.first_seen)} />
                    <Fact k="Last seen" v={fmtWat(f.last_seen)} />
                    <Fact k="Owner · due" v={`${f.owner ?? 'Unassigned'} · ${f.due_at ? fmtWat(f.due_at) : 'no deadline'}`} />
                </dl>
            </div>

            <Notice msg={msg} />

            {/* Actions */}
            {can.manage && (
                <section className="space-y-3">
                    <div className="flex flex-wrap gap-2">
                        {(NEXT[f.status] ?? []).map((s) => <button key={s} onClick={() => setPending({ kind: 'status', to: s })} className={btn('secondary')}>{STATUS_LABEL[s]}</button>)}
                        {f.status === 'fixed_pending_verification' && <button onClick={() => setPending({ kind: 'verify' })} className={btn('primary')}><ScanSearch className="w-3.5 h-3.5" aria-hidden /> Verify with a rescan</button>}
                        {f.case_id ? <Link href={`/admin/secops/cases?case=${f.case_id}`} className={btn('secondary')}><Briefcase className="w-3.5 h-3.5" aria-hidden /> Open case</Link>
                            : <button onClick={() => setPending({ kind: 'case' })} className={btn('secondary')}><Briefcase className="w-3.5 h-3.5" aria-hidden /> Promote to case</button>}
                    </div>
                    <div className="flex flex-wrap gap-3 items-end">
                        <label className="text-[11px] font-semibold text-foreground-muted">Owner
                            <input key={`o-${f.id}-${f.owner}`} defaultValue={f.owner ?? ''} maxLength={200} placeholder="team or person" onBlur={(e) => { const v = e.target.value.trim(); if (v !== (f.owner ?? '')) void run('PATCH', `/api/vms/findings/${f.id}`, { owner: v || null }, 'Owner saved'); }} className="block mt-1 bg-card border border-border rounded-lg px-2 py-1.5 text-xs text-foreground" />
                        </label>
                        <label className="text-[11px] font-semibold text-foreground-muted">Deadline
                            <input type="date" key={`d-${f.id}-${f.due_at}`} defaultValue={f.due_at?.slice(0, 10) ?? ''} onChange={(e) => { if (e.target.value) void run('PATCH', `/api/vms/findings/${f.id}`, { due_at: new Date(`${e.target.value}T23:59:59Z`).toISOString() }, 'Deadline saved'); }} className="block mt-1 bg-card border border-border rounded-lg px-2 py-1.5 text-xs text-foreground" />
                        </label>
                    </div>
                </section>
            )}

            {/* Why this priority */}
            <Section title="Why this priority">
                {f.risk_factors && Object.keys(f.risk_factors).length ? (
                    <table className="w-full">
                        <tbody>
                            {Object.entries(f.risk_factors).map(([k, v]) => (
                                <tr key={k} className="border-t border-border first:border-0">
                                    <td className="py-1.5 pr-2 font-semibold text-foreground whitespace-nowrap">{FACTOR_LABEL[k] ?? k.replace(/_/g, ' ')}</td>
                                    <td className="py-1.5 text-foreground-muted">{typeof v === 'string' ? v : v.basis}</td>
                                    <td className="py-1.5 pl-2 text-right tabular-nums text-foreground whitespace-nowrap">{typeof v === 'string' ? '' : v.points !== undefined && v.weight !== undefined ? `${v.points} × ${v.weight} = ${Math.round(v.points * v.weight * 10) / 10}` : ''}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                ) : <p className="text-foreground-muted">No breakdown stored for this finding.</p>}
                <p className="text-[11px] text-foreground-muted mt-2">Score = 45% technical + 30% exploitation + 15% exposure + 10% criticality. <Link href="/admin/vms/risk" className="underline">How risk is calculated</Link></p>
            </Section>

            {/* Threat context */}
            {data.cve_intel.length > 0 && (
                <Section title="Threat context">
                    <div className="space-y-2">
                        {data.cve_intel.map((c) => (
                            <div key={c.cve_id} className="border border-border rounded-xl p-3 bg-card space-y-1">
                                <p className="font-bold text-foreground flex flex-wrap items-center gap-2">{c.cve_id}{c.kev && <Tag strong>CISA KEV{c.kev_ransomware === 'Known' ? ' · ransomware' : ''}</Tag>}</p>
                                <p className="text-foreground-muted">CVSS {c.cvss_score ?? 'unknown'} · EPSS {c.epss_score !== null ? `${(c.epss_score * 100).toFixed(1)}%${c.epss_percentile !== null ? ` (percentile ${(c.epss_percentile * 100).toFixed(0)})` : ''}` : 'unknown'} · KEV {c.kev_checked_at ? (c.kev ? `yes, added ${c.kev_date_added}` : 'no') : 'not checked yet'}</p>
                                {c.kev_required_action && <p className="text-foreground">CISA required action: {c.kev_required_action}</p>}
                                {c.description && <p className="text-foreground leading-relaxed">{c.description}</p>}
                                {c.osv_status === 'found' && (c.osv_affected ?? []).filter((a) => a.fixed.length).slice(0, 4).map((a, i) => <p key={i} className="text-foreground-muted">Fixed in {a.fixed.join(', ')} — {a.name ?? a.repo}{a.ecosystem ? ` (${a.ecosystem})` : ''}</p>)}
                            </div>
                        ))}
                    </div>
                </Section>
            )}

            {(f.description || f.remediation) && (
                <Section title="Scanner guidance">
                    {f.description && <p className="whitespace-pre-wrap text-foreground leading-relaxed">{f.description}</p>}
                    {f.remediation && <><p className="text-[11px] font-semibold text-foreground-muted mt-2">Remediation</p><p className="whitespace-pre-wrap text-foreground leading-relaxed">{f.remediation}</p></>}
                </Section>
            )}

            {(data.correlated ?? []).length > 0 && (
                <Section title="Same CVE elsewhere">
                    {data.correlated!.map((c) => (
                        <div key={c.other.id} className="border-t border-border first:border-0 py-1.5">
                            <p><Tag>{c.basis}</Tag> <Link href={`/admin/vms/findings?id=${c.other.id}`} className="font-mono font-semibold text-purple dark:text-[var(--vz-prog-4)]">{c.other.asset_value}</Link> <span className="text-foreground-muted">· {STATUS_LABEL[c.other.status] ?? c.other.status} · {c.cves.join(', ')}</span></p>
                            <p className="text-foreground-muted">{c.explanation}</p>
                        </div>
                    ))}
                </Section>
            )}
            {data.correlation_error && <p className="text-foreground-muted">{data.correlation_error}</p>}

            <AiPanel key={f.id} purpose="finding_explanation" subjectId={f.id} title="AI analysis (draft — check before acting)"
                purposes={[{ value: 'finding_explanation', label: 'Explain this vulnerability' }, { value: 'remediation_plan', label: 'Remediation plan' }, { value: 'rescan_interpretation', label: 'Interpret the rescan' }]} />

            {/* Tasks */}
            <Section title={`Remediation tasks (${data.tasks.length})`}>
                {data.tasks.length === 0 && <p className="text-foreground-muted">No tasks yet.</p>}
                {data.tasks.map((t) => (
                    <div key={t.id} className="flex flex-wrap items-center gap-2 border-t border-border first:border-0 py-2">
                        <span className="flex-1 min-w-[160px] text-foreground">{t.title}{t.ai_artifact_id ? <span className="text-foreground-muted"> · from AI plan</span> : null}</span>
                        <span className="text-foreground-muted">{t.owner ?? 'Unassigned'} · {t.due_at ? fmtWat(t.due_at) : 'no deadline'}</span>
                        {can.manage
                            ? <select aria-label={`Status of ${t.title}`} value={t.status} onChange={(e) => void run('PATCH', `/api/vms/tasks/${t.id}`, { status: e.target.value }, 'Task updated')} className="bg-card border border-border rounded-lg px-1.5 py-1 text-[11px] text-foreground">{Object.entries(TASK_LABEL).map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
                            : <span className="font-semibold">{TASK_LABEL[t.status] ?? t.status}</span>}
                    </div>
                ))}
                {can.manage && (
                    <form className="flex flex-wrap gap-2 items-end mt-2" onSubmit={async (e) => { e.preventDefault(); if (task.title.trim().length < 3) return; const ok = await run('POST', `/api/vms/findings/${f.id}/tasks`, { title: task.title.trim(), ...(task.owner.trim() ? { owner: task.owner.trim() } : {}), ...(task.due ? { due_at: new Date(`${task.due}T23:59:59Z`).toISOString() } : {}) }, 'Task added'); if (ok) setTask({ title: '', owner: '', due: '' }); }}>
                        <input aria-label="New task" value={task.title} onChange={(e) => setTask({ ...task, title: e.target.value })} minLength={3} maxLength={300} placeholder="New task (at least 3 characters)" className="flex-1 min-w-[180px] bg-card border border-border rounded-lg px-2 py-1.5 text-xs text-foreground" />
                        <input aria-label="Task owner" value={task.owner} onChange={(e) => setTask({ ...task, owner: e.target.value })} maxLength={200} placeholder="Owner" className="w-32 bg-card border border-border rounded-lg px-2 py-1.5 text-xs text-foreground" />
                        <input aria-label="Task due date" type="date" value={task.due} onChange={(e) => setTask({ ...task, due: e.target.value })} className="bg-card border border-border rounded-lg px-2 py-1.5 text-xs text-foreground" />
                        <button type="submit" disabled={task.title.trim().length < 3} className={btn('secondary')}><Plus className="w-3.5 h-3.5" aria-hidden /> Add task</button>
                    </form>
                )}
            </Section>

            {/* Comments */}
            <Section title="Comments">
                {data.events.filter((e) => e.action === 'note').length === 0 && <p className="text-foreground-muted">No comments yet.</p>}
                {data.events.filter((e) => e.action === 'note').map((e) => (
                    <div key={e.id} className="border-t border-border first:border-0 py-2"><p className="text-[11px] text-foreground-muted">{e.actor} · {fmtWat(e.at)}</p><p className="text-foreground whitespace-pre-wrap">{e.details}</p></div>
                ))}
                {can.manage && (
                    <form className="flex gap-2 mt-2" onSubmit={async (e) => { e.preventDefault(); if (!note.trim()) return; if (await run('POST', `/api/vms/findings/${f.id}/notes`, { note: note.trim() }, 'Comment added')) setNote(''); }}>
                        <input aria-label="Add a comment" value={note} onChange={(e) => setNote(e.target.value)} maxLength={4000} placeholder="Add a comment" className="flex-1 bg-card border border-border rounded-lg px-2 py-1.5 text-xs text-foreground" />
                        <button type="submit" disabled={!note.trim()} className={btn('secondary')}><MessageSquare className="w-3.5 h-3.5" aria-hidden /> Comment</button>
                    </form>
                )}
            </Section>

            <Section title={`Evidence (${data.evidence.length})`}>
                <EvidenceViewer items={data.evidence.map((e) => ({ id: e.id, title: `${e.source}${e.matched_at ? ` · ${e.matched_at}` : ''}`, meta: fmtWat(e.observed_at), content: e.evidence }))} />
            </Section>

            <Section title="History">
                <Timeline items={data.events.slice().reverse().map((e) => ({
                    id: e.id, at: e.at,
                    title: e.action === 'status' ? `Status: ${STATUS_LABEL[e.from_value ?? ''] ?? e.from_value ?? '—'} → ${STATUS_LABEL[e.to_value ?? ''] ?? e.to_value}` : e.action.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase()) + (e.to_value && e.action !== 'note' && e.action !== 'verification_queued' ? `: ${e.to_value}` : ''),
                    meta: `${e.actor} · ${fmtWat(e.at)}`, body: e.action !== 'note' ? e.details : null,
                    tone: e.action === 'verified' ? 'good' : e.action === 'reopened' ? 'critical' : undefined,
                }))} />
            </Section>

            <ConfirmDialog
                open={pending?.kind === 'status'}
                title={pending?.kind === 'status' ? `Mark as ${STATUS_LABEL[pending.to].toLowerCase()}?` : ''}
                body={pending?.kind === 'status' && (pending.to === 'risk_accepted' || pending.to === 'false_positive')
                    ? 'The finding leaves the open queue. Give the reason; it is recorded in the finding history and the audit trail.'
                    : pending?.kind === 'status' && pending.to === 'fixed_pending_verification' ? 'The finding stays open until a rescan (or Wazuh) shows it is gone.' : 'The change is recorded in the finding history.'}
                confirmLabel="Confirm"
                reason={pending?.kind === 'status' ? { label: 'Reason', required: pending.to === 'risk_accepted' || pending.to === 'false_positive' } : undefined}
                onCancel={() => setPending(null)}
                onConfirm={async (reason) => { if (pending?.kind !== 'status') return; await run('PATCH', `/api/vms/findings/${f.id}`, { status: pending.to, ...(reason ? { note: reason } : {}) }, `Marked ${STATUS_LABEL[pending.to].toLowerCase()}`); setPending(null); }}
            />
            <ConfirmDialog
                open={pending?.kind === 'verify'}
                title="Queue a verification scan?"
                body={<>{f.source_class === 'wazuh' ? 'Wazuh findings are verified by the next Wazuh sync; nothing is scanned.' : <>A scan of <span className="font-mono">{f.asset_value}</span> is queued, only if the asset is still inside active vulnerability-scan scope. It runs on an engine that a connected worker has enabled.</>}</>}
                confirmLabel="Queue verification"
                onCancel={() => setPending(null)}
                onConfirm={async () => { await run('POST', `/api/vms/findings/${f.id}/verify`, {}, 'Verification scan queued'); setPending(null); }}
            />
            <ConfirmDialog
                open={pending?.kind === 'case'}
                title="Promote to a case?"
                body="A security case is opened from this finding (or the existing one is linked) for incident handling."
                confirmLabel="Open case"
                onCancel={() => setPending(null)}
                onConfirm={async () => { await run('POST', `/api/vms/findings/${f.id}/case`, {}, 'Case opened'); setPending(null); }}
            />
            {!can.manage && <p className="text-[11px] text-foreground-muted flex items-center gap-1"><ShieldAlert className="w-3.5 h-3.5" aria-hidden /> Read-only: changes need an analyst or manager role.</p>}
        </div>
    );
}

function Fact({ k, v }: { k: string; v: React.ReactNode }) {
    return <div className="min-w-0"><dt className="text-[10px] font-semibold uppercase tracking-wide text-foreground-muted">{k}</dt><dd className="text-xs text-foreground mt-0.5 break-words">{v}</dd></div>;
}
function Section({ title, children }: { title: string; children: React.ReactNode }) {
    return <section><h3 className="text-[11px] font-bold uppercase tracking-wide text-foreground-muted mb-2">{title}</h3>{children}</section>;
}
