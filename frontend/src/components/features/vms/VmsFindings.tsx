'use client';

// Findings (phase P5) — one list for Nuclei, OpenVAS and Wazuh findings, prioritised by the risk
// engine. Verified and reopened come only from scan evidence; people move findings through the
// other states, set owners and deadlines, add tasks, request verification and open cases.

import { useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { Bug, Search } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { loadJson } from '@/lib/alerts';
import { getAdminUser } from '@/lib/admin-auth';
import { AiPanel } from '@/components/shared/AiPanel';
import { fmtWat } from '@/lib/vms';

export interface Finding {
    id: string; asset_id: string | null; asset_value: string; port: number | null; protocol: string | null; source_class: 'active_scan' | 'wazuh'; detected_by: string[];
    rule_id: string; title: string; finding_type: string; cve_ids: string[]; scanner_severity: string; scanner_cvss: number | null; risk_score: number | null;
    priority: 'P1' | 'P2' | 'P3' | 'P4' | null; status: string; owner: string | null; due_at: string | null; first_seen: string; last_seen: string; verified_at: string | null; case_id: string | null;
    description?: string | null; remediation?: string | null; references_urls?: string[]; risk_factors?: Record<string, { points?: number; basis?: string; weight?: number } | string>;
}
interface Detail {
    finding: Finding;
    evidence: { id: string; source: string; observed_at: string; matched_at: string | null; evidence: unknown; job_id: string | null }[];
    events: { id: string; at: string; actor: string; action: string; from_value: string | null; to_value: string | null; details: string | null }[];
    cve_intel: { cve_id: string; description: string | null; cvss_score: number | null; cvss_vector: string | null; epss_score: number | null; epss_percentile: number | null; kev: boolean; kev_checked_at: string | null; kev_date_added: string | null; kev_required_action: string | null; kev_ransomware: string | null }[];
    asset: { id: string; value: string; exposure: string; criticality: string; owner: string | null } | null;
    tasks: { id: string; title: string; status: string; owner: string | null; due_at: string | null }[];
}
interface Summary { open: number; by_severity: Record<string, number>; by_priority: Record<string, number>; known_exploited_open: number; overdue: number; by_source: Record<string, number> }

export const PRIORITY_STYLE: Record<string, string> = { P1: 'bg-red-500 text-white', P2: 'bg-orange text-white', P3: 'bg-amber text-white', P4: 'bg-card-muted text-foreground-muted' };
export const STATUS_LABEL: Record<string, string> = {
    open: 'Open', acknowledged: 'Acknowledged', in_progress: 'In progress', fixed_pending_verification: 'Fixed — awaiting verification', verified: 'Verified fixed',
    reopened: 'Reopened', risk_accepted: 'Risk accepted', false_positive: 'False positive',
};
const NEXT: Record<string, string[]> = {
    open: ['acknowledged', 'in_progress', 'fixed_pending_verification', 'risk_accepted', 'false_positive'], reopened: ['acknowledged', 'in_progress', 'fixed_pending_verification', 'risk_accepted', 'false_positive'],
    acknowledged: ['in_progress', 'fixed_pending_verification', 'risk_accepted', 'false_positive', 'open'], in_progress: ['fixed_pending_verification', 'acknowledged', 'risk_accepted', 'false_positive', 'open'],
    fixed_pending_verification: ['in_progress', 'open'], verified: [], risk_accepted: ['open'], false_positive: ['open'],
};
const SEVS = ['critical', 'high', 'medium', 'low', 'info'];

function isOverdue(f: Finding): boolean {
    return !!f.due_at && Date.parse(f.due_at) < Date.now() && !['verified', 'risk_accepted', 'false_positive'].includes(f.status);
}

export function VmsFindings() {
    const params = useSearchParams();
    const role = getAdminUser().role;
    const canManage = ['super_admin', 'soc_manager', 'analyst'].includes(role);
    const [filter, setFilter] = useState({ status: 'open_all', priority: params.get('priority') ?? '', source: '', kev: false, overdue: params.get('overdue') === 'true' });
    const [search, setSearch] = useState('');
    const [text, setText] = useState('');
    const [findings, setFindings] = useState<Finding[] | null>(null);
    const [summary, setSummary] = useState<Summary | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [detail, setDetail] = useState<Detail | null>(null);
    const [msg, setMsg] = useState<string | null>(null);
    const [reloadKey, setReloadKey] = useState(0);

    useEffect(() => {
        let active = true;
        const p = new URLSearchParams({ status: filter.status });
        if (filter.priority) p.set('priority', filter.priority);
        if (filter.source) p.set('source', filter.source);
        if (filter.kev) p.set('kev', 'true');
        if (filter.overdue) p.set('overdue', 'true');
        if (text) p.set('q', text);
        void Promise.all([loadJson<{ findings: Finding[] }>(`/api/vms/findings?${p.toString()}`), loadJson<Summary>('/api/vms/findings/summary')]).then(([f, s]) => {
            if (!active) return;
            setFindings(f.ok ? f.data.findings : null);
            setError(f.ok ? null : f.error);
            setSummary(s.ok ? s.data : null);
        });
        return () => { active = false; };
    }, [filter, text, reloadKey]);

    // Opened from a link (e.g. the remediation queue): /admin/vms/findings?id=…
    useEffect(() => {
        const id = params.get('id');
        if (!id) return;
        let active = true;
        void loadJson<Detail>(`/api/vms/findings/${id}`).then((r) => { if (active && r.ok) setDetail(r.data); });
        return () => { active = false; };
    }, [params]);

    async function open(id: string) {
        setMsg(null);
        const r = await loadJson<Detail>(`/api/vms/findings/${id}`);
        setDetail(r.ok ? r.data : null);
    }
    async function call(method: string, path: string, body: unknown, done: string) {
        setMsg(null);
        const r = await apiFetch(apiUrl(path), { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        const d = await r.json().catch(() => null);
        if (!r.ok) { setMsg(d?.error ?? `HTTP ${r.status}`); return null; }
        setMsg(d?.message ?? done);
        if (detail) await open(detail.finding.id);
        setReloadKey((k) => k + 1);
        return d;
    }
    async function setStatus(next: string) {
        if (!detail) return;
        const needsReason = next === 'risk_accepted' || next === 'false_positive';
        const note = needsReason ? window.prompt(`Reason for ${STATUS_LABEL[next].toLowerCase()} (required)`) : window.prompt('Note (optional)') ?? undefined;
        if (needsReason && !note) return;
        await call('PATCH', `/api/vms/findings/${detail.finding.id}`, { status: next, ...(note ? { note } : {}) }, `Marked ${STATUS_LABEL[next].toLowerCase()}`);
    }
    async function tasksFromPlan() {
        if (!detail) return;
        const r = await loadJson<{ artifacts: { id: string; purpose: string; status: string; content: { steps?: { order: number; action: string; details: string; owner_suggestion: string; proposed_deadline_days: number }[] } }[] }>(`/api/ai/artifacts?subject_type=finding&subject_id=${detail.finding.id}`);
        const plan = r.ok ? r.data.artifacts.find((a) => a.purpose === 'remediation_plan' && a.status === 'accepted') : undefined;
        if (!plan?.content.steps?.length) { setMsg('Mark an AI remediation plan as "Useful" first; tasks are created only from a plan a person accepted.'); return; }
        for (const s of [...plan.content.steps].sort((a, b) => a.order - b.order)) {
            const due = Number.isFinite(s.proposed_deadline_days) && s.proposed_deadline_days > 0 ? new Date(Date.now() + s.proposed_deadline_days * 86_400_000).toISOString() : undefined;
            await apiFetch(apiUrl(`/api/vms/findings/${detail.finding.id}/tasks`), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title: s.action.slice(0, 300), details: s.details?.slice(0, 4000), owner: s.owner_suggestion?.slice(0, 200), due_at: due, ai_artifact_id: plan.id }) });
        }
        setMsg(`Created ${plan.content.steps.length} task(s) from the accepted plan`);
        await open(detail.finding.id);
    }

    const f = detail?.finding;
    const chip = (on: boolean) => `text-[11px] font-bold px-2.5 py-1 rounded-md ${on ? 'bg-blue text-white' : 'text-foreground-muted hover:text-foreground'}`;
    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground flex items-center gap-2"><Bug className="w-5 h-5" /> Findings</h1>
                <p className="text-xs text-foreground-muted">Vulnerabilities from active scans (Nuclei, OpenVAS) and Wazuh endpoints, prioritised by severity, exploitation evidence, exposure and asset criticality.</p>
            </div>
            {summary && (
                <div className="grid grid-cols-2 lg:grid-cols-6 gap-3">
                    {[['Open', summary.open], ['Known exploited (KEV)', summary.known_exploited_open], ['Overdue', summary.overdue], ['P1', summary.by_priority.P1 ?? 0], ['P2', summary.by_priority.P2 ?? 0], ['Wazuh-reported', summary.by_source.wazuh ?? 0]].map(([k, v]) => (
                        <div key={String(k)} className="bg-card border border-border rounded-xl p-3"><p className="text-[10px] font-bold text-foreground-muted uppercase">{k}</p><p className="text-xl font-black text-foreground">{v}</p></div>
                    ))}
                </div>
            )}
            {summary && summary.open > 0 && (
                <div className="bg-card border border-border rounded-xl p-3">
                    <p className="text-[10px] font-bold text-foreground-muted uppercase mb-2">Open findings by scanner severity</p>
                    <div className="flex h-3 rounded overflow-hidden" role="img" aria-label="Severity distribution">
                        {SEVS.map((s) => (summary.by_severity[s] ? <div key={s} title={`${s}: ${summary.by_severity[s]}`} style={{ width: `${(summary.by_severity[s] / summary.open) * 100}%` }} className={{ critical: 'bg-red-500', high: 'bg-orange', medium: 'bg-amber', low: 'bg-blue', info: 'bg-grey-300' }[s]} /> : null))}
                    </div>
                    <p className="text-[10px] text-foreground-muted mt-1">{SEVS.filter((s) => summary.by_severity[s]).map((s) => `${s} ${summary.by_severity[s]}`).join(' · ')}</p>
                </div>
            )}
            <div className="flex flex-wrap gap-2 items-center">
                <div className="flex gap-1 bg-card border border-border rounded-lg p-1">{[['open_all', 'Open'], ['fixed_pending_verification', 'Awaiting verification'], ['verified', 'Verified'], ['risk_accepted,false_positive', 'Accepted / FP'], ['all', 'All']].map(([v, l]) => <button key={v} onClick={() => setFilter({ ...filter, status: v })} className={chip(filter.status === v)}>{l}</button>)}</div>
                <div className="flex gap-1 bg-card border border-border rounded-lg p-1">{['', 'P1', 'P2', 'P3', 'P4'].map((v) => <button key={v || 'any'} onClick={() => setFilter({ ...filter, priority: v })} className={chip(filter.priority === v)}>{v || 'Any priority'}</button>)}</div>
                <div className="flex gap-1 bg-card border border-border rounded-lg p-1">{[['', 'All sources'], ['active_scan', 'Active scans'], ['wazuh', 'Wazuh']].map(([v, l]) => <button key={v || 'all'} onClick={() => setFilter({ ...filter, source: v })} className={chip(filter.source === v)}>{l}</button>)}</div>
                <button onClick={() => setFilter({ ...filter, kev: !filter.kev })} className={`${chip(filter.kev)} border border-border`}>Known exploited</button>
                <button onClick={() => setFilter({ ...filter, overdue: !filter.overdue })} className={`${chip(filter.overdue)} border border-border`}>Overdue</button>
                <form onSubmit={(e) => { e.preventDefault(); setText(search.trim()); }} className="flex items-center gap-1 bg-card border border-border rounded-lg px-2 py-1">
                    <Search className="w-3.5 h-3.5 text-foreground-muted" />
                    <input aria-label="Search findings" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="CVE, title or asset" className="bg-transparent text-[11px] outline-none w-40" />
                </form>
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
                <div className="lg:col-span-2 bg-card border border-border rounded-xl overflow-hidden">
                    {findings && findings.length === 0 && <p className="text-sm text-foreground-muted text-center py-10">No data — no findings for these filters.</p>}
                    <div className="max-h-[700px] overflow-y-auto divide-y divide-border">
                        {findings?.map((x) => (
                            <button key={x.id} onClick={() => void open(x.id)} className={`w-full text-left p-3 hover:bg-card-muted ${f?.id === x.id ? 'bg-card-muted' : ''}`}>
                                <div className="flex items-center gap-2">
                                    <span className={`text-[9px] font-black px-1.5 py-0.5 rounded ${PRIORITY_STYLE[x.priority ?? 'P4']}`}>{x.priority ?? '—'}</span>
                                    <span className="text-[10px] text-foreground-muted">risk {x.risk_score ?? '—'}</span>
                                    {isOverdue(x) && <span className="text-[9px] font-bold text-red uppercase">overdue</span>}
                                </div>
                                <p className="text-xs font-bold text-foreground mt-1">{x.title}</p>
                                <p className="text-[10px] text-foreground-muted">{x.asset_value}{x.port ? `:${x.port}` : ''} · {x.detected_by.join(', ')} · {STATUS_LABEL[x.status] ?? x.status}</p>
                            </button>
                        ))}
                    </div>
                </div>
                <div className="lg:col-span-3 bg-card border border-border rounded-xl p-4">
                    {!detail || !f ? <p className="text-xs text-foreground-muted text-center py-10">Select a finding.</p> : (
                        <div className="space-y-4 text-xs">
                            <div>
                                <div className="flex items-center gap-2 flex-wrap">
                                    <span className={`text-[10px] font-black px-2 py-0.5 rounded ${PRIORITY_STYLE[f.priority ?? 'P4']}`}>{f.priority}</span>
                                    <span className="text-foreground-muted">risk {f.risk_score} · scanner severity {f.scanner_severity}{f.scanner_cvss !== null ? ` · CVSS ${f.scanner_cvss}` : ''}</span>
                                    <span className="font-bold text-foreground">{STATUS_LABEL[f.status]}</span>
                                </div>
                                <h2 className="text-sm font-black text-foreground mt-1">{f.title}</h2>
                                <p className="text-foreground-muted">{detail.asset ? <Link className="underline" href={`/admin/vms/assets`}>{f.asset_value}</Link> : f.asset_value}{f.port ? ` port ${f.port}/${f.protocol}` : ''} · {f.source_class === 'wazuh' ? 'reported by Wazuh' : `found by ${f.detected_by.join(' and ')}`} · first seen {fmtWat(f.first_seen)} · last seen {fmtWat(f.last_seen)}</p>
                            </div>
                            {msg && <p role="status" className="font-semibold text-foreground">{msg}</p>}
                            {canManage && (
                                <div className="flex flex-wrap gap-2">
                                    {(NEXT[f.status] ?? []).map((s) => <button key={s} onClick={() => void setStatus(s)} className="text-[11px] font-bold border border-border rounded-lg px-2.5 py-1 hover:bg-card-muted">{STATUS_LABEL[s]}</button>)}
                                    {f.status === 'fixed_pending_verification' && <button onClick={() => void call('POST', `/api/vms/findings/${f.id}/verify`, {}, 'Verification scan queued')} className="text-[11px] font-bold text-white bg-purple rounded-lg px-2.5 py-1">Verify with a rescan</button>}
                                    {f.case_id ? <Link href={`/admin/secops/cases?case=${f.case_id}`} className="text-[11px] font-bold text-purple border border-purple/40 rounded-lg px-2.5 py-1">Open case</Link>
                                        : <button onClick={() => void call('POST', `/api/vms/findings/${f.id}/case`, {}, 'Case opened')} className="text-[11px] font-bold border border-border rounded-lg px-2.5 py-1">Promote to case</button>}
                                </div>
                            )}
                            {canManage && (
                                <div className="flex flex-wrap gap-3 items-end">
                                    <label className="text-[11px] font-bold text-foreground-muted">Owner
                                        <input key={`o-${f.id}`} defaultValue={f.owner ?? ''} onBlur={(e) => { if (e.target.value !== (f.owner ?? '')) void call('PATCH', `/api/vms/findings/${f.id}`, { owner: e.target.value.trim() || null }, 'Owner saved'); }} className="block bg-card-muted border border-border rounded px-2 py-1" />
                                    </label>
                                    <label className="text-[11px] font-bold text-foreground-muted">Due ({f.due_at ? fmtWat(f.due_at) : 'none'})
                                        <input type="date" onChange={(e) => { if (e.target.value) void call('PATCH', `/api/vms/findings/${f.id}`, { due_at: new Date(`${e.target.value}T23:59:59Z`).toISOString() }, 'Deadline saved'); }} className="block bg-card-muted border border-border rounded px-2 py-1" />
                                    </label>
                                </div>
                            )}
                            {f.risk_factors && (
                                <div><p className="text-[10px] font-bold text-foreground-muted uppercase">Why this priority</p>
                                    {Object.entries(f.risk_factors).map(([k, v]) => <p key={k} className="text-foreground-muted">{k}: {typeof v === 'string' ? v : `${v.basis} (${v.points} pts × ${v.weight})`}</p>)}
                                </div>
                            )}
                            {detail.cve_intel.map((c) => (
                                <div key={c.cve_id} className="border border-border rounded-lg p-2">
                                    <p className="font-bold">{c.cve_id}{c.kev ? <span className="ml-2 text-[10px] font-black text-white bg-red-500 rounded px-1.5">KNOWN EXPLOITED (CISA KEV)</span> : null}</p>
                                    <p className="text-foreground-muted">CVSS {c.cvss_score ?? 'unknown'} · EPSS {c.epss_score !== null ? `${(c.epss_score * 100).toFixed(1)}% (percentile ${c.epss_percentile !== null ? (c.epss_percentile * 100).toFixed(0) : '?'})` : 'unknown'} · KEV {c.kev_checked_at ? (c.kev ? `yes, added ${c.kev_date_added}${c.kev_ransomware === 'Known' ? ', used in ransomware' : ''}` : 'no') : 'not checked yet'}</p>
                                    {c.kev_required_action && <p className="text-foreground">CISA required action: {c.kev_required_action}</p>}
                                    {c.description && <p className="text-foreground mt-1">{c.description}</p>}
                                </div>
                            ))}
                            {f.description && <div><p className="text-[10px] font-bold text-foreground-muted uppercase">Scanner description</p><p className="whitespace-pre-wrap">{f.description}</p></div>}
                            {f.remediation && <div><p className="text-[10px] font-bold text-foreground-muted uppercase">Scanner remediation</p><p className="whitespace-pre-wrap">{f.remediation}</p></div>}
                            <AiPanel key={f.id} purpose="finding_explanation" subjectId={f.id} title="AI analysis"
                                purposes={[{ value: 'finding_explanation', label: 'Explain this vulnerability' }, { value: 'remediation_plan', label: 'Remediation plan' }, { value: 'rescan_interpretation', label: 'Interpret the rescan' }]} />
                            <div>
                                <div className="flex items-center justify-between"><p className="text-[10px] font-bold text-foreground-muted uppercase">Remediation tasks</p>
                                    {canManage && <button onClick={() => void tasksFromPlan()} className="text-[11px] font-bold text-purple">Create tasks from accepted AI plan</button>}</div>
                                {detail.tasks.length === 0 ? <p className="text-foreground-muted">None yet.</p> : detail.tasks.map((t) => (
                                    <div key={t.id} className="flex items-center gap-2 border-t border-border py-1">
                                        <span className="flex-1">{t.title}</span><span className="text-foreground-muted">{t.owner ?? '—'} · {t.due_at ? fmtWat(t.due_at) : 'no deadline'}</span>
                                        {canManage ? <select aria-label="Task status" value={t.status} onChange={(e) => void call('PATCH', `/api/vms/tasks/${t.id}`, { status: e.target.value }, 'Task updated')} className="bg-card-muted border border-border rounded px-1 py-0.5 text-[11px]">{['todo', 'doing', 'done', 'cancelled'].map((s) => <option key={s}>{s}</option>)}</select> : <span>{t.status}</span>}
                                    </div>
                                ))}
                                {canManage && <button onClick={() => { const t = window.prompt('Task'); if (t) void call('POST', `/api/vms/findings/${f.id}/tasks`, { title: t }, 'Task added'); }} className="text-[11px] font-bold text-foreground-muted mt-1">+ Add task</button>}
                            </div>
                            <div>
                                <p className="text-[10px] font-bold text-foreground-muted uppercase">Evidence ({detail.evidence.length})</p>
                                {detail.evidence.map((e) => <div key={e.id} className="border-t border-border py-1"><p className="text-foreground-muted">{fmtWat(e.observed_at)} · {e.source} · {e.matched_at ?? ''}</p><pre className="text-[10px] font-mono whitespace-pre-wrap break-all text-foreground-muted max-h-40 overflow-y-auto">{JSON.stringify(e.evidence, null, 2)}</pre></div>)}
                            </div>
                            <div>
                                <p className="text-[10px] font-bold text-foreground-muted uppercase">History</p>
                                {detail.events.map((e) => <p key={e.id} className="text-foreground-muted">{fmtWat(e.at)} · {e.actor} · {e.action}{e.to_value ? `: ${e.from_value ? `${e.from_value} → ` : ''}${e.to_value}` : ''}{e.details ? ` — ${e.details}` : ''}</p>)}
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
