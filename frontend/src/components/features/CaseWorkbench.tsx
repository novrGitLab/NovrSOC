'use client';

import { useEffect, useState } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { apiUrl, apiFetch } from '@/lib/api';
import { exportDataAsPDF } from '@/lib/exportPDF';
import { ASSIGNABLE_ANALYSTS } from '@/lib/mockTeam';
import {
    AlertTriangle, Clock, CheckCircle, RefreshCw, TrendingUp, FileText, ChevronRight, MessageSquarePlus,
    FileDown, Briefcase, Server, Terminal, UserCheck, ListChecks, Plus, X, UserPlus, BookOpen,
    ClipboardList, Crosshair, Lock, Play,
} from 'lucide-react';

// Case workbench — reads and writes /api/cases (Supabase). Cases come from two places: the SOAR
// engine on the Wazuh manager (one per level 7+ alert) and analyst actions elsewhere in the
// platform. The queue excludes tier-1 cases the engine auto-closed; those never needed an
// analyst and are reported on SOAR Automation instead.

type Severity = 'critical' | 'high' | 'medium' | 'low';
type CaseStatus = 'open' | 'investigating' | 'contained' | 'resolved';
type NoteType = 'Update' | 'Evidence' | 'Decision' | 'Escalation';
type Filter = 'all' | CaseStatus;

interface CaseItem {
    id: string;
    case_number: string;
    title: string;
    description: string | null;
    severity: Severity;
    status: CaseStatus;
    source: string;
    agent_id: string | null;
    agent_name: string | null;
    source_ip: string | null;
    rule_id: string | null;
    rule_level: number | null;
    mitre_technique: string | null;
    mitre_tactic: string | null;
    assigned_to: string | null;
    created_at: string;
    updated_at: string;
    resolved_at: string | null;
    tier: number;
    auto_closed: boolean;
    containment_done: boolean;
    escalated: boolean;
    tags: string[] | null;
}

interface CaseNote { id: string; author: string; type: NoteType; content: string; created_at: string }
interface CaseTask { id: string; step_id: string; title: string; description: string | null; status: string; result?: string | null; executed_by?: string | null }

// Tasks whose step_id is one of these have an action the backend can run (POST
// /api/cases/:id/execute-step). Must match EXECUTABLE_STEPS in backend services/responseActions.ts.
const EXECUTABLE_STEPS = new Set(['block_ip', 'isolate_agent', 'enrich_iocs', 'notify_email', 'notify_ciso']);
interface TimelineEntry { id: string; actor: string; action: string; details: string | null; automated: boolean; created_at: string }
interface CaseIoc { id: string; type: string; value: string; verdict: string | null; risk_score: number | null }
interface CaseDetail { case: CaseItem; notes: CaseNote[]; tasks: CaseTask[]; timeline: TimelineEntry[]; iocs: CaseIoc[] }

interface Summary { open: number; investigating: number; contained: number; active: number; critical: number; resolved: number; resolvedToday: number }

interface PlaybookSummary {
    id: string;
    name: string;
    icon: string;
    description: string;
    steps: { order: number; title: string }[] | null;
}

const SEV_STYLE: Record<Severity, string> = {
    critical: 'bg-red-500/10 text-red-500 border-red-500/30',
    high: 'bg-orange/10 text-orange border-orange/30',
    medium: 'bg-amber-500/10 text-amber-500 border-amber-500/30',
    low: 'bg-blue/10 text-blue border-blue/30',
};

const STATUS_STYLE: Record<CaseStatus, string> = {
    open: 'bg-red-500/10 text-red-500 border-red-500/30',
    investigating: 'bg-blue/10 text-blue border-blue/30',
    contained: 'bg-amber-500/10 text-amber-500 border-amber-500/30',
    resolved: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/30',
};

const WORKFLOW_STEPS: { id: CaseStatus; label: string }[] = [
    { id: 'open', label: 'Open' },
    { id: 'investigating', label: 'Investigating' },
    { id: 'contained', label: 'Contained' },
    { id: 'resolved', label: 'Resolved' },
];
const NEXT_STEP_LABEL = ['Start Investigation', 'Mark as Contained', 'Resolve Case'];

// Per-analyst working checklist, kept in this browser only. Anything the team needs to see
// belongs in Response Tasks (stored on the case) or a note.
const INVESTIGATION_STEPS = [
    { id: 'triage', label: 'Initial Triage', desc: 'Review alert details, confirm severity, identify affected assets' },
    { id: 'contain', label: 'Containment', desc: 'Isolate affected systems, block malicious IPs, revoke credentials' },
    { id: 'evidence', label: 'Evidence Collection', desc: 'Capture logs, memory dumps, network traffic, screenshots' },
    { id: 'eradicate', label: 'Eradication', desc: 'Remove malware, patch vulnerability, close attack vector' },
    { id: 'recover', label: 'Recovery', desc: 'Restore systems, verify clean state, resume normal operations' },
    { id: 'review', label: 'Post-Incident Review', desc: 'Document lessons learned, update playbooks, report to management' },
];
const CHECKLIST_KEY = (caseId: string) => `novrsoc.case-checklist.${caseId}`;

const NOTE_TYPES: NoteType[] = ['Update', 'Evidence', 'Decision', 'Escalation'];
const NOTE_TYPE_STYLE: Record<NoteType, string> = {
    Update: 'bg-blue/15 text-blue border-blue/30',
    Evidence: 'bg-card-muted text-foreground-muted border-border',
    Decision: 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30',
    Escalation: 'bg-red-500/15 text-red-500 border-red-500/30',
};

const wat = (iso: string | null | undefined) =>
    iso ? `${new Date(iso).toLocaleString('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })} WAT` : '—';

type ListState =
    | { kind: 'loading' }
    | { kind: 'ready'; cases: CaseItem[]; total: number; summary: Summary | null }
    | { kind: 'unauthorised' }
    | { kind: 'error'; message: string };

// State is only set in the promise callbacks, so this is safe to start from the mount effect;
// handlers that refetch set the loading state themselves first.
function loadCases(f: Filter, setList: (s: ListState) => void) {
    const params = new URLSearchParams({ exclude_auto_closed: 'true', limit: '100' });
    if (f !== 'all') params.set('status', f);
    return apiFetch(apiUrl(`/api/cases?${params}`), { cache: 'no-store' })
        .then(async (r) => {
            if (r.status === 401 || r.status === 403) { setList({ kind: 'unauthorised' }); return; }
            const data = await r.json();
            if (!r.ok) { setList({ kind: 'error', message: data?.error ?? `HTTP ${r.status}` }); return; }
            setList({ kind: 'ready', cases: Array.isArray(data?.cases) ? data.cases : [], total: data?.total ?? 0, summary: data?.summary ?? null });
        })
        .catch(() => setList({ kind: 'error', message: 'Could not reach the backend' }));
}

export function CaseWorkbench() {
    const [filter, setFilter] = useState<Filter>('all');
    const [list, setList] = useState<ListState>({ kind: 'loading' });
    const [selectedId, setSelectedId] = useState<string | null>(null);
    const [detail, setDetail] = useState<CaseDetail | null>(null);
    const [detailError, setDetailError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);
    const [actionError, setActionError] = useState<string | null>(null);
    const [showAddNote, setShowAddNote] = useState(false);
    const [noteType, setNoteType] = useState<NoteType>('Update');
    const [noteText, setNoteText] = useState('');
    const [newTaskTitle, setNewTaskTitle] = useState('');
    const [checkedSteps, setCheckedSteps] = useState<Set<string>>(new Set());
    const [escalationNote, setEscalationNote] = useState('');
    const [escalating, setEscalating] = useState(false);
    const [escalationResult, setEscalationResult] = useState<{ ok: boolean; message: string } | null>(null);
    const [generatingReport, setGeneratingReport] = useState(false);
    const [showPlaybookModal, setShowPlaybookModal] = useState(false);
    const [playbooks, setPlaybooks] = useState<PlaybookSummary[] | null>(null);
    const [attachingPlaybook, setAttachingPlaybook] = useState<string | null>(null);
    const [executing, setExecuting] = useState<string | null>(null);
    const [execResult, setExecResult] = useState<{ taskId: string; ok: boolean; text: string } | null>(null);

    useEffect(() => { void loadCases('all', setList); }, []);

    // ?id=<case uuid> opens that case — how the header search and the notification bell link to a
    // specific case. Synced during render (React's "adjusting state when a prop changes"
    // pattern) rather than in an effect, so a new ?id reopens the right case even when this page
    // is already mounted.
    const router = useRouter();
    const pathname = usePathname();
    const linkedId = useSearchParams().get('id');
    const [seenLink, setSeenLink] = useState<string | null>(null);
    if (linkedId !== seenLink) {
        setSeenLink(linkedId);
        if (linkedId) openCase(linkedId);
    }

    // Detail + this analyst's checklist load whenever a case is opened. State is only set in the
    // promise callbacks.
    useEffect(() => {
        if (!selectedId) return;
        apiFetch(apiUrl(`/api/cases/${selectedId}`), { cache: 'no-store' })
            .then(async (r) => {
                const data = await r.json();
                if (!r.ok) { setDetailError(data?.error ?? `HTTP ${r.status}`); return; }
                const d = data as CaseDetail;
                setDetail(d);
                setList((prev) => (prev.kind === 'ready' ? { ...prev, cases: prev.cases.map((x) => (x.id === d.case.id ? d.case : x)) } : prev));
                try {
                    const raw = localStorage.getItem(CHECKLIST_KEY(selectedId));
                    setCheckedSteps(new Set(raw ? (JSON.parse(raw) as string[]) : []));
                } catch {
                    setCheckedSteps(new Set());
                }
            })
            .catch(() => setDetailError('Could not reach the backend'));
    }, [selectedId]);

    function closeCase() {
        setSelectedId(null);
        // Drop ?id so the same search result can open this case again later.
        if (linkedId) router.replace(pathname);
    }

    const reload = (f: Filter = filter) => {
        setFilter(f);
        setList({ kind: 'loading' });
        void loadCases(f, setList);
    };

    const cases = list.kind === 'ready' ? list.cases : [];
    const summary = list.kind === 'ready' ? list.summary : null;
    const selected = detail && detail.case.id === selectedId ? detail : null;

    // Applies a server-returned case to both the queue row and the open detail.
    const applyCase = (c: CaseItem) => {
        setList((prev) => (prev.kind === 'ready' ? { ...prev, cases: prev.cases.map((x) => (x.id === c.id ? c : x)) } : prev));
        setDetail((prev) => (prev && prev.case.id === c.id ? { ...prev, case: c } : prev));
    };

    const refreshDetail = (id: string) =>
        apiFetch(apiUrl(`/api/cases/${id}`), { cache: 'no-store' })
            .then(async (r) => {
                const data = await r.json();
                if (!r.ok) { setDetailError(data?.error ?? `HTTP ${r.status}`); return; }
                setDetail(data as CaseDetail);
                applyCase((data as CaseDetail).case);
            })
            .catch(() => setDetailError('Could not reach the backend'));

    function openCase(id: string) {
        setSelectedId(id);
        setDetail(null);
        setDetailError(null);
        setActionError(null);
        setEscalationNote('');
        setEscalationResult(null);
        setShowAddNote(false);
        setExecResult(null);
        setCheckedSteps(new Set());
    }

    function toggleStep(caseId: string, stepId: string) {
        setCheckedSteps((prev) => {
            const next = new Set(prev);
            if (next.has(stepId)) next.delete(stepId);
            else next.add(stepId);
            try { localStorage.setItem(CHECKLIST_KEY(caseId), JSON.stringify([...next])); } catch { /* blocked storage — works for this session */ }
            return next;
        });
    }

    // Every write goes to the server and then re-reads the case, so the timeline entry the
    // backend adds for the action appears immediately.
    async function mutate(id: string, path: string, init: RequestInit): Promise<boolean> {
        setBusy(true);
        setActionError(null);
        try {
            const res = await apiFetch(apiUrl(`/api/cases/${id}${path}`), { headers: { 'Content-Type': 'application/json' }, ...init });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) { setActionError(data?.error ?? `Request failed (HTTP ${res.status})`); return false; }
            await refreshDetail(id);
            return true;
        } catch {
            setActionError('Could not reach the backend');
            return false;
        } finally {
            setBusy(false);
        }
    }

    const updateStatus = (id: string, status: CaseStatus) => mutate(id, '', { method: 'PATCH', body: JSON.stringify({ status }) });
    const assignAnalyst = (id: string, assigned_to: string) => mutate(id, '', { method: 'PATCH', body: JSON.stringify({ assigned_to }) });
    const setTask = (id: string, taskId: string, status: 'pending' | 'completed') => mutate(id, `/tasks/${taskId}`, { method: 'PATCH', body: JSON.stringify({ status }) });

    // Runs a task's response action. The backend completes the task only when the action
    // succeeded; a skip or failure comes back with its reason, shown under the task.
    async function executeTask(caseId: string, task: CaseTask) {
        setExecuting(task.id);
        setExecResult(null);
        try {
            const res = await apiFetch(apiUrl(`/api/cases/${caseId}/execute-step`), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ step_id: task.step_id, task_id: task.id }),
            });
            const data = await res.json().catch(() => ({}));
            const text = data?.message ?? data?.error ?? `HTTP ${res.status}`;
            setExecResult({ taskId: task.id, ok: Boolean(data?.success), text: data?.outcome === 'skipped' ? `Skipped — ${text}` : text });
            await refreshDetail(caseId);
        } catch {
            setExecResult({ taskId: task.id, ok: false, text: 'Could not reach the backend' });
        } finally {
            setExecuting(null);
        }
    }

    async function addNote(id: string) {
        if (!noteText.trim()) return;
        if (await mutate(id, '/notes', { method: 'POST', body: JSON.stringify({ content: noteText.trim(), type: noteType }) })) {
            setNoteText('');
            setShowAddNote(false);
        }
    }

    async function addTask(id: string) {
        if (!newTaskTitle.trim()) return;
        if (await mutate(id, '/tasks', { method: 'POST', body: JSON.stringify({ title: newTaskTitle.trim() }) })) setNewTaskTitle('');
    }

    async function escalate(id: string) {
        setEscalating(true);
        setEscalationResult(null);
        try {
            const res = await apiFetch(apiUrl(`/api/cases/${id}/escalate`), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ note: escalationNote.trim() }),
            });
            const data = await res.json();
            if (!res.ok) { setEscalationResult({ ok: false, message: data?.error ?? `Escalation failed (HTTP ${res.status})` }); return; }
            // Shown verbatim: the backend says when the email was skipped or failed rather than
            // claiming the CISO was told.
            setEscalationResult({ ok: Boolean(data?.success), message: data?.message ?? 'Escalation recorded' });
            if (data?.success) setEscalationNote('');
            await refreshDetail(id);
        } catch {
            setEscalationResult({ ok: false, message: 'Escalation failed — could not reach the backend' });
        } finally {
            setEscalating(false);
        }
    }

    async function downloadReport(c: CaseItem) {
        setGeneratingReport(true);
        setActionError(null);
        try {
            const res = await apiFetch(apiUrl(`/api/cases/${c.id}/report`));
            if (!res.ok) { setActionError(`Report failed (HTTP ${res.status})`); return; }
            const url = URL.createObjectURL(await res.blob());
            const a = document.createElement('a');
            a.href = url;
            a.download = `${c.case_number}-report.md`;
            a.click();
            URL.revokeObjectURL(url);
        } finally {
            setGeneratingReport(false);
        }
    }

    function openPlaybookModal() {
        setShowPlaybookModal(true);
        if (playbooks === null) {
            apiFetch(apiUrl('/api/playbooks'))
                .then((r) => r.json())
                .then((data) => setPlaybooks(Array.isArray(data?.playbooks) ? data.playbooks : []))
                .catch(() => setPlaybooks([]));
        }
    }

    async function attachPlaybook(caseId: string, pb: PlaybookSummary) {
        setAttachingPlaybook(pb.id);
        setActionError(null);
        try {
            const res = await apiFetch(apiUrl(`/api/playbooks/${pb.id}/run`), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ case_id: caseId }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) { setActionError(data?.error ?? `Could not attach playbook (HTTP ${res.status})`); return; }
            setShowPlaybookModal(false);
            await refreshDetail(caseId);
        } finally {
            setAttachingPlaybook(null);
        }
    }

    function exportCasePDF(d: CaseDetail) {
        const c = d.case;
        exportDataAsPDF(c.title, `case-${c.case_number}`, [
            {
                heading: 'Case Overview',
                rows: [
                    { label: 'Case', value: c.case_number },
                    { label: 'Severity', value: c.severity.toUpperCase() },
                    { label: 'Status', value: c.status.toUpperCase() },
                    { label: 'MITRE ATT&CK', value: [c.mitre_tactic, c.mitre_technique].filter(Boolean).join(' · ') || 'N/A' },
                    { label: 'Assignee', value: c.assigned_to || 'Unassigned' },
                    { label: 'Agent', value: c.agent_name || 'N/A' },
                    { label: 'Source IP', value: c.source_ip || 'N/A' },
                    { label: 'Rule', value: c.rule_id ? `${c.rule_id} (level ${c.rule_level ?? 0})` : 'N/A' },
                    { label: 'Created', value: wat(c.created_at) },
                ],
            },
            { heading: 'Description', rows: [{ label: 'Detail', value: c.description || 'No description' }] },
            {
                heading: 'Timeline',
                rows: d.timeline.length > 0 ? [...d.timeline].reverse().map((t) => ({ label: `${wat(t.created_at)} · ${t.actor}`, value: t.action })) : [{ label: 'Timeline', value: 'No entries' }],
            },
            {
                heading: 'Analyst Notes',
                rows: d.notes.length > 0 ? d.notes.map((n) => ({ label: `${wat(n.created_at)} · ${n.author} [${n.type}]`, value: n.content })) : [{ label: 'Notes', value: 'No analyst notes recorded.' }],
            },
        ]);
    }

    if (list.kind === 'unauthorised') {
        return (
            <div className="bg-card border border-dashed border-border rounded-xl p-12 text-center max-w-2xl mx-auto">
                <Briefcase size={32} className="text-foreground-muted mx-auto mb-3" />
                <h1 className="font-bold text-sm text-foreground mb-1">Cases are available to NovrSOC analysts</h1>
                <p className="text-xs text-foreground-muted">
                    Case records hold the SOC&apos;s investigation detail. Your SOC team shares case reports with you directly; sign in with an analyst account to work cases here.
                </p>
            </div>
        );
    }

    return (
        <div className="space-y-5 max-w-7xl mx-auto">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-4">
                <div>
                    <div className="flex items-center gap-2.5">
                        <div className="w-8 h-8 rounded-lg bg-orange/10 flex items-center justify-center">
                            <Briefcase className="w-4 h-4 text-orange" />
                        </div>
                        <h1 className="text-xl font-bold tracking-tight text-foreground">Cases</h1>
                    </div>
                    <p className="text-xs text-foreground-muted mt-1">
                        Analyst queue. Tier-1 cases the SOAR engine closed automatically are listed under SOAR Automation.
                    </p>
                </div>
                <button
                    onClick={() => reload()}
                    className="flex items-center gap-1.5 text-xs font-bold text-foreground-muted hover:text-foreground border border-border bg-card px-3.5 py-2 rounded-lg transition-colors self-start sm:self-auto"
                >
                    <RefreshCw className="w-3.5 h-3.5" /> Refresh
                </button>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5">
                {[
                    { label: 'Open', value: summary?.open, color: 'text-blue', icon: FileText },
                    { label: 'Investigating', value: summary?.investigating, color: 'text-orange', icon: Clock },
                    { label: 'Critical (unresolved)', value: summary?.critical, color: 'text-red-500', icon: AlertTriangle },
                    { label: 'Resolved Today', value: summary?.resolvedToday, color: 'text-emerald-500', icon: CheckCircle },
                ].map((k) => (
                    <div key={k.label} className="bg-card border border-border rounded-xl p-4 flex items-center justify-between shadow-xs">
                        <div>
                            <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{k.label}</p>
                            <p className={`text-2xl font-black ${k.color} mt-0.5`}>{typeof k.value === 'number' ? k.value : '—'}</p>
                        </div>
                        <div className="w-9 h-9 rounded-xl bg-card-muted flex items-center justify-center">
                            <k.icon className={`w-4 h-4 ${k.color}`} />
                        </div>
                    </div>
                ))}
            </div>

            <div className="flex items-center gap-1.5 bg-card border border-border rounded-lg p-1 w-fit max-w-full overflow-x-auto">
                {(['all', 'open', 'investigating', 'contained', 'resolved'] as const).map((s) => (
                    <button
                        key={s}
                        onClick={() => reload(s)}
                        className={`text-xs font-bold px-3 py-1.5 rounded-md capitalize transition-all whitespace-nowrap ${filter === s ? 'bg-blue text-white shadow-xs' : 'text-foreground-muted hover:text-foreground'}`}
                    >
                        {s === 'all' ? 'All Cases' : s}
                    </button>
                ))}
            </div>

            {list.kind === 'loading' ? (
                <div className="space-y-3">
                    {Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-20 bg-card-muted/60 border border-border rounded-xl animate-pulse" />)}
                </div>
            ) : list.kind === 'error' ? (
                <div className="bg-red-500/5 border border-red-500/30 rounded-xl py-10 text-center">
                    <p className="text-xs font-bold text-red-500">Could not load cases</p>
                    <p className="text-[11px] text-foreground-muted mt-1">{list.message}</p>
                </div>
            ) : cases.length === 0 ? (
                <div className="bg-card border border-border rounded-xl py-12 text-center shadow-xs">
                    <p className="text-xs text-foreground-muted">
                        {filter === 'all' ? 'No cases yet. Cases appear here when the SOAR engine or an analyst opens one.' : `No ${filter} cases.`}
                    </p>
                </div>
            ) : (
                <div className="space-y-2.5">
                    {cases.map((c) => (
                        <button
                            key={c.id}
                            onClick={() => openCase(c.id)}
                            className="w-full text-left bg-card border border-border rounded-xl p-4 hover:border-orange/40 hover:bg-card-muted/30 transition-all flex items-center justify-between gap-4 shadow-xs group"
                        >
                            <div className="min-w-0 space-y-1">
                                <div className="flex items-center gap-2 flex-wrap">
                                    <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full border uppercase ${SEV_STYLE[c.severity]}`}>{c.severity}</span>
                                    <span className="font-mono text-[10px] text-foreground-muted font-bold">{c.case_number}</span>
                                    <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full border capitalize ${STATUS_STYLE[c.status]}`}>{c.status}</span>
                                    {c.mitre_technique && (
                                        <span className="text-[10px] text-amber-500 font-mono bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded-full">
                                            {[c.mitre_tactic, c.mitre_technique].filter(Boolean).join(' · ')}
                                        </span>
                                    )}
                                    {c.escalated && <span className="text-[9px] font-bold px-2 py-0.5 rounded-full border bg-purple/10 text-purple border-purple/30">Escalated</span>}
                                    {c.containment_done && <span className="text-[9px] font-bold px-2 py-0.5 rounded-full border bg-emerald-500/10 text-emerald-500 border-emerald-500/30">Contained by SOAR</span>}
                                </div>
                                <p className="text-sm font-bold text-foreground group-hover:text-orange transition-colors truncate">{c.title}</p>
                                <div className="flex items-center gap-3 text-[11px] text-foreground-muted flex-wrap">
                                    {c.agent_name && <span className="flex items-center gap-1 font-mono text-[10px]"><Server size={11} />{c.agent_name}</span>}
                                    {c.source_ip && <span className="font-mono text-[10px]">{c.source_ip}</span>}
                                    <span>Analyst: <strong className="text-foreground">{c.assigned_to || 'Unassigned'}</strong></span>
                                    <span>Opened {wat(c.created_at)}</span>
                                </div>
                            </div>
                            <ChevronRight className="w-4 h-4 text-foreground-muted group-hover:text-foreground shrink-0" />
                        </button>
                    ))}
                    {list.kind === 'ready' && list.total > cases.length && (
                        <p className="text-[11px] text-foreground-muted text-center">Showing the newest {cases.length} of {list.total}.</p>
                    )}
                </div>
            )}

            {selectedId && (
                <div className="fixed inset-0 bg-black/40 z-50 flex items-stretch justify-end" onClick={closeCase}>
                    <div className="bg-card border-l border-border h-full w-full max-w-4xl overflow-y-auto scrollbar-thin" onClick={(e) => e.stopPropagation()}>
                        {!selected ? (
                            <div className="p-6 flex items-center justify-between">
                                <p className="text-xs text-foreground-muted">{detailError ? `Could not load case: ${detailError}` : 'Loading case…'}</p>
                                <button onClick={closeCase} className="text-foreground-muted hover:text-foreground" aria-label="Close"><X className="w-5 h-5" /></button>
                            </div>
                        ) : (() => {
                            const c = selected.case;
                            const currentStep = Math.max(0, WORKFLOW_STEPS.findIndex((s) => s.id === c.status));
                            const nextStep = WORKFLOW_STEPS[currentStep + 1];
                            return (
                                <div className="p-5 sm:p-6 space-y-5">
                                    <div className="flex items-start justify-between gap-4 border-b border-border pb-4">
                                        <div className="min-w-0">
                                            <div className="flex items-center gap-2 flex-wrap">
                                                <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border uppercase ${SEV_STYLE[c.severity]}`}>{c.severity}</span>
                                                <span className="font-mono text-xs text-foreground-muted font-bold">{c.case_number}</span>
                                                <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border capitalize ${STATUS_STYLE[c.status]}`}>{c.status}</span>
                                                <span className="text-[10px] font-bold px-2.5 py-0.5 rounded-full border border-border text-foreground-muted">Tier {c.tier}</span>
                                            </div>
                                            <h2 className="text-xl font-black text-foreground mt-2 tracking-tight">{c.title}</h2>
                                            <p className="text-xs text-foreground-muted mt-0.5">Created {wat(c.created_at)} · source: {c.source}</p>
                                        </div>
                                        <button onClick={closeCase} className="text-foreground-muted hover:text-foreground shrink-0" aria-label="Close"><X className="w-5 h-5" /></button>
                                    </div>

                                    {/* Status bar — every step stays clickable so a premature
                                        "contained" can be stepped back. */}
                                    <div className="space-y-3">
                                        <div className="flex items-center rounded-xl overflow-hidden border border-border">
                                            {WORKFLOW_STEPS.map((step, i) => (
                                                <button
                                                    key={step.id}
                                                    disabled={busy || step.id === c.status}
                                                    onClick={() => updateStatus(c.id, step.id)}
                                                    className={`flex-1 py-2.5 px-2 text-xs font-bold text-center transition-colors disabled:cursor-default ${
                                                        i === currentStep ? 'bg-purple text-white' : i < currentStep ? 'bg-emerald-500 text-white' : 'bg-card-muted text-foreground-muted hover:bg-border'
                                                    } ${i > 0 ? 'border-l border-border' : ''}`}
                                                >
                                                    {i < currentStep ? '✓ ' : ''}{step.label}
                                                </button>
                                            ))}
                                        </div>
                                        <div className="flex items-center gap-2 flex-wrap">
                                            {nextStep && (
                                                <button
                                                    disabled={busy}
                                                    onClick={() => updateStatus(c.id, nextStep.id)}
                                                    className="flex-1 min-w-[200px] bg-purple text-white font-bold py-3 rounded-xl hover:opacity-90 disabled:opacity-50 text-sm transition-opacity"
                                                >
                                                    → {NEXT_STEP_LABEL[currentStep]}
                                                </button>
                                            )}
                                            <button onClick={openPlaybookModal} className="flex items-center gap-1.5 text-xs font-bold text-purple border border-purple/30 bg-purple/5 hover:bg-purple/10 px-3.5 py-2 rounded-lg transition-colors">
                                                <BookOpen size={14} /> Attach Playbook
                                            </button>
                                            <button
                                                onClick={() => downloadReport(c)}
                                                disabled={generatingReport}
                                                className="flex items-center gap-1.5 text-xs font-bold text-foreground-muted hover:text-foreground border border-border bg-card px-3 py-2 rounded-lg transition-colors disabled:opacity-50"
                                            >
                                                <FileText size={14} /> {generatingReport ? 'Generating…' : 'Report (MD)'}
                                            </button>
                                            <button onClick={() => exportCasePDF(selected)} className="flex items-center gap-1.5 text-xs font-bold text-foreground-muted hover:text-foreground border border-border bg-card px-3 py-2 rounded-lg transition-colors">
                                                <FileDown size={14} /> PDF
                                            </button>
                                        </div>
                                        {actionError && <p className="text-[11px] font-bold text-red-500">{actionError}</p>}
                                    </div>

                                    {(c.severity === 'high' || c.severity === 'critical') && c.status !== 'resolved' && (
                                        <div className="bg-red-500/5 border border-red-500/30 rounded-xl p-4 sm:p-5 space-y-3">
                                            <div>
                                                <h3 className="text-sm font-bold text-red-500">Escalation{c.escalated ? ' — already escalated' : ''}</h3>
                                                <p className="text-[11px] text-red-500/80 mt-0.5">
                                                    {c.severity === 'critical' ? 'Critical case — escalate within 30 minutes' : 'High severity — escalate if unresolved after 2 hours'}
                                                </p>
                                            </div>
                                            <textarea
                                                value={escalationNote}
                                                onChange={(e) => setEscalationNote(e.target.value)}
                                                placeholder="Describe what you found and why you are escalating…"
                                                aria-label="Escalation reason"
                                                className="w-full bg-card border border-red-500/30 rounded-xl p-3 text-sm text-foreground resize-none focus:outline-none focus:border-red-500 min-h-[70px]"
                                            />
                                            <button
                                                onClick={() => escalate(c.id)}
                                                disabled={escalating}
                                                className="w-full flex items-center justify-center gap-1.5 bg-red-500 text-white text-xs font-bold px-4 py-2.5 rounded-xl hover:bg-red-600 disabled:opacity-50 transition-colors"
                                            >
                                                <TrendingUp size={14} /> {escalating ? 'Escalating…' : 'Escalate to CISO — notify now'}
                                            </button>
                                            {escalationResult && (
                                                <p className={`text-[11px] font-bold ${escalationResult.ok ? 'text-emerald-500' : 'text-red-500'}`}>{escalationResult.message}</p>
                                            )}
                                        </div>
                                    )}

                                    <div className="flex items-center gap-2 bg-card-muted/40 border border-border rounded-xl px-3.5 py-2.5 w-fit">
                                        <UserPlus size={14} className="text-foreground-muted" />
                                        <span className="text-xs text-foreground-muted">Assigned to</span>
                                        <select
                                            value={c.assigned_to ?? ''}
                                            onChange={(e) => e.target.value && assignAnalyst(c.id, e.target.value)}
                                            disabled={busy}
                                            aria-label="Assign analyst"
                                            className="bg-card border border-border rounded-lg px-2.5 py-1 text-xs font-bold text-foreground focus:outline-none focus:border-purple disabled:opacity-50"
                                        >
                                            <option value="">{c.assigned_to ? c.assigned_to : 'Unassigned'}</option>
                                            {ASSIGNABLE_ANALYSTS.filter((n) => n !== c.assigned_to).map((n) => <option key={n} value={n}>{n}</option>)}
                                        </select>
                                    </div>

                                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                                        <div className="lg:col-span-2 space-y-4">
                                            <div className="bg-card border border-border rounded-xl p-4 sm:p-5 shadow-xs space-y-3">
                                                <div className="flex items-center justify-between border-b border-border pb-2.5 gap-2">
                                                    <h3 className="text-xs font-bold text-foreground uppercase tracking-wider flex items-center gap-2">
                                                        <Terminal size={14} className="text-orange" /> Alert Context
                                                    </h3>
                                                    {c.rule_id && (
                                                        <span className="text-[10px] font-mono text-foreground-muted bg-card-muted px-2 py-0.5 rounded border border-border">
                                                            Rule {c.rule_id} · level {c.rule_level ?? 0}
                                                        </span>
                                                    )}
                                                </div>
                                                <p className="font-mono text-xs bg-card-muted/60 p-3 rounded-lg border border-border text-foreground leading-relaxed whitespace-pre-wrap break-words">
                                                    {c.description || 'No description recorded.'}
                                                </p>
                                                <div className="grid grid-cols-2 gap-4 pt-1 text-xs">
                                                    {[
                                                        ['Agent', c.agent_name ? `${c.agent_name}${c.agent_id ? ` (${c.agent_id})` : ''}` : '—'],
                                                        ['Source IP', c.source_ip || '—'],
                                                        ['MITRE', [c.mitre_tactic, c.mitre_technique].filter(Boolean).join(' · ') || '—'],
                                                        ['Tags', c.tags && c.tags.length > 0 ? c.tags.join(', ') : '—'],
                                                    ].map(([label, value]) => (
                                                        <div key={label} className="min-w-0">
                                                            <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{label}</p>
                                                            <p className="font-bold text-foreground mt-0.5 break-words">{value}</p>
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>

                                            <div className="bg-card border border-border rounded-xl p-4 sm:p-5 shadow-xs">
                                                <h3 className="text-xs font-bold text-foreground uppercase tracking-wider mb-4 flex items-center gap-2">
                                                    <Clock size={14} className="text-blue" /> Timeline
                                                </h3>
                                                {selected.timeline.length === 0 ? (
                                                    <p className="text-xs text-foreground-muted">No timeline entries.</p>
                                                ) : (
                                                    <div>
                                                        {selected.timeline.map((t, idx) => (
                                                            <div key={t.id} className="flex gap-3">
                                                                <div className="flex flex-col items-center">
                                                                    <div className={`w-2.5 h-2.5 rounded-full ring-4 shrink-0 mt-1 ${t.automated ? 'bg-purple ring-purple/10' : 'bg-blue ring-blue/10'}`} />
                                                                    {idx < selected.timeline.length - 1 && <div className="w-px flex-1 bg-border my-1" />}
                                                                </div>
                                                                <div className="pb-4 min-w-0">
                                                                    <div className="flex items-center gap-2 flex-wrap">
                                                                        <p className="text-xs font-bold text-foreground break-words">{t.action}</p>
                                                                        <span className="text-[10px] text-foreground-muted">{wat(t.created_at)}</span>
                                                                    </div>
                                                                    <p className="text-[11px] text-foreground-muted">{t.actor}{t.automated ? ' · automated' : ''}</p>
                                                                    {t.details && <p className="text-xs text-foreground-muted mt-1 break-words">{t.details}</p>}
                                                                </div>
                                                            </div>
                                                        ))}
                                                    </div>
                                                )}
                                            </div>

                                            <div className="bg-card border border-border rounded-xl p-4 sm:p-5 shadow-xs space-y-3">
                                                <div className="flex items-center justify-between border-b border-border pb-2.5">
                                                    <h3 className="text-xs font-bold text-foreground uppercase tracking-wider flex items-center gap-2">
                                                        <UserCheck size={14} className="text-purple" /> Investigation Notes
                                                    </h3>
                                                    <button onClick={() => setShowAddNote((v) => !v)} className="flex items-center gap-1 text-xs font-bold text-orange hover:text-orange-hover">
                                                        <MessageSquarePlus size={14} /> Add Note
                                                    </button>
                                                </div>
                                                {showAddNote && (
                                                    <div className="p-3 bg-card-muted/40 rounded-xl border border-border space-y-2.5">
                                                        <div className="flex items-center gap-1.5 flex-wrap">
                                                            {NOTE_TYPES.map((t) => (
                                                                <button
                                                                    key={t}
                                                                    onClick={() => setNoteType(t)}
                                                                    className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border transition-all ${noteType === t ? NOTE_TYPE_STYLE[t] : 'bg-card text-foreground-muted border-border'}`}
                                                                >
                                                                    {t}
                                                                </button>
                                                            ))}
                                                        </div>
                                                        <textarea
                                                            value={noteText}
                                                            onChange={(e) => setNoteText(e.target.value)}
                                                            rows={2}
                                                            placeholder="Add investigation notes…"
                                                            aria-label="Note"
                                                            className="w-full bg-card border border-border rounded-lg p-2.5 text-xs text-foreground focus:outline-none focus:border-orange resize-none"
                                                        />
                                                        <div className="flex justify-end gap-2">
                                                            <button onClick={() => setShowAddNote(false)} className="text-xs font-semibold text-foreground-muted px-3 py-1.5">Cancel</button>
                                                            <button
                                                                disabled={busy || !noteText.trim()}
                                                                onClick={() => addNote(c.id)}
                                                                className="text-xs font-bold text-white bg-orange hover:bg-orange-hover px-3.5 py-1.5 rounded-lg disabled:opacity-50"
                                                            >
                                                                Save Note
                                                            </button>
                                                        </div>
                                                    </div>
                                                )}
                                                {selected.notes.length === 0 ? (
                                                    <p className="text-xs text-foreground-muted py-2">No analyst notes yet.</p>
                                                ) : (
                                                    <div className="space-y-2.5 divide-y divide-border/40">
                                                        {selected.notes.map((n) => (
                                                            <div key={n.id} className="pt-2 flex gap-2.5 items-start">
                                                                <div className="w-7 h-7 rounded-lg bg-purple/10 flex items-center justify-center font-bold text-xs text-purple shrink-0">
                                                                    {n.author.slice(0, 2).toUpperCase()}
                                                                </div>
                                                                <div className="min-w-0 flex-1">
                                                                    <div className="flex items-center gap-2 flex-wrap">
                                                                        <span className="text-xs font-bold text-foreground">{n.author}</span>
                                                                        <span className={`text-[9px] font-bold px-1.5 rounded-full border ${NOTE_TYPE_STYLE[n.type]}`}>{n.type}</span>
                                                                        <span className="text-[10px] text-foreground-muted ml-auto">{wat(n.created_at)}</span>
                                                                    </div>
                                                                    <p className="text-xs text-foreground mt-0.5 leading-relaxed break-words">{n.content}</p>
                                                                </div>
                                                            </div>
                                                        ))}
                                                    </div>
                                                )}
                                            </div>
                                        </div>

                                        <div className="space-y-4">
                                            <div className="bg-card border border-border rounded-xl p-4 sm:p-5 shadow-xs">
                                                <h3 className="text-xs font-bold text-foreground uppercase tracking-wider mb-3 flex items-center gap-2">
                                                    <ListChecks size={14} className="text-emerald-500" /> Response Tasks
                                                </h3>
                                                {selected.tasks.length === 0 ? (
                                                    <p className="text-xs text-foreground-muted py-1 mb-3">No tasks yet — attach a playbook or add one below.</p>
                                                ) : (
                                                    <div className="space-y-2 mb-3">
                                                        {selected.tasks.map((t) => {
                                                            const done = t.status === 'completed';
                                                            const runnable = EXECUTABLE_STEPS.has(t.step_id);
                                                            return (
                                                                <div key={t.id} className="rounded-lg bg-card-muted/30 border border-border p-2">
                                                                    <div className="flex items-center gap-2">
                                                                        <button
                                                                            disabled={busy}
                                                                            onClick={() => setTask(c.id, t.id, done ? 'pending' : 'completed')}
                                                                            aria-pressed={done}
                                                                            aria-label={done ? `Reopen ${t.title}` : `Mark ${t.title} done`}
                                                                            className="flex items-center gap-2.5 flex-1 min-w-0 text-left disabled:opacity-60"
                                                                        >
                                                                            <div className={`w-3.5 h-3.5 rounded-full border-2 shrink-0 ${done ? 'bg-emerald-500 border-emerald-500' : 'border-border'}`} />
                                                                            <span className={`text-xs flex-1 min-w-0 ${done ? 'text-foreground-muted line-through' : 'text-foreground'}`}>{t.title}</span>
                                                                        </button>
                                                                        {runnable && (
                                                                            <button
                                                                                onClick={() => executeTask(c.id, t)}
                                                                                disabled={done || executing !== null}
                                                                                className={`flex items-center gap-1 text-[10px] font-bold px-2 py-1 rounded-lg shrink-0 transition-colors ${
                                                                                    done ? 'bg-emerald-500/10 text-emerald-500' : 'bg-purple text-white hover:opacity-90 disabled:opacity-40'
                                                                                }`}
                                                                            >
                                                                                {executing === t.id ? 'Running…' : done ? '✓ Done' : <><Play size={10} /> Execute</>}
                                                                            </button>
                                                                        )}
                                                                    </div>
                                                                    {execResult?.taskId === t.id ? (
                                                                        <p role="status" className={`text-[10px] mt-1 pl-6 ${execResult.ok ? 'text-emerald-500' : 'text-amber-500'}`}>{execResult.text}</p>
                                                                    ) : t.result ? (
                                                                        <p className="text-[10px] mt-1 pl-6 text-foreground-muted">{t.result}</p>
                                                                    ) : null}
                                                                </div>
                                                            );
                                                        })}
                                                    </div>
                                                )}
                                                <div className="flex items-center gap-1.5">
                                                    <input
                                                        value={newTaskTitle}
                                                        onChange={(e) => setNewTaskTitle(e.target.value)}
                                                        onKeyDown={(e) => { if (e.key === 'Enter') void addTask(c.id); }}
                                                        placeholder="New task title…"
                                                        aria-label="New task title"
                                                        className="flex-1 min-w-0 bg-card border border-border rounded-lg px-2.5 py-1.5 text-xs text-foreground focus:outline-none focus:border-emerald-500"
                                                    />
                                                    <button
                                                        disabled={busy || !newTaskTitle.trim()}
                                                        onClick={() => addTask(c.id)}
                                                        aria-label="Add task"
                                                        className="flex items-center gap-1 text-xs font-bold text-white bg-emerald-500 hover:bg-emerald-600 px-2.5 py-1.5 rounded-lg disabled:opacity-50 shrink-0"
                                                    >
                                                        <Plus size={13} />
                                                    </button>
                                                </div>
                                            </div>

                                            <div className="bg-card border border-border rounded-xl p-4 sm:p-5 shadow-xs">
                                                <h3 className="text-xs font-bold text-foreground uppercase tracking-wider mb-3 flex items-center gap-2">
                                                    <Crosshair size={14} className="text-red-500" /> IOCs
                                                </h3>
                                                {selected.iocs.length === 0 ? (
                                                    <p className="text-xs text-foreground-muted">No IOCs recorded on this case.</p>
                                                ) : (
                                                    <div className="space-y-2">
                                                        {selected.iocs.map((i) => (
                                                            <div key={i.id} className="p-2 rounded-lg bg-card-muted/30 border border-border">
                                                                <p className="text-xs font-mono text-foreground break-all">{i.value}</p>
                                                                <p className="text-[10px] text-foreground-muted mt-0.5">{i.type} · {i.verdict || 'unknown'} · score {i.risk_score ?? 0}</p>
                                                            </div>
                                                        ))}
                                                    </div>
                                                )}
                                            </div>

                                            <div className="bg-card border border-border rounded-xl p-4 sm:p-5 shadow-xs">
                                                <div className="flex items-center justify-between mb-3">
                                                    <h3 className="text-xs font-bold text-foreground uppercase tracking-wider flex items-center gap-2">
                                                        <ClipboardList size={14} className="text-purple" /> My Checklist
                                                    </h3>
                                                    <span className="text-[10px] text-foreground-muted">{checkedSteps.size}/{INVESTIGATION_STEPS.length}</span>
                                                </div>
                                                <div className="space-y-1.5">
                                                    {INVESTIGATION_STEPS.map((step) => {
                                                        const done = checkedSteps.has(step.id);
                                                        return (
                                                            <button
                                                                key={step.id}
                                                                onClick={() => toggleStep(c.id, step.id)}
                                                                aria-pressed={done}
                                                                title={step.desc}
                                                                className={`w-full flex items-center gap-2.5 p-2 rounded-lg text-left border ${done ? 'bg-emerald-500/5 border-emerald-500/30' : 'bg-card-muted/40 border-transparent hover:border-border'}`}
                                                            >
                                                                <div className={`w-4 h-4 rounded-full border-2 shrink-0 ${done ? 'bg-emerald-500 border-emerald-500' : 'border-border'}`} />
                                                                <span className={`text-xs font-bold ${done ? 'text-emerald-500 line-through' : 'text-foreground'}`}>{step.label}</span>
                                                            </button>
                                                        );
                                                    })}
                                                </div>
                                                <p className="text-[10px] text-foreground-muted mt-3 flex items-center gap-1">
                                                    <Lock size={10} /> Saved in this browser only.
                                                </p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            );
                        })()}
                    </div>
                </div>
            )}

            {showPlaybookModal && selected && (
                <div className="fixed inset-0 bg-black/50 z-[60] flex items-center justify-center p-4" onClick={() => setShowPlaybookModal(false)}>
                    <div className="bg-card border border-border rounded-2xl p-6 w-full max-w-lg max-h-[80vh] overflow-y-auto scrollbar-thin" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="font-bold text-sm text-foreground">Attach Playbook to {selected.case.case_number}</h3>
                            <button onClick={() => setShowPlaybookModal(false)} className="text-foreground-muted hover:text-foreground" aria-label="Close"><X size={16} /></button>
                        </div>
                        <div className="space-y-2">
                            {playbooks === null ? (
                                <p className="text-xs text-foreground-muted py-4 text-center">Loading playbooks…</p>
                            ) : playbooks.length === 0 ? (
                                <p className="text-xs text-foreground-muted py-4 text-center">No playbooks available.</p>
                            ) : (
                                playbooks.map((pb) => (
                                    <button
                                        key={pb.id}
                                        onClick={() => attachPlaybook(selected.case.id, pb)}
                                        disabled={attachingPlaybook !== null}
                                        className="w-full text-left flex items-center justify-between gap-3 bg-card-muted/40 hover:bg-card-muted border border-border rounded-xl px-4 py-3 transition-colors disabled:opacity-50"
                                    >
                                        <div className="min-w-0">
                                            <p className="text-sm font-bold text-foreground truncate">{pb.icon} {pb.name}</p>
                                            <p className="text-[11px] text-foreground-muted truncate">{pb.description}</p>
                                        </div>
                                        <span className="text-[10px] font-bold text-purple shrink-0">
                                            {attachingPlaybook === pb.id ? 'Adding…' : `${pb.steps?.length ?? 0} steps`}
                                        </span>
                                    </button>
                                ))
                            )}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
