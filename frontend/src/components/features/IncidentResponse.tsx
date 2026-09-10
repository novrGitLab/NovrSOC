'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { apiUrl, apiFetch } from '@/lib/api';
import { getAdminUser } from '@/lib/admin-auth';
import { exportDataAsPDF } from '@/lib/exportPDF';
import { ASSIGNABLE_ANALYSTS } from '@/lib/mockTeam';
import {
    AlertTriangle,
    Clock,
    CheckCircle,
    RefreshCw,
    TrendingUp,
    FileText,
    ChevronRight,
    MessageSquarePlus,
    FileDown,
    Shield,
    Server,
    Laptop,
    Terminal,
    UserCheck,
    Lock,
    ListChecks,
    Plus,
    X,
    UserPlus,
    BookOpen,
    ClipboardList
} from 'lucide-react';
interface PlaybookSummary {
    id: string;
    name: string;
    icon: string;
    description: string;
    steps: { order: number; title: string; phase: string; est_mins: number; description: string }[];
}

type IncidentSeverity = 'critical' | 'high' | 'medium' | 'low';
type IncidentStatus = 'new' | 'investigating' | 'contained' | 'resolved' | 'escalated';
type ActionStatus = 'completed' | 'pending' | 'failed';
type NoteType = 'Update' | 'Evidence' | 'Decision' | 'Escalation';

interface TimelineEntry {
    id: string;
    timestamp: string;
    actor: string;
    action: string;
    detail: string;
}

interface ContainmentAction {
    id: string;
    label: string;
    status: ActionStatus;
    completed_at: string | null;
}

interface AnalystNote {
    id: string;
    author: string;
    type: NoteType;
    text: string;
    timestamp: string;
}

interface Incident {
    id: string;
    // Display identifier (INC-{year}-{n}) — shown instead of `id`, which for a TheHive-backed
    // incident is a raw TheHive `~1234567` value. `id` itself is still what every API call
    // below (updateStatus/addNote/addTask/the detail fetch) uses; only the two rendered badges
    // switch to this. Optional because Wazuh-derived incidents already have an `id` in this
    // exact shape and don't need a separate field.
    incident_number?: string;
    title: string;
    severity: IncidentSeverity;
    status: IncidentStatus;
    mitre_tactic: string;
    mitre_technique: string;
    affected_assets: string[];
    assigned_analyst: string;
    opened_at: string;
    updated_at: string;
    summary: string;
    source_alert_id: string | null;
    timeline: TimelineEntry[];
    containment_actions: ContainmentAction[];
    notes: AnalystNote[];
    source?: 'wazuh' | 'thehive' | 'internal';
    rule_id?: string;
    sla_remaining?: string;
    // TheHive-backed incidents only — populated by a GET /api/incidents/:id detail fetch, not
    // present on the list-level data. Wazuh-derived incidents use containment_actions instead.
    tasks?: TheHiveTask[];
}

interface TheHiveTask {
    _id: string;
    title: string;
    description: string;
    status: string;
}

interface Summary {
    total: number;
    open: number;
    critical: number;
    investigating: number;
    resolved: number;
    resolvedToday: number;
}

const SEV_CONFIG: Record<IncidentSeverity, { bg: string; text: string; border: string }> = {
    critical: { bg: 'bg-red-500/10', text: 'text-red-500', border: 'border-red-500/30' },
    high: { bg: 'bg-orange/10', text: 'text-orange', border: 'border-orange/30' },
    medium: { bg: 'bg-amber-500/10', text: 'text-amber-500', border: 'border-amber-500/30' },
    low: { bg: 'bg-blue/10', text: 'text-blue', border: 'border-blue/30' },
};

const STATUS_CONFIG: Record<IncidentStatus, { bg: string; text: string; border: string }> = {
    new: { bg: 'bg-red-500/10', text: 'text-red-500', border: 'border-red-500/30' },
    investigating: { bg: 'bg-blue/10', text: 'text-blue', border: 'border-blue/30' },
    contained: { bg: 'bg-amber-500/10', text: 'text-amber-500', border: 'border-amber-500/30' },
    resolved: { bg: 'bg-emerald-500/10', text: 'text-emerald-500', border: 'border-emerald-500/30' },
    escalated: { bg: 'bg-purple/10', text: 'text-purple', border: 'border-purple/30' },
};

// The four-step lifecycle the status bar walks through. `id` is the value sent to
// PATCH /api/incidents/:id — 'new' rather than 'open', which is what this codebase's
// IncidentStatus union and TheHive mapping both use.
//
// 'escalated' is deliberately not a step. Escalating is an action taken *during* an
// investigation, not a stage between contained and resolved — the backend's escalate endpoint
// leaves status untouched for the same reason. A case already carrying the legacy 'escalated'
// status renders at the Investigating step (see currentStepFor) instead of falling off the bar.
const WORKFLOW_STEPS = [
    { id: 'new' as const, label: 'Open' },
    { id: 'investigating' as const, label: 'Investigating' },
    { id: 'contained' as const, label: 'Contained' },
    { id: 'resolved' as const, label: 'Resolved' },
];

const NEXT_STEP_LABEL: Record<number, string> = {
    0: 'Start Investigation',
    1: 'Mark as Contained',
    2: 'Resolve Incident',
};

function currentStepFor(status: IncidentStatus): number {
    if (status === 'escalated') return 1; // escalated cases are still being investigated
    const idx = WORKFLOW_STEPS.findIndex((s) => s.id === status);
    return idx === -1 ? 0 : idx;
}

// Standard IR phases (NIST SP 800-61-shaped). This is a per-analyst working checklist, not case
// state: it's kept in localStorage per incident, NOT written to TheHive, because TheHive already
// has a real per-case task list (the Response Tasks panel below, backed by
// POST /api/incidents/:id/tasks) and pushing a second parallel task concept into the same case
// would leave two disagreeing lists on the same incident. Anything that needs to be shared with
// another analyst belongs in Response Tasks or a note.
const INVESTIGATION_STEPS = [
    { id: 'triage', label: 'Initial Triage', desc: 'Review alert details, confirm severity, identify affected assets' },
    { id: 'contain', label: 'Containment', desc: 'Isolate affected systems, block malicious IPs, revoke credentials' },
    { id: 'evidence', label: 'Evidence Collection', desc: 'Capture logs, memory dumps, network traffic, screenshots' },
    { id: 'eradicate', label: 'Eradication', desc: 'Remove malware, patch vulnerability, close attack vector' },
    { id: 'recover', label: 'Recovery', desc: 'Restore systems, verify clean state, resume normal operations' },
    { id: 'review', label: 'Post-Incident Review', desc: 'Document lessons learned, update playbooks, report to management' },
];

const CHECKLIST_KEY = (incidentId: string) => `novrsoc.ir-checklist.${incidentId}`;

const NOTE_TYPE_STYLE: Record<NoteType, string> = {
    Update: 'bg-blue/15 text-blue border-blue/30',
    Evidence: 'bg-card-muted text-foreground-muted border-border',
    Decision: 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30',
    Escalation: 'bg-red-500/15 text-red-500 border-red-500/30',
};

const NOTE_TYPES: NoteType[] = ['Update', 'Evidence', 'Decision', 'Escalation'];

export function IncidentResponse() {
    const [incidents, setIncidents] = useState<Incident[]>([]);
    const [summary, setSummary] = useState<Summary | null>(null);
    const [loading, setLoading] = useState(true);
    const [statusFilter, setStatusFilter] = useState<'all' | IncidentStatus>('all');
    const [selectedId, setSelectedId] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);
    const [showAddNote, setShowAddNote] = useState(false);
    const [noteType, setNoteType] = useState<NoteType>('Update');
    const [noteText, setNoteText] = useState('');
    const [newTaskTitle, setNewTaskTitle] = useState('');
    const [addingTask, setAddingTask] = useState(false);
    const [assigning, setAssigning] = useState(false);
    const [showPlaybookModal, setShowPlaybookModal] = useState(false);
    const [attachingPlaybook, setAttachingPlaybook] = useState<string | null>(null);
    const [playbooks, setPlaybooks] = useState<PlaybookSummary[] | null>(null);
    const [checkedSteps, setCheckedSteps] = useState<Set<string>>(new Set());
    const [escalationNote, setEscalationNote] = useState('');
    const [escalating, setEscalating] = useState(false);
    const [escalationResult, setEscalationResult] = useState<{ ok: boolean; message: string } | null>(null);
    const [generatingReport, setGeneratingReport] = useState(false);

    const load = () => {
        setLoading(true);
        apiFetch(apiUrl('/api/incidents'))
            .then((r) => r.json())
            .then((data) => {
                setIncidents(Array.isArray(data?.incidents) ? data.incidents : []);
                setSummary(data?.summary ?? null);
            })
            .catch(() => setIncidents([]))
            .finally(() => setLoading(false));
    };

    useEffect(() => { load(); }, []);

    const filtered = incidents.filter((i) => statusFilter === 'all' || i.status === statusFilter);
    const selected = incidents.find((i) => i.id === selectedId) ?? null;

    // TheHive-backed incidents carry Response Tasks and real investigation notes that only the
    // per-id detail endpoint returns (the list endpoint above doesn't fetch each case's tasks/
    // comments — too expensive to do for every row). Fetch that detail once a TheHive-sourced
    // incident is opened and merge it into local state; Wazuh-derived incidents already have
    // everything they need from the list load, so this only fires for source === 'thehive'.
    useEffect(() => {
        if (!selectedId) return;
        const target = incidents.find((i) => i.id === selectedId);
        if (!target || target.source !== 'thehive' || target.tasks) return; // already fetched

        apiFetch(apiUrl(`/api/incidents/${selectedId}`))
            .then((r) => (r.ok ? r.json() : null))
            .then((data) => {
                if (!data) return;
                setIncidents((prev) => prev.map((i) => (
                    i.id === selectedId ? { ...i, tasks: data.tasks ?? [], notes: data.notes ?? i.notes } : i
                )));
            })
            .catch(() => {});
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [selectedId]);

    async function addTask(id: string) {
        if (!newTaskTitle.trim()) return;
        setAddingTask(true);
        try {
            const res = await apiFetch(apiUrl(`/api/incidents/${id}/tasks`), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ title: newTaskTitle.trim() }),
            });
            const data = await res.json();
            if (data?.task) {
                setIncidents((prev) => prev.map((i) => (
                    i.id === id ? { ...i, tasks: [...(i.tasks ?? []), data.task] } : i
                )));
            }
            setNewTaskTitle('');
        } finally {
            setAddingTask(false);
        }
    }

    async function assignAnalyst(id: string, assignee: string) {
        setAssigning(true);
        try {
            await apiFetch(apiUrl(`/api/incidents/${id}`), {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ assignee }),
            });
            setIncidents((prev) => prev.map((i) => (i.id === id ? { ...i, assigned_analyst: assignee } : i)));
        } finally {
            setAssigning(false);
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

    // POST /api/playbooks/:id/run — the backend creates one TheHive task per step (same
    // primitive the Response Tasks panel's own "+" button uses), so this just needs to refetch
    // the incident's tasks afterward rather than build the task list itself.
    async function attachPlaybook(incidentId: string, playbook: PlaybookSummary) {
        setAttachingPlaybook(playbook.id);
        try {
            const res = await apiFetch(apiUrl(`/api/playbooks/${playbook.id}/run`), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ incident_id: incidentId }),
            });
            const data = await res.json();
            if (data?.tasks) {
                setIncidents((prev) => prev.map((i) => (
                    i.id === incidentId ? { ...i, tasks: [...(i.tasks ?? []), ...data.tasks] } : i
                )));
            }
            setShowPlaybookModal(false);
        } finally {
            setAttachingPlaybook(null);
        }
    }

    async function updateStatus(id: string, status: IncidentStatus) {
        setBusy(true);
        try {
            await apiFetch(apiUrl(`/api/incidents/${id}`), {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status }),
            });
            setIncidents((prev) => prev.map((i) => (i.id === id ? { ...i, status } : i)));
        } finally {
            setBusy(false);
        }
    }

    // Opens the slide-over and loads that incident's per-analyst checklist.
    //
    // Done in the click handler rather than an effect on selectedId: reading localStorage is an
    // external-store read that belongs in an event handler, and resetting the escalation fields
    // here (instead of reactively) guarantees one incident's draft escalation note can never be
    // shown against another incident.
    function openIncident(id: string) {
        setEscalationNote('');
        setEscalationResult(null);
        try {
            const raw = localStorage.getItem(CHECKLIST_KEY(id));
            setCheckedSteps(new Set(raw ? (JSON.parse(raw) as string[]) : []));
        } catch {
            setCheckedSteps(new Set());
        }
        setSelectedId(id);
    }

    function toggleStep(incidentId: string, stepId: string) {
        setCheckedSteps((prev) => {
            const next = new Set(prev);
            if (next.has(stepId)) next.delete(stepId);
            else next.add(stepId);
            try {
                localStorage.setItem(CHECKLIST_KEY(incidentId), JSON.stringify([...next]));
            } catch {
                // Blocked site data — the checklist still works for this session.
            }
            return next;
        });
    }

    async function escalate(id: string) {
        setEscalating(true);
        setEscalationResult(null);
        try {
            const res = await apiFetch(apiUrl(`/api/incidents/${id}/escalate`), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ note: escalationNote.trim() }),
            });
            const data = await res.json();
            if (!res.ok) {
                setEscalationResult({ ok: false, message: data?.error ?? `Escalation failed (HTTP ${res.status})` });
                return;
            }
            // The backend reports each channel separately — it deliberately does NOT claim the
            // CISO was emailed when EMAIL_ENABLED is off, so surface its message verbatim
            // rather than a blanket "email sent".
            setEscalationResult({ ok: Boolean(data?.success), message: data?.message ?? 'Escalation recorded' });
            if (data?.success) setEscalationNote('');
        } catch {
            setEscalationResult({ ok: false, message: 'Escalation failed — could not reach the backend' });
        } finally {
            setEscalating(false);
        }
    }

    async function generateReport(incident: Incident) {
        setGeneratingReport(true);
        try {
            const res = await apiFetch(apiUrl(`/api/incidents/${incident.id}/report`));
            if (!res.ok) return;
            const blob = await res.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${incident.incident_number ?? incident.id}-report.md`;
            a.click();
            URL.revokeObjectURL(url);
        } finally {
            setGeneratingReport(false);
        }
    }

    async function addNote(id: string) {
        if (!noteText.trim()) return;
        setBusy(true);
        try {
            const author = getAdminUser()?.name || 'RayneOps';
            const res = await apiFetch(apiUrl(`/api/incidents/${id}/notes`), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ author, type: noteType, text: noteText.trim() }),
            });
            const data = await res.json();
            if (data?.note) {
                setIncidents((prev) => prev.map((i) => (i.id === id ? { ...i, notes: [...i.notes, data.note] } : i)));
            }
            setNoteText('');
            setShowAddNote(false);
        } finally {
            setBusy(false);
        }
    }

    function exportIncidentPDF(incident: Incident) {
        exportDataAsPDF(incident.title, `incident-${incident.id}`, [
            {
                heading: 'Incident Overview',
                rows: [
                    { label: 'Incident ID', value: incident.incident_number ?? incident.id },
                    { label: 'Severity', value: incident.severity.toUpperCase() },
                    { label: 'Status', value: incident.status.toUpperCase() },
                    { label: 'MITRE ATT&CK', value: `${incident.mitre_tactic} · ${incident.mitre_technique}` },
                    { label: 'Lead Analyst', value: incident.assigned_analyst },
                    { label: 'Affected Asset(s)', value: incident.affected_assets.join(', ') },
                    { label: 'Rule ID', value: incident.rule_id || 'N/A' },
                ],
            },
            { heading: 'Telemetry & Evidence', rows: [{ label: 'Raw Alert Log', value: incident.summary }] },
            {
                heading: 'Audit Timeline',
                rows: incident.timeline.map((t) => ({ label: `${t.timestamp} · ${t.actor}`, value: `${t.action}${t.detail ? ` — ${t.detail}` : ''}` })),
            },
            {
                heading: 'Analyst Case Notes',
                rows: incident.notes.length > 0
                    ? incident.notes.map((n) => ({ label: `${n.timestamp} · ${n.author} [${n.type}]`, value: n.text }))
                    : [{ label: 'Notes', value: 'No analyst notes recorded.' }],
            },
        ]);
    }

    // Detail slide-over — rendered as an overlay alongside the list (not a full-page swap), so
    // the analyst never leaves the incident queue to work a case. `selected` gates the overlay
    // block appended near the end of the list-view return below.

    // List View
    return (
        <div className="space-y-5 max-w-7xl mx-auto">
            {/* Header Strip */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-4">
                <div>
                    <div className="flex items-center gap-2.5">
                        <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center text-primary">
                            <Shield className="w-4 h-4 text-orange" />
                        </div>
                        <h1 className="text-xl font-bold tracking-tight text-foreground">Incident Response</h1>
                    </div>
                    <p className="text-xs text-foreground-muted mt-1">
                        SecOps Triage · High and Critical severity cases — Low/Medium are handled automatically by SOAR
                    </p>
                </div>
                <button
                    onClick={load}
                    className="flex items-center gap-1.5 text-xs font-bold text-foreground-muted hover:text-foreground border border-border bg-card px-3.5 py-2 rounded-lg transition-colors self-start sm:self-auto"
                >
                    <RefreshCw className="w-3.5 h-3.5" /> Refresh Feeds
                </button>
            </div>

            {/* Metric Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5">
                {[
                    { label: 'Open', value: summary?.open ?? 0, color: 'text-blue', icon: FileText },
                    { label: 'Investigating', value: summary?.investigating ?? 0, color: 'text-orange', icon: Clock },
                    { label: 'Critical', value: summary?.critical ?? 0, color: 'text-red-500', icon: AlertTriangle },
                    { label: 'Resolved Today', value: summary?.resolvedToday ?? 0, color: 'text-emerald-500', icon: CheckCircle },
                ].map((k) => (
                    <div key={k.label} className="bg-card border border-border rounded-xl p-4 flex items-center justify-between shadow-xs">
                        <div>
                            <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{k.label}</p>
                            <p className={`text-2xl font-black ${k.color} mt-0.5`}>{k.value}</p>
                        </div>
                        <div className="w-9 h-9 rounded-xl bg-card-muted flex items-center justify-center">
                            <k.icon className={`w-4 h-4 ${k.color}`} />
                        </div>
                    </div>
                ))}
            </div>

            {/* Filter Tabs */}
            <div className="flex items-center gap-1.5 bg-card border border-border rounded-lg p-1 w-fit overflow-x-auto">
                {(['all', 'new', 'investigating', 'contained', 'resolved', 'escalated'] as const).map((s) => (
                    <button
                        key={s}
                        onClick={() => setStatusFilter(s)}
                        className={`text-xs font-bold px-3 py-1.5 rounded-md capitalize transition-all whitespace-nowrap ${
                            statusFilter === s ? 'bg-blue text-white shadow-xs' : 'text-foreground-muted hover:text-foreground'
                        }`}
                    >
                        {s === 'all' ? 'All Incidents' : s}
                    </button>
                ))}
            </div>

            {/* Main Incident List */}
            {loading ? (
                <div className="space-y-3">
                    {Array.from({ length: 4 }).map((_, i) => (
                        <div key={i} className="h-20 bg-card-muted/60 border border-border rounded-xl animate-pulse" />
                    ))}
                </div>
            ) : filtered.length === 0 ? (
                <div className="bg-card border border-border rounded-xl py-12 text-center shadow-xs">
                    <p className="text-xs text-foreground-muted">No incidents match the active filter criteria.</p>
                </div>
            ) : (
                <div className="space-y-2.5">
                    {filtered.map((inc) => {
                        const sev = SEV_CONFIG[inc.severity];
                        const stat = STATUS_CONFIG[inc.status];
                        const isDesktop = inc.affected_assets[0]?.includes('DESKTOP');

                        return (
                            <div
                                key={inc.id}
                                onClick={() => openIncident(inc.id)}
                                className="w-full bg-card border border-border rounded-xl p-4 hover:border-orange/40 hover:bg-card-muted/30 transition-all flex items-center justify-between gap-4 cursor-pointer shadow-xs group"
                            >
                                <div className="min-w-0 space-y-1">
                                    <div className="flex items-center gap-2 flex-wrap">
                                        <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full border uppercase ${sev.bg} ${sev.text} ${sev.border}`}>
                                            {inc.severity}
                                        </span>
                                        <span className="font-mono text-[10px] text-foreground-muted font-bold">{inc.incident_number ?? inc.id}</span>
                                        <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full border capitalize ${stat.bg} ${stat.text} ${stat.border}`}>
                                            {inc.status}
                                        </span>
                                        <span className="text-[10px] text-amber-500 font-mono bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded-full">
                                            {inc.mitre_tactic} · {inc.mitre_technique}
                                        </span>
                                    </div>

                                    <p className="text-sm font-bold text-foreground group-hover:text-orange transition-colors truncate">
                                        {inc.title}
                                    </p>

                                    <div className="flex items-center gap-3 text-[11px] text-foreground-muted flex-wrap">
                                        <span className="flex items-center gap-1 font-mono text-[10px]">
                                            {isDesktop ? <Laptop size={11} /> : <Server size={11} />}
                                            {inc.affected_assets.join(', ')}
                                        </span>
                                        <span>•</span>
                                        <span>Analyst: <strong className="text-foreground">{inc.assigned_analyst}</strong></span>
                                        <span>•</span>
                                        <span>Updated: {inc.updated_at}</span>
                                    </div>
                                </div>

                                <div className="flex items-center gap-3 shrink-0">
                                    {inc.sla_remaining && (
                                        <div className="hidden md:flex flex-col items-end text-right">
                                            <span className="text-[9px] uppercase font-bold text-foreground-muted">SLA Target</span>
                                            <span className="text-xs font-mono text-foreground font-semibold flex items-center gap-1">
                                                <Clock size={11} className="text-orange" /> {inc.sla_remaining}
                                            </span>
                                        </div>
                                    )}
                                    <ChevronRight className="w-4 h-4 text-foreground-muted group-hover:text-foreground group-hover:translate-x-0.5 transition-all" />
                                </div>
                            </div>
                        );
                    })}
                </div>
            )}

            {/* Detail slide-over */}
            {selected && (() => {
                const sev = SEV_CONFIG[selected.severity];
                const stat = STATUS_CONFIG[selected.status];
                return (
                    <div className="fixed inset-0 bg-black/40 z-50 flex items-stretch justify-end" onClick={() => setSelectedId(null)}>
                        <div
                            className="bg-card border-l border-border h-full w-full max-w-4xl overflow-y-auto scrollbar-thin"
                            onClick={(e) => e.stopPropagation()}
                        >
                            <div className="p-5 sm:p-6 space-y-5">
                                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-4">
                                    <div className="min-w-0">
                                        <div className="flex items-center gap-2 flex-wrap">
                                            <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border uppercase ${sev.bg} ${sev.text} ${sev.border}`}>
                                                {selected.severity}
                                            </span>
                                            <span className="font-mono text-xs text-foreground-muted font-bold">{selected.incident_number ?? selected.id}</span>
                                            <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border capitalize ${stat.bg} ${stat.text} ${stat.border}`}>
                                                {selected.status}
                                            </span>
                                        </div>
                                        <h1 className="text-xl font-black text-foreground mt-2 tracking-tight">{selected.title}</h1>
                                        <p className="text-xs text-foreground-muted mt-0.5">
                                            Created: <span className="text-foreground">{selected.opened_at}</span>
                                        </p>
                                    </div>
                                    <button onClick={() => setSelectedId(null)} className="text-foreground-muted hover:text-foreground shrink-0" aria-label="Close">
                                        <X className="w-5 h-5" />
                                    </button>
                                </div>

                                {/* Status workflow bar. Every step stays clickable, not just the
                                    next one — an analyst who marked contained prematurely has to
                                    be able to step back to investigating. */}
                                {(() => {
                                    const currentStep = currentStepFor(selected.status);
                                    const nextStep = WORKFLOW_STEPS[currentStep + 1];
                                    return (
                                        <div className="space-y-3">
                                            <div className="flex items-center rounded-xl overflow-hidden border border-border">
                                                {WORKFLOW_STEPS.map((step, i) => (
                                                    <button
                                                        key={step.id}
                                                        disabled={busy}
                                                        onClick={() => updateStatus(selected.id, step.id)}
                                                        className={`flex-1 py-2.5 px-2 text-xs font-bold text-center transition-colors disabled:opacity-60 ${
                                                            i === currentStep
                                                                ? 'bg-purple text-white'
                                                                : i < currentStep
                                                                    ? 'bg-emerald-500 text-white'
                                                                    : 'bg-card-muted text-foreground-muted hover:bg-border'
                                                        } ${i > 0 ? 'border-l border-border' : ''}`}
                                                    >
                                                        {i < currentStep ? '✓ ' : ''}{step.label}
                                                    </button>
                                                ))}
                                            </div>

                                            {selected.status === 'escalated' && (
                                                <p className="text-[11px] text-red-500 font-bold">
                                                    This incident carries the legacy &quot;escalated&quot; status — shown at the Investigating step.
                                                </p>
                                            )}

                                            <div className="flex items-center gap-2 flex-wrap">
                                                {nextStep && (
                                                    <button
                                                        disabled={busy}
                                                        onClick={() => updateStatus(selected.id, nextStep.id)}
                                                        className="flex-1 min-w-[200px] bg-purple text-white font-bold py-3 rounded-xl hover:opacity-90 disabled:opacity-50 text-sm transition-opacity"
                                                    >
                                                        → {NEXT_STEP_LABEL[currentStep] ?? `Move to ${nextStep.label}`}
                                                    </button>
                                                )}
                                                <button onClick={openPlaybookModal} className="flex items-center gap-1.5 text-xs font-bold text-purple border border-purple/30 bg-purple/5 hover:bg-purple/10 px-3.5 py-2 rounded-lg transition-colors">
                                                    <BookOpen size={14} /> Attach Playbook
                                                </button>
                                                {selected.source === 'thehive' && (
                                                    <button
                                                        onClick={() => generateReport(selected)}
                                                        disabled={generatingReport}
                                                        className="flex items-center gap-1.5 text-xs font-bold text-foreground-muted hover:text-foreground border border-border bg-card px-3 py-2 rounded-lg transition-colors disabled:opacity-50"
                                                    >
                                                        <FileText size={14} /> {generatingReport ? 'Generating…' : 'Report (MD)'}
                                                    </button>
                                                )}
                                                <button onClick={() => exportIncidentPDF(selected)} className="flex items-center gap-1.5 text-xs font-bold text-foreground-muted hover:text-foreground border border-border bg-card px-3 py-2 rounded-lg transition-colors">
                                                    <FileDown size={14} /> PDF
                                                </button>
                                            </div>
                                        </div>
                                    );
                                })()}

                                {/* Escalation — high/critical only, and only while still open.
                                    Escalating does not change status: it notifies the CISO and
                                    records the reason on the case, and the investigation carries
                                    on from whatever step it was at. */}
                                {(selected.severity === 'high' || selected.severity === 'critical') && selected.status !== 'resolved' && (
                                    <div className="bg-red-500/5 border border-red-500/30 rounded-xl p-4 sm:p-5 space-y-3">
                                        <div>
                                            <h3 className="text-sm font-bold text-red-500">Escalation</h3>
                                            <p className="text-[11px] text-red-500/80 mt-0.5">
                                                {selected.severity === 'critical'
                                                    ? 'Critical incident — escalate within 30 minutes'
                                                    : 'High severity — escalate if unresolved after 2 hours'}
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
                                            onClick={() => escalate(selected.id)}
                                            disabled={escalating || selected.source !== 'thehive'}
                                            className="w-full flex items-center justify-center gap-1.5 bg-red-500 text-white text-xs font-bold px-4 py-2.5 rounded-xl hover:bg-red-600 disabled:opacity-50 transition-colors"
                                        >
                                            <TrendingUp size={14} />
                                            {escalating ? 'Escalating…' : 'Escalate to CISO — notify now'}
                                        </button>
                                        {selected.source !== 'thehive' && (
                                            <p className="text-[10px] text-foreground-muted">
                                                Escalation is only available for TheHive-backed incidents.
                                            </p>
                                        )}
                                        {escalationResult && (
                                            <p className={`text-[11px] font-bold ${escalationResult.ok ? 'text-emerald-500' : 'text-red-500'}`}>
                                                {escalationResult.message}
                                            </p>
                                        )}
                                    </div>
                                )}

                                {/* Investigation checklist */}
                                <div className="bg-card border border-border rounded-xl p-4 sm:p-5 shadow-xs">
                                    <div className="flex items-center justify-between mb-3">
                                        <h3 className="text-xs font-bold text-foreground uppercase tracking-wider flex items-center gap-2">
                                            <ClipboardList size={14} className="text-purple" /> Investigation Steps
                                        </h3>
                                        <span className="text-[10px] text-foreground-muted">
                                            {checkedSteps.size}/{INVESTIGATION_STEPS.length} complete
                                        </span>
                                    </div>

                                    <div className="h-1.5 bg-card-muted rounded-full mb-4 overflow-hidden">
                                        <div
                                            className="h-full bg-purple rounded-full transition-all"
                                            style={{ width: `${(checkedSteps.size / INVESTIGATION_STEPS.length) * 100}%` }}
                                        />
                                    </div>

                                    <div className="space-y-2">
                                        {INVESTIGATION_STEPS.map((step) => {
                                            const done = checkedSteps.has(step.id);
                                            return (
                                                <button
                                                    key={step.id}
                                                    onClick={() => toggleStep(selected.id, step.id)}
                                                    aria-pressed={done}
                                                    className={`w-full flex items-start gap-3 p-3 rounded-xl text-left transition-colors border ${
                                                        done ? 'bg-emerald-500/5 border-emerald-500/30' : 'bg-card-muted/40 border-transparent hover:border-border'
                                                    }`}
                                                >
                                                    <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center shrink-0 mt-0.5 transition-colors ${
                                                        done ? 'bg-emerald-500 border-emerald-500' : 'border-border'
                                                    }`}>
                                                        {done && <span className="text-white text-[8px] font-black">✓</span>}
                                                    </div>
                                                    <div>
                                                        <div className={`text-xs font-bold ${done ? 'text-emerald-500 line-through' : 'text-foreground'}`}>
                                                            {step.label}
                                                        </div>
                                                        <div className="text-[10px] text-foreground-muted mt-0.5 leading-relaxed">{step.desc}</div>
                                                    </div>
                                                </button>
                                            );
                                        })}
                                    </div>
                                    <p className="text-[10px] text-foreground-muted mt-3">
                                        Personal working checklist — saved in this browser only. Use Response Tasks for anything the team needs to see.
                                    </p>
                                </div>

                                {/* Assign to analyst */}
                                <div className="flex items-center gap-2 bg-card-muted/40 border border-border rounded-xl px-3.5 py-2.5 w-fit">
                                    <UserPlus size={14} className="text-foreground-muted" />
                                    <span className="text-xs text-foreground-muted">Assigned to</span>
                                    <select
                                        value={ASSIGNABLE_ANALYSTS.includes(selected.assigned_analyst) ? selected.assigned_analyst : ''}
                                        onChange={(e) => e.target.value && assignAnalyst(selected.id, e.target.value)}
                                        disabled={assigning}
                                        className="bg-card border border-border rounded-lg px-2.5 py-1 text-xs font-bold text-foreground focus:outline-none focus:border-purple disabled:opacity-50"
                                    >
                                        <option value="">
                                            {ASSIGNABLE_ANALYSTS.includes(selected.assigned_analyst) ? selected.assigned_analyst : selected.assigned_analyst || 'Unassigned'}
                                        </option>
                                        {ASSIGNABLE_ANALYSTS.filter((n) => n !== selected.assigned_analyst).map((n) => (
                                            <option key={n} value={n}>{n}</option>
                                        ))}
                                    </select>
                                </div>

                                {/* Detail Columns */}
                                <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                                    <div className="lg:col-span-2 space-y-4">
                                        {/* Description & alert context */}
                                        <div className="bg-card border border-border rounded-xl p-4 sm:p-5 shadow-xs space-y-3">
                                            <div className="flex items-center justify-between border-b border-border pb-2.5">
                                                <h3 className="text-xs font-bold text-foreground uppercase tracking-wider flex items-center gap-2">
                                                    <Terminal size={14} className="text-orange" /> Description & Alert Context
                                                </h3>
                                                {selected.rule_id && (
                                                    <span className="text-[10px] font-mono text-foreground-muted bg-card-muted px-2 py-0.5 rounded border border-border">
                                                        Rule: {selected.rule_id}
                                                    </span>
                                                )}
                                            </div>
                                            <p className="font-mono text-xs bg-card-muted/60 p-3 rounded-lg border border-border text-foreground leading-relaxed overflow-x-auto whitespace-pre-wrap">
                                                {selected.summary}
                                            </p>
                                            <div className="grid grid-cols-2 gap-4 pt-2 text-xs">
                                                <div>
                                                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">Tags</p>
                                                    <p className="font-bold text-foreground mt-0.5">{selected.mitre_tactic}</p>
                                                </div>
                                                <div>
                                                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">Affected Host</p>
                                                    <p className="font-bold text-foreground mt-0.5">{selected.affected_assets.join(', ') || '—'}</p>
                                                </div>
                                            </div>
                                        </div>

                                        {/* Timeline */}
                                        <div className="bg-card border border-border rounded-xl p-4 sm:p-5 shadow-xs">
                                            <h3 className="text-xs font-bold text-foreground uppercase tracking-wider mb-4 flex items-center gap-2">
                                                <Clock size={14} className="text-blue" /> Timeline
                                            </h3>
                                            {/* Case events and analyst notes in one thread. They
                                                were previously two disconnected panels, so the
                                                order in which things actually happened during an
                                                investigation wasn't readable anywhere.
                                                Deliberately NOT re-sorted by time: `timestamp`
                                                and note timestamps are preformatted display
                                                strings from different sources (locale date-time
                                                vs. time-only), so string-comparing them would
                                                interleave them wrongly. Case events first, then
                                                notes in the order they were added. */}
                                            {(() => {
                                                const entries = [
                                                    ...selected.timeline.map((t) => ({
                                                        key: t.id, dot: 'bg-blue ring-blue/10',
                                                        title: t.action, when: t.timestamp,
                                                        who: `Triggered by ${t.actor}`, detail: t.detail,
                                                    })),
                                                    ...selected.notes.map((n) => ({
                                                        key: `note-${n.id}`, dot: 'bg-purple ring-purple/10',
                                                        title: `Note added — ${n.type}`, when: n.timestamp,
                                                        who: n.author, detail: n.text,
                                                    })),
                                                ];
                                                return (
                                                    <div className="space-y-0">
                                                        {entries.map((e, idx) => (
                                                            <div key={e.key} className="flex gap-3">
                                                                <div className="flex flex-col items-center">
                                                                    <div className={`w-2.5 h-2.5 rounded-full ring-4 shrink-0 mt-1 ${e.dot}`} />
                                                                    {idx < entries.length - 1 && <div className="w-px flex-1 bg-border my-1" />}
                                                                </div>
                                                                <div className="pb-4 min-w-0">
                                                                    <div className="flex items-center gap-2 flex-wrap">
                                                                        <p className="text-xs font-bold text-foreground">{e.title}</p>
                                                                        <span className="text-[10px] text-foreground-muted">{e.when}</span>
                                                                    </div>
                                                                    <p className="text-[11px] text-foreground-muted">{e.who}</p>
                                                                    {e.detail && <p className="text-xs text-foreground-muted mt-1 leading-relaxed break-words">{e.detail}</p>}
                                                                </div>
                                                            </div>
                                                        ))}
                                                    </div>
                                                );
                                            })()}
                                        </div>

                                        {/* Investigation notes */}
                                        <div className="bg-card border border-border rounded-xl p-4 sm:p-5 shadow-xs space-y-3">
                                            <div className="flex items-center justify-between border-b border-border pb-2.5">
                                                <h3 className="text-xs font-bold text-foreground uppercase tracking-wider flex items-center gap-2">
                                                    <UserCheck size={14} className="text-purple" /> Investigation Notes
                                                </h3>
                                                <button
                                                    onClick={() => setShowAddNote((v) => !v)}
                                                    className="flex items-center gap-1 text-xs font-bold text-orange hover:text-orange-hover"
                                                >
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
                                                                className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border transition-all ${
                                                                    noteType === t ? NOTE_TYPE_STYLE[t] : 'bg-card text-foreground-muted border-border'
                                                                }`}
                                                            >
                                                                {t}
                                                            </button>
                                                        ))}
                                                    </div>
                                                    <textarea
                                                        value={noteText}
                                                        onChange={(e) => setNoteText(e.target.value)}
                                                        rows={2}
                                                        placeholder="Add timestamped investigative notes..."
                                                        className="w-full bg-card border border-border rounded-lg p-2.5 text-xs text-foreground focus:outline-none focus:border-orange resize-none"
                                                    />
                                                    <div className="flex justify-end gap-2">
                                                        <button onClick={() => setShowAddNote(false)} className="text-xs font-semibold text-foreground-muted px-3 py-1.5">
                                                            Cancel
                                                        </button>
                                                        <button
                                                            disabled={busy || !noteText.trim()}
                                                            onClick={() => addNote(selected.id)}
                                                            className="text-xs font-bold text-white bg-orange hover:bg-orange-hover px-3.5 py-1.5 rounded-lg disabled:opacity-50"
                                                        >
                                                            Save Note
                                                        </button>
                                                    </div>
                                                </div>
                                            )}

                                            {selected.notes.length === 0 ? (
                                                <p className="text-xs text-foreground-muted py-2">No analyst notes added to this investigation yet.</p>
                                            ) : (
                                                <div className="space-y-2.5 divide-y divide-border/40">
                                                    {selected.notes.map((n) => (
                                                        <div key={n.id} className="pt-2 flex gap-2.5 items-start">
                                                            <div className="w-7 h-7 rounded-lg bg-primary/10 flex items-center justify-center font-bold text-xs text-primary shrink-0">
                                                                {n.author.slice(0, 2).toUpperCase()}
                                                            </div>
                                                            <div className="min-w-0 flex-1">
                                                                <div className="flex items-center gap-2">
                                                                    <span className="text-xs font-bold text-foreground">{n.author}</span>
                                                                    <span className={`text-[9px] font-bold px-1.5 py-0.2 rounded-full border ${NOTE_TYPE_STYLE[n.type]}`}>
                                                                        {n.type}
                                                                    </span>
                                                                    <span className="text-[10px] text-foreground-muted ml-auto">{n.timestamp}</span>
                                                                </div>
                                                                <p className="text-xs text-foreground mt-0.5 leading-relaxed">{n.text}</p>
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            )}
                                        </div>
                                    </div>

                                    {/* Containment Checklist (Wazuh-derived) / Response Tasks Sidebar */}
                                    <div className="space-y-4">
                                        {selected.containment_actions.length > 0 && (
                                            <div className="bg-card border border-border rounded-xl p-4 sm:p-5 shadow-xs">
                                                <h3 className="text-xs font-bold text-foreground uppercase tracking-wider mb-3 flex items-center gap-2">
                                                    <Lock size={14} className="text-red-500" /> Containment Checklist
                                                </h3>
                                                <div className="space-y-2.5">
                                                    {selected.containment_actions.map((a) => (
                                                        <div key={a.id} className="flex items-start gap-2.5 p-2 rounded-lg bg-card-muted/30 border border-border">
                                                            <CheckCircle className={`w-4 h-4 mt-0.5 shrink-0 ${a.status === 'completed' ? 'text-emerald-500' : 'text-amber-500'}`} />
                                                            <div className="min-w-0">
                                                                <p className={`text-xs font-medium ${a.status === 'completed' ? 'line-through text-foreground-muted' : 'text-foreground'}`}>{a.label}</p>
                                                                {a.completed_at && <p className="text-[10px] text-foreground-muted mt-0.5">{a.completed_at}</p>}
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        )}

                                        <div className="bg-card border border-border rounded-xl p-4 sm:p-5 shadow-xs">
                                            <h3 className="text-xs font-bold text-foreground uppercase tracking-wider mb-3 flex items-center gap-2">
                                                <ListChecks size={14} className="text-emerald-500" /> Response Tasks
                                            </h3>

                                            {selected.tasks === undefined ? (
                                                <p className="text-xs text-foreground-muted py-1">Loading tasks…</p>
                                            ) : selected.tasks.length === 0 ? (
                                                <p className="text-xs text-foreground-muted py-1">No tasks yet — attach a playbook or add one below.</p>
                                            ) : (
                                                <div className="space-y-2 mb-3">
                                                    {selected.tasks.map((t) => (
                                                        <div key={t._id} className="flex items-center gap-2.5 p-2 rounded-lg bg-card-muted/30 border border-border">
                                                            <div className={`w-3.5 h-3.5 rounded-full border-2 shrink-0 ${t.status === 'Completed' ? 'bg-emerald-500 border-emerald-500' : 'border-border'}`} />
                                                            <span className={`text-xs flex-1 min-w-0 truncate ${t.status === 'Completed' ? 'text-foreground-muted line-through' : 'text-foreground'}`}>{t.title}</span>
                                                            <span className="text-[9px] text-foreground-muted shrink-0">{t.status}</span>
                                                        </div>
                                                    ))}
                                                </div>
                                            )}

                                            <div className="flex items-center gap-1.5">
                                                <input
                                                    value={newTaskTitle}
                                                    onChange={(e) => setNewTaskTitle(e.target.value)}
                                                    onKeyDown={(e) => { if (e.key === 'Enter') addTask(selected.id); }}
                                                    placeholder="New task title..."
                                                    className="flex-1 min-w-0 bg-card border border-border rounded-lg px-2.5 py-1.5 text-xs text-foreground focus:outline-none focus:border-emerald-500"
                                                />
                                                <button
                                                    disabled={addingTask || !newTaskTitle.trim()}
                                                    onClick={() => addTask(selected.id)}
                                                    className="flex items-center gap-1 text-xs font-bold text-white bg-emerald-500 hover:bg-emerald-600 px-2.5 py-1.5 rounded-lg disabled:opacity-50 shrink-0"
                                                >
                                                    <Plus size={13} />
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                );
            })()}

            {/* Attach Playbook modal */}
            {showPlaybookModal && selected && (
                <div className="fixed inset-0 bg-black/50 z-[60] flex items-center justify-center p-4" onClick={() => setShowPlaybookModal(false)}>
                    <div className="bg-card border border-border rounded-2xl p-6 w-full max-w-lg max-h-[80vh] overflow-y-auto scrollbar-thin" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="font-heading font-bold text-sm text-foreground">Attach Playbook to {selected.incident_number ?? selected.id}</h3>
                            <button onClick={() => setShowPlaybookModal(false)} className="text-foreground-muted hover:text-foreground"><X size={16} /></button>
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
                                        onClick={() => attachPlaybook(selected.id, pb)}
                                        disabled={attachingPlaybook !== null}
                                        className="w-full text-left flex items-center justify-between gap-3 bg-card-muted/40 hover:bg-card-muted border border-border rounded-xl px-4 py-3 transition-colors disabled:opacity-50"
                                    >
                                        <div className="min-w-0">
                                            <p className="text-sm font-bold text-foreground truncate">{pb.icon} {pb.name}</p>
                                            <p className="text-[11px] text-foreground-muted truncate">{pb.description}</p>
                                        </div>
                                        <span className="text-[10px] font-bold text-purple shrink-0">
                                            {attachingPlaybook === pb.id ? 'Adding…' : `${pb.steps.length} steps`}
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