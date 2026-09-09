'use client';

import { useEffect, useState } from 'react';
import { ArrowLeft, Play, Plus, X, Clock, AlertTriangle, ListChecks } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Playbooks now come from GET /api/playbooks (routes/playbooks.ts, Supabase-backed) — the same
// source the CISO's Security Ops Management → Playbooks tab creates and edits, so both pages
// show one library instead of the two that used to disagree. This page previously rendered a
// hardcoded 6-entry array that no amount of editing in Management would ever change.
//
// The table has no use_count/last_used/tags columns (see routes/playbooks.ts's header, which
// confirms that against the live table), so those are no longer displayed rather than shown as
// permanent zeros. Step count is derived from the steps array itself.
//
// "Start Playbook" is unchanged and still real: it POSTs to routes/incidentResponse.ts and
// creates an actual incident with the playbook's steps pre-filled as its containment checklist.

export interface PlaybookStep {
    order: number;
    title: string;
    phase: string;
    est_mins: number;
    description: string;
}

// Mirrors the row shape routes/playbooks.ts returns.
export interface Playbook {
    id: string;
    name: string;
    icon?: string;
    severity: 'critical' | 'high' | 'medium';
    description: string;
    estimated_time?: string;
    steps?: PlaybookStep[];
}

const SEVERITY_BADGE: Record<string, string> = {
    critical: 'bg-red/10 text-red border-red/30',
    high: 'bg-amber/10 text-amber border-amber/30',
    medium: 'bg-blue/10 text-blue border-blue/30',
};
const PHASE_COLOR: Record<string, string> = {
    URGENT: 'bg-red text-white', Containment: 'bg-red/10 text-red border border-red/30',
    Analysis: 'bg-blue/10 text-blue border border-blue/30', Evidence: 'bg-blue/10 text-blue border border-blue/30',
    Communication: 'bg-purple/10 text-purple border border-purple/30', Remediation: 'bg-amber/10 text-amber border border-amber/30',
    Hardening: 'bg-green/10 text-green border border-green/30', Recovery: 'bg-green/10 text-green border border-green/30',
    Legal: 'bg-purple/10 text-purple border border-purple/30', Closure: 'bg-card-muted text-foreground-muted border border-border',
};

function severityClass(severity: string): string {
    return SEVERITY_BADGE[severity] ?? 'bg-card-muted text-foreground-muted border-border';
}

export function Playbooks() {
    const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
    const [loading, setLoading] = useState(true);
    const [loadError, setLoadError] = useState<string | null>(null);

    const [selected, setSelected] = useState<Playbook | null>(null);
    const [startModal, setStartModal] = useState<Playbook | null>(null);
    const [form, setForm] = useState({ title: '', host: '', severity: 'high' });

    useEffect(() => {
        let cancelled = false;
        apiFetch(apiUrl('/api/playbooks'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => {
                if (cancelled) return;
                setPlaybooks(Array.isArray(data?.playbooks) ? data.playbooks : []);
                setLoading(false);
            })
            .catch(() => {
                if (cancelled) return;
                setLoadError('Could not load the playbook library.');
                setLoading(false);
            });
        return () => { cancelled = true; };
    }, []);

    if (selected) {
        const steps = selected.steps ?? [];
        return (
            <div className="space-y-4">
                <button onClick={() => setSelected(null)} className="flex items-center gap-1.5 text-xs font-bold text-blue hover:text-purple transition-colors">
                    <ArrowLeft size={14} /> Back to Playbooks
                </button>
                <div className="bg-card border border-border rounded-xl p-5">
                    <div className="flex items-start justify-between flex-wrap gap-4">
                        <div>
                            <div className="flex items-center gap-2 mb-1">
                                <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase ${severityClass(selected.severity)}`}>{selected.severity}</span>
                                <h1 className="text-lg font-black text-foreground">{selected.icon ? `${selected.icon} ` : ''}{selected.name}</h1>
                            </div>
                            <p className="text-xs text-foreground-muted">{selected.description}</p>
                            <p className="text-[10px] text-foreground-muted mt-2 flex items-center gap-3">
                                {selected.estimated_time && <span className="flex items-center gap-1"><Clock size={11} /> {selected.estimated_time}</span>}
                                <span className="flex items-center gap-1"><ListChecks size={11} /> {steps.length} step{steps.length === 1 ? '' : 's'}</span>
                            </p>
                        </div>
                        <button onClick={() => setStartModal(selected)} className="flex items-center gap-2 bg-orange hover:bg-orange-hover text-white text-xs font-bold px-4 py-2.5 rounded-lg transition-colors flex-shrink-0">
                            <Play size={14} /> Start Playbook
                        </button>
                    </div>
                </div>

                <div className="space-y-2">
                    {steps.map((s) => (
                        <div key={s.order} className="bg-card border border-border rounded-xl p-4 flex gap-3">
                            <span className="w-6 h-6 rounded-full bg-card-muted text-foreground text-[11px] font-black flex items-center justify-center flex-shrink-0">{s.order}</span>
                            <div className="min-w-0 flex-1">
                                <div className="flex items-center gap-2 flex-wrap mb-1">
                                    <span className="text-sm font-bold text-foreground">{s.title}</span>
                                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full ${PHASE_COLOR[s.phase] ?? 'bg-card-muted text-foreground-muted'}`}>{s.phase}</span>
                                    {s.est_mins > 0 && <span className="text-[10px] text-foreground-muted ml-auto flex items-center gap-1"><Clock size={10} /> ~{s.est_mins}m</span>}
                                </div>
                                <p className="text-xs text-foreground-muted">{s.description}</p>
                            </div>
                        </div>
                    ))}
                    {steps.length === 0 && (
                        <div className="bg-card border border-dashed border-grey-300 rounded-xl p-6 text-center text-xs text-foreground-muted">
                            No steps have been added to this playbook yet — add them in Security Ops Management → Playbooks.
                        </div>
                    )}
                </div>

                {startModal && (
                    <StartModal playbook={startModal} form={form} setForm={setForm} onClose={() => setStartModal(null)} />
                )}
            </div>
        );
    }

    return (
        <div className="space-y-4">
            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div>
                    <h1 className="text-lg font-black text-foreground">Response Playbooks</h1>
                    <p className="text-xs text-foreground-muted">SecOps &amp; Response · Pre-built incident response procedures per attack type.</p>
                </div>
                <a href="/admin/secops/management" className="flex items-center gap-2 bg-orange hover:bg-orange-hover text-white text-xs font-bold px-4 py-2.5 rounded-lg transition-colors flex-shrink-0">
                    <Plus size={14} /> Create Playbook
                </a>
            </div>

            <div className="bg-blue/5 border border-blue/20 rounded-xl p-4 text-xs text-foreground-muted leading-relaxed">
                A playbook is a structured, step-by-step response procedure for a specific type of security incident.
                When an incident occurs, the analyst attaches the relevant playbook to ensure no critical response step
                is missed under pressure. Playbooks are managed in Security Ops Management.
            </div>

            {loading ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {[0, 1, 2, 3].map((i) => <div key={i} className="h-44 bg-card-muted rounded-xl animate-pulse" />)}
                </div>
            ) : loadError ? (
                <div className="flex items-center gap-2 text-xs text-red bg-red/10 border border-red/30 rounded-lg px-3 py-2">
                    <AlertTriangle size={14} /> {loadError}
                </div>
            ) : playbooks.length === 0 ? (
                <div className="bg-card border border-dashed border-grey-300 rounded-xl p-8 text-center">
                    <p className="text-sm font-bold text-foreground mb-1">No playbooks yet</p>
                    <p className="text-xs text-foreground-muted">Create one in Security Ops Management → Playbooks and it will appear here.</p>
                </div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {playbooks.map((pb) => {
                        const stepCount = (pb.steps ?? []).length;
                        return (
                            <div key={pb.id} className="bg-card border border-border rounded-xl p-4">
                                <div className="flex items-start justify-between gap-2 mb-2">
                                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase ${severityClass(pb.severity)}`}>{pb.severity}</span>
                                    <span className="text-[10px] text-foreground-muted flex-shrink-0">{stepCount} step{stepCount === 1 ? '' : 's'}</span>
                                </div>
                                <p className="text-sm font-bold text-foreground mb-1">{pb.icon ? `${pb.icon} ` : ''}{pb.name}</p>
                                <p className="text-xs text-foreground-muted mb-3">{pb.description}</p>
                                {pb.estimated_time && (
                                    <div className="flex items-center text-[10px] text-foreground-muted mb-3">
                                        <span className="flex items-center gap-1"><Clock size={11} /> {pb.estimated_time}</span>
                                    </div>
                                )}
                                <div className="flex gap-2">
                                    <button onClick={() => setSelected(pb)} className="flex-1 text-[10px] font-bold px-3 py-1.5 bg-blue hover:opacity-90 text-white rounded-lg transition-colors">View Playbook</button>
                                    <button onClick={() => setStartModal(pb)} className="flex items-center gap-1 text-[10px] font-bold px-3 py-1.5 border border-orange text-orange rounded-lg hover:bg-orange/5 transition-colors"><Play size={10} /> Start</button>
                                </div>
                            </div>
                        );
                    })}
                </div>
            )}

            {startModal && (
                <StartModal playbook={startModal} form={form} setForm={setForm} onClose={() => setStartModal(null)} />
            )}
        </div>
    );
}

function StartModal({ playbook, form, setForm, onClose }: {
    playbook: Playbook;
    form: { title: string; host: string; severity: string };
    setForm: (fn: (f: { title: string; host: string; severity: string }) => { title: string; host: string; severity: string }) => void;
    onClose: () => void;
}) {
    const [status, setStatus] = useState<'idle' | 'creating' | 'created' | 'failed'>('idle');
    const [createdId, setCreatedId] = useState<string | null>(null);
    const [errorMsg, setErrorMsg] = useState<string | null>(null);
    // Placeholder text only (never submitted as-is) — a fixed suffix avoids calling
    // new Date() during render, which react-hooks/purity disallows.
    const title = form.title || `${playbook.name} — today`;

    const createIncident = async () => {
        setStatus('creating');
        setErrorMsg(null);
        try {
            const res = await apiFetch(apiUrl('/api/incidents'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    title: form.title || title,
                    description: `Incident response initiated using the ${playbook.name} playbook.`,
                    severity: form.severity || playbook.severity,
                    affected_host: form.host,
                    source: 'playbook',
                    playbook_id: playbook.id,
                    containment: (playbook.steps ?? []).map((step) => ({
                        action: step.title,
                        phase: step.phase,
                        description: step.description,
                        est_mins: step.est_mins,
                        status: 'pending',
                    })),
                }),
            });
            const data = await res.json();
            if (!res.ok || !data?.success) throw new Error(data?.error || `HTTP ${res.status}`);
            setCreatedId(data.incident_number ?? data.id ?? null);
            setStatus('created');
        } catch (err) {
            setErrorMsg(err instanceof Error ? err.message : 'Failed to create incident');
            setStatus('failed');
        }
    };

    return (
        <div className="fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-4" onClick={onClose}>
            <div className="bg-card border border-border rounded-xl p-6 max-w-md w-full" onClick={(e) => e.stopPropagation()}>
                <div className="flex items-center justify-between mb-4">
                    <h3 className="font-heading font-semibold text-sm text-foreground">Create incident from this playbook</h3>
                    <button onClick={onClose} className="text-foreground-muted hover:text-foreground"><X size={16} /></button>
                </div>
                {status === 'created' ? (
                    <div className="text-center py-4">
                        <p className="text-sm text-green font-bold mb-1">Incident {createdId} created</p>
                        <p className="text-xs text-foreground-muted">All {(playbook.steps ?? []).length} steps were added as a containment checklist in Incident Response.</p>
                    </div>
                ) : (
                    <div className="space-y-3">
                        <div>
                            <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Incident Title</label>
                            <input value={form.title} onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))} placeholder={title}
                                className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue text-foreground" />
                        </div>
                        <div>
                            <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Affected Host</label>
                            <input value={form.host} onChange={(e) => setForm((f) => ({ ...f, host: e.target.value }))} placeholder="e.g. ec2-app-server"
                                className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue text-foreground" />
                        </div>
                        <div>
                            <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Severity</label>
                            <select value={form.severity} onChange={(e) => setForm((f) => ({ ...f, severity: e.target.value }))}
                                className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm focus:outline-none text-foreground">
                                {['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
                            </select>
                        </div>
                        {status === 'failed' && errorMsg && (
                            <div className="flex items-center gap-2 text-xs text-red bg-red/10 border border-red/30 rounded-lg px-3 py-2">
                                <AlertTriangle size={14} /> {errorMsg}
                            </div>
                        )}
                        <button onClick={createIncident} disabled={status === 'creating'}
                            className="w-full bg-orange hover:bg-orange-hover text-white text-sm font-bold py-2.5 rounded-lg disabled:opacity-50 transition-colors">
                            {status === 'creating' ? 'Creating…' : 'Create Incident'}
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
}
