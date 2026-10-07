'use client';

import { useEffect, useState } from 'react';
import { Plus, Trash2, ArrowUp, ArrowDown, Save, X, Pencil, ShieldAlert } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { getAdminUser } from '@/lib/admin-auth';

interface PlaybookStep {
    order: number;
    title: string;
    phase: string;
    est_mins: number;
    description: string;
}
interface PlaybookRow {
    id: string;
    name: string;
    icon: string;
    severity: 'critical' | 'high' | 'medium';
    description: string;
    steps: PlaybookStep[];
    estimated_time: string;
}

const SEVERITIES: PlaybookRow['severity'][] = ['critical', 'high', 'medium'];
const SEVERITY_BADGE: Record<PlaybookRow['severity'], string> = {
    critical: 'bg-red/10 text-red border-red/30',
    high: 'bg-amber/10 text-amber border-amber/30',
    medium: 'bg-blue/10 text-blue border-blue/30',
};

function emptyStep(order: number): PlaybookStep {
    return { order, title: '', phase: 'Response', est_mins: 0, description: '' };
}
function emptyPlaybook(): PlaybookRow {
    return { id: '', name: '', icon: '📋', severity: 'high', description: '', estimated_time: '', steps: [emptyStep(1)] };
}

// CISO / SOC manager playbook CRUD — backend enforces super_admin/soc_manager on the mutating
// routes (routes/playbooks.ts) regardless of this check, but hiding the tab's actions from
// anyone else is still worth doing so an analyst doesn't see edit/delete controls that will
// just 403.
export function PlaybookManagement() {
    const role = getAdminUser().role;
    const canEdit = role === 'super_admin' || role === 'soc_manager';

    const [playbooks, setPlaybooks] = useState<PlaybookRow[] | null>(null);
    const [editing, setEditing] = useState<PlaybookRow | null>(null);
    const [isNew, setIsNew] = useState(false);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const load = () => {
        apiFetch(apiUrl('/api/playbooks'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => setPlaybooks(Array.isArray(data?.playbooks) ? data.playbooks : []))
            .catch(() => setPlaybooks([]));
    };

    useEffect(load, []);

    const startCreate = () => { setEditing(emptyPlaybook()); setIsNew(true); setError(null); };
    const startEdit = (pb: PlaybookRow) => { setEditing({ ...pb, steps: pb.steps.map((s) => ({ ...s })) }); setIsNew(false); setError(null); };

    const save = async () => {
        if (!editing || !editing.name.trim()) {
            setError('Name is required.');
            return;
        }
        setSaving(true);
        setError(null);
        try {
            const body = {
                name: editing.name.trim(),
                icon: editing.icon || '📋',
                severity: editing.severity,
                description: editing.description,
                estimated_time: editing.estimated_time,
                steps: editing.steps.map((s, i) => ({ ...s, order: i + 1 })),
            };
            const res = await apiFetch(apiUrl(isNew ? '/api/playbooks' : `/api/playbooks/${editing.id}`), {
                method: isNew ? 'POST' : 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            const data = await res.json();
            if (!res.ok || !data?.success) throw new Error(data?.error || `HTTP ${res.status}`);
            setEditing(null);
            load();
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to save playbook');
        } finally {
            setSaving(false);
        }
    };

    const remove = async (id: string) => {
        if (!confirm('Delete this playbook? This cannot be undone.')) return;
        await apiFetch(apiUrl(`/api/playbooks/${id}`), { method: 'DELETE' });
        load();
    };

    const updateStep = (index: number, patch: Partial<PlaybookStep>) => {
        setEditing((prev) => prev && { ...prev, steps: prev.steps.map((s, i) => (i === index ? { ...s, ...patch } : s)) });
    };
    const addStep = () => {
        setEditing((prev) => prev && { ...prev, steps: [...prev.steps, emptyStep(prev.steps.length + 1)] });
    };
    const removeStep = (index: number) => {
        setEditing((prev) => prev && { ...prev, steps: prev.steps.filter((_, i) => i !== index) });
    };
    const moveStep = (index: number, dir: -1 | 1) => {
        setEditing((prev) => {
            if (!prev) return prev;
            const target = index + dir;
            if (target < 0 || target >= prev.steps.length) return prev;
            const steps = [...prev.steps];
            [steps[index], steps[target]] = [steps[target], steps[index]];
            return { ...prev, steps };
        });
    };

    if (!canEdit) {
        return (
            <div className="bg-card border border-border rounded-xl p-8 text-center">
                <ShieldAlert size={28} className="text-foreground-muted mx-auto mb-2" />
                <p className="text-sm font-bold text-foreground">Manager access required</p>
                <p className="text-xs text-foreground-muted mt-1">Only super_admin and soc_manager can manage playbooks.</p>
            </div>
        );
    }

    if (editing) {
        return (
            <div className="space-y-4">
                <div className="flex items-center justify-between">
                    <h2 className="text-sm font-black text-foreground">{isNew ? 'New Playbook' : `Edit ${editing.name}`}</h2>
                    <button onClick={() => setEditing(null)} className="text-foreground-muted hover:text-foreground"><X size={18} /></button>
                </div>

                <div className="bg-card border border-border rounded-xl p-5 space-y-4">
                    <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                        <div className="sm:col-span-2">
                            <label className="text-[10px] font-bold text-foreground-muted uppercase tracking-wide">Name</label>
                            <input value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })}
                                className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-purple" />
                        </div>
                        <div>
                            <label className="text-[10px] font-bold text-foreground-muted uppercase tracking-wide">Icon</label>
                            <input value={editing.icon} onChange={(e) => setEditing({ ...editing, icon: e.target.value })} maxLength={4}
                                className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-purple text-center" />
                        </div>
                        <div>
                            <label className="text-[10px] font-bold text-foreground-muted uppercase tracking-wide">Severity</label>
                            <select value={editing.severity} onChange={(e) => setEditing({ ...editing, severity: e.target.value as PlaybookRow['severity'] })}
                                className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none">
                                {SEVERITIES.map((s) => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
                            </select>
                        </div>
                    </div>
                    <div>
                        <label className="text-[10px] font-bold text-foreground-muted uppercase tracking-wide">Description</label>
                        <textarea value={editing.description} onChange={(e) => setEditing({ ...editing, description: e.target.value })} rows={2}
                            className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-purple resize-none" />
                    </div>
                    <div>
                        <label className="text-[10px] font-bold text-foreground-muted uppercase tracking-wide">Estimated Time</label>
                        <input value={editing.estimated_time} onChange={(e) => setEditing({ ...editing, estimated_time: e.target.value })} placeholder="e.g. 1-2 hours"
                            className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-purple" />
                    </div>
                </div>

                <div className="bg-card border border-border rounded-xl p-5">
                    <div className="flex items-center justify-between mb-3">
                        <h3 className="text-xs font-bold text-foreground uppercase tracking-wider">Steps</h3>
                        <button onClick={addStep} className="flex items-center gap-1 text-xs font-bold text-purple hover:underline">
                            <Plus size={13} /> Add Step
                        </button>
                    </div>
                    <div className="space-y-2.5">
                        {editing.steps.map((step, i) => (
                            <div key={i} className="bg-card-muted/40 border border-border rounded-xl p-3 space-y-2">
                                <div className="flex items-center gap-2">
                                    <span className="w-6 h-6 rounded-full bg-card text-foreground text-[11px] font-black flex items-center justify-center shrink-0 border border-border">{i + 1}</span>
                                    <input
                                        value={step.title}
                                        onChange={(e) => updateStep(i, { title: e.target.value })}
                                        placeholder="Step title"
                                        className="flex-1 min-w-0 border border-border bg-card rounded-lg px-2.5 py-1.5 text-xs text-foreground focus:outline-none focus:border-purple"
                                    />
                                    <input
                                        value={step.phase}
                                        onChange={(e) => updateStep(i, { phase: e.target.value })}
                                        placeholder="Phase"
                                        className="w-28 border border-border bg-card rounded-lg px-2.5 py-1.5 text-xs text-foreground focus:outline-none focus:border-purple"
                                    />
                                    <input
                                        type="number"
                                        value={step.est_mins}
                                        onChange={(e) => updateStep(i, { est_mins: Number(e.target.value) || 0 })}
                                        placeholder="Mins"
                                        className="w-16 border border-border bg-card rounded-lg px-2.5 py-1.5 text-xs text-foreground focus:outline-none focus:border-purple"
                                    />
                                    <div className="flex items-center gap-0.5 shrink-0">
                                        <button onClick={() => moveStep(i, -1)} disabled={i === 0} className="text-foreground-muted hover:text-foreground disabled:opacity-30 p-1"><ArrowUp size={13} /></button>
                                        <button onClick={() => moveStep(i, 1)} disabled={i === editing.steps.length - 1} className="text-foreground-muted hover:text-foreground disabled:opacity-30 p-1"><ArrowDown size={13} /></button>
                                        <button onClick={() => removeStep(i)} className="text-red-500 hover:text-red-600 p-1"><Trash2 size={13} /></button>
                                    </div>
                                </div>
                                <textarea
                                    value={step.description}
                                    onChange={(e) => updateStep(i, { description: e.target.value })}
                                    placeholder="Step description"
                                    rows={2}
                                    className="w-full border border-border bg-card rounded-lg px-2.5 py-1.5 text-xs text-foreground focus:outline-none focus:border-purple resize-none"
                                />
                            </div>
                        ))}
                        {editing.steps.length === 0 && (
                            <p className="text-xs text-foreground-muted text-center py-4">No steps yet — add one above.</p>
                        )}
                    </div>
                </div>

                {error && <div className="text-xs text-red-500 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">{error}</div>}

                <div className="flex items-center gap-2">
                    <button onClick={save} disabled={saving} className="flex items-center gap-1.5 bg-orange hover:bg-orange-hover text-white text-xs font-bold px-4 py-2.5 rounded-lg disabled:opacity-50 transition-colors">
                        <Save size={14} /> {saving ? 'Saving…' : 'Save Playbook'}
                    </button>
                    <button onClick={() => setEditing(null)} className="text-xs font-bold text-foreground-muted px-4 py-2.5">Cancel</button>
                </div>
            </div>
        );
    }

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-sm font-black text-foreground">Playbook Management</h2>
                    <p className="text-xs text-foreground-muted">Create, edit, and delete the response playbooks analysts can attach to cases.</p>
                </div>
                <button onClick={startCreate} className="flex items-center gap-1.5 bg-orange hover:bg-orange-hover text-white text-xs font-bold px-4 py-2.5 rounded-lg transition-colors">
                    <Plus size={14} /> New Playbook
                </button>
            </div>

            {playbooks === null ? (
                <div className="space-y-2">
                    {Array.from({ length: 3 }).map((_, i) => <div key={i} className="h-16 bg-card-muted rounded-xl animate-pulse" />)}
                </div>
            ) : playbooks.length === 0 ? (
                <div className="bg-card border border-border rounded-xl p-8 text-center text-xs text-foreground-muted">No playbooks yet.</div>
            ) : (
                <div className="space-y-2">
                    {playbooks.map((pb) => (
                        <div key={pb.id} className="bg-card border border-border rounded-xl p-4 flex items-center justify-between gap-3">
                            <div className="min-w-0 flex items-center gap-3">
                                <span className="text-xl shrink-0">{pb.icon}</span>
                                <div className="min-w-0">
                                    <div className="flex items-center gap-2">
                                        <p className="text-sm font-bold text-foreground truncate">{pb.name}</p>
                                        <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full border uppercase shrink-0 ${SEVERITY_BADGE[pb.severity]}`}>{pb.severity}</span>
                                    </div>
                                    <p className="text-[11px] text-foreground-muted truncate">{pb.description || 'No description'} · {pb.steps.length} steps</p>
                                </div>
                            </div>
                            <div className="flex items-center gap-1.5 shrink-0">
                                <button onClick={() => startEdit(pb)} className="flex items-center gap-1 text-xs font-bold text-blue hover:underline px-2 py-1.5"><Pencil size={12} /> Edit</button>
                                <button onClick={() => remove(pb.id)} className="flex items-center gap-1 text-xs font-bold text-red-500 hover:underline px-2 py-1.5"><Trash2 size={12} /> Delete</button>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
