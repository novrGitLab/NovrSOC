'use client';

// Organisation Access (phase P21): which analyst accounts may act on which client
// organisations, via X-Org-Id (lib/resolveOrg.ts). super_admin and soc_manager already see every
// organisation; this assigns the narrower, audited access an analyst needs for a specific one.
// Real data only — GET/POST/DELETE /api/admin/org-assignments.

import { useCallback, useEffect, useState } from 'react';
import { Building2, Trash2 } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

interface Assignment { id: string; user_id: string; user_email: string; org_slug: string; assigned_by: string; assigned_at: string; note: string | null }
interface Analyst { id: string; email: string; name: string | null; status: string; home_org: string | null }
interface Org { id: string; slug: string; name: string }

export function OrgAccess() {
    const [assignments, setAssignments] = useState<Assignment[] | null>(null);
    const [analysts, setAnalysts] = useState<Analyst[] | null>(null);
    const [orgs, setOrgs] = useState<Org[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [userId, setUserId] = useState('');
    const [orgSlug, setOrgSlug] = useState('');
    const [note, setNote] = useState('');
    const [saving, setSaving] = useState(false);
    const [formError, setFormError] = useState<string | null>(null);

    const load = useCallback(() => {
        apiFetch(apiUrl('/api/admin/org-assignments'), { cache: 'no-store' })
            .then(async (r) => { const d = await r.json().catch(() => null); if (!r.ok) throw new Error(d?.error ?? `HTTP ${r.status}`); setAssignments(d.assignments); setError(null); })
            .catch((e: unknown) => { setAssignments([]); setError(e instanceof Error ? e.message : 'Could not reach the backend'); });
    }, []);

    useEffect(() => {
        load();
        apiFetch(apiUrl('/api/admin/org-assignments/analysts'), { cache: 'no-store' }).then((r) => r.json()).then((d) => setAnalysts(d?.analysts ?? [])).catch(() => setAnalysts([]));
        apiFetch(apiUrl('/api/organisations'), { cache: 'no-store' }).then((r) => r.json()).then((d) => setOrgs(d?.organisations ?? [])).catch(() => setOrgs([]));
    }, [load]);

    const assign = async () => {
        if (!userId || !orgSlug) return;
        setSaving(true);
        setFormError(null);
        try {
            const r = await apiFetch(apiUrl('/api/admin/org-assignments'), {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId, org_slug: orgSlug, note: note.trim() || undefined }),
            });
            const d = await r.json().catch(() => null);
            if (!r.ok) { setFormError(d?.error ?? `HTTP ${r.status}`); return; }
            setUserId(''); setOrgSlug(''); setNote('');
            load();
        } catch {
            setFormError('Could not reach the backend');
        } finally {
            setSaving(false);
        }
    };

    const remove = async (id: string) => {
        if (!window.confirm('Remove this assignment? The analyst will no longer be able to act on that organisation.')) return;
        const r = await apiFetch(apiUrl(`/api/admin/org-assignments/${id}`), { method: 'DELETE' });
        if (r.ok) load();
    };

    const analystLabel = (a: Analyst) => `${a.name || a.email} (${a.email})`;
    const orgLabel = (o: Org) => o.name || o.slug;

    return (
        <div className="space-y-5">
            <div>
                <h1 className="text-lg font-black text-foreground flex items-center gap-2"><Building2 size={18} /> Organisation Access</h1>
                <p className="text-xs text-foreground-muted">Which analyst accounts may act on which client organisations. super_admin and soc_manager already see every organisation and are not listed here.</p>
            </div>

            <div className="bg-card border border-border rounded-xl p-4 space-y-3">
                <h2 className="text-sm font-bold text-foreground">Assign an analyst</h2>
                <div className="flex flex-wrap items-end gap-2">
                    <div className="flex-1 min-w-[220px]">
                        <label htmlFor="assign-analyst" className="block text-[10px] font-semibold text-foreground-muted uppercase tracking-wider mb-1">Analyst</label>
                        <select id="assign-analyst" value={userId} onChange={(e) => setUserId(e.target.value)} className="w-full border border-border bg-card-muted rounded-lg px-3 py-2 text-sm text-foreground">
                            <option value="">Select an analyst…</option>
                            {(analysts ?? []).map((a) => <option key={a.id} value={a.id}>{analystLabel(a)}</option>)}
                        </select>
                    </div>
                    <div className="flex-1 min-w-[220px]">
                        <label htmlFor="assign-org" className="block text-[10px] font-semibold text-foreground-muted uppercase tracking-wider mb-1">Organisation</label>
                        <select id="assign-org" value={orgSlug} onChange={(e) => setOrgSlug(e.target.value)} className="w-full border border-border bg-card-muted rounded-lg px-3 py-2 text-sm text-foreground">
                            <option value="">Select an organisation…</option>
                            {(orgs ?? []).map((o) => <option key={o.id} value={o.slug}>{orgLabel(o)}</option>)}
                        </select>
                    </div>
                    <div className="flex-1 min-w-[180px]">
                        <label htmlFor="assign-note" className="block text-[10px] font-semibold text-foreground-muted uppercase tracking-wider mb-1">Note (optional)</label>
                        <input id="assign-note" value={note} onChange={(e) => setNote(e.target.value)} placeholder="e.g. covering for Ada this quarter" className="w-full border border-border bg-card-muted rounded-lg px-3 py-2 text-sm text-foreground" />
                    </div>
                    <button onClick={() => void assign()} disabled={saving || !userId || !orgSlug} className="text-xs font-bold text-white bg-orange hover:bg-orange-hover rounded-lg px-4 py-2 disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap">
                        {saving ? 'Assigning…' : 'Assign'}
                    </button>
                </div>
                {formError && <p role="alert" className="text-xs text-red-500 font-semibold">{formError}</p>}
                {analysts?.length === 0 && <p className="text-[11px] text-foreground-muted">No analyst accounts exist yet — invite one from Team first.</p>}
            </div>

            {error ? (
                <p role="alert" className="text-xs text-red-500 bg-red-500/5 border border-red-500/30 rounded-lg px-3 py-2">{error}</p>
            ) : !assignments ? (
                <div className="h-24 bg-card-muted rounded-xl animate-pulse" />
            ) : assignments.length === 0 ? (
                <p className="text-xs text-foreground-muted py-6 text-center">No analyst is assigned to another organisation yet.</p>
            ) : (
                <div className="bg-card border border-border rounded-xl divide-y divide-border">
                    {assignments.map((a) => (
                        <div key={a.id} className="px-4 py-2.5 flex items-center justify-between gap-3">
                            <div>
                                <p className="text-xs font-bold text-foreground">{a.user_email} <span className="text-foreground-muted font-normal">may act on</span> {a.org_slug}</p>
                                <p className="text-[10px] text-foreground-muted">Assigned by {a.assigned_by} · {new Date(a.assigned_at).toLocaleString()}{a.note ? ` · ${a.note}` : ''}</p>
                            </div>
                            <button onClick={() => void remove(a.id)} className="text-red-500 hover:text-red-600 p-1.5" aria-label={`Remove ${a.user_email}'s access to ${a.org_slug}`}>
                                <Trash2 size={14} />
                            </button>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
