'use client';

// Release 3.1 — every organisation's onboarding record: in-progress drafts to resume, and
// active ones available to review/update. GET /api/admin/onboarding (org_onboarding), joined
// client-side with GET /api/organisations for names and ids (the UUID the wizard's routes use).

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Plus, ClipboardList, ArrowRight } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

interface OnboardingRecord { org_id: string; status: 'draft' | 'active'; current_step: number; completed_steps: number[]; updated_at: string; activated_at: string | null }
interface Org { id: string; slug: string; name: string }

export function OnboardingList() {
    const [records, setRecords] = useState<OnboardingRecord[] | null>(null);
    const [orgs, setOrgs] = useState<Org[]>([]);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        void Promise.all([
            apiFetch(apiUrl('/api/admin/onboarding'), { cache: 'no-store' }).then((r) => r.json().then((d) => ({ ok: r.ok, d }))),
            apiFetch(apiUrl('/api/organisations'), { cache: 'no-store' }).then((r) => r.json().then((d) => ({ ok: r.ok, d }))),
        ]).then(([rec, org]) => {
            setRecords(rec.ok ? rec.d.records : []);
            setError(rec.ok ? null : rec.d?.error ?? 'Could not load onboarding records');
            setOrgs(org.ok ? org.d.organisations : []);
        }).catch(() => { setRecords([]); setError('Could not reach the backend'); });
    }, []);

    const orgFor = (slug: string) => orgs.find((o) => o.slug === slug);
    const loading = records === null;
    const drafts = (records ?? []).filter((r) => r.status === 'draft');
    const active = (records ?? []).filter((r) => r.status === 'active');

    return (
        <div className="space-y-5">
            <div className="flex items-start justify-between">
                <div>
                    <h1 className="text-lg font-black text-foreground flex items-center gap-2"><ClipboardList size={18} /> Client Onboarding</h1>
                    <p className="text-xs text-foreground-muted">Resume an in-progress setup, or review a client that is already active.</p>
                </div>
                <Link href="/admin/onboarding/new" className="flex items-center gap-2 bg-orange hover:bg-orange-hover text-white text-xs font-black px-4 py-2.5 rounded-lg transition-colors flex-shrink-0">
                    <Plus size={14} /> Onboard New Client
                </Link>
            </div>

            {error && <p role="alert" className="text-xs text-red-500 bg-red-500/5 border border-red-500/30 rounded-lg px-3 py-2">{error}</p>}

            <section className="space-y-2">
                <h2 className="text-xs font-bold text-foreground-muted uppercase tracking-wider">In progress</h2>
                {loading ? <div className="h-16 bg-card-muted rounded-xl animate-pulse" /> : drafts.length === 0 ? (
                    <p className="text-xs text-foreground-muted py-4 text-center bg-card border border-border rounded-xl">No onboarding in progress.</p>
                ) : (
                    <div className="bg-card border border-border rounded-xl divide-y divide-border">
                        {drafts.map((r) => {
                            const org = orgFor(r.org_id);
                            return (
                                <Link key={r.org_id} href={org ? `/admin/onboarding/${org.id}` : '#'} className="px-4 py-3 flex items-center justify-between gap-3 hover:bg-card-muted transition-colors">
                                    <div><p className="text-sm font-bold text-foreground">{org?.name ?? r.org_id}</p><p className="text-[10px] text-foreground-muted">Step {r.current_step} of 6 · {r.completed_steps.length} completed · updated {new Date(r.updated_at).toLocaleString()}</p></div>
                                    <ArrowRight size={14} className="text-foreground-muted flex-shrink-0" />
                                </Link>
                            );
                        })}
                    </div>
                )}
            </section>

            <section className="space-y-2">
                <h2 className="text-xs font-bold text-foreground-muted uppercase tracking-wider">Active</h2>
                {loading ? <div className="h-16 bg-card-muted rounded-xl animate-pulse" /> : active.length === 0 ? (
                    <p className="text-xs text-foreground-muted py-4 text-center bg-card border border-border rounded-xl">No organisation has completed activation yet.</p>
                ) : (
                    <div className="bg-card border border-border rounded-xl divide-y divide-border">
                        {active.map((r) => {
                            const org = orgFor(r.org_id);
                            return (
                                <Link key={r.org_id} href={org ? `/admin/onboarding/${org.id}` : '#'} className="px-4 py-3 flex items-center justify-between gap-3 hover:bg-card-muted transition-colors">
                                    <div><p className="text-sm font-bold text-foreground">{org?.name ?? r.org_id}</p><p className="text-[10px] text-foreground-muted">Activated {r.activated_at ? new Date(r.activated_at).toLocaleString() : '—'}</p></div>
                                    <span className="text-[10px] font-bold text-purple">Review →</span>
                                </Link>
                            );
                        })}
                    </div>
                )}
            </section>
        </div>
    );
}
