'use client';

// Response approvals (phase P3) — consequential actions (block an IP, isolate a host) wait here
// until a SOC manager approves them. Reads /api/response-approvals; the backend enforces who may
// approve (response:approve), forbids approving your own request, and runs the action only on
// approval. The result shown is what the firewall / Wazuh actually returned.

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { CheckCircle2, XCircle, RefreshCw, ShieldCheck } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { getAdminUser } from '@/lib/admin-auth';
import { loadJson } from '@/lib/alerts';

interface Approval {
    id: string; action: 'block_ip' | 'isolate_agent'; target: string; target_label: string | null; reason: string;
    case_id: string | null; threat_id: string | null; source: string; status: string;
    requested_by: string; requested_at: string; decided_by: string | null; decided_at: string | null;
    decision_note: string | null; result: string | null;
}

const fmt = (iso: string | null) => (iso ? new Intl.DateTimeFormat('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }).format(new Date(iso)) + ' WAT' : '—');
const what = (a: Approval) => (a.action === 'block_ip' ? `Block IP ${a.target}` : `Isolate host ${a.target_label ? `${a.target_label} (agent ${a.target})` : `agent ${a.target}`}`);
const STATUS_STYLE: Record<string, string> = {
    pending: 'bg-amber/10 text-amber', executed: 'bg-green/10 text-green', failed: 'bg-red/10 text-red',
    skipped: 'bg-card-muted text-foreground-muted', rejected: 'bg-card-muted text-foreground-muted', cancelled: 'bg-card-muted text-foreground-muted', approved: 'bg-blue/10 text-blue',
};

export function ResponseApprovals() {
    const me = getAdminUser();
    const canApprove = me.role === 'super_admin' || me.role === 'soc_manager';
    const [tab, setTab] = useState<'pending' | 'all'>('pending');
    const [items, setItems] = useState<Approval[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [msg, setMsg] = useState<string | null>(null);
    const [busy, setBusy] = useState<string | null>(null);
    const [reloadKey, setReloadKey] = useState(0);
    const reload = useCallback(() => setReloadKey((k) => k + 1), []);

    useEffect(() => {
        let active = true;
        void loadJson<{ approvals: Approval[] }>(`/api/response-approvals${tab === 'pending' ? '?status=pending' : ''}`).then((r) => {
            if (!active) return;
            setItems(r.ok ? r.data.approvals : null);
            setError(r.ok ? null : r.notConnected ? 'Not connected — approvals are unavailable.' : r.error);
        });
        return () => { active = false; };
    }, [tab, reloadKey]);

    async function decide(a: Approval, kind: 'approve' | 'reject' | 'cancel') {
        if (kind === 'approve' && !window.confirm(`${what(a)}?\n\nReason: ${a.reason}\n\nThis runs the action now.`)) return;
        const note = kind === 'reject' ? window.prompt('Reason for rejecting (optional)') : null;
        setBusy(a.id);
        setMsg(null);
        try {
            const r = await apiFetch(apiUrl(`/api/response-approvals/${a.id}/${kind}`), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(note ? { note } : {}) });
            const d = await r.json().catch(() => null);
            if (!r.ok) setMsg(d?.error ?? `HTTP ${r.status}`);
            else if (kind === 'approve') setMsg(`${what(a)}: ${d?.approval?.result ?? d?.approval?.status}`);
            reload();
        } catch {
            setMsg('Could not reach the backend');
        } finally {
            setBusy(null);
        }
    }

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
                <div>
                    <h1 className="text-lg font-black text-foreground flex items-center gap-2"><ShieldCheck className="w-5 h-5" /> Response Approvals</h1>
                    <p className="text-xs text-foreground-muted">Blocking an IP or isolating a host runs only after a SOC manager approves it. Nobody approves their own request.</p>
                </div>
                <div className="flex gap-2">
                    {(['pending', 'all'] as const).map((t) => (
                        <button key={t} onClick={() => setTab(t)} className={`text-[11px] font-bold rounded-lg px-3 py-1.5 border ${tab === t ? 'bg-purple text-white border-purple' : 'border-border text-foreground'}`}>{t === 'pending' ? 'Waiting' : 'History'}</button>
                    ))}
                    <button onClick={reload} className="flex items-center gap-1.5 text-[11px] font-bold text-foreground-muted border border-border rounded-lg px-3 py-1.5"><RefreshCw className="w-3.5 h-3.5" /> Refresh</button>
                </div>
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {msg && <p role="status" className="text-xs text-foreground font-semibold">{msg}</p>}
            {items === null && !error && <div className="h-20 bg-card-muted rounded-xl animate-pulse" />}
            {items && items.length === 0 && <p className="text-sm text-foreground-muted text-center py-10 bg-card border border-border rounded-xl">{tab === 'pending' ? 'No data — nothing is waiting for approval.' : 'No data — no response action has been requested yet.'}</p>}
            {items && items.length > 0 && (
                <div className="bg-card border border-border rounded-xl divide-y divide-border">
                    {items.map((a) => {
                        const mine = a.requested_by.toLowerCase() === (me.email ?? '').toLowerCase();
                        return (
                            <div key={a.id} className="p-4 space-y-1.5">
                                <div className="flex items-center justify-between gap-3 flex-wrap">
                                    <p className="text-sm font-bold text-foreground">{what(a)}</p>
                                    <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${STATUS_STYLE[a.status] ?? ''}`}>{a.status}</span>
                                </div>
                                <p className="text-xs text-foreground">{a.reason}</p>
                                <p className="text-[11px] text-foreground-muted">
                                    Requested by {a.requested_by} · {fmt(a.requested_at)} · from {a.source}
                                    {a.case_id && <> · <Link className="underline" href={`/admin/secops/cases?case=${a.case_id}`}>open case</Link></>}
                                </p>
                                {a.decided_by && <p className="text-[11px] text-foreground-muted">{a.status === 'cancelled' ? 'Cancelled' : 'Decided'} by {a.decided_by} · {fmt(a.decided_at)}{a.decision_note ? ` — ${a.decision_note}` : ''}</p>}
                                {a.result && <p className="text-[11px] font-mono text-foreground">{a.result}</p>}
                                {a.status === 'pending' && (
                                    <div className="flex gap-2 pt-1">
                                        {canApprove && !mine && (
                                            <>
                                                <button disabled={busy === a.id} onClick={() => void decide(a, 'approve')} className="flex items-center gap-1 text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5 disabled:opacity-50"><CheckCircle2 className="w-3.5 h-3.5" /> Approve and run</button>
                                                <button disabled={busy === a.id} onClick={() => void decide(a, 'reject')} className="flex items-center gap-1 text-[11px] font-bold text-red border border-border rounded-lg px-3 py-1.5 disabled:opacity-50"><XCircle className="w-3.5 h-3.5" /> Reject</button>
                                            </>
                                        )}
                                        {(mine || canApprove) && <button disabled={busy === a.id} onClick={() => void decide(a, 'cancel')} className="text-[11px] font-bold text-foreground-muted border border-border rounded-lg px-3 py-1.5 disabled:opacity-50">Cancel request</button>}
                                        {mine && canApprove && <span className="text-[10px] text-foreground-muted self-center">Another manager must approve your own request.</span>}
                                    </div>
                                )}
                            </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
}
