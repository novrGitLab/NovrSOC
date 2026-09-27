'use client';

import { useEffect, useState, useSyncExternalStore } from 'react';
import { CheckCircle2, XCircle, Loader2, MinusCircle, Play, Zap } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Automated steps of a playbook (its step_ids), each with an Execute button that runs the real
// action — the same engine as a case's Execute button, without a case:
//   block_ip       → POST /api/secops/actions/block-ip   (OPNsense alias)
//   isolate_agent  → POST /api/secops/actions/isolate    (Wazuh active response)
//   notify_email   → POST /api/notifications/send        (SOC mailbox)
//   notify_ciso    → POST /api/notifications/send        (CISO)
// Steps with no backend action show "Not connected". A green check means the remote system
// accepted the action — never a stub. "Create case" is the page's Start Playbook button.
//
// Results live in a module-level store, so they survive navigating away and back within the app
// (not a full reload).

type ExecState = 'idle' | 'executing' | 'success' | 'failed' | 'skipped';
interface ExecResult { state: ExecState; message?: string; at?: string }

const results = new Map<string, ExecResult>();
const listeners = new Set<() => void>();
let version = 0;
const store = {
    subscribe(fn: () => void) { listeners.add(fn); return () => { listeners.delete(fn); }; },
    getSnapshot: () => version,
    getServerSnapshot: () => 0,
    set(key: string, r: ExecResult) { results.set(key, r); version++; listeners.forEach((l) => l()); },
};

interface StepInfo { step_id: string; name: string; description: string | null }
interface AgentOption { id: string; name: string; status: string }

const RUNNABLE = new Set(['block_ip', 'isolate_agent', 'notify_email', 'notify_ciso']);
const CASE_ONLY: Record<string, string> = {
    enrich_iocs: 'Runs against a case\'s source IP — start the playbook, then execute it from the case.',
};

const wat = (iso: string) => new Intl.DateTimeFormat('en-GB', { timeZone: 'Africa/Lagos', hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(iso)) + ' WAT';

function StatusIcon({ state }: { state: ExecState }) {
    if (state === 'executing') return <Loader2 size={15} className="text-blue animate-spin" aria-label="Executing" />;
    if (state === 'success') return <CheckCircle2 size={15} className="text-green" aria-label="Succeeded" />;
    if (state === 'failed') return <XCircle size={15} className="text-red" aria-label="Failed" />;
    if (state === 'skipped') return <MinusCircle size={15} className="text-foreground-muted" aria-label="Not connected" />;
    return null;
}

function StepRow({ playbookId, playbookName, stepId, info, agents }: {
    playbookId: string; playbookName: string; stepId: string; info?: StepInfo; agents: AgentOption[] | null;
}) {
    useSyncExternalStore(store.subscribe, store.getSnapshot, store.getServerSnapshot);
    const key = `${playbookId}:${stepId}`;
    const result = results.get(key) ?? { state: 'idle' as ExecState };
    const [ip, setIp] = useState('');
    const [reason, setReason] = useState('');
    const [agentId, setAgentId] = useState('');
    const [message, setMessage] = useState('');
    const runnable = RUNNABLE.has(stepId);

    const execute = async () => {
        let path = '';
        let body: Record<string, unknown> = {};
        if (stepId === 'block_ip') { path = '/api/secops/actions/block-ip'; body = { ip: ip.trim(), reason: reason.trim() }; }
        if (stepId === 'isolate_agent') {
            path = '/api/secops/actions/isolate';
            body = { endpoint_id: agentId, endpoint_name: agents?.find((a) => a.id === agentId)?.name, reason: reason.trim() || undefined };
        }
        if (stepId === 'notify_email' || stepId === 'notify_ciso') {
            path = '/api/notifications/send';
            body = {
                subject: `${playbookName} — playbook action`, message: message.trim(), severity: 'high',
                ...(stepId === 'notify_ciso' ? { recipient: 'ciso' } : {}),
            };
        }
        store.set(key, { state: 'executing' });
        try {
            const res = await apiFetch(apiUrl(path), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
            const data = await res.json().catch(() => ({}));
            const at = new Date().toISOString();
            if (data?.success) store.set(key, { state: 'success', message: data.message, at });
            else if (data?.outcome === 'skipped') store.set(key, { state: 'skipped', message: data.message, at });
            else store.set(key, { state: 'failed', message: data?.message ?? data?.error ?? `HTTP ${res.status}`, at });
        } catch {
            store.set(key, { state: 'failed', message: 'Could not reach the backend', at: new Date().toISOString() });
        }
    };

    const ready =
        stepId === 'block_ip' ? ip.trim() !== '' && reason.trim() !== '' :
        stepId === 'isolate_agent' ? agentId !== '' :
        stepId === 'notify_email' || stepId === 'notify_ciso' ? message.trim() !== '' : false;

    return (
        <div className="border border-border rounded-xl p-3">
            <div className="flex items-start gap-2.5">
                <Zap size={14} className={`mt-0.5 shrink-0 ${runnable ? 'text-purple' : 'text-foreground-muted'}`} />
                <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-bold text-foreground">{info?.name ?? stepId}</span>
                        <span className="text-[10px] font-mono text-foreground-muted">{stepId}</span>
                        <span className="ml-auto flex items-center gap-1.5"><StatusIcon state={result.state} /></span>
                    </div>
                    {info?.description && <p className="text-xs text-foreground-muted mt-0.5">{info.description}</p>}

                    {runnable ? (
                        <div className="mt-2.5 space-y-2">
                            {stepId === 'block_ip' && (
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                    <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="IP address, e.g. 185.220.101.47" aria-label="IP address to block"
                                        className="border border-border bg-card rounded-lg px-2.5 py-1.5 text-xs font-mono focus:outline-none focus:border-purple" />
                                    <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (recorded with the block)" aria-label="Reason"
                                        className="border border-border bg-card rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:border-purple" />
                                </div>
                            )}
                            {stepId === 'isolate_agent' && (
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                    <select value={agentId} onChange={(e) => setAgentId(e.target.value)} aria-label="Endpoint to isolate"
                                        className="border border-border bg-card rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:border-purple">
                                        <option value="">{agents === null ? 'Loading endpoints…' : agents.length === 0 ? 'No endpoints found' : 'Select endpoint…'}</option>
                                        {(agents ?? []).filter((a) => a.id !== '000').map((a) => <option key={a.id} value={a.id}>{a.name} ({a.id}) — {a.status}</option>)}
                                    </select>
                                    <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (optional)" aria-label="Reason"
                                        className="border border-border bg-card rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:border-purple" />
                                </div>
                            )}
                            {(stepId === 'notify_email' || stepId === 'notify_ciso') && (
                                <textarea value={message} onChange={(e) => setMessage(e.target.value)} rows={2}
                                    placeholder={stepId === 'notify_ciso' ? 'Message to the CISO…' : 'Message to the SOC mailbox…'} aria-label="Notification message"
                                    className="w-full border border-border bg-card rounded-lg px-2.5 py-1.5 text-xs resize-none focus:outline-none focus:border-purple" />
                            )}
                            <div className="flex items-center gap-2 flex-wrap">
                                <button onClick={() => void execute()} disabled={!ready || result.state === 'executing'}
                                    className="flex items-center gap-1.5 text-[11px] font-bold text-white rounded-lg px-3 py-1.5 disabled:opacity-40" style={{ backgroundColor: '#6B1FA8' }}>
                                    {result.state === 'executing' ? <Loader2 size={12} className="animate-spin" /> : <Play size={11} />}
                                    {result.state === 'executing' ? 'Executing…' : 'Execute'}
                                </button>
                                {result.state !== 'idle' && result.state !== 'executing' && result.message && (
                                    <span role="status" className={`text-[11px] ${result.state === 'success' ? 'text-green' : result.state === 'failed' ? 'text-red' : 'text-foreground-muted'}`}>
                                        {result.state === 'skipped' ? `Not connected — ${result.message}` : result.message}
                                        {result.at ? ` · ${wat(result.at)}` : ''}
                                    </span>
                                )}
                            </div>
                        </div>
                    ) : (
                        <p className="text-[11px] text-foreground-muted mt-1.5">
                            {CASE_ONLY[stepId] ?? 'Not connected — NovrSOC has no automated action for this step yet; do it manually.'}
                        </p>
                    )}
                </div>
            </div>
        </div>
    );
}

export function PlaybookActions({ playbookId, playbookName, stepIds }: { playbookId: string; playbookName: string; stepIds: string[] }) {
    const [catalog, setCatalog] = useState<Record<string, StepInfo>>({});
    const [agents, setAgents] = useState<AgentOption[] | null>(null);
    const needsAgents = stepIds.includes('isolate_agent');

    useEffect(() => {
        let active = true;
        apiFetch(apiUrl('/api/playbooks/steps'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((d) => { if (active && Array.isArray(d?.steps)) setCatalog(Object.fromEntries((d.steps as StepInfo[]).map((s) => [s.step_id, s]))); })
            .catch(() => {});
        return () => { active = false; };
    }, []);

    useEffect(() => {
        if (!needsAgents) return;
        let active = true;
        apiFetch(apiUrl('/api/wazuh/agents'), { cache: 'no-store' })
            .then((r) => (r.ok ? r.json() : null))
            .then((d) => { if (active) setAgents(Array.isArray(d?.agents) ? d.agents : []); })
            .catch(() => { if (active) setAgents([]); });
        return () => { active = false; };
    }, [needsAgents]);

    if (stepIds.length === 0) return null;

    return (
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <div>
                <h2 className="text-sm font-bold text-foreground">Automated actions</h2>
                <p className="text-[11px] text-foreground-muted">
                    Execute runs the action for real. A green check means the firewall, Wazuh or mail provider accepted it; grey means it isn&apos;t connected yet.
                </p>
            </div>
            {stepIds.map((id) => (
                <StepRow key={id} playbookId={playbookId} playbookName={playbookName} stepId={id} info={catalog[id]} agents={agents} />
            ))}
        </div>
    );
}
