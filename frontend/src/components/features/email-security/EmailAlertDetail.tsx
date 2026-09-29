'use client';

import { useState } from 'react';
import Link from 'next/link';
import { FolderPlus } from 'lucide-react';
import {
    useEmailApi, send, useRole, isAnalyst, PageHeader, Panel, Gate, SevBadge, StatusBadge, Badge, Button, Feedback, KeyValue,
    inputCls, selectCls, wat, label,
} from './shared';
import { EventsTable, type EventRow } from './MessagingSuite';

// One Email Security alert: the correlated evidence from every module that observed it, the
// analyst workflow (status, assignment, notes) and escalation into the SOC case system.

interface Alert {
    id: string; severity: string; source_module: string; modules: string[]; detection_type: string; entity: string; title: string; description: string | null;
    evidence: { at: string; module: string; summary: string; ref?: { kind: string; id: string } }[]; timeline: { at: string; actor: string; action: string; detail?: string }[];
    indicators: { type: string; value: string }[]; occurrences: number; status: string; assigned_to: string | null; case_id: string | null; case_number: string | null;
    first_seen: string; last_seen: string;
}
interface Detail { alert: Alert; events: EventRow[]; soc_alerts: { available: boolean; error?: string; alerts: { id: string; timestamp: string; rule: string; level: number; agent: string | null; match: string }[] } }

const MODULE: Record<string, string> = { dmarc: 'DMARC', phishid: 'Phish ID', messaging: 'Messaging' };
const STATUSES = ['new', 'investigating', 'resolved', 'false_positive', 'suppressed'];
const refHref = (r?: { kind: string; id: string }) => r?.kind === 'email_event' ? `/admin/email/messaging/${r.id}` : r?.kind === 'phishing_domain' ? `/admin/email/phishid/${r.id}` : null;

export function EmailAlertDetail({ id }: { id: string }) {
    const role = useRole();
    const [nonce, setNonce] = useState(0);
    const state = useEmailApi<Detail>(`/alerts/${id}`, nonce);
    const [busy, setBusy] = useState<string | null>(null);
    const [fb, setFb] = useState<{ ok: boolean; text: string } | null>(null);
    const [note, setNote] = useState('');
    const [assignee, setAssignee] = useState<string | null>(null);
    const [caseId, setCaseId] = useState('');
    const a = state.data?.alert;

    async function run(key: string, method: string, path: string, body: unknown, ok: (d: Record<string, unknown>) => string) {
        setBusy(key); setFb(null);
        const r = await send(method, path, body);
        setBusy(null);
        setFb({ ok: r.ok, text: r.ok ? ok(r.data ?? {}) : r.error ?? 'Failed' });
        if (r.ok) setNonce((x) => x + 1);
        return r.ok;
    }

    return (
        <div className="space-y-4">
            <PageHeader back={{ href: '/admin/email', label: 'Email Security' }} title={a?.title ?? 'Alert'}
                subtitle={a && <>{label(a.detection_type)} · first seen {wat(a.first_seen)} · last seen {wat(a.last_seen)} · {a.occurrences} observation{a.occurrences === 1 ? '' : 's'}</>} />
            <Feedback result={fb} />
            <Gate state={state} rows={6}>
                {a && state.data && (
                    <>
                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                            <Panel title="Alert">
                                <KeyValue rows={[
                                    ['Severity', <SevBadge key="s" s={a.severity} />], ['Status', <StatusBadge key="st" s={a.status} />], ['Entity', <span key="e" className="font-mono break-all">{a.entity}</span>],
                                    ['Opened by', MODULE[a.source_module] ?? a.source_module], ['Evidence from', a.modules.map((m) => MODULE[m] ?? m).join(', ')],
                                    ['Assigned to', a.assigned_to ?? 'Unassigned'],
                                    ['Case', a.case_id ? <Link key="c" href={`/admin/secops/cases?id=${a.case_id}`} className="text-purple hover:underline">{a.case_number}</Link> : 'None'],
                                ]} />
                                {a.description && <p className="text-xs text-foreground mt-3">{a.description}</p>}
                            </Panel>
                            <Panel title="Response" className="lg:col-span-2">
                                {!isAnalyst(role) ? <p className="text-xs text-foreground-muted">Analysts and managers can change the status, assign and escalate this alert.</p> : (
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div className="space-y-2">
                                            <label className="block text-[10px] font-bold text-foreground-muted uppercase">Status</label>
                                            <select value={a.status} disabled={busy === 'status'} aria-label="Alert status" className={`${selectCls} w-full`}
                                                onChange={(e) => void run('status', 'PATCH', `/alerts/${id}`, { status: e.target.value }, () => `Status set to ${label(e.target.value)}.`)}>
                                                {STATUSES.map((s) => <option key={s} value={s}>{label(s)}</option>)}
                                            </select>
                                            <label className="block text-[10px] font-bold text-foreground-muted uppercase pt-1">Assign</label>
                                            <div className="flex gap-2">
                                                <input value={assignee ?? a.assigned_to ?? ''} onChange={(e) => setAssignee(e.target.value)} placeholder="Analyst email" aria-label="Assignee" className={`${inputCls} flex-1`} />
                                                <Button busy={busy === 'assign'} onClick={() => void run('assign', 'PATCH', `/alerts/${id}`, { assigned_to: assignee ?? '' }, () => 'Assignment saved.').then((ok) => ok && setAssignee(null))}>Save</Button>
                                            </div>
                                        </div>
                                        <div className="space-y-2">
                                            <label className="block text-[10px] font-bold text-foreground-muted uppercase">SOC case</label>
                                            {a.case_id ? <p className="text-xs">Linked to <Link href={`/admin/secops/cases?id=${a.case_id}`} className="text-purple font-bold hover:underline">{a.case_number}</Link>. New evidence is added to its timeline automatically.</p> : (
                                                <>
                                                    <Button variant="primary" busy={busy === 'case'} onClick={() => void run('case', 'POST', `/alerts/${id}/case`, {}, (d) => `Case ${d.case_number} ${d.created ? 'opened' : 'linked'}.`)}><FolderPlus size={12} /> Open a case</Button>
                                                    <div className="flex gap-2">
                                                        <input value={caseId} onChange={(e) => setCaseId(e.target.value)} placeholder="…or existing case ID" aria-label="Existing case ID" className={`${inputCls} flex-1 font-mono`} />
                                                        <Button busy={busy === 'attach'} disabled={!caseId.trim()} onClick={() => void run('attach', 'POST', `/alerts/${id}/case`, { case_id: caseId.trim() }, (d) => `Linked to ${d.case_number}.`)}>Attach</Button>
                                                    </div>
                                                </>
                                            )}
                                        </div>
                                        <form className="md:col-span-2 flex gap-2" onSubmit={(e) => { e.preventDefault(); void run('note', 'PATCH', `/alerts/${id}`, { note }, () => 'Note added.').then((ok) => ok && setNote('')); }}>
                                            <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add an analyst note" aria-label="Analyst note" className={`${inputCls} flex-1`} required />
                                            <Button type="submit" busy={busy === 'note'}>Add note</Button>
                                        </form>
                                    </div>
                                )}
                            </Panel>
                        </div>

                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                            <Panel title={`Evidence (${a.evidence.length})`}>
                                <ol className="space-y-2">
                                    {[...a.evidence].reverse().map((ev, k) => {
                                        const href = refHref(ev.ref);
                                        return (
                                            <li key={k} className="text-xs flex gap-2">
                                                <span className="shrink-0"><Badge tone="purple">{MODULE[ev.module] ?? ev.module}</Badge></span>
                                                <span className="min-w-0"><span className="text-foreground">{ev.summary}</span> <span className="text-foreground-muted">— {wat(ev.at)}</span>{href && <Link href={href} className="ml-1 text-purple hover:underline">Open</Link>}</span>
                                            </li>
                                        );
                                    })}
                                </ol>
                            </Panel>
                            <Panel title="Indicators & related SOC alerts">
                                <div className="flex flex-wrap gap-1.5">{a.indicators.map((i) => <span key={`${i.type}|${i.value}`} className="text-[10px] font-mono border border-border rounded px-1.5 py-0.5 break-all"><span className="text-foreground-muted">{i.type}:</span> {i.value}</span>)}</div>
                                <div className="mt-3 pt-3 border-t border-border">
                                    <p className="text-[11px] font-bold text-foreground mb-1">Wazuh alerts sharing these indicators (30 days)</p>
                                    {!state.data.soc_alerts.available ? <p className="text-[11px] text-foreground-muted">Not available: {state.data.soc_alerts.error}</p>
                                        : state.data.soc_alerts.alerts.length === 0 ? <p className="text-[11px] text-foreground-muted">None.</p>
                                        : <ul className="text-[11px] space-y-1">{state.data.soc_alerts.alerts.map((s) => <li key={s.id}>{wat(s.timestamp)} · level {s.level} · {s.rule}{s.agent ? ` · ${s.agent}` : ''}</li>)}</ul>}
                                </div>
                            </Panel>
                        </div>

                        {state.data.events.length > 0 && <Panel title={`Related emails (${state.data.events.length})`}><EventsTable events={state.data.events} /></Panel>}

                        <Panel title="Timeline">
                            <ol className="space-y-1.5">
                                {[...a.timeline].reverse().map((t, k) => (
                                    <li key={k} className="text-xs flex gap-3">
                                        <span className="text-foreground-muted whitespace-nowrap w-40 shrink-0">{wat(t.at)}</span>
                                        <span className="min-w-0 break-words"><span className="font-bold text-foreground">{t.action}</span>{t.detail && <span className="text-foreground-muted"> — {t.detail}</span>} <span className="text-foreground-muted">({t.actor})</span></span>
                                    </li>
                                ))}
                            </ol>
                        </Panel>
                    </>
                )}
            </Gate>
        </div>
    );
}
