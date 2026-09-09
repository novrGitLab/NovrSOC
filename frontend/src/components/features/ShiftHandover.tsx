'use client';

import { useEffect, useState } from 'react';
import { FileDown, Send, RefreshCw, AlertTriangle, Clock } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { getAdminUser } from '@/lib/admin-auth';
import { exportDataAsPDF } from '@/lib/exportPDF';
import { ASSIGNABLE_ANALYSTS } from '@/lib/mockTeam';

interface Incident {
    id: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    status: 'new' | 'investigating' | 'contained' | 'resolved' | 'escalated';
    assigned_analyst: string;
    updated_at: string;
}

interface HandoverLog {
    id: string;
    shift_start: string;
    shift_end: string;
    analyst_on: string;
    analyst_off: string;
    alerts_received: number;
    alerts_resolved: number;
    alerts_pending: number;
    critical_incidents: string[];
    ongoing_incidents: string[];
    watch_items: string;
    notes: string;
    submitted_at: string;
}

const WATCH_PRIORITIES = ['Low', 'Medium', 'High'] as const;

export function ShiftHandover() {
    const [incidents, setIncidents] = useState<Incident[]>([]);
    const [pastLogs, setPastLogs] = useState<HandoverLog[]>([]);
    // 'supabase' = durable rows from the handover_logs table; 'memory' = the backend's in-process
    // fallback, which is what you get if Supabase is unreachable. Surfaced so an analyst can tell
    // whether the handover they just filed will still be there tomorrow.
    const [logSource, setLogSource] = useState<'supabase' | 'memory' | null>(null);
    const [loading, setLoading] = useState(true);
    const [submitting, setSubmitting] = useState(false);
    const [submitError, setSubmitError] = useState<string | null>(null);
    const [submitted, setSubmitted] = useState(false);

    const admin = getAdminUser();
    const nowLocal = new Date().toISOString().slice(0, 16);

    const [shiftStart, setShiftStart] = useState(nowLocal);
    const [shiftEnd, setShiftEnd] = useState(nowLocal);
    const [analystOn, setAnalystOn] = useState(admin.name);
    const [analystOff, setAnalystOff] = useState('');
    const [watchItems, setWatchItems] = useState('');
    const [watchPriority, setWatchPriority] = useState<typeof WATCH_PRIORITIES[number]>('Medium');
    const [notes, setNotes] = useState('');

    const load = () => {
        setLoading(true);
        Promise.all([
            apiFetch(apiUrl('/api/incidents'), { cache: 'no-store' }).then((r) => r.json()).catch(() => null),
            apiFetch(apiUrl('/api/handover'), { cache: 'no-store' }).then((r) => r.json()).catch(() => null),
        ]).then(([incData, logData]) => {
            setIncidents(Array.isArray(incData?.incidents) ? incData.incidents : []);
            setPastLogs(Array.isArray(logData?.logs) ? logData.logs : []);
            setLogSource(logData?.source === 'supabase' ? 'supabase' : logData ? 'memory' : null);
            setLoading(false);
        });
    };

    useEffect(() => { load(); }, []);

    // Real incident data (from /api/incidents, the same feed Incident Response uses) —
    // "critical incidents handled this shift" and "ongoing incidents" are derived views over
    // it, not a separate fabricated list.
    const criticalIncidents = incidents.filter((i) => i.severity === 'critical');
    const ongoingIncidents = incidents.filter((i) => !['resolved'].includes(i.status));

    const alertsReceived = incidents.length;
    const alertsResolved = incidents.filter((i) => i.status === 'resolved').length;
    const alertsPending = incidents.filter((i) => i.status !== 'resolved').length;

    function buildSections() {
        return [
            {
                heading: 'Shift Summary',
                rows: [
                    { label: 'Shift', value: `${shiftStart.replace('T', ' ')} → ${shiftEnd.replace('T', ' ')}` },
                    { label: 'Analyst Coming On', value: analystOn || '—' },
                    { label: 'Analyst Going Off', value: analystOff || '—' },
                    { label: 'Alerts Received', value: String(alertsReceived) },
                    { label: 'Alerts Resolved', value: String(alertsResolved) },
                    { label: 'Alerts Pending', value: String(alertsPending) },
                ],
            },
            {
                heading: 'Critical Incidents This Shift',
                rows: criticalIncidents.length > 0
                    ? criticalIncidents.map((i) => ({ label: i.id, value: `${i.title} (${i.status})` }))
                    : [{ label: 'None', value: 'No critical incidents this shift' }],
            },
            {
                heading: 'Ongoing Incidents Requiring Follow-Up',
                rows: ongoingIncidents.length > 0
                    ? ongoingIncidents.map((i) => ({ label: i.id, value: `${i.title} — ${i.status}, assigned to ${i.assigned_analyst}` }))
                    : [{ label: 'None', value: 'Nothing carried forward' }],
            },
            {
                heading: 'Watch Items for Next Shift',
                rows: [{ label: `Priority: ${watchPriority}`, value: watchItems || '—' }],
            },
            {
                heading: 'Notes',
                rows: [{ label: 'Free text', value: notes || '—' }],
            },
        ];
    }

    function handleGeneratePDF() {
        exportDataAsPDF('Shift Handover', 'shift-handover', buildSections());
    }

    async function handleSubmit() {
        if (!analystOn || !analystOff) {
            setSubmitError('Both analyst names are required.');
            return;
        }
        setSubmitting(true);
        setSubmitError(null);
        try {
            const res = await apiFetch(apiUrl('/api/handover'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    shift_start: shiftStart,
                    shift_end: shiftEnd,
                    analyst_on: analystOn,
                    analyst_off: analystOff,
                    alerts_received: alertsReceived,
                    alerts_resolved: alertsResolved,
                    alerts_pending: alertsPending,
                    critical_incidents: criticalIncidents.map((i) => `${i.id} — ${i.title}`),
                    ongoing_incidents: ongoingIncidents.map((i) => `${i.id} — ${i.title} (${i.status})`),
                    watch_items: watchItems ? `[${watchPriority}] ${watchItems}` : '',
                    notes,
                }),
            });
            if (!res.ok) {
                const body = await res.json().catch(() => ({}));
                setSubmitError(body?.error ?? 'Failed to submit handover.');
                return;
            }
            setSubmitted(true);
            setNotes('');
            setWatchItems('');
            load();
        } catch {
            setSubmitError('Could not reach the handover service.');
        } finally {
            setSubmitting(false);
        }
    }

    const SEV_STYLE: Record<Incident['severity'], string> = {
        critical: 'bg-red-500/10 text-red-500 border-red-500/30',
        high: 'bg-grey-100 text-amber border-amber/30',
        medium: 'bg-grey-100 text-amber border-amber/30',
        low: 'bg-card-muted text-foreground-muted border-border',
    };

    return (
        <div className="space-y-5">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-lg font-black text-foreground">Shift Handover</h1>
                    <p className="text-xs text-foreground-muted">SecOps &amp; Response · Log outgoing/incoming analyst context between shifts</p>
                </div>
                <button onClick={load} className="flex items-center gap-1.5 text-[11px] font-bold text-foreground-muted hover:text-foreground border border-border rounded-lg px-3 py-1.5">
                    <RefreshCw className="w-3.5 h-3.5" /> Refresh
                </button>
            </div>

            <div className="grid lg:grid-cols-3 gap-4">
                <div className="lg:col-span-2 space-y-4">
                    {/* Shift summary */}
                    <div className="bg-card border border-border rounded-xl p-4 space-y-3">
                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">Shift Summary</p>
                        <div className="grid grid-cols-2 gap-3">
                            <div>
                                <label className="block text-[10px] text-foreground-muted mb-1">Shift Start</label>
                                <input type="datetime-local" value={shiftStart} onChange={(e) => setShiftStart(e.target.value)}
                                    className="w-full border border-border rounded-lg px-2.5 py-1.5 text-xs bg-card focus:outline-none focus:border-purple" />
                            </div>
                            <div>
                                <label className="block text-[10px] text-foreground-muted mb-1">Shift End</label>
                                <input type="datetime-local" value={shiftEnd} onChange={(e) => setShiftEnd(e.target.value)}
                                    className="w-full border border-border rounded-lg px-2.5 py-1.5 text-xs bg-card focus:outline-none focus:border-purple" />
                            </div>
                            <div>
                                <label className="block text-[10px] text-foreground-muted mb-1">Analyst Coming On</label>
                                <input value={analystOn} onChange={(e) => setAnalystOn(e.target.value)}
                                    className="w-full border border-border rounded-lg px-2.5 py-1.5 text-xs bg-card focus:outline-none focus:border-purple" />
                            </div>
                            <div>
                                <label className="block text-[10px] text-foreground-muted mb-1">Analyst Going Off</label>
                                <select value={analystOff} onChange={(e) => setAnalystOff(e.target.value)}
                                    className="w-full border border-border rounded-lg px-2.5 py-1.5 text-xs bg-card focus:outline-none focus:border-purple">
                                    <option value="">Select analyst…</option>
                                    {ASSIGNABLE_ANALYSTS.map((n) => <option key={n} value={n}>{n}</option>)}
                                </select>
                            </div>
                        </div>
                        <div className="grid grid-cols-3 gap-3 pt-2 border-t border-border">
                            <div className="text-center">
                                <p className="text-lg font-black text-foreground">{alertsReceived}</p>
                                <p className="text-[9px] text-foreground-muted uppercase tracking-wider">Received</p>
                            </div>
                            <div className="text-center">
                                <p className="text-lg font-black text-green">{alertsResolved}</p>
                                <p className="text-[9px] text-foreground-muted uppercase tracking-wider">Resolved</p>
                            </div>
                            <div className="text-center">
                                <p className="text-lg font-black text-amber">{alertsPending}</p>
                                <p className="text-[9px] text-foreground-muted uppercase tracking-wider">Pending</p>
                            </div>
                        </div>
                    </div>

                    {/* Critical incidents */}
                    <div className="bg-card border border-border rounded-xl p-4">
                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-3">Critical Incidents This Shift</p>
                        {loading ? (
                            <div className="h-12 bg-card-muted rounded-lg animate-pulse" />
                        ) : criticalIncidents.length === 0 ? (
                            <p className="text-xs text-foreground-muted">No critical incidents this shift.</p>
                        ) : (
                            <div className="space-y-2">
                                {criticalIncidents.map((i) => (
                                    <div key={i.id} className="flex items-center gap-2 text-xs">
                                        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase ${SEV_STYLE[i.severity]}`}>{i.severity}</span>
                                        <span className="font-mono text-foreground-muted">{i.id}</span>
                                        <span className="text-foreground truncate">{i.title}</span>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    {/* Ongoing incidents */}
                    <div className="bg-card border border-border rounded-xl p-4">
                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-3">Ongoing Incidents Requiring Follow-Up</p>
                        {loading ? (
                            <div className="h-12 bg-card-muted rounded-lg animate-pulse" />
                        ) : ongoingIncidents.length === 0 ? (
                            <p className="text-xs text-foreground-muted">Nothing carried forward — all incidents resolved.</p>
                        ) : (
                            <div className="space-y-2">
                                {ongoingIncidents.map((i) => (
                                    <div key={i.id} className="flex items-center justify-between text-xs">
                                        <span className="text-foreground truncate">{i.id} · {i.title}</span>
                                        <span className="text-foreground-muted shrink-0 ml-2">{i.assigned_analyst}</span>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    {/* Watch items + notes */}
                    <div className="bg-card border border-border rounded-xl p-4 space-y-3">
                        <div className="flex items-center justify-between">
                            <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">Watch Items for Next Shift</p>
                            <div className="flex items-center gap-1">
                                {WATCH_PRIORITIES.map((p) => (
                                    <button
                                        key={p}
                                        onClick={() => setWatchPriority(p)}
                                        className={`text-[9px] font-bold px-2 py-0.5 rounded-full uppercase ${
                                            watchPriority === p
                                                ? p === 'High' ? 'bg-red-500 text-white' : p === 'Medium' ? 'bg-amber text-white' : 'bg-blue text-white'
                                                : 'bg-card-muted text-foreground-muted'
                                        }`}
                                    >
                                        {p}
                                    </button>
                                ))}
                            </div>
                        </div>
                        <textarea
                            value={watchItems} onChange={(e) => setWatchItems(e.target.value)} rows={3}
                            placeholder="e.g. Keep an eye on repeated auth failures from 45.155.205.233 — may resume after quiet period."
                            className="w-full border border-border rounded-lg px-3 py-2 text-xs bg-card resize-none focus:outline-none focus:border-purple"
                        />
                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">Notes</p>
                        <textarea
                            value={notes} onChange={(e) => setNotes(e.target.value)} rows={3}
                            placeholder="Anything else the next shift should know…"
                            className="w-full border border-border rounded-lg px-3 py-2 text-xs bg-card resize-none focus:outline-none focus:border-purple"
                        />
                    </div>

                    {submitError && (
                        <div className="flex items-center gap-2 text-xs text-red-500 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">
                            <AlertTriangle className="w-3.5 h-3.5 shrink-0" /> {submitError}
                        </div>
                    )}
                    {submitted && !submitError && (
                        <div className="text-xs text-green bg-green/10 border border-green/30 rounded-lg px-3 py-2">
                            Handover logged.
                        </div>
                    )}

                    <div className="flex items-center gap-2">
                        <button
                            onClick={handleGeneratePDF}
                            className="flex items-center gap-1.5 text-[11px] font-bold text-foreground border border-border rounded-lg px-3 py-1.5"
                        >
                            <FileDown className="w-3.5 h-3.5" /> Generate Handover PDF
                        </button>
                        <button
                            disabled={submitting}
                            onClick={handleSubmit}
                            className="flex items-center gap-1.5 text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5 disabled:opacity-50"
                        >
                            <Send className="w-3.5 h-3.5" /> {submitting ? 'Submitting…' : 'Submit Handover'}
                        </button>
                    </div>
                </div>

                {/* Past handovers */}
                <div className="bg-card border border-border rounded-xl p-4 h-fit">
                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-3">Recent Handovers</p>
                    {pastLogs.length === 0 ? (
                        <p className="text-xs text-foreground-muted">No handovers logged yet.</p>
                    ) : (
                        <div className="space-y-3">
                            {pastLogs.slice(0, 8).map((log) => (
                                <div key={log.id} className="border-b border-border last:border-0 pb-3 last:pb-0">
                                    <div className="flex items-center gap-1.5 text-[10px] text-foreground-muted">
                                        <Clock className="w-3 h-3" /> {new Date(log.submitted_at).toLocaleString()}
                                    </div>
                                    <p className="text-xs text-foreground mt-1">{log.analyst_on} took over from {log.analyst_off}</p>
                                    <p className="text-[10px] text-foreground-muted">
                                        {log.alerts_pending} pending · {log.ongoing_incidents.length} ongoing incident{log.ongoing_incidents.length === 1 ? '' : 's'}
                                    </p>
                                </div>
                            ))}
                        </div>
                    )}
                    <p className="text-[9px] text-foreground-muted mt-3 pt-3 border-t border-border">
                        {logSource === 'memory'
                            ? 'Database unreachable — handovers are being held in the backend’s in-memory store and won’t survive a restart.'
                            : 'Saved to the handover_logs table — entries persist across backend restarts and redeploys.'}
                    </p>
                </div>
            </div>
        </div>
    );
}
