'use client';

import { useEffect, useMemo, useState } from 'react';
import { Send, X, Mail, AlertTriangle, CheckCircle2, Loader2, Eye, RefreshCw } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Alert Communication — compose an alert email, preview it, send it, and see the log.
//
// Sends are real: POST /api/communications/send goes through the platform email service and the
// log records the true outcome (Sent, or Failed with the provider's error). Recipients are the
// real team (platform_users) and real client contacts (organisations) — nothing here is sample
// data. The log is only as durable as its store: until the alert_communications table exists
// the backend keeps it in memory, and the page says so.

type RecipientType = 'client' | 'analyst' | 'all_analysts' | 'custom';
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

interface Analyst { name: string; email: string; role: string }
interface ClientContact { org: string; name: string | null; email: string; kind: 'contact' | 'ciso' }
interface OpenCase { id: string; case_number: string; title: string; severity: Severity; status: string }
interface LogEntry {
    id: string; recipient_type: RecipientType; recipients: string[]; subject: string; body: string;
    severity: Severity; case_number: string | null; sent_by: string; status: 'sent' | 'failed'; error: string | null; created_at: string;
}

const BRAND = { blue: '#2B3BCC', red: '#CC2B2B', purple: '#6B1FA8', text: '#1C1F2E', muted: '#7A8099', bg: '#F8F9FC' };
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'informational'];
const SEV_COLOUR: Record<Severity, string> = { critical: BRAND.red, high: '#E8730C', medium: '#D4A017', low: BRAND.blue, informational: BRAND.muted };
const RECIPIENT_LABEL: Record<RecipientType, string> = { client: 'Client Contact', analyst: 'Analyst', all_analysts: 'All Analysts', custom: 'Custom' };
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const wat = (iso: string) => new Intl.DateTimeFormat('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(iso)) + ' WAT';
// YYYY-MM-DD of a timestamp in Lagos time, for the date-range filter.
const watDay = (iso: string) => new Intl.DateTimeFormat('en-CA', { timeZone: 'Africa/Lagos', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(iso));

function SeverityBadge({ severity }: { severity: Severity }) {
    return (
        <span className="text-[9px] font-bold px-2 py-0.5 rounded-full uppercase text-white whitespace-nowrap" style={{ backgroundColor: SEV_COLOUR[severity] ?? BRAND.muted }}>
            {severity}
        </span>
    );
}

type SendState = { kind: 'idle' } | { kind: 'sending' } | { kind: 'sent'; to: string[] } | { kind: 'failed'; error: string };

export function AlertCommunication() {
    const [unauthorised, setUnauthorised] = useState(false);
    const [analysts, setAnalysts] = useState<Analyst[] | null>(null);
    const [clients, setClients] = useState<ClientContact[] | null>(null);
    const [cases, setCases] = useState<OpenCase[] | null>(null);
    const [log, setLog] = useState<{ entries: LogEntry[]; source: 'supabase' | 'memory' } | null>(null);
    const [logError, setLogError] = useState<string | null>(null);

    // Compose
    const [recipientType, setRecipientType] = useState<RecipientType>('analyst');
    const [analystEmail, setAnalystEmail] = useState('');
    const [clientEmail, setClientEmail] = useState('');
    const [customEmail, setCustomEmail] = useState('');
    const [caseId, setCaseId] = useState('');
    const [subject, setSubject] = useState('');
    const [subjectTouched, setSubjectTouched] = useState(false);
    const [severity, setSeverity] = useState<Severity>('high');
    const [body, setBody] = useState('');
    const [showBodyPreview, setShowBodyPreview] = useState(false);
    const [formError, setFormError] = useState<string | null>(null);
    const [previewOpen, setPreviewOpen] = useState(false);
    const [sendState, setSendState] = useState<SendState>({ kind: 'idle' });

    // Log filters
    const [sevFilter, setSevFilter] = useState<'all' | Severity>('all');
    const [fromDay, setFromDay] = useState('');
    const [toDay, setToDay] = useState('');

    const loadLog = () =>
        apiFetch(apiUrl('/api/communications'), { cache: 'no-store' })
            .then(async (r) => {
                if (r.status === 401 || r.status === 403) { setUnauthorised(true); return; }
                const d = await r.json().catch(() => null);
                if (!r.ok || !d) { setLogError(d?.error ?? `HTTP ${r.status}`); return; }
                setLogError(null);
                setLog({ entries: Array.isArray(d.entries) ? d.entries : [], source: d.source === 'supabase' ? 'supabase' : 'memory' });
            })
            .catch(() => setLogError('Could not reach the backend'));

    useEffect(() => {
        let active = true;
        void loadLog();
        apiFetch(apiUrl('/api/communications/recipients'), { cache: 'no-store' })
            .then((r) => (r.ok ? r.json() : null))
            .then((d) => { if (!active) return; setAnalysts(Array.isArray(d?.analysts) ? d.analysts : []); setClients(Array.isArray(d?.clients) ? d.clients : []); })
            .catch(() => { if (active) { setAnalysts([]); setClients([]); } });
        apiFetch(apiUrl('/api/cases?exclude_auto_closed=true&limit=100'), { cache: 'no-store' })
            .then((r) => (r.ok ? r.json() : null))
            .then((d) => { if (active) setCases(Array.isArray(d?.cases) ? (d.cases as OpenCase[]).filter((c) => c.status !== 'resolved') : []); })
            .catch(() => { if (active) setCases([]); });
        return () => { active = false; };
    }, []);

    const linkedCase = cases?.find((c) => c.id === caseId) ?? null;

    const selectCase = (id: string) => {
        setCaseId(id);
        const c = cases?.find((x) => x.id === id);
        // Pre-fill from the case until the analyst types their own subject.
        if (c && !subjectTouched) setSubject(`[${c.case_number}] ${c.title}`);
        if (c && SEVERITIES.includes(c.severity)) setSeverity(c.severity);
    };

    const resolvedRecipients: string[] = useMemo(() => {
        if (recipientType === 'all_analysts') return (analysts ?? []).map((a) => a.email);
        if (recipientType === 'analyst') return analystEmail ? [analystEmail] : [];
        if (recipientType === 'client') return clientEmail ? [clientEmail] : [];
        return EMAIL_RE.test(customEmail.trim()) ? [customEmail.trim()] : [];
    }, [recipientType, analysts, analystEmail, clientEmail, customEmail]);

    const openPreview = () => {
        if (resolvedRecipients.length === 0) { setFormError(recipientType === 'custom' ? 'Enter a valid email address.' : 'Choose a recipient.'); return; }
        if (!subject.trim() || !body.trim()) { setFormError('Subject and body are required.'); return; }
        setFormError(null);
        setSendState({ kind: 'idle' });
        setPreviewOpen(true);
    };

    const confirmSend = async () => {
        setSendState({ kind: 'sending' });
        try {
            const res = await apiFetch(apiUrl('/api/communications/send'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    recipient_type: recipientType, analyst_email: analystEmail, client_email: clientEmail, custom_email: customEmail.trim(),
                    subject: subject.trim(), body: body.trim(), severity, case_id: caseId || undefined,
                }),
            });
            const d = await res.json().catch(() => ({}));
            if (d?.success) {
                setSendState({ kind: 'sent', to: d.entry?.recipients ?? resolvedRecipients });
                setBody('');
            } else {
                setSendState({ kind: 'failed', error: d?.error ?? `HTTP ${res.status}` });
            }
            void loadLog();
        } catch {
            setSendState({ kind: 'failed', error: 'Could not reach the backend' });
        }
    };

    const filteredLog = useMemo(() => (log?.entries ?? []).filter((e) => {
        if (sevFilter !== 'all' && e.severity !== sevFilter) return false;
        const day = watDay(e.created_at);
        if (fromDay && day < fromDay) return false;
        if (toDay && day > toDay) return false;
        return true;
    }), [log, sevFilter, fromDay, toDay]);

    if (unauthorised) {
        return (
            <div className="bg-card border border-dashed border-border rounded-xl p-12 text-center max-w-2xl mx-auto">
                <Mail size={30} className="text-foreground-muted mx-auto mb-3" />
                <h1 className="font-bold text-sm text-foreground mb-1">Alert Communication is available to NovrSOC analysts</h1>
                <p className="text-xs text-foreground-muted">Your SOC team contacts you directly when an alert needs your attention.</p>
            </div>
        );
    }

    const input = 'w-full border border-border bg-card rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-purple';
    const label = 'block text-[10px] font-bold uppercase tracking-wider mb-1.5 text-foreground-muted';

    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground">Alert Communication</h1>
                <p className="text-xs text-foreground-muted">Compose, preview and send alert emails to your team or client contacts. Every send is logged with its real outcome.</p>
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-5 gap-4">
                {/* ── Compose ───────────────────────────────────────────────────── */}
                <div className="xl:col-span-2 bg-card border border-border rounded-xl p-5 space-y-4 h-fit">
                    <h2 className="text-sm font-bold text-foreground">Compose Alert Communication</h2>

                    <div>
                        <span className={label}>Recipient</span>
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-1 bg-card-muted rounded-lg p-1" role="radiogroup" aria-label="Recipient type">
                            {(Object.keys(RECIPIENT_LABEL) as RecipientType[]).map((t) => (
                                <button key={t} role="radio" aria-checked={recipientType === t} onClick={() => { setRecipientType(t); setFormError(null); }}
                                    className={`text-[11px] font-bold px-2 py-1.5 rounded-md transition-colors ${recipientType === t ? 'text-white shadow-xs' : 'text-foreground-muted hover:text-foreground'}`}
                                    style={recipientType === t ? { backgroundColor: BRAND.purple } : undefined}>
                                    {RECIPIENT_LABEL[t]}
                                </button>
                            ))}
                        </div>
                        <div className="mt-2">
                            {recipientType === 'analyst' && (
                                <select value={analystEmail} onChange={(e) => setAnalystEmail(e.target.value)} className={input} aria-label="Analyst">
                                    <option value="">{analysts === null ? 'Loading team…' : analysts.length === 0 ? 'No analysts on file' : 'Select analyst…'}</option>
                                    {(analysts ?? []).map((a) => <option key={a.email} value={a.email}>{a.name} — {a.email}</option>)}
                                </select>
                            )}
                            {recipientType === 'all_analysts' && (
                                <p className="text-xs text-foreground-muted bg-card-muted rounded-lg px-3 py-2">
                                    {analysts === null ? 'Loading team…' : analysts.length === 0 ? 'No analysts on file.' : `${analysts.length} recipient${analysts.length === 1 ? '' : 's'}: ${analysts.map((a) => a.email).join(', ')}`}
                                </p>
                            )}
                            {recipientType === 'client' && (clients !== null && clients.length === 0 ? (
                                <p className="text-xs text-foreground-muted bg-card-muted rounded-lg px-3 py-2">
                                    No client contact email on file. Add a contact or CISO email to the organisation in Settings → Organisations.
                                </p>
                            ) : (
                                <select value={clientEmail} onChange={(e) => setClientEmail(e.target.value)} className={input} aria-label="Client contact">
                                    <option value="">{clients === null ? 'Loading contacts…' : 'Select client contact…'}</option>
                                    {(clients ?? []).map((c) => <option key={`${c.org}-${c.email}`} value={c.email}>{c.org} — {c.name ?? c.email} ({c.kind === 'ciso' ? 'CISO' : 'contact'})</option>)}
                                </select>
                            ))}
                            {recipientType === 'custom' && (
                                <input type="email" value={customEmail} onChange={(e) => setCustomEmail(e.target.value)} placeholder="name@company.com" className={input} aria-label="Recipient email" />
                            )}
                        </div>
                    </div>

                    <div>
                        <label htmlFor="ac-case" className={label}>Linked case</label>
                        <select id="ac-case" value={caseId} onChange={(e) => selectCase(e.target.value)} className={input}>
                            <option value="">{cases === null ? 'Loading open cases…' : cases.length === 0 ? 'No open cases' : 'None'}</option>
                            {(cases ?? []).map((c) => <option key={c.id} value={c.id}>{c.case_number} — {c.title.slice(0, 70)}</option>)}
                        </select>
                    </div>

                    <div>
                        <label htmlFor="ac-subject" className={label}>Subject</label>
                        <input id="ac-subject" value={subject} onChange={(e) => { setSubject(e.target.value); setSubjectTouched(true); }}
                            placeholder={linkedCase ? '' : 'e.g. Suspicious login activity on your mail server'} className={input} />
                    </div>

                    <div>
                        <span className={label}>Severity</span>
                        <div className="flex flex-wrap gap-1.5" role="radiogroup" aria-label="Severity">
                            {SEVERITIES.map((s) => (
                                <button key={s} role="radio" aria-checked={severity === s} onClick={() => setSeverity(s)}
                                    className="text-[10px] font-bold px-2.5 py-1 rounded-full uppercase border transition-colors"
                                    style={severity === s ? { backgroundColor: SEV_COLOUR[s], borderColor: SEV_COLOUR[s], color: '#fff' } : { borderColor: SEV_COLOUR[s], color: SEV_COLOUR[s] }}>
                                    {s}
                                </button>
                            ))}
                        </div>
                    </div>

                    <div>
                        <div className="flex items-center justify-between mb-1.5">
                            <label htmlFor="ac-body" className={`${label} mb-0`}>Body</label>
                            <button onClick={() => setShowBodyPreview((v) => !v)} className="text-[10px] font-bold text-foreground-muted hover:text-foreground flex items-center gap-1">
                                <Eye size={11} /> {showBodyPreview ? 'Edit' : 'Preview'}
                            </button>
                        </div>
                        {showBodyPreview ? (
                            <div className="min-h-[140px] border border-border rounded-lg px-3 py-2 text-sm text-foreground whitespace-pre-wrap bg-card-muted/40">
                                {body || <span className="text-foreground-muted">Nothing written yet.</span>}
                            </div>
                        ) : (
                            <textarea id="ac-body" value={body} onChange={(e) => setBody(e.target.value)} rows={7}
                                placeholder="What happened, what it affects, and what the recipient should do…" className={`${input} resize-y`} />
                        )}
                    </div>

                    {formError && <p role="alert" className="text-xs font-bold" style={{ color: BRAND.red }}>{formError}</p>}

                    <button onClick={openPreview} className="w-full flex items-center justify-center gap-2 text-white text-sm font-bold py-2.5 rounded-xl hover:opacity-90 transition-opacity" style={{ backgroundColor: BRAND.purple }}>
                        <Send size={14} /> Send Communication
                    </button>
                </div>

                {/* ── Log ───────────────────────────────────────────────────────── */}
                <div className="xl:col-span-3 bg-card border border-border rounded-xl p-5 space-y-3">
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                        <h2 className="text-sm font-bold text-foreground">Communication Log</h2>
                        <button onClick={() => void loadLog()} className="flex items-center gap-1 text-[11px] font-bold text-foreground-muted hover:text-foreground"><RefreshCw size={12} /> Refresh</button>
                    </div>
                    <div className="flex flex-wrap items-end gap-2">
                        <label className="text-[10px] text-foreground-muted">Severity
                            <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value as typeof sevFilter)} className="block mt-1 border border-border bg-card rounded-lg px-2 py-1.5 text-xs text-foreground capitalize">
                                <option value="all">All</option>
                                {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
                            </select>
                        </label>
                        <label className="text-[10px] text-foreground-muted">From
                            <input type="date" value={fromDay} onChange={(e) => setFromDay(e.target.value)} className="block mt-1 border border-border bg-card rounded-lg px-2 py-1 text-xs text-foreground" />
                        </label>
                        <label className="text-[10px] text-foreground-muted">To
                            <input type="date" value={toDay} onChange={(e) => setToDay(e.target.value)} className="block mt-1 border border-border bg-card rounded-lg px-2 py-1 text-xs text-foreground" />
                        </label>
                        {(sevFilter !== 'all' || fromDay || toDay) && (
                            <button onClick={() => { setSevFilter('all'); setFromDay(''); setToDay(''); }} className="text-[11px] font-bold text-foreground-muted hover:text-foreground pb-1.5">Clear</button>
                        )}
                    </div>

                    {log?.source === 'memory' && (
                        <p className="text-[11px] bg-amber-500/10 border border-amber-500/30 text-amber-600 rounded-lg px-3 py-2">
                            The log table isn&apos;t set up yet, so this log is kept in the backend&apos;s memory and is lost on restart. Run backend/sql/2026-09-alert-communications.sql in Supabase to keep it.
                        </p>
                    )}

                    {logError ? (
                        <p className="text-xs py-6 text-center" style={{ color: BRAND.red }}>Could not load the log: {logError}</p>
                    ) : log === null ? (
                        <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-9 bg-card-muted rounded animate-pulse" />)}</div>
                    ) : filteredLog.length === 0 ? (
                        <p className="text-xs text-foreground-muted py-8 text-center">
                            {log.entries.length === 0 ? 'No communications sent yet.' : 'No communications match these filters.'}
                        </p>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="w-full text-xs min-w-[640px]">
                                <thead>
                                    <tr className="text-left text-[10px] uppercase tracking-wider text-foreground-muted border-b border-border">
                                        {['Date', 'Recipient', 'Subject', 'Severity', 'Sent By', 'Status'].map((h) => <th key={h} className="py-2 pr-3 font-bold">{h}</th>)}
                                    </tr>
                                </thead>
                                <tbody>
                                    {filteredLog.map((e) => (
                                        <tr key={e.id} className="border-b border-border/60 last:border-0 align-top">
                                            <td className="py-2 pr-3 text-foreground-muted whitespace-nowrap">{wat(e.created_at)}</td>
                                            <td className="py-2 pr-3 text-foreground">
                                                <span className="block text-[10px] text-foreground-muted">{RECIPIENT_LABEL[e.recipient_type] ?? e.recipient_type}</span>
                                                <span className="break-all">{e.recipients.join(', ')}</span>
                                            </td>
                                            <td className="py-2 pr-3 text-foreground max-w-[220px]"><span className="line-clamp-2">{e.subject}</span></td>
                                            <td className="py-2 pr-3"><SeverityBadge severity={e.severity} /></td>
                                            <td className="py-2 pr-3 text-foreground-muted">{e.sent_by}</td>
                                            <td className="py-2">
                                                {e.status === 'sent'
                                                    ? <span className="text-[10px] font-bold text-green">Sent</span>
                                                    : <span className="text-[10px] font-bold" style={{ color: BRAND.red }} title={e.error ?? undefined}>Failed</span>}
                                                {e.status === 'failed' && e.error && <p className="text-[10px] text-foreground-muted max-w-[180px]">{e.error}</p>}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            </div>

            {/* ── Preview modal ─────────────────────────────────────────────────── */}
            {previewOpen && (
                <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4" onClick={() => sendState.kind !== 'sending' && setPreviewOpen(false)}>
                    <div role="dialog" aria-modal="true" aria-label="Preview alert communication" className="bg-card border border-border rounded-2xl w-full max-w-xl max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
                            <h3 className="text-sm font-bold text-foreground">Preview before sending</h3>
                            <button onClick={() => setPreviewOpen(false)} disabled={sendState.kind === 'sending'} aria-label="Close" className="text-foreground-muted hover:text-foreground"><X size={16} /></button>
                        </div>
                        <div className="p-5 space-y-3">
                            <dl className="text-xs space-y-1">
                                <div className="flex gap-2"><dt className="w-16 text-foreground-muted">To</dt><dd className="text-foreground break-all">{resolvedRecipients.join(', ')}</dd></div>
                                <div className="flex gap-2"><dt className="w-16 text-foreground-muted">From</dt><dd className="text-foreground">NovrSOC by Cybernovr &lt;alerts@cybernovr.com&gt;</dd></div>
                                <div className="flex gap-2"><dt className="w-16 text-foreground-muted">Subject</dt><dd className="text-foreground">[NovrSOC {severity.toUpperCase()}] {subject}</dd></div>
                            </dl>
                            {/* Mirrors the HTML email the backend sends (sendAlertCommunicationEmail). */}
                            <div className="rounded-xl overflow-hidden border border-border" style={{ backgroundColor: BRAND.bg }}>
                                <div className="px-5 py-3" style={{ backgroundColor: BRAND.purple }}><span className="text-white text-xs font-bold tracking-wide">NovrSOC</span></div>
                                <div className="bg-white mx-3 my-3 rounded-lg p-5">
                                    <div className="flex items-center gap-2"><SeverityBadge severity={severity} />{linkedCase && <span className="text-[11px]" style={{ color: BRAND.muted }}>{linkedCase.case_number}</span>}</div>
                                    <h4 className="text-base font-bold mt-3 mb-2" style={{ color: BRAND.text }}>{subject}</h4>
                                    <p className="text-sm whitespace-pre-wrap leading-relaxed" style={{ color: BRAND.text }}>{body}</p>
                                    <p className="text-[11px] mt-5" style={{ color: BRAND.muted }}>Sent by you via NovrSOC</p>
                                </div>
                            </div>

                            {sendState.kind === 'sent' && (
                                <p role="status" className="flex items-center gap-2 text-xs font-bold text-green"><CheckCircle2 size={14} /> Sent to {sendState.to.join(', ')}</p>
                            )}
                            {sendState.kind === 'failed' && (
                                <p role="alert" className="flex items-start gap-2 text-xs font-bold" style={{ color: BRAND.red }}><AlertTriangle size={14} className="shrink-0 mt-0.5" /> Not sent — {sendState.error}</p>
                            )}
                        </div>
                        <div className="flex justify-end gap-2 px-5 py-4 border-t border-border">
                            {sendState.kind === 'sent' ? (
                                <button onClick={() => setPreviewOpen(false)} className="text-xs font-bold text-white px-4 py-2 rounded-lg" style={{ backgroundColor: BRAND.purple }}>Done</button>
                            ) : (
                                <>
                                    <button onClick={() => setPreviewOpen(false)} disabled={sendState.kind === 'sending'} className="text-xs font-bold text-foreground-muted px-4 py-2 rounded-lg border border-border disabled:opacity-50">Cancel</button>
                                    <button onClick={() => void confirmSend()} disabled={sendState.kind === 'sending'}
                                        className="flex items-center gap-1.5 text-xs font-bold text-white px-4 py-2 rounded-lg disabled:opacity-60" style={{ backgroundColor: BRAND.purple }}>
                                        {sendState.kind === 'sending' ? <Loader2 size={13} className="animate-spin" /> : <Send size={13} />}
                                        {sendState.kind === 'sending' ? 'Sending…' : sendState.kind === 'failed' ? 'Try again' : 'Confirm Send'}
                                    </button>
                                </>
                            )}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
