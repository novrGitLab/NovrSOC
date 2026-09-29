'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { RefreshCw, PlugZap, Unplug, CheckCircle2, Inbox } from 'lucide-react';
import {
    useEmailApi, send, useRole, isManager, isAnalyst, PageHeader, Panel, Tabs, Gate, Empty, SevBadge, StatusBadge, Badge, Button, Feedback, ErrorNote,
    inputCls, selectCls, wat, label, th, td,
} from './shared';

// Messaging Suite — are dangerous emails actually reaching our users?
// NovrSOC does not own the customer's mail system: it connects to Microsoft 365, Google
// Workspace or the NovrSOC mail gateway with least-privilege, metadata-only access, and shows
// each connection's real, verified state. Actions shown on messages are the PROVIDER's actions.

interface ConnectionInfo {
    provider: 'microsoft365' | 'google_workspace' | 'gateway'; label: string; permissions: string[]; missing_config: string[]; status: string;
    connection: null | { tenant_id: string | null; tenant_name: string | null; admin_email: string | null; last_sync: string | null; last_success_sync: string | null; last_event_at: string | null; last_error: string | null; connected_by: string | null; connected_at: string | null };
}
export interface EventRow {
    id: string; provider: string; message_id: string | null; sender: string | null; sender_domain: string | null; recipient: string | null; subject: string | null; received_at: string;
    source_ip: string | null; spf: string | null; dkim: string | null; dmarc: string | null; detection: string; categories: string[]; severity: string; action: string; action_by: string; alert_id: string | null;
}

const STATUS_TEXT: Record<string, string> = { connected: 'CONNECTED', not_connected: 'NOT CONNECTED', auth_error: 'AUTHENTICATION ERROR', permission_error: 'PERMISSION ERROR', sync_error: 'SYNC ERROR' };
const PROVIDER: Record<string, string> = { microsoft365: 'Microsoft 365', google_workspace: 'Google Workspace', gateway: 'Mail gateway' };
const DETECTIONS = ['phishing', 'malware', 'bec', 'impersonation', 'malicious_url', 'suspicious_attachment', 'spoofing', 'auth_failure', 'spam', 'clean'];
const ONBOARD: Record<string, string> = {
    microsoft365: 'Connect your Microsoft 365 tenant to begin collecting authorised email-security telemetry (Defender for Office 365 alerts and message metadata).',
    google_workspace: 'Connect your Google Workspace domain to collect Gmail security log events — metadata only, no mailbox access.',
    gateway: 'Point your domain’s MX record at the NovrSOC mail gateway and it reports a verdict for every message it scans.',
};

type Tab = 'connections' | 'events' | 'threats' | 'quarantine';

export function MessagingSuite() {
    const [tab, setTab] = useState<Tab>('connections');
    const params = useSearchParams();
    const callback = params.get('provider') ? { provider: params.get('provider')!, result: params.get('result') ?? '', detail: params.get('detail') ?? '' } : null;
    return (
        <div className="space-y-4">
            <PageHeader title="Messaging Suite" subtitle="Are dangerous emails actually reaching your users? Telemetry from your own mail providers, normalised, enriched and correlated with DMARC and Phish ID." />
            {callback && (callback.result === 'connected'
                ? <p role="status" className="text-xs font-bold text-green bg-green/5 border border-green/30 rounded-lg px-3 py-2">{PROVIDER[callback.provider] ?? callback.provider} connected and verified.</p>
                : <ErrorNote message={`${PROVIDER[callback.provider] ?? callback.provider}: ${STATUS_TEXT[callback.result] ?? callback.result} — ${callback.detail}`} />)}
            <Tabs<Tab> value={tab} onChange={setTab} tabs={[
                { id: 'connections', label: 'Connections' }, { id: 'events', label: 'All events' }, { id: 'threats', label: 'Threats' }, { id: 'quarantine', label: 'Quarantine' },
            ]} />
            {tab === 'connections' ? <Connections /> : <Events view={tab} />}
        </div>
    );
}

function Connections() {
    const role = useRole();
    const [nonce, setNonce] = useState(0);
    const state = useEmailApi<{ connections: ConnectionInfo[] }>('/messaging/connections', nonce);
    const [busy, setBusy] = useState<string | null>(null);
    const [fb, setFb] = useState<Record<string, { ok: boolean; text: string } | null>>({});
    const [adminEmail, setAdminEmail] = useState('');

    async function act(p: string, key: string, method: string, path: string, body?: unknown, okText?: (d: Record<string, unknown>) => string) {
        setBusy(`${p}:${key}`); setFb((x) => ({ ...x, [p]: null }));
        const r = await send(method, path, body);
        setBusy(null);
        const conn = (r.data as { connection?: { status: string; last_error: string | null } } | null)?.connection;
        const text = r.ok ? (okText ? okText(r.data ?? {}) : 'Done.') : conn ? `${STATUS_TEXT[conn.status] ?? conn.status}: ${conn.last_error ?? ''}` : r.error ?? 'Failed';
        setFb((x) => ({ ...x, [p]: { ok: r.ok, text } }));
        setNonce((x) => x + 1);
        return r;
    }
    async function connectM365() {
        setBusy('microsoft365:connect');
        const r = await send<{ consent_url: string }>('POST', '/messaging/connections/microsoft365/start');
        setBusy(null);
        if (r.ok && r.data?.consent_url) window.location.href = r.data.consent_url;
        else setFb((x) => ({ ...x, microsoft365: { ok: false, text: r.error ?? 'Could not start the connection' } }));
    }

    return (
        <Gate state={state}>
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                {(state.data?.connections ?? []).map((c) => {
                    const p = c.provider;
                    const connected = c.connection !== null;
                    const unavailable = c.missing_config.length > 0;
                    return (
                        <Panel key={p} title={<span className="flex items-center gap-2">{c.label}</span>} action={<StatusBadge s={c.status} />}>
                            <p className="text-[11px] font-black tracking-wider text-foreground">{STATUS_TEXT[c.status] ?? c.status}</p>
                            {!connected && <p className="text-xs text-foreground-muted mt-1">{ONBOARD[p]}</p>}
                            {connected && c.connection && (
                                <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-[11px] mt-2">
                                    <dt className="text-foreground-muted">Organisation / tenant</dt><dd className="break-all">{c.connection.tenant_name ?? c.connection.tenant_id ?? c.connection.admin_email ?? '—'}</dd>
                                    <dt className="text-foreground-muted">Last synchronisation</dt><dd>{wat(c.connection.last_sync)}</dd>
                                    <dt className="text-foreground-muted">Last successful sync</dt><dd>{wat(c.connection.last_success_sync)}</dd>
                                    <dt className="text-foreground-muted">Last event received</dt><dd>{wat(c.connection.last_event_at)}</dd>
                                    <dt className="text-foreground-muted">Connected by</dt><dd>{c.connection.connected_by ?? '—'} · {wat(c.connection.connected_at)}</dd>
                                </dl>
                            )}
                            {c.connection?.last_error && <div className="mt-2"><ErrorNote message={c.connection.last_error} /></div>}
                            <div className="mt-3">
                                <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">Permissions requested</p>
                                <ul className="text-[11px] text-foreground list-disc pl-4 mt-1">{c.permissions.map((x) => <li key={x}>{x}</li>)}</ul>
                            </div>
                            {unavailable && <p className="text-[11px] text-amber-600 mt-2">Not available on this NovrSOC deployment yet — the backend needs {c.missing_config.join(', ')}.</p>}
                            <div className="flex flex-wrap gap-2 mt-3">
                                {isManager(role) && !connected && p === 'microsoft365' && <Button variant="primary" disabled={unavailable} busy={busy === 'microsoft365:connect'} onClick={connectM365}><PlugZap size={12} /> Connect Microsoft 365</Button>}
                                {isManager(role) && !connected && p === 'google_workspace' && (
                                    <form className="flex gap-2 w-full" onSubmit={(e) => { e.preventDefault(); void act(p, 'connect', 'POST', '/messaging/connections/google_workspace', { admin_email: adminEmail }, () => 'Connected and verified.'); }}>
                                        <input value={adminEmail} onChange={(e) => setAdminEmail(e.target.value)} type="email" required placeholder="Workspace super-admin email" aria-label="Workspace admin email" className={`${inputCls} flex-1`} disabled={unavailable} />
                                        <Button type="submit" variant="primary" disabled={unavailable} busy={busy === `${p}:connect`}><PlugZap size={12} /> Connect</Button>
                                    </form>
                                )}
                                {isManager(role) && !connected && p === 'gateway' && <Button variant="primary" disabled={unavailable} busy={busy === `${p}:connect`} onClick={() => void act(p, 'connect', 'POST', '/messaging/connections/gateway', undefined, () => 'Connected.')}><PlugZap size={12} /> Connect gateway</Button>}
                                {connected && isAnalyst(role) && <Button busy={busy === `${p}:verify`} onClick={() => void act(p, 'verify', 'POST', `/messaging/connections/${p}/verify`, undefined, () => 'Verified.')}><CheckCircle2 size={12} /> Verify</Button>}
                                {connected && isAnalyst(role) && <Button busy={busy === `${p}:sync`} onClick={() => void act(p, 'sync', 'POST', `/messaging/connections/${p}/sync`, undefined, (d) => `Synced: ${d.fetched ?? 0} fetched, ${d.stored ?? 0} events stored.`)}><RefreshCw size={12} /> Sync now</Button>}
                                {connected && isManager(role) && <Button variant="danger" busy={busy === `${p}:disconnect`} onClick={() => { if (window.confirm(`Disconnect ${c.label}? Stored events are kept.`)) void act(p, 'disconnect', 'DELETE', `/messaging/connections/${p}`, undefined, (d) => String(d.note ?? 'Disconnected.')); }}><Unplug size={12} /> Disconnect</Button>}
                            </div>
                            <div className="mt-2"><Feedback result={fb[p] ?? null} /></div>
                        </Panel>
                    );
                })}
            </div>
            <p className="text-[11px] text-foreground-muted mt-3">Connected providers sync automatically every 10 minutes. NovrSOC reads security telemetry and message metadata only; it never copies mailboxes, and full message content is not collected.</p>
        </Gate>
    );
}

export function EventsTable({ events }: { events: EventRow[] }) {
    return (
        <div className="overflow-x-auto -m-4">
            <table className="w-full text-xs min-w-[1000px]">
                <thead><tr className="border-b border-border">{['Received', 'Sender', 'Recipient', 'Subject', 'Detection', 'Severity', 'Action', 'Auth (SPF/DKIM/DMARC)', 'Provider'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
                <tbody>
                    {events.map((e) => (
                        <tr key={e.id} className="border-b border-border/60 last:border-0 hover:bg-card-muted/40 align-top">
                            <td className={`${td} whitespace-nowrap text-foreground-muted`}><Link href={`/admin/email/messaging/${e.id}`} className="hover:text-purple">{wat(e.received_at)}</Link></td>
                            <td className={`${td} break-all max-w-[200px]`}>{e.sender ?? '—'}{e.source_ip && <p className="text-[10px] font-mono text-foreground-muted">{e.source_ip}</p>}</td>
                            <td className={`${td} break-all max-w-[180px]`}>{e.recipient ?? '—'}</td>
                            <td className={`${td} max-w-[220px]`}><Link href={`/admin/email/messaging/${e.id}`} className="line-clamp-2 text-foreground hover:text-purple">{e.subject ?? <span className="text-foreground-muted">(not provided)</span>}</Link></td>
                            <td className={td}>{e.detection === 'clean' ? <span className="text-foreground-muted">Clean</span> : <span className="font-bold text-foreground">{label(e.detection)}</span>}{e.alert_id && <Link href={`/admin/email/alerts/${e.alert_id}`} className="block text-[10px] text-purple hover:underline">Alert →</Link>}</td>
                            <td className={td}><SevBadge s={e.severity} /></td>
                            <td className={td}><Badge tone={e.action === 'block' || e.action === 'quarantine' ? 'green' : e.action === 'flag' ? 'amber' : 'grey'}>{e.action}</Badge><p className="text-[10px] text-foreground-muted mt-0.5">{e.action_by === 'none' ? (e.action === 'allow' || e.action === 'flag' ? 'Delivered' : '') : `by ${e.action_by}`}</p></td>
                            <td className={`${td} whitespace-nowrap`}>{[e.spf, e.dkim, e.dmarc].map((x) => x ?? '—').join(' / ')}</td>
                            <td className={`${td} text-foreground-muted`}>{PROVIDER[e.provider] ?? e.provider}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

function Events({ view }: { view: 'events' | 'threats' | 'quarantine' }) {
    const [nonce, setNonce] = useState(0);
    const [q, setQ] = useState('');
    const [severity, setSeverity] = useState('');
    const [detection, setDetection] = useState('');
    const [provider, setProvider] = useState('');
    const [from, setFrom] = useState('');
    const [to, setTo] = useState('');
    const qs = new URLSearchParams({
        ...(view !== 'events' ? { view } : {}), ...(q.trim() ? { q: q.trim() } : {}), ...(severity ? { severity } : {}), ...(detection ? { detection } : {}),
        ...(provider ? { provider } : {}), ...(from ? { from } : {}), ...(to ? { to: `${to}T23:59:59` } : {}),
    }).toString();
    const state = useEmailApi<{ events: EventRow[] }>(`/messaging/events?${qs}`, nonce);
    const events = state.data?.events ?? [];
    const title = view === 'threats' ? 'Threats' : view === 'quarantine' ? 'Quarantined by the provider' : 'Email events';
    return (
        <div className="space-y-3">
            <div className="flex flex-wrap gap-2 items-center">
                <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Sender address or @domain" aria-label="Search sender" className={`${inputCls} w-56`} />
                <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity" className={selectCls}><option value="">All severities</option>{['critical', 'high', 'medium', 'low', 'informational'].map((s) => <option key={s} value={s}>{label(s)}</option>)}</select>
                <select value={detection} onChange={(e) => setDetection(e.target.value)} aria-label="Detection" className={selectCls}><option value="">All detections</option>{DETECTIONS.map((s) => <option key={s} value={s}>{label(s)}</option>)}</select>
                <select value={provider} onChange={(e) => setProvider(e.target.value)} aria-label="Provider" className={selectCls}><option value="">All providers</option>{Object.entries(PROVIDER).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
                <label className="text-[11px] text-foreground-muted flex items-center gap-1">From <input type="date" value={from} onChange={(e) => setFrom(e.target.value)} className={inputCls} /></label>
                <label className="text-[11px] text-foreground-muted flex items-center gap-1">To <input type="date" value={to} onChange={(e) => setTo(e.target.value)} className={inputCls} /></label>
                <Button onClick={() => setNonce((x) => x + 1)}><RefreshCw size={12} /> Refresh</Button>
            </div>
            <Panel title={title} action={<span className="text-[10px] text-foreground-muted">Newest 200 · actions are those taken by the mail provider</span>}>
                <Gate state={state}>
                    {events.length === 0
                        ? <Empty icon={<Inbox size={18} />} title={qs.replace(/view=\w+&?/, '') ? 'No events match these filters' : 'No email events yet'} body="Events appear once a mail provider is connected and has synchronised." />
                        : <EventsTable events={events} />}
                </Gate>
            </Panel>
        </div>
    );
}
