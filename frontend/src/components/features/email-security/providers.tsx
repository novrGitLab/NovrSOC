'use client';

import { useState } from 'react';
import { PlugZap, Unplug, CheckCircle2, RefreshCw, Mail } from 'lucide-react';
import { send, useRole, isManager, isAnalyst, StatusBadge, Button, Feedback, ErrorNote, inputCls, wat } from './shared';
import { useEmailSecurity, type ProviderRow } from './context';

// Email sources (Microsoft 365, Google Workspace, NovrSOC Mail Gateway). Shared by Messaging
// Suite and Setup so both show the same, backend-verified state. Connections use the existing
// flows: Microsoft sign-in + tenant consent, Google delegated service account, gateway token.
// Nothing here ever shows a credential, and nothing is "connected" until the backend verifies it.

const PROVIDER_LABEL: Record<string, string> = { microsoft365: 'Microsoft 365', google_workspace: 'Google Workspace', gateway: 'NovrSOC Mail Gateway' };
export const providerName = (p: string) => PROVIDER_LABEL[p] ?? p;

const ABOUT: Record<ProviderRow['provider'], string> = {
    microsoft365: 'Defender for Office 365 alerts and message metadata. A Global Administrator signs in, then approves read-only access for that tenant.',
    google_workspace: 'Gmail security log events through a delegated, read-only service account. Metadata only — no mailbox access.',
    gateway: 'Postfix + Amavis gateway: point a domain\'s MX at it and it reports a verdict for every message it scans.',
};

export function ProviderCards({ compact = false }: { compact?: boolean }) {
    const { providers, reload } = useEmailSecurity();
    const role = useRole();
    const [busy, setBusy] = useState<string | null>(null);
    const [fb, setFb] = useState<Record<string, { ok: boolean; text: string } | null>>({});
    const [adminEmail, setAdminEmail] = useState('');

    async function act(p: string, key: string, method: string, path: string, body?: unknown, okText?: (d: Record<string, unknown>) => string) {
        setBusy(`${p}:${key}`); setFb((x) => ({ ...x, [p]: null }));
        const r = await send(method, path, body);
        setBusy(null);
        const conn = (r.data as { connection?: { status: string; last_error: string | null } } | null)?.connection;
        setFb((x) => ({ ...x, [p]: { ok: r.ok, text: r.ok ? (okText ? okText(r.data ?? {}) : 'Done.') : conn ? `${conn.status.replace(/_/g, ' ')}: ${conn.last_error ?? ''}` : r.error ?? 'Failed' } }));
        reload();
    }
    async function connectM365() {
        setBusy('microsoft365:connect');
        const r = await send<{ authorize_url: string }>('POST', '/messaging/connections/microsoft365/start');
        setBusy(null);
        if (r.ok && r.data?.authorize_url) window.location.href = r.data.authorize_url; // sign in, then consent for that tenant
        else setFb((x) => ({ ...x, microsoft365: { ok: false, text: r.error ?? 'Could not start the connection' } }));
    }

    return (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
            {providers.map((c) => {
                const p = c.provider;
                const connected = c.connection !== null && c.status === 'connected';
                const hasRow = c.connection !== null;
                const needsConfig = c.missing_config.length > 0;
                return (
                    <section key={p} className="bg-card border border-border rounded-xl p-4 flex flex-col min-w-0">
                        <div className="flex items-start justify-between gap-2 flex-wrap">
                            <div className="flex items-center gap-2 min-w-0">
                                <Mail size={14} className="text-foreground-muted shrink-0" aria-hidden />
                                <h3 className="text-sm font-black text-foreground">{providerName(p)}</h3>
                            </div>
                            <StatusBadge s={c.status} />
                        </div>
                        {!compact && <p className="text-[11px] text-foreground-muted mt-2">{ABOUT[p]}</p>}
                        {hasRow && c.connection && (
                            <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-[11px] mt-3">
                                <dt className="text-foreground-muted">Tenant / org</dt><dd className="min-w-0 wrap-anywhere">{c.connection.tenant_name ?? c.connection.tenant_id ?? c.connection.admin_email ?? '—'}</dd>
                                <dt className="text-foreground-muted">Last sync</dt><dd>{wat(c.connection.last_sync)}</dd>
                                <dt className="text-foreground-muted">Last event</dt><dd>{wat(c.connection.last_event_at)}</dd>
                            </dl>
                        )}
                        {c.connection?.last_error && <div className="mt-2"><ErrorNote message={c.connection.last_error} /></div>}
                        {needsConfig && (
                            <p className="text-[11px] text-amber-700 dark:text-amber-500 mt-3"><span className="font-bold">Requires configuration.</span> The NovrSOC backend needs <span className="font-mono wrap-anywhere">{c.missing_config.join(', ')}</span> before this source can connect.</p>
                        )}
                        {!compact && (
                            <details className="mt-3 text-[11px]">
                                <summary className="cursor-pointer font-bold text-foreground-muted">Permissions requested</summary>
                                <ul className="list-disc pl-4 mt-1 text-foreground wrap-anywhere">{c.permissions.map((x) => <li key={x}>{x}</li>)}</ul>
                            </details>
                        )}
                        <div className="flex flex-wrap gap-2 mt-auto pt-3">
                            {isManager(role) && !hasRow && p === 'microsoft365' && <Button variant="primary" disabled={needsConfig} busy={busy === 'microsoft365:connect'} onClick={connectM365}><PlugZap size={12} /> Connect</Button>}
                            {isManager(role) && !hasRow && p === 'google_workspace' && (
                                <form className="flex gap-2 w-full" onSubmit={(e) => { e.preventDefault(); void act(p, 'connect', 'POST', '/messaging/connections/google_workspace', { admin_email: adminEmail }, () => 'Connected and verified.'); }}>
                                    <input value={adminEmail} onChange={(e) => setAdminEmail(e.target.value)} type="email" required placeholder="Workspace super-admin email" aria-label="Workspace admin email" className={`${inputCls} flex-1 min-w-0`} disabled={needsConfig} />
                                    <Button type="submit" variant="primary" disabled={needsConfig} busy={busy === `${p}:connect`}><PlugZap size={12} /> Connect</Button>
                                </form>
                            )}
                            {isManager(role) && !hasRow && p === 'gateway' && <Button variant="primary" disabled={needsConfig} busy={busy === `${p}:connect`} onClick={() => void act(p, 'connect', 'POST', '/messaging/connections/gateway', undefined, () => 'Connected.')}><PlugZap size={12} /> Configure</Button>}
                            {hasRow && isAnalyst(role) && <Button busy={busy === `${p}:verify`} onClick={() => void act(p, 'verify', 'POST', `/messaging/connections/${p}/verify`, undefined, () => 'Verified.')}><CheckCircle2 size={12} /> Verify</Button>}
                            {connected && isAnalyst(role) && <Button busy={busy === `${p}:sync`} onClick={() => void act(p, 'sync', 'POST', `/messaging/connections/${p}/sync`, undefined, (d) => `Synced: ${d.fetched ?? 0} fetched, ${d.stored ?? 0} stored.`)}><RefreshCw size={12} /> Sync now</Button>}
                            {hasRow && isManager(role) && <Button variant="danger" busy={busy === `${p}:disconnect`} onClick={() => { if (window.confirm(`Disconnect ${providerName(p)}? Stored events are kept.`)) void act(p, 'disconnect', 'DELETE', `/messaging/connections/${p}`, undefined, (d) => String(d.note ?? 'Disconnected.')); }}><Unplug size={12} /> Disconnect</Button>}
                            {!isManager(role) && !hasRow && <p className="text-[10px] text-foreground-muted">A SOC manager can connect this source.</p>}
                        </div>
                        <Feedback result={fb[p] ?? null} />
                    </section>
                );
            })}
        </div>
    );
}
