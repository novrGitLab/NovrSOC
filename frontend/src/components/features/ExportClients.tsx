'use client';

// Export Clients — super_admin management of vendor export credentials (phase X2), on
// /api/admin/export-clients. The backend enforces super_admin; this page also says so up front.
//
// Tokens: the plaintext token exists only in the create/rotate response. It is held in this
// component's state just long enough to show it once, then cleared — never written to
// localStorage, sessionStorage, cookies or logs.

import { useCallback, useEffect, useState } from 'react';
import { Copy, KeyRound, Plus, RefreshCw, ShieldAlert, X } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { getAdminUser } from '@/lib/admin-auth';
import { loadJson } from '@/lib/alerts';

/** Stored when no IPs are given yet: TEST-NET-1, never routable, so the client can't connect. */
export const PENDING_CIDR = '192.0.2.1/32';
const isPending = (cidrs: string[]) => cidrs.length === 1 && cidrs[0] === PENDING_CIDR;

interface ExportClient {
    id: string;
    name: string | null;
    org_ids: string[];
    allowed_cidrs: string[];
    enabled: boolean | null;
    redaction_profile: string | null;
    created_at: string;
    rotated_at: string | null;
    last_used_at: string | null;
}
interface Org { slug: string; name: string }
interface AccessEntry { at: string; source_ip: string | null; org_ids: string[] | null; row_count: number | null; status_code: number }

const fmt = (iso: string | null) => (iso ? new Intl.DateTimeFormat('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(iso)) + ' WAT' : 'Never');
const parseCidrLines = (text: string) => text.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

async function send(method: string, path: string, body?: unknown): Promise<{ ok: boolean; data: Record<string, unknown> | null; error: string }> {
    try {
        const r = await apiFetch(apiUrl(path), { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
        const data = await r.json().catch(() => null);
        return { ok: r.ok, data, error: r.ok ? '' : data?.error ?? `HTTP ${r.status}` };
    } catch {
        return { ok: false, data: null, error: 'Could not reach the backend' };
    }
}

/** Shows a token once. Closing the panel discards it. */
function TokenOnce({ title, token, onClose }: { title: string; token: string; onClose: () => void }) {
    const [copied, setCopied] = useState(false);
    return (
        <div role="dialog" aria-modal="true" className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4">
            <div className="bg-card border border-border rounded-xl max-w-lg w-full p-5 space-y-4">
                <div className="flex items-start gap-3">
                    <ShieldAlert className="w-5 h-5 text-red-500 shrink-0 mt-0.5" />
                    <div>
                        <h2 className="text-sm font-black text-foreground">{title}</h2>
                        <p className="text-xs text-red-500 font-semibold mt-1">
                            This token is shown once. NovrSOC keeps only a hash of it — it cannot be shown again or recovered. Copy it now and hand it to the vendor over a secure channel. If it is lost, rotate it.
                        </p>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    <code className="flex-1 bg-card-muted border border-border rounded-lg px-3 py-2 text-[11px] font-mono break-all select-all">{token}</code>
                    <button
                        onClick={() => { void navigator.clipboard.writeText(token).then(() => setCopied(true), () => setCopied(false)); }}
                        className="flex items-center gap-1.5 text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-2"
                    >
                        <Copy className="w-3.5 h-3.5" /> {copied ? 'Copied' : 'Copy'}
                    </button>
                </div>
                <div className="flex justify-end">
                    <button onClick={onClose} className="text-[11px] font-bold text-foreground border border-border rounded-lg px-3 py-1.5 hover:bg-card-muted">
                        I have stored the token — close
                    </button>
                </div>
            </div>
        </div>
    );
}

function CreateWizard({ orgs, onCreated, onCancel }: { orgs: Org[]; onCreated: (token: string) => void; onCancel: () => void }) {
    const [step, setStep] = useState(1);
    const [name, setName] = useState('');
    const [picked, setPicked] = useState<string[]>([]);
    const [ipText, setIpText] = useState('');
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const cidrs = parseCidrLines(ipText);

    async function create() {
        setBusy(true);
        setError(null);
        const r = await send('POST', '/api/admin/export-clients', { name: name.trim(), org_ids: picked, allowed_cidrs: cidrs.length ? cidrs : [PENDING_CIDR] });
        setBusy(false);
        if (!r.ok || typeof r.data?.token !== 'string') { setError(r.error || 'Creation failed'); return; }
        onCreated(r.data.token);
    }

    const canNext = step === 1 ? name.trim().length > 0 : step === 2 ? picked.length > 0 : true;
    return (
        <div className="bg-card border border-border rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
                <p className="text-sm font-black text-foreground">New export client · step {step} of 4</p>
                <button onClick={onCancel} aria-label="Cancel" className="text-foreground-muted hover:text-foreground"><X className="w-4 h-4" /></button>
            </div>

            {step === 1 && (
                <label className="block">
                    <span className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">Vendor name</span>
                    <input value={name} onChange={(e) => setName(e.target.value)} maxLength={100}
                        className="mt-1 w-full bg-card-muted border border-border rounded-lg px-3 py-2 text-sm" placeholder="e.g. Acme XDR" />
                </label>
            )}

            {step === 2 && (
                <div>
                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">Organisations this vendor may read</p>
                    {orgs.length === 0 ? (
                        <p className="text-xs text-foreground-muted">No organisations available.</p>
                    ) : (
                        <div className="max-h-60 overflow-y-auto space-y-1">
                            {orgs.map((o) => (
                                <label key={o.slug} className="flex items-center gap-2 text-sm">
                                    <input type="checkbox" checked={picked.includes(o.slug)}
                                        onChange={(e) => setPicked((p) => (e.target.checked ? [...p, o.slug] : p.filter((x) => x !== o.slug)))} />
                                    {o.name} <span className="text-[10px] text-foreground-muted font-mono">{o.slug}</span>
                                </label>
                            ))}
                        </div>
                    )}
                </div>
            )}

            {step === 3 && (
                <label className="block">
                    <span className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">Vendor IP allowlist (one address or CIDR per line)</span>
                    <textarea value={ipText} onChange={(e) => setIpText(e.target.value)} rows={4}
                        className="mt-1 w-full bg-card-muted border border-border rounded-lg px-3 py-2 text-sm font-mono" placeholder="e.g. 198.51.100.0/29" />
                    <span className="text-[11px] text-foreground-muted">
                        Leave empty if the vendor hasn&apos;t sent its addresses yet: the client is created as <b>Pending IPs</b> (placeholder {PENDING_CIDR}, which can&apos;t connect). 0.0.0.0/0 is refused.
                    </span>
                </label>
            )}

            {step === 4 && (
                <div className="text-xs space-y-1">
                    <p><b>Name:</b> {name.trim()}</p>
                    <p><b>Organisations:</b> {picked.join(', ')}</p>
                    <p><b>IP allowlist:</b> {cidrs.length ? cidrs.join(', ') : `Pending IPs (${PENDING_CIDR})`}</p>
                    <p><b>Redaction:</b> standard — the raw alert is included, with secrets masked</p>
                </div>
            )}

            {error && <p className="text-xs text-red-500 font-semibold">{error}</p>}

            <div className="flex justify-between">
                <button disabled={step === 1 || busy} onClick={() => setStep((s) => s - 1)}
                    className="text-[11px] font-bold text-foreground border border-border rounded-lg px-3 py-1.5 disabled:opacity-40">Back</button>
                {step < 4 ? (
                    <button disabled={!canNext} onClick={() => setStep((s) => s + 1)}
                        className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5 disabled:opacity-40">Next</button>
                ) : (
                    <button disabled={busy} onClick={() => void create()}
                        className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5 disabled:opacity-40">Create client</button>
                )}
            </div>
        </div>
    );
}

function ClientRow({ c, orgNames, onChanged, onToken }: { c: ExportClient; orgNames: Map<string, string>; onChanged: () => void; onToken: (t: string, title: string) => void }) {
    const [editing, setEditing] = useState(false);
    const [ipText, setIpText] = useState('');
    const [busy, setBusy] = useState(false);
    const [msg, setMsg] = useState<string | null>(null);
    const [log, setLog] = useState<AccessEntry[] | null>(null);
    const pending = isPending(c.allowed_cidrs);

    async function act(method: string, path: string, body?: unknown, onOk?: (d: Record<string, unknown> | null) => void) {
        setBusy(true);
        setMsg(null);
        const r = await send(method, path, body);
        setBusy(false);
        if (!r.ok) { setMsg(r.error); return; }
        onOk?.(r.data);
        onChanged();
    }

    async function toggleLog() {
        if (log) { setLog(null); return; }
        const r = await loadJson<{ entries: AccessEntry[] }>(`/api/admin/export-clients/${c.id}/access-log?limit=20`);
        if (r.ok) setLog(r.data.entries); else setMsg(r.error);
    }

    return (
        <div className="border-b border-border last:border-0 p-4 space-y-2">
            <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                    <p className="text-sm font-bold text-foreground flex items-center gap-2">
                        {c.name ?? 'Unnamed'}
                        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${c.enabled === false ? 'bg-card-muted text-foreground-muted border-border' : 'bg-green/10 text-green border-green/30'}`}>{c.enabled === false ? 'Disabled' : 'Enabled'}</span>
                        {pending && <span className="text-[9px] font-bold px-1.5 py-0.5 rounded border bg-amber/10 text-amber border-amber/40">Pending IPs</span>}
                    </p>
                    <p className="text-[11px] text-foreground-muted mt-0.5">Orgs: {c.org_ids.map((o) => orgNames.get(o) ?? o).join(', ')}</p>
                    <p className="text-[11px] text-foreground-muted">IPs: <span className="font-mono">{pending ? 'none yet' : c.allowed_cidrs.join(', ')}</span></p>
                    <p className="text-[11px] text-foreground-muted">Last used: {fmt(c.last_used_at)} · Created {fmt(c.created_at)}{c.rotated_at ? ` · Rotated ${fmt(c.rotated_at)}` : ''}</p>
                </div>
                <div className="flex flex-wrap gap-2">
                    <button disabled={busy} onClick={() => { setEditing((v) => !v); setIpText(pending ? '' : c.allowed_cidrs.join('\n')); }}
                        className="text-[11px] font-bold text-foreground border border-border rounded-lg px-2.5 py-1.5 disabled:opacity-50">Edit IPs</button>
                    <button disabled={busy} onClick={() => {
                        if (!window.confirm('Rotate this token? The current token stops working immediately.')) return;
                        void act('POST', `/api/admin/export-clients/${c.id}/rotate`, undefined, (d) => { if (typeof d?.token === 'string') onToken(d.token, `New token for ${c.name ?? 'client'}`); });
                    }} className="flex items-center gap-1 text-[11px] font-bold text-foreground border border-border rounded-lg px-2.5 py-1.5 disabled:opacity-50"><KeyRound className="w-3.5 h-3.5" /> Rotate</button>
                    <button disabled={busy} onClick={() => void act('POST', `/api/admin/export-clients/${c.id}/${c.enabled === false ? 'enable' : 'disable'}`)}
                        className="text-[11px] font-bold text-foreground border border-border rounded-lg px-2.5 py-1.5 disabled:opacity-50">{c.enabled === false ? 'Enable' : 'Disable'}</button>
                    <button onClick={() => void toggleLog()} className="text-[11px] font-bold text-foreground-muted border border-border rounded-lg px-2.5 py-1.5">{log ? 'Hide access log' : 'Access log'}</button>
                </div>
            </div>

            {editing && (
                <div className="space-y-2">
                    <textarea value={ipText} onChange={(e) => setIpText(e.target.value)} rows={3}
                        className="w-full bg-card-muted border border-border rounded-lg px-3 py-2 text-xs font-mono" placeholder="One address or CIDR per line" />
                    <div className="flex gap-2">
                        <button disabled={busy} onClick={() => {
                            const cidrs = parseCidrLines(ipText);
                            void act('PATCH', `/api/admin/export-clients/${c.id}`, { allowed_cidrs: cidrs.length ? cidrs : [PENDING_CIDR] }, () => setEditing(false));
                        }} className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5 disabled:opacity-50">Save IPs</button>
                        <span className="text-[11px] text-foreground-muted self-center">Empty = Pending IPs (no access). 0.0.0.0/0 is refused.</span>
                    </div>
                </div>
            )}

            {msg && <p className="text-xs text-red-500 font-semibold">{msg}</p>}

            {log && (
                log.length === 0 ? <p className="text-xs text-foreground-muted">No calls recorded.</p> : (
                    <table className="w-full text-[11px]">
                        <thead><tr className="text-left text-foreground-muted">{['Time', 'Source IP', 'Status', 'Rows', 'Orgs'].map((h) => <th key={h} className="py-1 pr-3 font-bold">{h}</th>)}</tr></thead>
                        <tbody>
                            {log.map((e, i) => (
                                <tr key={i} className="border-t border-border">
                                    <td className="py-1 pr-3">{fmt(e.at)}</td>
                                    <td className="py-1 pr-3 font-mono">{e.source_ip ?? '—'}</td>
                                    <td className={`py-1 pr-3 font-bold ${e.status_code === 200 ? 'text-green' : 'text-red-500'}`}>{e.status_code}</td>
                                    <td className="py-1 pr-3">{e.row_count ?? '—'}</td>
                                    <td className="py-1 pr-3">{e.org_ids?.join(', ') ?? '—'}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )
            )}
        </div>
    );
}

export function ExportClients() {
    const isSuperAdmin = getAdminUser().role === 'super_admin';
    const [clients, setClients] = useState<ExportClient[] | null>(null);
    const [orgs, setOrgs] = useState<Org[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [wizard, setWizard] = useState(false);
    const [shownToken, setShownToken] = useState<{ token: string; title: string } | null>(null);
    const [reloadKey, setReloadKey] = useState(0);
    const reload = useCallback(() => setReloadKey((k) => k + 1), []);

    useEffect(() => {
        if (!isSuperAdmin) return;
        let active = true;
        void Promise.all([
            loadJson<{ clients: ExportClient[] }>('/api/admin/export-clients'),
            loadJson<{ organisations: Org[] }>('/api/organisations'),
        ]).then(([c, o]) => {
            if (!active) return;
            setClients(c.ok ? c.data.clients : null);
            setError(c.ok ? null : c.notConnected ? 'Not connected — the export client store is unavailable.' : c.error);
            setOrgs(o.ok ? o.data.organisations.map((x) => ({ slug: x.slug, name: x.name })) : []);
        });
        return () => { active = false; };
    }, [isSuperAdmin, reloadKey]);

    if (!isSuperAdmin) {
        return (
            <div className="bg-card border border-border rounded-xl p-8 text-center">
                <ShieldAlert className="w-8 h-8 text-foreground-muted mx-auto mb-2" />
                <p className="text-sm font-bold text-foreground">Super admin only</p>
                <p className="text-xs text-foreground-muted mt-1">Export clients can only be managed by a super_admin.</p>
            </div>
        );
    }

    const orgNames = new Map(orgs.map((o) => [o.slug, o.name]));
    return (
        <div className="space-y-5">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-lg font-black text-foreground">Export Clients</h1>
                    <p className="text-xs text-foreground-muted">Vendor credentials for the alert export API (GET /api/export/v1/events)</p>
                </div>
                <div className="flex gap-2">
                    <button onClick={reload} className="flex items-center gap-1.5 text-[11px] font-bold text-foreground-muted hover:text-foreground border border-border rounded-lg px-3 py-1.5">
                        <RefreshCw className="w-3.5 h-3.5" /> Refresh
                    </button>
                    {!wizard && (
                        <button onClick={() => setWizard(true)} className="flex items-center gap-1.5 text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5">
                            <Plus className="w-3.5 h-3.5" /> New client
                        </button>
                    )}
                </div>
            </div>

            {wizard && (
                <CreateWizard orgs={orgs} onCancel={() => setWizard(false)}
                    onCreated={(token) => { setWizard(false); setShownToken({ token, title: 'Export client created' }); reload(); }} />
            )}

            {error && <p role="alert" className="text-xs text-red-500 font-semibold">{error}</p>}

            <div className="bg-card border border-border rounded-xl overflow-hidden">
                {clients === null ? (
                    !error && <div className="p-4 space-y-2">{Array.from({ length: 3 }).map((_, i) => <div key={i} className="h-14 bg-card-muted rounded animate-pulse" />)}</div>
                ) : clients.length === 0 ? (
                    <p className="text-sm text-foreground-muted text-center py-10">No data — no export clients yet.</p>
                ) : (
                    clients.map((c) => <ClientRow key={c.id} c={c} orgNames={orgNames} onChanged={reload} onToken={(t, title) => setShownToken({ token: t, title })} />)
                )}
            </div>

            {shownToken && <TokenOnce title={shownToken.title} token={shownToken.token} onClose={() => setShownToken(null)} />}
        </div>
    );
}
