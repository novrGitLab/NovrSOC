'use client';

// Authorised scope (phase P4) — the only targets VMS may ever touch. A soc_manager / super_admin
// requests each entry with the authorisation that permits testing (contract, letter of
// authorisation, ticket), an expiry and, optionally, scan windows and a job limit. Since P27 an
// entry that permits active scanning is pending until the organisation's administrator approves it
// (Scan Authorisation page); passive-only entries are registered at once. The backend enforces who
// may do each step. Revoking an entry cancels its queued scans and stops running ones.

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { ShieldCheck, Plus } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { getAdminUser } from '@/lib/admin-auth';
import { loadJson } from '@/lib/alerts';
import { fmtWat, type VmsScope as Scope, type VmsScanWindows } from '@/lib/vms';

/** An active entry past its expiry covers nothing. */
function expired(s: Scope): boolean {
    return Date.parse(s.expires_at) <= Date.now();
}

const inThreeMonths = () => new Date(Date.now() + 90 * 86_400_000).toISOString().slice(0, 10);
const DAY = ['', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
export const METHOD_LABEL: Record<string, string> = { in_platform: 'Approved in NovrSOC', offline_document: 'Signed document', passive_registration: 'Passive registration', legacy: 'Recorded before approvals', cnii: 'CNII authorisation' };

export function describeWindows(w: VmsScanWindows | null | undefined): string {
    if (!w || !w.windows?.length) return 'Any time';
    return `${w.windows.map((x) => `${x.days.length === 7 ? 'Every day' : x.days.map((d) => DAY[d]).join(', ')} ${x.start}–${x.end}`).join('; ')} (${w.tz})`;
}

function StatusCell({ s }: { s: Scope }) {
    if (s.status === 'pending') return <><span className="font-semibold text-amber">Waiting for approval</span>{s.request_group_id && <Link href={`/admin/vms/authorisation?request=${s.request_group_id}`} className="block underline text-foreground-muted">Open request</Link>}</>;
    if (s.status === 'rejected') return <><span className="font-semibold text-red">Rejected</span><span className="block text-foreground-muted">{s.rejected_by}{s.rejection_reason ? `: ${s.rejection_reason}` : ''}</span></>;
    if (s.status === 'revoked') return <>Revoked by {s.revoked_by}</>;
    return <>{expired(s) ? 'Expired' : 'Active'}</>;
}

export function VmsScope() {
    const role = getAdminUser().role;
    const canRequest = role === 'super_admin' || role === 'soc_manager';
    const canRevoke = canRequest || role === 'executive';
    const [scopes, setScopes] = useState<Scope[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [msg, setMsg] = useState<string | null>(null);
    const [adding, setAdding] = useState(false);
    const [form, setForm] = useState({ kind: 'domain' as Scope['kind'], value: '', include_subdomains: true, allow_port_scan: false, allow_vuln_scan: false, authorization_reference: '', expires_at: inThreeMonths(), notes: '', exclusions: '', windowed: false, days: [1, 2, 3, 4, 5] as number[], start: '22:00', end: '05:00', tz: 'Africa/Lagos', max_active_jobs: '' });
    const [reloadKey, setReloadKey] = useState(0);
    const reload = useCallback(() => setReloadKey((k) => k + 1), []);

    useEffect(() => {
        let active = true;
        void loadJson<{ scopes: Scope[] }>('/api/vms/scopes').then((r) => {
            if (!active) return;
            setScopes(r.ok ? r.data.scopes : null);
            setError(r.ok ? null : r.error);
        });
        return () => { active = false; };
    }, [reloadKey]);

    async function save() {
        setMsg(null);
        const r = await apiFetch(apiUrl('/api/vms/scopes'), {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                kind: form.kind, value: form.value, include_subdomains: form.include_subdomains, allow_port_scan: form.allow_port_scan, allow_vuln_scan: form.allow_vuln_scan,
                authorization_reference: form.authorization_reference, expires_at: new Date(`${form.expires_at}T23:59:59Z`).toISOString(), notes: form.notes || undefined,
                exclusions: form.exclusions.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean),
                ...(form.windowed ? { scan_windows: { tz: form.tz, windows: [{ days: form.days, start: form.start, end: form.end }] } } : {}),
                ...(form.max_active_jobs ? { max_active_jobs: Number(form.max_active_jobs) } : {}),
            }),
        });
        const d = await r.json().catch(() => null);
        if (!r.ok) { setMsg(d?.error ?? `HTTP ${r.status}`); return; }
        setAdding(false);
        setForm((f) => ({ ...f, value: '', authorization_reference: '', notes: '' }));
        setMsg(d?.approval_required ? `Requested ${d.scope?.value}. It authorises nothing until the organisation's administrator approves it on the Scan Authorisation page.` : `Registered ${d?.scope?.value} for passive monitoring.`);
        reload();
    }

    async function revoke(s: Scope) {
        if (!window.confirm(`Revoke ${s.value}? Queued scans under it are cancelled and running ones stopped.`)) return;
        const r = await apiFetch(apiUrl(`/api/vms/scopes/${s.id}/revoke`), { method: 'POST' });
        const d = await r.json().catch(() => null);
        setMsg(r.ok ? `Revoked ${s.value}` : d?.error ?? `HTTP ${r.status}`);
        reload();
    }

    const input = 'w-full bg-card-muted border border-border rounded-lg px-3 py-2 text-xs text-foreground';
    const active = form.kind !== 'asn';
    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
                <div>
                    <h2 className="text-sm font-bold text-foreground flex items-center gap-2"><ShieldCheck className="w-4 h-4" /> Authorised Scope</h2>
                    <p className="text-xs text-foreground-muted">Nothing outside this list is ever scanned. Each entry records the authorisation that permits testing and when it expires; entries that permit scanning are approved by the organisation before they take effect.</p>
                </div>
                {canRequest && <button onClick={() => setAdding((a) => !a)} className="flex items-center gap-1.5 text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5"><Plus className="w-3.5 h-3.5" /> Request scope</button>}
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {msg && <p role="status" className="text-xs text-foreground font-semibold">{msg}</p>}
            {adding && (
                <div className="bg-card border border-border rounded-xl p-4 grid grid-cols-1 md:grid-cols-2 gap-3">
                    <label className="text-[11px] font-bold text-foreground-muted">Type
                        <select className={input} value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value as Scope['kind'] })}>
                            <option value="domain">Domain</option><option value="ip">IP address</option><option value="cidr">IP range (CIDR, /22 or smaller)</option><option value="asn">AS number (passive monitoring only)</option>
                        </select>
                    </label>
                    <label className="text-[11px] font-bold text-foreground-muted">Value
                        <input className={input} value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} placeholder={form.kind === 'domain' ? 'example.com' : form.kind === 'ip' ? '203.0.113.10' : form.kind === 'asn' ? 'AS64500' : '203.0.113.0/28'} />
                    </label>
                    <label className="text-[11px] font-bold text-foreground-muted md:col-span-2">Authorisation reference (required)
                        <input className={input} value={form.authorization_reference} onChange={(e) => setForm({ ...form, authorization_reference: e.target.value })} placeholder="e.g. Letter of authorisation LOA-2026-014 signed by the client's CISO on 12 Oct 2026" />
                    </label>
                    <label className="text-[11px] font-bold text-foreground-muted">Expires
                        <input type="date" className={input} value={form.expires_at} onChange={(e) => setForm({ ...form, expires_at: e.target.value })} />
                    </label>
                    <div className="space-y-1 text-[11px] text-foreground">
                        {form.kind === 'domain' && <label className="flex items-center gap-2"><input type="checkbox" checked={form.include_subdomains} onChange={(e) => setForm({ ...form, include_subdomains: e.target.checked })} /> Include subdomains</label>}
                        {active && <label className="flex items-center gap-2"><input type="checkbox" checked={form.allow_port_scan} onChange={(e) => setForm({ ...form, allow_port_scan: e.target.checked })} /> Allow port and service scanning</label>}
                        {active && <label className="flex items-center gap-2"><input type="checkbox" checked={form.allow_vuln_scan} onChange={(e) => setForm({ ...form, allow_vuln_scan: e.target.checked })} /> Allow vulnerability scanning</label>}
                        {active && <label className="text-[11px] font-bold text-foreground-muted md:col-span-2">Exclusions — never touched (hosts, .subdomains, IPs or CIDRs, comma-separated)
                            <input className={input} value={form.exclusions} onChange={(e) => setForm({ ...form, exclusions: e.target.value })} placeholder="payments.example.com, .legacy.example.com, 203.0.113.7" />
                        </label>}
                    </div>
                    {active && (
                        <fieldset className="md:col-span-2 border border-border rounded-lg p-3 space-y-2">
                            <legend className="text-[11px] font-bold text-foreground-muted px-1">Scan windows and limits (approved with the scope)</legend>
                            <label className="flex items-center gap-2 text-[11px] text-foreground"><input type="checkbox" checked={form.windowed} onChange={(e) => setForm({ ...form, windowed: e.target.checked })} /> Scan only inside a window (otherwise any time)</label>
                            {form.windowed && (
                                <div className="flex flex-wrap items-end gap-3">
                                    <div role="group" aria-label="Days" className="flex gap-1">
                                        {[1, 2, 3, 4, 5, 6, 7].map((d) => (
                                            <label key={d} className="flex items-center gap-1 text-[11px]"><input type="checkbox" checked={form.days.includes(d)} onChange={(e) => setForm({ ...form, days: e.target.checked ? [...form.days, d].sort() : form.days.filter((x) => x !== d) })} />{DAY[d]}</label>
                                        ))}
                                    </div>
                                    <label className="text-[11px] font-bold text-foreground-muted">From<input type="time" className={input} value={form.start} onChange={(e) => setForm({ ...form, start: e.target.value })} /></label>
                                    <label className="text-[11px] font-bold text-foreground-muted">Until<input type="time" className={input} value={form.end} onChange={(e) => setForm({ ...form, end: e.target.value })} /></label>
                                    <label className="text-[11px] font-bold text-foreground-muted">Time zone<input className={input} value={form.tz} onChange={(e) => setForm({ ...form, tz: e.target.value })} /></label>
                                    <p className="text-[10.5px] text-foreground-muted w-full">A window that ends before it starts runs past midnight. Scans queued outside a window wait for the next one; a running scan finishes.</p>
                                </div>
                            )}
                            <label className="text-[11px] font-bold text-foreground-muted block max-w-xs">Most scans at once under this entry (1–20, optional)
                                <input type="number" min={1} max={20} className={input} value={form.max_active_jobs} onChange={(e) => setForm({ ...form, max_active_jobs: e.target.value })} placeholder="platform default" />
                            </label>
                        </fieldset>
                    )}
                    <label className="text-[11px] font-bold text-foreground-muted md:col-span-2">Notes
                        <input className={input} value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} placeholder="Contacts, change tickets" />
                    </label>
                    <p className="md:col-span-2 text-[11px] text-foreground-muted">{active ? 'This entry permits active scanning, so it is sent to the organisation\'s administrator to approve with a declaration of authority. It authorises nothing until then.' : 'An AS number is registered for passive monitoring at once; it permits no traffic to the network.'}</p>
                    <div className="md:col-span-2 flex gap-2">
                        <button onClick={() => void save()} disabled={!form.value.trim() || form.authorization_reference.trim().length < 3 || (form.windowed && !form.days.length)} className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5 disabled:opacity-50">{active ? 'Send for approval' : 'Register'}</button>
                        <button onClick={() => setAdding(false)} className="text-[11px] font-bold text-foreground border border-border rounded-lg px-3 py-1.5">Cancel</button>
                    </div>
                </div>
            )}
            {scopes && scopes.length === 0 && <p className="text-sm text-foreground-muted text-center py-10 bg-card border border-border rounded-xl">No data — no scope has been requested or authorised yet.</p>}
            {scopes && scopes.length > 0 && (
                <div className="bg-card border border-border rounded-xl overflow-x-auto">
                    <table className="w-full text-xs">
                        <thead><tr className="text-left text-foreground-muted border-b border-border">
                            <th className="p-3">Target</th><th>Allows</th><th>Authorisation</th><th>Approved</th><th>Windows</th><th>Expires</th><th>Status</th><th />
                        </tr></thead>
                        <tbody>
                            {scopes.map((s) => (
                                <tr key={s.id} className="border-b border-border last:border-0 align-top">
                                    <td className="p-3 font-mono">{s.value}{s.kind === 'domain' && s.include_subdomains ? ' (+ subdomains)' : ''}{(s.exclusions ?? []).length ? <span className="block text-amber font-sans">excluding {(s.exclusions ?? []).join(', ')}</span> : null}</td>
                                    <td className="py-3">{s.allow_discovery === false ? 'Passive only' : 'Discovery'}{s.allow_port_scan ? ', ports' : ''}{s.allow_vuln_scan ? ', vulnerabilities' : ''}</td>
                                    <td className="py-3 max-w-xs">{s.authorization_reference}{s.requested_by && <span className="block text-foreground-muted">requested by {s.requested_by}</span>}</td>
                                    <td className="py-3">{s.approved_by ?? '—'}<br /><span className="text-foreground-muted">{s.approved_at ? fmtWat(s.approved_at) : ''}{s.approval_method ? ` · ${METHOD_LABEL[s.approval_method] ?? s.approval_method}` : ''}</span></td>
                                    <td className="py-3 text-foreground-muted">{describeWindows(s.scan_windows)}{s.max_active_jobs ? <span className="block">at most {s.max_active_jobs} at once</span> : null}</td>
                                    <td className={`py-3 ${expired(s) && s.status === 'active' ? 'text-red font-bold' : ''}`}>{fmtWat(s.expires_at)}</td>
                                    <td className="py-3"><StatusCell s={s} /></td>
                                    <td className="py-3 pr-3 text-right">{canRevoke && s.status === 'active' && <button onClick={() => void revoke(s)} className="text-[11px] font-bold text-red">Revoke</button>}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}
