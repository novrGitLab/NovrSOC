'use client';

// Authorised scope (phase P4) — the only targets VMS may ever touch. A soc_manager / super_admin
// records each entry with the authorisation that permits testing (contract, letter of
// authorisation, ticket) and an expiry; the backend enforces who may do this. Revoking an entry
// cancels its queued scans and stops running ones.

import { useCallback, useEffect, useState } from 'react';
import { ShieldCheck, Plus } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { getAdminUser } from '@/lib/admin-auth';
import { loadJson } from '@/lib/alerts';
import { fmtWat, type VmsScope as Scope } from '@/lib/vms';

/** An active entry past its expiry covers nothing. */
function expired(s: Scope): boolean {
    return Date.parse(s.expires_at) <= Date.now();
}

const inThreeMonths = () => new Date(Date.now() + 90 * 86_400_000).toISOString().slice(0, 10);

export function VmsScope() {
    const role = getAdminUser().role;
    const canApprove = role === 'super_admin' || role === 'soc_manager';
    const [scopes, setScopes] = useState<Scope[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [msg, setMsg] = useState<string | null>(null);
    const [adding, setAdding] = useState(false);
    const [form, setForm] = useState({ kind: 'domain' as Scope['kind'], value: '', include_subdomains: true, allow_port_scan: false, allow_vuln_scan: false, authorization_reference: '', expires_at: inThreeMonths(), notes: '' });
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
            body: JSON.stringify({ ...form, expires_at: new Date(`${form.expires_at}T23:59:59Z`).toISOString(), notes: form.notes || undefined }),
        });
        const d = await r.json().catch(() => null);
        if (!r.ok) { setMsg(d?.error ?? `HTTP ${r.status}`); return; }
        setAdding(false);
        setForm((f) => ({ ...f, value: '', authorization_reference: '', notes: '' }));
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
    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
                <div>
                    <h1 className="text-lg font-black text-foreground flex items-center gap-2"><ShieldCheck className="w-5 h-5" /> Authorised Scope</h1>
                    <p className="text-xs text-foreground-muted">Nothing outside this list is ever scanned. Each entry records the authorisation that permits testing and when it expires.</p>
                </div>
                {canApprove && <button onClick={() => setAdding((a) => !a)} className="flex items-center gap-1.5 text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5"><Plus className="w-3.5 h-3.5" /> Add scope</button>}
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {msg && <p role="status" className="text-xs text-foreground font-semibold">{msg}</p>}
            {adding && (
                <div className="bg-card border border-border rounded-xl p-4 grid grid-cols-1 md:grid-cols-2 gap-3">
                    <label className="text-[11px] font-bold text-foreground-muted">Type
                        <select className={input} value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value as Scope['kind'] })}>
                            <option value="domain">Domain</option><option value="ip">IP address</option><option value="cidr">IP range (CIDR, /22 or smaller)</option>
                        </select>
                    </label>
                    <label className="text-[11px] font-bold text-foreground-muted">Value
                        <input className={input} value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} placeholder={form.kind === 'domain' ? 'example.com' : form.kind === 'ip' ? '203.0.113.10' : '203.0.113.0/28'} />
                    </label>
                    <label className="text-[11px] font-bold text-foreground-muted md:col-span-2">Authorisation reference (required)
                        <input className={input} value={form.authorization_reference} onChange={(e) => setForm({ ...form, authorization_reference: e.target.value })} placeholder="e.g. Letter of authorisation LOA-2026-014 signed by the client's CISO on 12 Oct 2026" />
                    </label>
                    <label className="text-[11px] font-bold text-foreground-muted">Expires
                        <input type="date" className={input} value={form.expires_at} onChange={(e) => setForm({ ...form, expires_at: e.target.value })} />
                    </label>
                    <div className="space-y-1 text-[11px] text-foreground">
                        {form.kind === 'domain' && <label className="flex items-center gap-2"><input type="checkbox" checked={form.include_subdomains} onChange={(e) => setForm({ ...form, include_subdomains: e.target.checked })} /> Include subdomains</label>}
                        <label className="flex items-center gap-2"><input type="checkbox" checked={form.allow_port_scan} onChange={(e) => setForm({ ...form, allow_port_scan: e.target.checked })} /> Allow port and service scanning</label>
                        <label className="flex items-center gap-2"><input type="checkbox" checked={form.allow_vuln_scan} onChange={(e) => setForm({ ...form, allow_vuln_scan: e.target.checked })} /> Allow vulnerability scanning</label>
                    </div>
                    <label className="text-[11px] font-bold text-foreground-muted md:col-span-2">Notes
                        <input className={input} value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} placeholder="Testing windows, contacts, exclusions" />
                    </label>
                    <div className="md:col-span-2 flex gap-2">
                        <button onClick={() => void save()} disabled={!form.value.trim() || form.authorization_reference.trim().length < 3} className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5 disabled:opacity-50">Approve scope</button>
                        <button onClick={() => setAdding(false)} className="text-[11px] font-bold text-foreground border border-border rounded-lg px-3 py-1.5">Cancel</button>
                    </div>
                </div>
            )}
            {scopes && scopes.length === 0 && <p className="text-sm text-foreground-muted text-center py-10 bg-card border border-border rounded-xl">No data — no scope has been authorised yet.</p>}
            {scopes && scopes.length > 0 && (
                <div className="bg-card border border-border rounded-xl overflow-x-auto">
                    <table className="w-full text-xs">
                        <thead><tr className="text-left text-foreground-muted border-b border-border">
                            <th className="p-3">Target</th><th>Allows</th><th>Authorisation</th><th>Approved</th><th>Expires</th><th>Status</th><th />
                        </tr></thead>
                        <tbody>
                            {scopes.map((s) => (
                                <tr key={s.id} className="border-b border-border last:border-0 align-top">
                                    <td className="p-3 font-mono">{s.value}{s.kind === 'domain' && s.include_subdomains ? ' (+ subdomains)' : ''}</td>
                                    <td className="py-3">Discovery{s.allow_port_scan ? ', ports' : ''}{s.allow_vuln_scan ? ', vulnerabilities' : ''}</td>
                                    <td className="py-3 max-w-xs">{s.authorization_reference}</td>
                                    <td className="py-3">{s.approved_by}<br /><span className="text-foreground-muted">{fmtWat(s.approved_at)}</span></td>
                                    <td className={`py-3 ${expired(s) && s.status === 'active' ? 'text-red font-bold' : ''}`}>{fmtWat(s.expires_at)}</td>
                                    <td className="py-3">{s.status === 'revoked' ? `Revoked by ${s.revoked_by}` : expired(s) ? 'Expired' : 'Active'}</td>
                                    <td className="py-3 pr-3 text-right">{canApprove && s.status === 'active' && <button onClick={() => void revoke(s)} className="text-[11px] font-bold text-red">Revoke</button>}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}
