'use client';

// Wazuh Groups — super_admin view of which organisation owns each Wazuh agent group, and of the
// alerts held in quarantine because their group isn't mapped (phase P1). Mapping a group here
// replays its quarantined alerts into that organisation. Reads and writes
// /api/admin/wazuh-group-map; the backend enforces super_admin. Quarantined alert content is
// never shown — only per-group counts.
//
// Syslog sources (phase P24): syslog the Wazuh manager receives itself — OPNsense over WireGuard
// to UDP 514 — arrives as agent 000 with no group. Its owner is set by sender address here
// (/api/admin/wazuh-group-map/sources); mapping a sender replays its quarantined alerts. Only map
// addresses that reach the manager over an authenticated path (WireGuard), never the open internet.

import { useCallback, useEffect, useState } from 'react';
import { RefreshCw, ShieldAlert, Network } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { getAdminUser } from '@/lib/admin-auth';
import { loadJson } from '@/lib/alerts';

interface Mapping { wazuh_group: string; org_id: string; created_at: string }
interface QGroup { wazuh_group: string; alerts: number; oldest: string; newest: string; reason: string }
interface QSource { location: string; alerts: number; oldest: string; newest: string }
interface Source { location: string; org_id: string; device_name: string | null; device_type: string; created_at: string }
interface Org { slug: string; name: string }

const fmt = (iso: string) => new Intl.DateTimeFormat('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }).format(new Date(iso)) + ' WAT';

export function WazuhGroups() {
    const isSuperAdmin = getAdminUser().role === 'super_admin';
    const [mappings, setMappings] = useState<Mapping[] | null>(null);
    const [quarantine, setQuarantine] = useState<{ total: number; groups: QGroup[]; sources?: QSource[] } | null>(null);
    const [sources, setSources] = useState<Source[] | null>(null);
    const [srcError, setSrcError] = useState<string | null>(null);
    const [newSource, setNewSource] = useState({ location: '', org_id: '', device_name: '' });
    const [qError, setQError] = useState<string | null>(null);
    const [orgs, setOrgs] = useState<Org[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [msg, setMsg] = useState<string | null>(null);
    const [choice, setChoice] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const [reloadKey, setReloadKey] = useState(0);
    const reload = useCallback(() => setReloadKey((k) => k + 1), []);

    useEffect(() => {
        if (!isSuperAdmin) return;
        let active = true;
        void Promise.all([
            loadJson<{ mappings: Mapping[] }>('/api/admin/wazuh-group-map'),
            loadJson<{ total: number; groups: QGroup[]; sources?: QSource[] }>('/api/admin/wazuh-group-map/quarantine'),
            loadJson<{ organisations: Org[] }>('/api/organisations'),
            loadJson<{ sources: Source[] }>('/api/admin/wazuh-group-map/sources'),
        ]).then(([m, q, o, s]) => {
            if (!active) return;
            setMappings(m.ok ? m.data.mappings : null);
            setError(m.ok ? null : m.error);
            setQuarantine(q.ok ? q.data : null);
            setQError(q.ok ? null : q.error);
            setOrgs(o.ok ? o.data.organisations.map((x) => ({ slug: x.slug, name: x.name })) : []);
            setSources(s.ok ? s.data.sources : null);
            setSrcError(s.ok ? null : s.error);
        });
        return () => { active = false; };
    }, [isSuperAdmin, reloadKey]);

    async function send(method: string, path: string, body?: unknown) {
        setBusy(true);
        setMsg(null);
        try {
            const r = await apiFetch(apiUrl(path), { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
            const d = await r.json().catch(() => null);
            if (!r.ok) { setMsg(d?.error ?? `HTTP ${r.status}`); return; }
            const rp = d?.replay ?? d;
            if (rp && typeof rp.replayed === 'number') setMsg(`Replayed ${rp.replayed} alert(s); ${rp.duplicates} already stored; ${rp.still_quarantined} still quarantined.`);
            else if (rp?.error) setMsg(`Mapping saved, but replay failed: ${rp.error}`);
            else setMsg('Saved.');
        } catch {
            setMsg('Could not reach the backend');
        } finally {
            setBusy(false);
            reload();
        }
    }

    if (!isSuperAdmin) {
        return (
            <div className="bg-card border border-border rounded-xl p-8 text-center">
                <ShieldAlert className="w-8 h-8 text-foreground-muted mx-auto mb-2" />
                <p className="text-sm font-bold text-foreground">Super admin only</p>
            </div>
        );
    }

    const orgName = new Map(orgs.map((o) => [o.slug, o.name]));
    return (
        <div className="space-y-5">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-lg font-black text-foreground">Monitoring Groups</h1>
                    <p className="text-xs text-foreground-muted">Which organisation owns each monitoring agent group and syslog sender. Alerts nothing maps are held in quarantine for 14 days.</p>
                </div>
                <button onClick={reload} className="flex items-center gap-1.5 text-[11px] font-bold text-foreground-muted hover:text-foreground border border-border rounded-lg px-3 py-1.5">
                    <RefreshCw className="w-3.5 h-3.5" /> Refresh
                </button>
            </div>
            {error && <p role="alert" className="text-xs text-red-500 font-semibold">{error}</p>}
            {msg && <p className="text-xs text-foreground font-semibold">{msg}</p>}

            <div className="bg-card border border-border rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                    <h2 className="text-sm font-black text-foreground">Quarantined alerts</h2>
                    {!!quarantine?.total && (
                        <button disabled={busy} onClick={() => void send('POST', '/api/admin/wazuh-group-map/quarantine/replay')} className="text-[11px] font-bold text-foreground border border-border rounded-lg px-3 py-1.5 hover:bg-card-muted disabled:opacity-50">
                            Replay now
                        </button>
                    )}
                </div>
                {qError && <p className="text-xs text-red-500 font-semibold">{qError}</p>}
                {quarantine && quarantine.total === 0 && <p className="text-xs text-foreground-muted">No data — no alerts are in quarantine.</p>}
                {quarantine && (quarantine.sources?.length ?? 0) > 0 && (
                    <table className="w-full text-xs">
                        <thead><tr className="text-left text-foreground-muted"><th className="py-1">Syslog sender</th><th>Alerts</th><th>Oldest</th><th>Newest</th><th>Map to</th></tr></thead>
                        <tbody>
                            {quarantine.sources!.map((s) => (
                                <tr key={s.location} className="border-t border-border">
                                    <td className="py-2 font-mono">{s.location}</td>
                                    <td>{s.alerts.toLocaleString()}</td>
                                    <td>{fmt(s.oldest)}</td>
                                    <td>{fmt(s.newest)}</td>
                                    <td>
                                        {s.location === '(no sender address)' ? <span className="text-foreground-muted">No sender address recorded</span> : (
                                            <div className="flex gap-2">
                                                <select aria-label={`Organisation for ${s.location}`} value={choice[`src:${s.location}`] ?? ''} onChange={(e) => setChoice((c) => ({ ...c, [`src:${s.location}`]: e.target.value }))} className="bg-card border border-border rounded px-2 py-1">
                                                    <option value="">Choose…</option>
                                                    {orgs.map((o) => <option key={o.slug} value={o.slug}>{o.name}</option>)}
                                                </select>
                                                <button disabled={busy || !choice[`src:${s.location}`]} onClick={() => void send('PUT', '/api/admin/wazuh-group-map/sources', { sources: [{ location: s.location, org_id: choice[`src:${s.location}`] }] })} className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1 disabled:opacity-50">
                                                    Map
                                                </button>
                                            </div>
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
                {quarantine && quarantine.groups.length > 0 && (
                    <table className="w-full text-xs">
                        <thead><tr className="text-left text-foreground-muted"><th className="py-1">Group</th><th>Alerts</th><th>Oldest</th><th>Newest</th><th>Map to</th></tr></thead>
                        <tbody>
                            {quarantine.groups.map((g) => (
                                <tr key={g.wazuh_group} className="border-t border-border">
                                    <td className="py-2 font-mono">{g.wazuh_group}{g.reason === 'ambiguous_org' && <span className="ml-2 text-[10px] text-amber-600">maps to several orgs</span>}</td>
                                    <td>{g.alerts.toLocaleString()}</td>
                                    <td>{fmt(g.oldest)}</td>
                                    <td>{fmt(g.newest)}</td>
                                    <td>
                                        {g.wazuh_group === '(no group)' ? <span className="text-foreground-muted">Assign the agent to a group in Wazuh</span> : (
                                            <div className="flex gap-2">
                                                <select aria-label={`Organisation for ${g.wazuh_group}`} value={choice[g.wazuh_group] ?? ''} onChange={(e) => setChoice((c) => ({ ...c, [g.wazuh_group]: e.target.value }))} className="bg-card border border-border rounded px-2 py-1">
                                                    <option value="">Choose…</option>
                                                    {orgs.map((o) => <option key={o.slug} value={o.slug}>{o.name}</option>)}
                                                </select>
                                                <button disabled={busy || !choice[g.wazuh_group]} onClick={() => void send('PUT', '/api/admin/wazuh-group-map', { mappings: [{ wazuh_group: g.wazuh_group, org_id: choice[g.wazuh_group] }] })} className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1 disabled:opacity-50">
                                                    Map
                                                </button>
                                            </div>
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            <div className="bg-card border border-border rounded-xl p-4 space-y-3">
                <div>
                    <h2 className="text-sm font-black text-foreground flex items-center gap-2"><Network className="w-4 h-4" /> Syslog sources</h2>
                    <p className="text-[11px] text-foreground-muted">Firewalls and other devices that send syslog straight to the Wazuh manager (e.g. OPNsense over WireGuard to UDP 514). Their alerts are matched by the sender address Wazuh records as <span className="font-mono">location</span>. Map only addresses that reach the manager over an authenticated path.</p>
                </div>
                {srcError && <p className="text-xs text-red-500 font-semibold">{srcError}</p>}
                {sources === null && !srcError && <div className="h-10 bg-card-muted rounded animate-pulse" />}
                {sources && sources.length === 0 && <p className="text-xs text-foreground-muted">No data — no syslog sender is mapped, so their alerts are quarantined.</p>}
                {sources && sources.length > 0 && (
                    <table className="w-full text-xs">
                        <thead><tr className="text-left text-foreground-muted"><th className="py-1">Sender</th><th>Device</th><th>Organisation</th><th>Since</th><th /></tr></thead>
                        <tbody>
                            {sources.map((s) => (
                                <tr key={s.location} className="border-t border-border">
                                    <td className="py-2 font-mono">{s.location}</td>
                                    <td>{s.device_name ?? '—'} <span className="text-foreground-muted">({s.device_type})</span></td>
                                    <td>{orgName.get(s.org_id) ?? s.org_id}</td>
                                    <td>{fmt(s.created_at)}</td>
                                    <td className="text-right">
                                        <button disabled={busy} onClick={() => { if (window.confirm(`Unmap ${s.location}? Its future alerts will be quarantined.`)) void send('PUT', '/api/admin/wazuh-group-map/sources', { sources: [{ location: s.location, org_id: null }] }); }} className="text-[11px] font-bold text-red-500 disabled:opacity-50">
                                            Unmap
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
                <form className="flex flex-wrap items-center gap-2" onSubmit={(e) => {
                    e.preventDefault();
                    void send('PUT', '/api/admin/wazuh-group-map/sources', { sources: [{ location: newSource.location.trim(), org_id: newSource.org_id, device_name: newSource.device_name.trim() || null }] });
                    setNewSource({ location: '', org_id: '', device_name: '' });
                }}>
                    <input value={newSource.location} onChange={(e) => setNewSource((s) => ({ ...s, location: e.target.value }))} placeholder="Sender IP, e.g. 10.0.0.4" aria-label="Sender IP address" maxLength={45} className="bg-card border border-border rounded px-2 py-1 text-xs font-mono w-44" />
                    <input value={newSource.device_name} onChange={(e) => setNewSource((s) => ({ ...s, device_name: e.target.value }))} placeholder="Device name (optional)" aria-label="Device name" maxLength={128} className="bg-card border border-border rounded px-2 py-1 text-xs w-44" />
                    <select aria-label="Organisation for the new sender" value={newSource.org_id} onChange={(e) => setNewSource((s) => ({ ...s, org_id: e.target.value }))} className="bg-card border border-border rounded px-2 py-1 text-xs">
                        <option value="">Organisation…</option>
                        {orgs.map((o) => <option key={o.slug} value={o.slug}>{o.name}</option>)}
                    </select>
                    <button type="submit" disabled={busy || !newSource.location.trim() || !newSource.org_id} className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1 disabled:opacity-50">Map sender</button>
                </form>
            </div>

            <div className="bg-card border border-border rounded-xl p-4 space-y-2">
                <h2 className="text-sm font-black text-foreground flex items-center gap-2"><Network className="w-4 h-4" /> Mapped groups</h2>
                {mappings === null && !error && <div className="h-10 bg-card-muted rounded animate-pulse" />}
                {mappings && mappings.length === 0 && <p className="text-xs text-foreground-muted">No data — no group is mapped, so every alert is quarantined.</p>}
                {mappings && mappings.length > 0 && (
                    <table className="w-full text-xs">
                        <thead><tr className="text-left text-foreground-muted"><th className="py-1">Group</th><th>Organisation</th><th>Since</th><th /></tr></thead>
                        <tbody>
                            {mappings.map((m) => (
                                <tr key={m.wazuh_group} className="border-t border-border">
                                    <td className="py-2 font-mono">{m.wazuh_group}</td>
                                    <td>{orgName.get(m.org_id) ?? m.org_id}</td>
                                    <td>{fmt(m.created_at)}</td>
                                    <td className="text-right">
                                        <button disabled={busy} onClick={() => { if (window.confirm(`Unmap ${m.wazuh_group}? Its future alerts will be quarantined.`)) void send('PUT', '/api/admin/wazuh-group-map', { mappings: [{ wazuh_group: m.wazuh_group, org_id: null }] }); }} className="text-[11px] font-bold text-red-500 disabled:opacity-50">
                                            Unmap
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    );
}
