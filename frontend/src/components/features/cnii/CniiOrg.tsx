'use client';

// One organisation in CNII Watch (phase P9): its sector profile and history, its authorised scope
// (what may be monitored and how), passive collection, and its inventory with each asset's
// authorisation status, observations, findings (confirmed vs unconfirmed) and indicator matches.
// Staff act on the organisation through X-Org-Id, which the backend audits; client roles always
// see their own organisation, whatever the address says.

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { ArrowLeft, Building2, Plus, RefreshCw, AlertTriangle } from 'lucide-react';
import { getAdminUser } from '@/lib/admin-auth';
import { CNII_SECTORS, SECTOR_BY_ID } from '@/lib/cnii-sectors';
import { cniiGet, apiSend, timeAgo, permits, AUTH_STYLE, AUTH_LABEL, type CniiProfile, type CniiProfileEvent, type CniiScope, type CniiAsset, type OrgStats } from '@/lib/cnii-types';
import { fmtWat } from '@/lib/vms';

interface ProfileResp { organisation: { slug: string; name?: string }; profile: CniiProfile | null; history: CniiProfileEvent[]; scopes: CniiScope[]; stats: OrgStats; gaps: string[] }
type Level = 'passive' | 'discovery';
const inThreeMonths = () => new Date(Date.now() + 90 * 86_400_000).toISOString().slice(0, 10);

export function CniiOrg({ org }: { org: string }) {
    const role = getAdminUser().role;
    const isManager = role === 'super_admin' || role === 'soc_manager';
    const isStaff = isManager || role === 'analyst';
    const [data, setData] = useState<ProfileResp | null>(null);
    const [loadedAt, setLoadedAt] = useState(0);
    const [assets, setAssets] = useState<CniiAsset[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [msg, setMsg] = useState<string | null>(null);
    const [editing, setEditing] = useState(false);
    const [form, setForm] = useState({ sector_id: 'ict', subfield: '', designation: 'candidate' as 'candidate' | 'designated', designation_reference: '', notes: '' });
    const [adding, setAdding] = useState(false);
    const [scopeForm, setScopeForm] = useState({ kind: 'domain' as CniiScope['kind'], value: '', include_subdomains: true, level: 'passive' as Level, allow_port_scan: false, allow_vuln_scan: false, authorization_reference: '', expires_at: inThreeMonths(), notes: '' });
    const [reloadKey, setReloadKey] = useState(0);
    const reload = useCallback(() => setReloadKey((k) => k + 1), []);
    const send = isStaff ? org : undefined;

    useEffect(() => {
        let active = true;
        void Promise.all([cniiGet<ProfileResp>('/profile', send), cniiGet<{ assets: CniiAsset[] }>('/inventory', send)]).then(([p, i]) => {
            if (!active) return;
            setData(p.ok ? p.data : null);
            setLoadedAt(Date.now());
            setError(p.ok ? null : p.error);
            setAssets(i.ok ? i.data.assets : []);
            if (p.ok && p.data.profile) {
                const pr = p.data.profile;
                setForm({ sector_id: pr.sector_id, subfield: pr.subfield ?? '', designation: pr.designation, designation_reference: pr.designation_reference ?? '', notes: pr.notes ?? '' });
            }
        });
        return () => { active = false; };
    }, [reloadKey, send]);

    async function saveProfile() {
        const r = await apiSend('/api/cnii/profile', 'PUT', { sector_id: form.sector_id, subfield: form.subfield || null, designation: form.designation, designation_reference: form.designation_reference || null, notes: form.notes || null }, send);
        setMsg(r.ok ? 'Profile saved' : r.error);
        if (r.ok) { setEditing(false); reload(); }
    }
    async function addScope() {
        const f = scopeForm;
        const asn = f.kind === 'asn';
        const r = await apiSend('/api/vms/scopes', 'POST', {
            kind: f.kind, value: f.value, include_subdomains: f.kind === 'domain' ? f.include_subdomains : false,
            allow_discovery: !asn && f.level === 'discovery', allow_port_scan: !asn && f.level === 'discovery' && f.allow_port_scan, allow_vuln_scan: !asn && f.level === 'discovery' && f.allow_vuln_scan,
            authorization_reference: f.authorization_reference, expires_at: new Date(`${f.expires_at}T23:59:59Z`).toISOString(), notes: f.notes || undefined,
        }, send);
        setMsg(r.ok ? `Scope added: ${f.kind} ${f.value}` : r.error);
        if (r.ok) { setAdding(false); setScopeForm({ ...f, value: '', authorization_reference: '', notes: '' }); reload(); }
    }
    async function collect(s: CniiScope) {
        const r = await apiSend<{ existing: boolean }>('/api/cnii/collect', 'POST', { scope_id: s.id }, send);
        setMsg(r.ok ? (r.data.existing ? `Passive collection for ${s.value} is already queued` : `Passive collection queued for ${s.value}; results appear when the runner finishes`) : r.error);
    }

    const sector = data?.profile ? SECTOR_BY_ID[data.profile.sector_id] : null;
    const input = 'w-full bg-card-muted border border-border rounded-lg px-3 py-2 text-xs text-foreground';
    const now = loadedAt;
    return (
        <div className="space-y-4">
            <Link href={sector ? `/admin/cnii/${sector.id}` : '/admin/cnii'} className="text-[11px] text-foreground-muted flex items-center gap-1"><ArrowLeft className="w-3 h-3" /> {sector?.label ?? 'CNII Watch'}</Link>
            <div className="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <h1 className="text-lg font-black text-foreground flex items-center gap-2"><Building2 className="w-5 h-5" /> {data?.organisation.name ?? org}</h1>
                    <p className="text-xs text-foreground-muted">{data?.profile ? `${sector?.label ?? data.profile.sector_id}${data.profile.subfield ? ` · ${data.profile.subfield}` : ''} · ${data.profile.designation}${data.profile.designation_reference ? ` (${data.profile.designation_reference})` : ''}` : 'Not classified into a CNII sector'}</p>
                </div>
                <div className="flex items-center gap-2">
                    <Link href={`/admin/cnii/org/${org}/report`} className="text-[11px] font-semibold text-purple dark:text-[var(--vz-prog-4)]">Report →</Link>
                    {isManager && <button onClick={() => setEditing((e) => !e)} className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5">{data?.profile ? 'Change classification' : 'Classify'}</button>}
                </div>
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {msg && <p role="status" className="text-xs text-foreground font-semibold">{msg}</p>}
            {data?.gaps.length ? <p className="rounded-xl p-3 border border-amber/30 bg-amber/10 text-xs text-amber font-semibold flex items-center gap-2"><AlertTriangle className="w-4 h-4" /> {data.gaps.join('; ')}</p> : null}

            {editing && (
                <div className="bg-card border border-border rounded-xl p-4 grid grid-cols-1 md:grid-cols-2 gap-3">
                    <label className="text-[11px] font-bold text-foreground-muted">Sector
                        <select className={input} value={form.sector_id} onChange={(e) => setForm({ ...form, sector_id: e.target.value, subfield: '' })}>{CNII_SECTORS.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}</select>
                    </label>
                    <label className="text-[11px] font-bold text-foreground-muted">Sub-entity
                        <select className={input} value={form.subfield} onChange={(e) => setForm({ ...form, subfield: e.target.value })}><option value="">—</option>{(SECTOR_BY_ID[form.sector_id]?.subfields ?? []).map((s) => <option key={s} value={s}>{s}</option>)}</select>
                    </label>
                    <label className="text-[11px] font-bold text-foreground-muted">Designation
                        <select className={input} value={form.designation} onChange={(e) => setForm({ ...form, designation: e.target.value as 'candidate' | 'designated' })}><option value="candidate">Candidate (not formally designated)</option><option value="designated">Designated CNII</option></select>
                    </label>
                    <label className="text-[11px] font-bold text-foreground-muted">Designation reference {form.designation === 'designated' ? '(required)' : ''}
                        <input className={input} value={form.designation_reference} onChange={(e) => setForm({ ...form, designation_reference: e.target.value })} placeholder="Gazette, regulator letter or contract reference" />
                    </label>
                    <label className="text-[11px] font-bold text-foreground-muted md:col-span-2">Notes
                        <textarea className={input} value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} rows={2} />
                    </label>
                    <div className="md:col-span-2"><button onClick={() => void saveProfile()} className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5">Save</button></div>
                </div>
            )}

            <div className="bg-card border border-border rounded-xl p-4">
                <div className="flex items-center justify-between gap-2 mb-2">
                    <h2 className="text-sm font-bold text-foreground">Authorised scope</h2>
                    {isManager && <button onClick={() => setAdding((a) => !a)} className="flex items-center gap-1.5 text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5"><Plus className="w-3.5 h-3.5" /> Add scope</button>}
                </div>
                <p className="text-[11px] text-foreground-muted mb-3">Being linked to a critical-infrastructure organisation does not make an address or domain theirs, or authorise anything. Each entry records the authorisation behind it. &quot;Passive&quot; means third parties are asked about the target and nothing connects to it.</p>
                {adding && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4 border border-border rounded-lg p-3">
                        <label className="text-[11px] font-bold text-foreground-muted">Type
                            <select className={input} value={scopeForm.kind} onChange={(e) => setScopeForm({ ...scopeForm, kind: e.target.value as CniiScope['kind'] })}><option value="domain">Domain</option><option value="ip">IP address</option><option value="cidr">IP range (CIDR, /22 or smaller)</option><option value="asn">Autonomous system (passive only)</option></select>
                        </label>
                        <label className="text-[11px] font-bold text-foreground-muted">Value
                            <input className={input} value={scopeForm.value} onChange={(e) => setScopeForm({ ...scopeForm, value: e.target.value })} placeholder={scopeForm.kind === 'asn' ? 'AS37282' : scopeForm.kind === 'cidr' ? '203.0.113.0/28' : scopeForm.kind === 'ip' ? '203.0.113.10' : 'example.gov.ng'} />
                        </label>
                        {scopeForm.kind !== 'asn' && (
                            <label className="text-[11px] font-bold text-foreground-muted">Monitoring allowed
                                <select className={input} value={scopeForm.level} onChange={(e) => setScopeForm({ ...scopeForm, level: e.target.value as Level })}><option value="passive">Passive only (nothing connects to the target)</option><option value="discovery">Active checks by the scanner worker</option></select>
                            </label>
                        )}
                        {scopeForm.kind !== 'asn' && scopeForm.level === 'discovery' && (
                            <div className="text-[11px] text-foreground-muted flex flex-col gap-1 justify-center">
                                <label><input type="checkbox" checked={scopeForm.allow_port_scan} onChange={(e) => setScopeForm({ ...scopeForm, allow_port_scan: e.target.checked })} /> Port and service scanning</label>
                                <label><input type="checkbox" checked={scopeForm.allow_vuln_scan} onChange={(e) => setScopeForm({ ...scopeForm, allow_vuln_scan: e.target.checked })} /> Vulnerability scanning</label>
                            </div>
                        )}
                        {scopeForm.kind === 'domain' && <label className="text-[11px] text-foreground-muted"><input type="checkbox" checked={scopeForm.include_subdomains} onChange={(e) => setScopeForm({ ...scopeForm, include_subdomains: e.target.checked })} /> Include subdomains</label>}
                        <label className="text-[11px] font-bold text-foreground-muted">Authorisation reference (required)
                            <input className={input} value={scopeForm.authorization_reference} onChange={(e) => setScopeForm({ ...scopeForm, authorization_reference: e.target.value })} placeholder="Letter of authorisation, contract or mandate reference" />
                        </label>
                        <label className="text-[11px] font-bold text-foreground-muted">Expires
                            <input type="date" className={input} value={scopeForm.expires_at} onChange={(e) => setScopeForm({ ...scopeForm, expires_at: e.target.value })} />
                        </label>
                        <div className="md:col-span-2"><button onClick={() => void addScope()} className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5">Approve scope entry</button></div>
                    </div>
                )}
                {data && data.scopes.length === 0 && <p className="text-xs text-foreground-muted">No scope. Nothing about this organisation is monitored.</p>}
                {data && data.scopes.length > 0 && (
                    <div className="overflow-x-auto">
                        <table className="w-full text-xs">
                            <thead><tr className="text-left text-foreground-muted"><th className="py-1 pr-3">Entry</th><th className="pr-3">Allows</th><th className="pr-3">Authorisation</th><th className="pr-3">Expires</th><th className="pr-3">Status</th><th /></tr></thead>
                            <tbody>
                                {data.scopes.map((s) => {
                                    const live = s.status === 'active' && Date.parse(s.expires_at) > now;
                                    return (
                                        <tr key={s.id} className="border-t border-border">
                                            <td className="py-1.5 pr-3 font-mono text-foreground">{s.kind} {s.value}{s.kind === 'domain' && s.include_subdomains ? ' (+ subdomains)' : ''}</td>
                                            <td className="pr-3">{permits({ passive: true, discovery: s.allow_discovery !== false && s.kind !== 'asn', ports: s.allow_port_scan, vuln: s.allow_vuln_scan })}</td>
                                            <td className="pr-3">{s.authorization_reference}<p className="text-foreground-muted">by {s.approved_by}</p></td>
                                            <td className="pr-3">{fmtWat(s.expires_at)}</td>
                                            <td className="pr-3">{s.status === 'revoked' ? <span className="text-red">revoked</span> : live ? <span className="text-green">active</span> : <span className="text-amber">expired</span>}</td>
                                            <td className="text-right">{live && isStaff && <button onClick={() => void collect(s)} className="flex items-center gap-1 text-[11px] font-bold text-purple"><RefreshCw className="w-3 h-3" /> Collect now</button>}</td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
                {data?.stats.last_collection && <p className="text-[11px] text-foreground-muted mt-2">Last passive collection {timeAgo(data.stats.last_collection.at)} ({data.stats.last_collection.status}). Active scans and their schedules are under Vulnerability Management.</p>}
            </div>

            <div className="bg-card border border-border rounded-xl p-4">
                <h2 className="text-sm font-bold text-foreground mb-2">Inventory ({assets.length})</h2>
                {assets.length === 0 && <p className="text-xs text-foreground-muted">No assets yet. They appear after passive collection or an authorised scan.</p>}
                {assets.length > 0 && (
                    <div className="overflow-x-auto">
                        <table className="w-full text-xs">
                            <thead><tr className="text-left text-foreground-muted"><th className="py-1 pr-3">Asset</th><th className="pr-3">Authorisation</th><th className="pr-3">Observations</th><th className="pr-3">Findings</th><th className="pr-3">Indicator matches</th><th>Last seen</th></tr></thead>
                            <tbody>
                                {assets.map((a) => (
                                    <tr key={a.id} className="border-t border-border align-top">
                                        <td className="py-1.5 pr-3">
                                            <Link href={`/admin/cnii/org/${encodeURIComponent(org)}/asset/${a.id}`} className="font-mono font-semibold text-purple">{a.value}</Link>
                                            <p className="text-foreground-muted">{a.asset_type} · {a.exposure}{a.confidence === 'probable' ? ' · probable (reported by a passive source)' : ''}{a.status === 'gone' ? ' · gone' : ''}</p>
                                        </td>
                                        <td className="pr-3"><span className={`px-1.5 py-0.5 rounded font-bold ${AUTH_STYLE[a.authorisation.status]}`}>{AUTH_LABEL[a.authorisation.status]}</span>{a.authorisation.status === 'authorised' && <p className="text-foreground-muted mt-0.5">{permits(a.authorisation)}</p>}</td>
                                        <td className="pr-3">{Object.entries(a.observations).map(([k, n]) => `${k} ${n}`).join(', ') || '—'}</td>
                                        <td className="pr-3">{a.findings.open ? <>{a.findings.confirmed} confirmed{a.findings.unconfirmed ? <span className="text-amber">, {a.findings.unconfirmed} unconfirmed</span> : null}{a.findings.p1_p2 ? <span className="text-red font-bold"> · {a.findings.p1_p2} P1/P2</span> : null}</> : '—'}</td>
                                        <td className="pr-3">{a.indicator_matches || '—'}</td>
                                        <td>{timeAgo(a.last_seen)}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {data && data.history.length > 0 && (
                <div className="bg-card border border-border rounded-xl p-4">
                    <h2 className="text-sm font-bold text-foreground mb-2">Classification history</h2>
                    <ul className="text-xs space-y-1">{data.history.map((h) => <li key={h.id}>{fmtWat(h.at)} · {h.actor}: {h.from_value ? `${h.from_value.sector_id}/${h.from_value.designation} → ` : ''}{h.to_value.sector_id}/{h.to_value.designation}</li>)}</ul>
                </div>
            )}
        </div>
    );
}
