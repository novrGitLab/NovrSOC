'use client';

// CNII Scan Authorisations (managers). Separate from asset intake: confirming an asset as CNII never
// permits scanning. A manager reviews a confirmed asset, records the written authorisation, expiry and
// scan types, reviews the exact targets, and submits. The backend (/api/cnii/intake/:id/authorise,
// cnii:manage + vms:scope) writes exact VMS scope entries — a domain without subdomains, pinned to the
// addresses it resolves to at approval, plus single IPs — so every existing scope check enforces it.
// This page only shows and requests; it grants nothing by itself.

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { KeyRound, RefreshCw, X } from 'lucide-react';
import { getAdminUser } from '@/lib/admin-auth';
import { loadJson } from '@/lib/alerts';
import { cniiGet, apiSend } from '@/lib/cnii-types';
import { fmtWat, ASSESSMENT_STATUS_LABEL, type VmsAssessment } from '@/lib/vms';
import { authState, scanTypes, networkContext, gapsOf, daysUntil, type IntakeSubmission, type AuthKey } from '@/lib/cnii-intake';

interface Scope { id: string; kind: string; value: string; status: string; expires_at: string; origin?: string; cnii_submission_id?: string | null; pinned_addresses?: string[]; authorization_reference: string; allow_port_scan: boolean; allow_vuln_scan: boolean }
interface AuditEntry { id: string; timestamp: string; user: string; action: string; details?: string; resource_id?: string }
const GROUPS: { key: string; title: string; keys: AuthKey[]; empty: string }[] = [
    { key: 'awaiting', title: 'Awaiting scan authorisation', keys: ['awaiting'], empty: 'No confirmed CNII asset is waiting for authorisation.' },
    { key: 'approved', title: 'Authorised', keys: ['authorised'], empty: 'No active CNII scan authorisation.' },
    { key: 'ended', title: 'Expired or revoked', keys: ['expired', 'revoked'], empty: 'None.' },
    { key: 'vms', title: 'Covered by an existing VMS scope entry', keys: ['vms_scope'], empty: 'None.' },
];
const Badge = ({ text, style }: { text: string; style: string }) => <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded whitespace-nowrap ${style}`}>{text}</span>;

export function CniiAuthorisations() {
    const role = getAdminUser().role;
    const isManager = role === 'super_admin' || role === 'soc_manager';
    const params = useSearchParams();
    const [list, setList] = useState<IntakeSubmission[] | null>(null);
    const [err, setErr] = useState<string | null>(null);
    const [sel, setSel] = useState<string | null>(params.get('id'));
    const [tick, setTick] = useState(0);

    useEffect(() => {
        if (!isManager) return;
        let active = true;
        void cniiGet<{ submissions: IntakeSubmission[] }>('/intake?status=confirmed').then((r) => {
            if (!active) return;
            setList(r.ok ? r.data.submissions : null);
            setErr(r.ok ? null : r.status === 503 ? 'CNII intake is not set up on this server yet (migrations P17/P18 pending).' : r.error);
        });
        return () => { active = false; };
    }, [tick, isManager]);

    if (!isManager) return (
        <div className="bg-card border border-border rounded-xl p-6 text-sm">
            <p className="font-bold text-foreground">CNII Scan Authorisations are managed by SOC managers.</p>
            <p className="text-foreground-muted mt-1">Analysts can submit and review assets on the <Link href="/admin/cnii" className="text-purple font-bold">CNII Watch overview</Link>; a manager authorises scanning.</p>
        </div>
    );
    const grouped = (k: AuthKey[]) => (list ?? []).filter((s) => k.includes(authState(s).key));
    return (
        <div className="space-y-4">
            <div className="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <h1 className="text-lg font-black text-foreground flex items-center gap-2"><KeyRound className="w-5 h-5" /> CNII Scan Authorisations</h1>
                    <p className="text-xs text-foreground-muted max-w-3xl">Permission to scan a confirmed CNII asset, kept separate from confirming it. Each authorisation needs a written reference and evidence, an expiry within 90 days and the scan types allowed. It becomes exact VMS scope entries; a domain is pinned to its approved addresses and is not scanned if its DNS changes until it is re-approved.</p>
                </div>
                <button onClick={() => setTick((t) => t + 1)} className="flex items-center gap-1 text-[11px] font-bold text-purple"><RefreshCw className="w-3.5 h-3.5" /> Refresh</button>
            </div>
            {err && <p role="alert" className="text-xs text-red font-semibold">{err}</p>}
            {!list && !err && <div className="space-y-1">{[0, 1, 2].map((i) => <div key={i} className="h-8 bg-card-muted/60 rounded animate-pulse" />)}</div>}
            {sel && <AuthorisationDetail key={sel} id={sel} onClose={() => setSel(null)} onChanged={() => setTick((t) => t + 1)} />}
            {list && GROUPS.map((g) => {
                const rows = grouped(g.keys);
                if (g.key === 'vms' && !rows.length) return null;
                return (
                    <section key={g.key} className="bg-card border border-border rounded-xl p-4 text-xs space-y-2" aria-labelledby={`g-${g.key}`}>
                        <h2 id={`g-${g.key}`} className="text-sm font-bold text-foreground">{g.title} ({rows.length})</h2>
                        {rows.length === 0 ? <p className="text-foreground-muted">{g.empty}</p> : (
                            <div className="overflow-x-auto">
                                <table className="w-full min-w-[900px]">
                                    <thead><tr className="text-left text-[10px] uppercase text-foreground-muted border-b border-border">{['Asset', 'Status', 'Targets / pinned addresses', 'Reference and evidence', 'Scan types', 'Approved by', 'Approved', 'Expires', ''].map((h) => <th key={h} className="py-1.5 pr-3 font-bold">{h}</th>)}</tr></thead>
                                    <tbody>{rows.map((s) => {
                                        const a = s.authorisation; const st = authState(s);
                                        return (
                                            <tr key={s.id} className="border-b border-border/60 align-top">
                                                <td className="py-1.5 pr-3"><span className="font-mono font-bold">{s.value}</span><p className="text-[10px] text-foreground-muted">{s.org_id} · {s.sector_id ?? 'sector unknown'}</p></td>
                                                <td className="py-1.5 pr-3"><Badge text={st.label} style={st.style} /></td>
                                                <td className="py-1.5 pr-3 font-mono">{a ? <>{a.targets.join(', ')}{a.approved_addresses.length ? <p className="text-[10px] text-foreground-muted">pinned: {a.approved_addresses.join(', ')}</p> : null}</> : <span className="text-foreground-muted">{s.ips.join(', ') || '—'}</span>}</td>
                                                <td className="py-1.5 pr-3 max-w-xs">{a ? <><p className="font-semibold">{a.reference}</p><p className="text-foreground-muted line-clamp-2">{a.evidence}</p></> : '—'}</td>
                                                <td className="py-1.5 pr-3">{a ? scanTypes(a) : '—'}</td>
                                                <td className="py-1.5 pr-3">{a?.approved_by ?? '—'}</td>
                                                <td className="py-1.5 pr-3">{a ? fmtWat(a.approved_at) : '—'}</td>
                                                <td className="py-1.5 pr-3">{a ? fmtWat(a.expires_at) : '—'}{a?.revoked_at ? <p className="text-[10px] text-red">revoked {fmtWat(a.revoked_at)}</p> : null}</td>
                                                <td className="py-1.5"><button onClick={() => setSel(s.id)} className="text-[11px] font-bold text-purple whitespace-nowrap">{st.key === 'awaiting' || st.key === 'expired' || st.key === 'revoked' ? 'Review and authorise' : 'View'}</button></td>
                                            </tr>
                                        );
                                    })}</tbody>
                                </table>
                            </div>
                        )}
                    </section>
                );
            })}
        </div>
    );
}

interface Detail { submission: IntakeSubmission; organisation: { slug: string; name: string } | null; assessments: VmsAssessment[] }

function AuthorisationDetail({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
    const [d, setD] = useState<Detail | null>(null);
    const [err, setErr] = useState<string | null>(null);
    const [scopes, setScopes] = useState<Scope[] | null>(null);
    const [audit, setAudit] = useState<AuditEntry[] | null>(null);
    const [showAudit, setShowAudit] = useState(false);
    const [form, setForm] = useState({ reference: '', evidence: '', expires: '', ports: false, vuln: false, addresses: [] as string[] });
    const [reviewing, setReviewing] = useState(false);
    const [busy, setBusy] = useState(false);
    const [result, setResult] = useState<{ text: string; error: boolean } | null>(null);
    const [revokeReason, setRevokeReason] = useState('');
    const [tick, setTick] = useState(0);

    useEffect(() => {
        let active = true;
        void cniiGet<Detail>(`/intake/${id}`).then((r) => {
            if (!active) return;
            setD(r.ok ? r.data : null); setErr(r.ok ? null : r.error);
            if (r.ok) setForm((f) => ({ ...f, addresses: f.addresses.length ? f.addresses : r.data.submission.resolution.addresses.filter((a) => a.public && !a.reserved).map((a) => a.ip) }));
        });
        return () => { active = false; };
    }, [id, tick]);
    const org = d?.submission.org_id ?? null;
    // The organisation's VMS scope entries for this asset (vms:read; staff act on the organisation with X-Org-Id).
    useEffect(() => {
        if (!org) return;
        let active = true;
        void loadJson<{ scopes: Scope[] }>('/api/vms/scopes', { headers: { 'X-Org-Id': org } }).then((r) => { if (active) setScopes(r.ok ? r.data.scopes : []); });
        return () => { active = false; };
    }, [org, tick]);
    // Recent audit entries for this asset (VMS Admin status: managers; the last 500 entries).
    useEffect(() => {
        if (!showAudit || !org) return;
        let active = true;
        void loadJson<{ audit: { entries: AuditEntry[] } }>('/api/vms/admin/status', { headers: { 'X-Org-Id': org } }).then((r) => { if (active) setAudit(r.ok ? r.data.audit.entries.filter((e) => e.resource_id === id) : []); });
        return () => { active = false; };
    }, [showAudit, org, id, tick]);

    const days = form.expires ? daysUntil(form.expires) : null;
    // Fixed when the panel opens: the date picker's range (today to 89 days ahead, within the 90-day maximum).
    const [{ today, maxDay }] = useState(() => { const n = new Date(); return { today: n.toISOString().slice(0, 10), maxDay: new Date(n.getTime() + 89 * 86_400_000).toISOString().slice(0, 10) }; });
    const box = 'border border-border rounded-lg p-3 space-y-1';
    if (err) return <div className={box}><p role="alert" className="text-xs text-red">{err}</p></div>;
    if (!d) return <div className={box}><p className="text-xs text-foreground-muted">Loading the asset…</p></div>;
    const s = d.submission;
    const st = authState(s);
    const a = s.authorisation;
    const current = s.resolution.addresses;
    const reserved = current.filter((x) => x.reserved);
    const related = (scopes ?? []).filter((x) => x.cnii_submission_id === s.id || x.value === s.value || s.ips.includes(x.value));
    const valid = form.reference.trim().length >= 3 && form.evidence.trim().length >= 10 && days !== null;
    const input = 'bg-card-muted border border-border rounded-lg px-2 py-1 text-xs text-foreground';

    async function submit() {
        if (busy || !valid) return;
        setBusy(true);
        const r = await apiSend<{ results: { target: string; outcome: string; detail?: string }[]; authorisation: { expires_at: string } }>(`/api/cnii/intake/${id}/authorise`, 'POST', {
            reference: form.reference.trim(), evidence: form.evidence.trim(), expires_days: days, allow_port_scan: form.ports, allow_vuln_scan: form.vuln,
            ...(s.kind === 'domain' ? { addresses: form.addresses } : {}),
        });
        setBusy(false);
        setReviewing(false);
        setResult(r.ok ? { text: `Authorised until ${fmtWat(r.data.authorisation.expires_at)}: ${r.data.results.map((x) => `${x.target} — ${x.outcome.replace(/_/g, ' ')}${x.detail ? ` (${x.detail})` : ''}`).join('; ')}.`, error: false } : { text: `Not authorised: ${r.error}`, error: true });
        setTick((t) => t + 1); onChanged();
    }
    async function revoke() {
        if (busy || revokeReason.trim().length < 5) return;
        setBusy(true);
        const r = await apiSend<{ revoked: string[] }>(`/api/cnii/intake/${id}/authorise/revoke`, 'POST', { reason: revokeReason.trim() });
        setBusy(false);
        setResult(r.ok ? { text: `Revoked: ${r.data.revoked.join(', ') || 'nothing was active'}. Its repeat schedules were stopped.`, error: false } : { text: r.error, error: true });
        setRevokeReason('');
        setTick((t) => t + 1); onChanged();
    }

    return (
        <section className="bg-card border-2 border-purple/30 rounded-xl p-4 space-y-3 text-xs" aria-label={`Authorisation for ${s.value}`}>
            <div className="flex items-start justify-between gap-2">
                <div>
                    <p className="text-sm font-black font-mono text-foreground">{s.value}</p>
                    <p className="text-foreground-muted">{s.kind === 'domain' ? 'Domain' : 'IP address'} · {d.organisation?.name ?? s.org_id} · {s.sector_id ?? 'sector unknown'} · <Badge text={st.label} style={st.style} /></p>
                </div>
                <button onClick={onClose} aria-label="Close"><X className="w-4 h-4" /></button>
            </div>
            {result && <p role={result.error ? 'alert' : 'status'} className={`font-semibold ${result.error ? 'text-red' : 'text-green'}`}>{result.text}</p>}

            <div className="grid md:grid-cols-2 gap-3">
                <div className={box}>
                    <p className="text-[10px] font-bold uppercase text-foreground-muted">1. Identity and evidence</p>
                    <p>{s.reason}</p>
                    <p><span className="text-foreground-muted">Network operator:</span> {networkContext(s)}</p>
                    <p><span className="text-foreground-muted">Resolved {fmtWat(s.resolution.resolved_at)}:</span> <span className="font-mono">{current.map((x) => `${x.ip}${x.reserved ? ' (reserved)' : x.public ? '' : ' (private)'}`).join(', ') || 'no address'}</span></p>
                    {gapsOf(s).map((g) => <p key={g} className="text-amber">• {g}</p>)}
                </div>
                <div className={box}>
                    <p className="text-[10px] font-bold uppercase text-foreground-muted">2. Existing VMS scope in {s.org_id}</p>
                    {scopes === null ? <p className="text-foreground-muted">Loading…</p> : related.length === 0 ? <p className="text-foreground-muted">No scope entry covers these values exactly.</p> : related.map((x) => (
                        <p key={x.id}><span className="font-mono">{x.kind} {x.value}</span> · {x.status}{x.status === 'active' ? ` until ${fmtWat(x.expires_at)}` : ''} · {x.origin === 'cnii' ? 'CNII approval' : 'VMS scope'} · ref {x.authorization_reference}{x.pinned_addresses?.length ? ` · pinned ${x.pinned_addresses.join(', ')}` : ''}</p>
                    ))}
                    <p><span className="text-foreground-muted">Latest assessment:</span> {d.assessments[0] ? `${ASSESSMENT_STATUS_LABEL[d.assessments[0].status]} (${fmtWat(d.assessments[0].requested_at)})` : 'none'}</p>
                </div>
            </div>

            {a && (
                <div className={box}>
                    <p className="text-[10px] font-bold uppercase text-foreground-muted">Current authorisation</p>
                    <p>Reference <span className="font-semibold">{a.reference}</span> · {scanTypes(a)} · approved by {a.approved_by} on {fmtWat(a.approved_at)} · expires {fmtWat(a.expires_at)}{a.revoked_at ? ` · revoked by ${a.revoked_by} on ${fmtWat(a.revoked_at)}${a.revoke_reason ? ` (${a.revoke_reason})` : ''}` : ''}</p>
                    <p className="text-foreground-muted">Evidence: {a.evidence}</p>
                    <p>Targets: <span className="font-mono">{a.targets.join(', ')}</span>{a.approved_addresses.length ? <> · {s.value} pinned to <span className="font-mono">{a.approved_addresses.join(', ')}</span></> : null}</p>
                    {st.key === 'authorised' && (
                        <div className="flex flex-wrap gap-2 items-center pt-1">
                            <input className={`${input} flex-1 min-w-[220px]`} placeholder="Reason for revoking" value={revokeReason} onChange={(e) => setRevokeReason(e.target.value)} aria-label="Reason for revoking" />
                            <button disabled={busy || revokeReason.trim().length < 5} onClick={() => { if (window.confirm(`Revoke scanning of ${s.value}? Its scope entries are revoked and repeat schedules stopped.`)) void revoke(); }} className="text-[11px] font-bold text-white bg-red rounded-lg px-3 py-1 disabled:opacity-50">{busy ? 'Revoking…' : 'Revoke'}</button>
                        </div>
                    )}
                </div>
            )}

            {st.key !== 'vms_scope' && (
                <div className={box}>
                    <p className="text-[10px] font-bold uppercase text-foreground-muted">3. {a && st.key === 'authorised' ? 'Change or renew the authorisation' : 'Record the authorisation'}</p>
                    {reserved.length > 0 ? <p className="text-red">{s.value} resolves to a reserved address ({reserved.map((x) => x.ip).join(', ')}): it cannot be authorised.</p> : (
                        <>
                            <div className="grid md:grid-cols-2 gap-2">
                                <label className="space-y-0.5"><span className="text-foreground-muted">Written authorisation reference</span><input className={`${input} w-full`} value={form.reference} onChange={(e) => setForm({ ...form, reference: e.target.value })} placeholder="e.g. letter or contract number" /></label>
                                <label className="space-y-0.5"><span className="text-foreground-muted">Expiry date (at most 90 days)</span><input type="date" min={today} max={maxDay} className={`${input} w-full`} value={form.expires} onChange={(e) => setForm({ ...form, expires: e.target.value })} />{form.expires && days === null && <span className="text-red block">Choose a date from today to 90 days ahead</span>}</label>
                            </div>
                            <label className="block space-y-0.5"><span className="text-foreground-muted">Supporting evidence (who authorised, what was agreed)</span><textarea className={`${input} w-full h-14`} value={form.evidence} onChange={(e) => setForm({ ...form, evidence: e.target.value })} /></label>
                            <fieldset className="flex flex-wrap gap-3"><legend className="text-foreground-muted">Permitted scan types</legend>
                                <label className="flex items-center gap-1"><input type="checkbox" checked disabled /> Discovery (always included)</label>
                                <label className="flex items-center gap-1"><input type="checkbox" checked={form.ports} onChange={(e) => setForm({ ...form, ports: e.target.checked })} /> Port scan</label>
                                <label className="flex items-center gap-1"><input type="checkbox" checked={form.vuln} onChange={(e) => setForm({ ...form, vuln: e.target.checked })} /> Vulnerability checks (extended vulnerability scanning not enabled)</label>
                            </fieldset>
                            {s.kind === 'domain' && current.length > 0 && (
                                <fieldset className="flex flex-wrap gap-3"><legend className="text-foreground-muted">Addresses to authorise as single-IP targets</legend>
                                    {current.map((x) => <label key={x.ip} className="flex items-center gap-1 font-mono"><input type="checkbox" checked={form.addresses.includes(x.ip)} onChange={(e) => setForm({ ...form, addresses: e.target.checked ? [...form.addresses, x.ip] : form.addresses.filter((y) => y !== x.ip) })} />{x.ip}{x.public ? '' : ' (private)'}</label>)}
                                </fieldset>
                            )}
                            {!reviewing ? (
                                <button disabled={!valid} onClick={() => { setResult(null); setReviewing(true); }} className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1 disabled:opacity-50">Review targets</button>
                            ) : (
                                <div className="border border-purple/40 rounded-lg p-3 space-y-1 bg-purple/5">
                                    <p className="font-bold">4. Review before submitting</p>
                                    {s.kind === 'domain' && <p>• <span className="font-mono">{s.value}</span> — this name only (no subdomains), pinned to the addresses it resolves to when you submit (now <span className="font-mono">{current.map((x) => x.ip).join(', ')}</span>). If the DNS answer has changed since it was checked, the pinned set is the new answer.</p>}
                                    {(s.kind === 'ip' ? [s.value] : form.addresses).map((ip) => <p key={ip}>• <span className="font-mono">{ip}</span> — this address only</p>)}
                                    <p>• Allowed: Discovery{form.ports ? ', port scan' : ''}{form.vuln ? ', vulnerability checks' : ''} · until {form.expires} ({days} day{days === 1 ? '' : 's'}) · reference {form.reference.trim()}</p>
                                    <p className="text-foreground-muted">Existing VMS scope entries for the same values are left unchanged. No scan starts until someone runs an assessment.</p>
                                    <div className="flex gap-2">
                                        <button disabled={busy} onClick={() => void submit()} className="text-[11px] font-bold text-white bg-green rounded-lg px-3 py-1 disabled:opacity-50">{busy ? 'Submitting…' : 'Submit authorisation'}</button>
                                        <button disabled={busy} onClick={() => setReviewing(false)} className="text-[11px] font-bold border border-border rounded-lg px-3 py-1">Back</button>
                                    </div>
                                </div>
                            )}
                        </>
                    )}
                </div>
            )}

            <div className={box}>
                <div className="flex justify-between"><p className="text-[10px] font-bold uppercase text-foreground-muted">Audit history</p><button onClick={() => setShowAudit((v) => !v)} className="text-[11px] font-bold text-purple">{showAudit ? 'Hide' : 'Show'}</button></div>
                {showAudit && (audit === null ? <p className="text-foreground-muted">Loading…</p> : audit.length === 0 ? <p className="text-foreground-muted">No entries for this asset among the recent audit records.</p> : audit.map((e) => <p key={e.id}><span className="text-foreground-muted">{fmtWat(e.timestamp)}</span> · {e.action.replace(/_/g, ' ').toLowerCase()} · {e.user}{e.details ? ` — ${e.details}` : ''}</p>))}
            </div>
        </section>
    );
}
