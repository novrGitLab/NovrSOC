'use client';

// CNII Watch — asset intake and watch list (P17/P18 backend, UX refined).
//
// Workflow shown to the analyst: add an asset (no organisation needed) → the backend resolves and
// enriches it → review its classification and evidence → a manager confirms or rejects it → scan
// authorisation is managed separately (CNII Scan Authorisations page) → assessments and findings.
// Everything shown comes from the backend (/api/cnii/intake); facts, platform records, suggestions
// and human decisions are labelled apart, and anything missing is named rather than filled in.

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { Plus, RefreshCw, ShieldCheck, Play, CalendarClock, X } from 'lucide-react';
import { cniiGet, apiSend, timeAgo, type CniiProfile } from '@/lib/cnii-types';
import { ASSESSMENT_STATUS_LABEL, ASSESSMENT_STATUS_STYLE, STEP_STATUS_LABEL, fmtWat, type VmsAssessment } from '@/lib/vms';
import { AiPanel } from '@/components/shared/AiPanel';
import {
    MAX_BULK, intakeInputError, splitEntries, CNII_STATUS, reviewBasis, authState, scanTypes, sectorContext, networkContext, gapsOf, evidenceGroups,
    type IntakeSubmission, type IntakeStatus, type IntakeEvidence,
} from '@/lib/cnii-intake';

interface Finding { id: string; title: string; rule_id: string; cve_ids: string[]; scanner_severity: string; priority: string | null; status: string; asset_value: string; port: number | null; evidence_class: string; remediation: string | null; first_seen: string; last_seen: string; latest_evidence: { matched_at: string | null; observed_at: string } | null }
interface Schedule { id: string; targets: string[]; interval_hours: number; next_run_at: string; ends_at: string | null; enabled: boolean; last_run_at: string | null; last_result: string | null }
interface Detail { submission: IntakeSubmission; organisation: { slug: string; name: string } | null; assessments: VmsAssessment[]; findings: Finding[]; severity: Record<string, number>; schedules: Schedule[]; note: string | null }
export interface IntakeOrg { slug: string; name: string; profile: CniiProfile | null }
interface BulkResult { input: string; value?: string; outcome: string; error?: string; reason?: string; id?: string }

const OUTCOME: Record<string, { label: string; style: string }> = {
    confirmed: { label: 'Confirmed CNII', style: 'text-green' }, candidate: { label: 'Requires review', style: 'text-amber' }, rejected: { label: 'Not CNII', style: 'text-foreground-muted' },
    invalid: { label: 'Invalid', style: 'text-red' }, failed: { label: 'Failed — try again', style: 'text-red' }, duplicate: { label: 'Duplicate in this list', style: 'text-foreground-muted' },
};
const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_STYLE: Record<string, string> = { critical: 'text-red', high: 'text-red/80', medium: 'text-amber', low: 'text-blue', info: 'text-foreground-muted' };
const sevLine = (s: Record<string, number> | undefined) => SEV.filter((k) => s?.[k]).map((k) => <span key={k} className={`font-bold ${SEV_STYLE[k]}`}>{s![k]} {k}</span>);
const Badge = ({ text, style }: { text: string; style: string }) => <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded whitespace-nowrap ${style}`}>{text}</span>;
const STEPS = ['Add asset', 'Enrichment', 'CNII review', 'Scan authorisation', 'Assessment'];

export function CniiIntake({ orgs, isManager, canScan }: { orgs: IntakeOrg[]; isManager: boolean; canScan: boolean }) {
    const [value, setValue] = useState('');
    const [busy, setBusy] = useState(false);
    const [msg, setMsg] = useState<{ text: string; error: boolean } | null>(null);
    const [list, setList] = useState<IntakeSubmission[] | null>(null);
    const [listErr, setListErr] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const [tab, setTab] = useState<IntakeStatus | 'all'>('all');
    const [sel, setSel] = useState<string | null>(null);
    const [bulk, setBulk] = useState<BulkResult[] | null>(null);
    const [tick, setTick] = useState(0);
    const reload = useCallback(() => setTick((t) => t + 1), []);

    useEffect(() => {
        let active = true;
        void cniiGet<{ submissions: IntakeSubmission[] }>('/intake').then((r) => {
            if (!active) return;
            setList(r.ok ? r.data.submissions : null);
            setListErr(r.ok ? null : r.status === 503 ? 'Asset intake is not set up on this server yet (database migration P17 pending).' : r.error);
            setLoading(false);
        });
        return () => { active = false; };
    }, [tick]);

    async function submit(v: string) {
        if (busy) return;
        const entries = splitEntries(v);
        if (!entries.length) { setMsg({ text: 'Enter a domain or IP address', error: true }); return; }
        if (entries.length > MAX_BULK) { setMsg({ text: `At most ${MAX_BULK} entries at a time (you entered ${entries.length})`, error: true }); return; }
        if (entries.length === 1) { const e = intakeInputError(entries[0]); if (e) { setMsg({ text: e, error: true }); return; } }
        setBusy(true);
        setMsg({ text: entries.length > 1 ? `Checking ${entries.length} entries: resolving DNS and registry data…` : `Checking ${entries[0]}: resolving DNS and registry data…`, error: false });
        if (entries.length > 1) {
            const r = await apiSend<{ results: BulkResult[]; counts: Record<string, number> }>('/api/cnii/intake', 'POST', { values: entries });
            setBusy(false);
            if (!r.ok) { setMsg({ text: r.error, error: true }); return; }
            setBulk(r.data.results);
            setMsg({ text: `Enrichment complete for ${entries.length} entries: ${Object.entries(r.data.counts).map(([k, n]) => `${n} ${(OUTCOME[k]?.label ?? k).toLowerCase()}`).join(', ')}.`, error: false });
        } else {
            const r = await apiSend<{ submission: IntakeSubmission; created: boolean }>('/api/cnii/intake', 'POST', { value: entries[0] });
            setBusy(false);
            if (!r.ok) { setMsg({ text: r.error, error: true }); return; }
            setBulk(null);
            setMsg({ text: `${r.data.created ? 'Submitted' : 'Re-checked'} ${r.data.submission.value}: enrichment complete — ${CNII_STATUS[r.data.submission.status].label}.`, error: false });
            setSel(r.data.submission.id);
        }
        setValue('');
        reload();
    }

    const shown = (list ?? []).filter((s) => tab === 'all' || s.status === tab);
    const count = (s: IntakeStatus) => (list ?? []).filter((x) => x.status === s).length;
    const input = 'bg-card-muted border border-border rounded-lg px-3 py-2 text-xs text-foreground';
    const TABS: [IntakeStatus | 'all', string][] = [['all', `All (${list?.length ?? 0})`], ['candidate', `Unverified candidates (${count('candidate')})`], ['confirmed', `Confirmed CNII (${count('confirmed')})`], ['rejected', `Not CNII (${count('rejected')})`]];
    return (
        <section className="bg-card border border-border rounded-xl p-4 space-y-3" aria-labelledby="intake-title">
            <div>
                <h2 id="intake-title" className="text-sm font-bold text-foreground flex items-center gap-2"><ShieldCheck className="w-4 h-4" /> Asset intake and watch list</h2>
                <ol className="flex flex-wrap gap-1 mt-1 text-[10px] font-bold text-foreground-muted" aria-label="Workflow">
                    {STEPS.map((s, i) => <li key={s} className="bg-card-muted rounded px-2 py-0.5">{i + 1}. {s}</li>)}
                </ol>
                <p className="text-[11px] text-foreground-muted mt-1 max-w-3xl">Enter a domain or IP — no organisation needed. NovrSOC resolves it and looks up its network operator and existing authorised scope. Registry and DNS data describe the network, not who owns the asset: an asset becomes <span className="font-bold">Confirmed CNII</span> only from a designated operator&apos;s authorised scope or a manager&apos;s confirmation, and scanning needs a separate authorisation.</p>
            </div>

            <form onSubmit={(e) => { e.preventDefault(); void submit(value); }} className="flex flex-wrap gap-2 items-start">
                <textarea className={`${input} flex-1 min-w-[260px] h-[38px] min-h-[38px] resize-y`} placeholder={`portal.example.gov.ng, 196.x.x.x, 2001:db8::1 … (up to ${MAX_BULK}, separated by commas or new lines)`} value={value} onChange={(e) => setValue(e.target.value)} aria-label="Domains or IP addresses to add" maxLength={6400} />
                <button disabled={busy || !value.trim()} className="flex items-center gap-1.5 text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-2 disabled:opacity-50"><Plus className="w-3.5 h-3.5" /> {busy ? 'Checking…' : 'Add and check'}</button>
            </form>
            {msg && <p role={msg.error ? 'alert' : 'status'} className={`text-xs ${msg.error ? 'text-red font-semibold' : 'text-foreground'}`}>{msg.text}</p>}
            {bulk && (
                <div className="border border-border rounded-lg p-2 text-xs">
                    <div className="flex justify-between"><p className="text-[10px] font-bold uppercase text-foreground-muted">Results per entry</p><button onClick={() => setBulk(null)} aria-label="Close results"><X className="w-3.5 h-3.5" /></button></div>
                    {bulk.map((b, i) => (
                        <p key={i} className="py-0.5"><span className="font-mono">{b.value ?? b.input}</span> <span className={`font-bold text-[10px] uppercase ${OUTCOME[b.outcome]?.style ?? ''}`}>{OUTCOME[b.outcome]?.label ?? b.outcome}</span> <span className="text-foreground-muted">{b.error ?? b.reason ?? ''}</span>{b.id && <button onClick={() => setSel(b.id!)} className="ml-1 text-purple font-bold">open</button>}</p>
                    ))}
                </div>
            )}

            {sel && <IntakeDetail key={sel} id={sel} orgs={orgs} isManager={isManager} canScan={canScan} onChanged={reload} onRecheck={(v) => void submit(v)} onClose={() => setSel(null)} />}

            <div className="flex flex-wrap gap-1 bg-card-muted rounded-lg p-1 w-fit text-[11px] font-bold" role="tablist" aria-label="Filter by CNII status">
                {TABS.map(([t, label]) => <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)} className={`px-2.5 py-1 rounded-md ${tab === t ? 'bg-blue text-white' : 'text-foreground-muted'}`}>{label}</button>)}
                <button onClick={reload} className="px-2 text-foreground-muted" aria-label="Refresh list"><RefreshCw className="w-3.5 h-3.5" /></button>
            </div>
            {listErr && <p role="alert" className="text-xs text-red font-semibold">{listErr}</p>}
            {loading && !list && !listErr && <div className="space-y-1">{[0, 1, 2].map((i) => <div key={i} className="h-7 bg-card-muted/60 rounded animate-pulse" />)}</div>}
            {list && (shown.length === 0 ? <p className="text-xs text-foreground-muted">{list.length ? 'Nothing with this status.' : 'No assets yet. Add a domain or IP above to start.'}</p> : (
                <div className="overflow-x-auto">
                    <table className="w-full text-xs min-w-[900px]">
                        <thead><tr className="text-left text-[10px] uppercase text-foreground-muted border-b border-border">{['Asset', 'Type', 'Sector / network context', 'CNII status', 'Scan authorisation', 'Last assessment', 'Open findings', ''].map((h) => <th key={h} className="py-1.5 pr-3 font-bold">{h}</th>)}</tr></thead>
                        <tbody>
                            {shown.map((s) => {
                                const sc = sectorContext(s);
                                const au = authState(s);
                                return (
                                    <tr key={s.id} className={`border-b border-border/60 align-top ${sel === s.id ? 'bg-purple/5' : ''}`}>
                                        <td className="py-1.5 pr-3"><button onClick={() => setSel(s.id)} className="font-mono font-bold text-purple text-left">{s.value}</button>{s.ips.length > 0 && s.kind === 'domain' && <p className="font-mono text-[10px] text-foreground-muted">{s.ips.slice(0, 2).join(', ')}{s.ips.length > 2 ? ` +${s.ips.length - 2}` : ''}</p>}</td>
                                        <td className="py-1.5 pr-3">{s.kind === 'domain' ? 'Domain' : 'IP address'}</td>
                                        <td className="py-1.5 pr-3"><span className={sc.kind === 'confirmed' ? 'text-foreground font-semibold' : 'text-foreground-muted'}>{sc.text}</span><p className="text-[10px] text-foreground-muted">{networkContext(s)}</p></td>
                                        <td className="py-1.5 pr-3"><Badge text={CNII_STATUS[s.status].label} style={CNII_STATUS[s.status].style} />{s.org_id && s.status === 'confirmed' && <p className="text-[10px] text-foreground-muted">{s.org_id}</p>}</td>
                                        <td className="py-1.5 pr-3">{au.key === 'not_applicable' ? <span className="text-foreground-muted">—</span> : <Badge text={au.label} style={au.style} />}</td>
                                        <td className="py-1.5 pr-3 text-foreground-muted">{s.last_assessment_at ? timeAgo(s.last_assessment_at) : 'Never'}</td>
                                        <td className="py-1.5 pr-3 space-x-1">{s.status === 'confirmed' ? (sevLine(s.open_by_severity).length ? sevLine(s.open_by_severity) : <span className="text-foreground-muted">None recorded</span>) : '—'}</td>
                                        <td className="py-1.5"><button onClick={() => setSel(s.id)} className="text-[11px] font-bold text-purple">Open</button></td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>
            ))}
        </section>
    );
}

function EvidenceList({ title, items, note }: { title: string; items: IntakeEvidence[]; note?: string }) {
    if (!items.length) return null;
    return (
        <div>
            <p className="text-[10px] font-bold uppercase text-foreground-muted">{title}{note ? <span className="normal-case font-normal"> — {note}</span> : null}</p>
            {items.map((e, i) => <p key={i}>{e.detail} <span className="text-foreground-muted">({e.source})</span></p>)}
        </div>
    );
}

function IntakeDetail({ id, orgs, isManager, canScan, onChanged, onRecheck, onClose }: { id: string; orgs: IntakeOrg[]; isManager: boolean; canScan: boolean; onChanged: () => void; onRecheck: (v: string) => void; onClose: () => void }) {
    const [d, setD] = useState<Detail | null>(null);
    const [err, setErr] = useState<string | null>(null);
    const [msg, setMsg] = useState<{ text: string; error: boolean } | null>(null);
    const [busy, setBusy] = useState<string | null>(null);
    const [org, setOrg] = useState('');
    const [note, setNote] = useState('');
    const [days, setDays] = useState(60);
    const [tick, setTick] = useState(0);
    const running = !!d?.assessments.some((a) => a.status === 'in_progress');

    useEffect(() => {
        let active = true;
        void cniiGet<Detail>(`/intake/${id}`).then((r) => { if (active) { setD(r.ok ? r.data : null); setErr(r.ok ? null : r.error); } });
        return () => { active = false; };
    }, [id, tick]);
    // Poll while an assessment is running (status is derived by the backend from the scan jobs).
    useEffect(() => {
        if (!running) return;
        const t = setInterval(() => setTick((x) => x + 1), 15_000);
        return () => clearInterval(t);
    }, [running]);

    async function act(key: string, path: string, body: unknown, ok: (data: Record<string, unknown>) => string) {
        if (busy) return;
        setBusy(key);
        const r = await apiSend<Record<string, unknown>>(`/api/cnii/intake/${id}/${path}`, 'POST', body);
        setBusy(null);
        setMsg(r.ok ? { text: ok(r.data), error: false } : { text: r.error, error: true });
        setTick((x) => x + 1);
        onChanged();
    }
    const box = 'border border-border rounded-lg p-3 space-y-1';
    if (err) return <div className={box}><p role="alert" className="text-xs text-red">{err}</p></div>;
    if (!d) return <div className={box}><p className="text-xs text-foreground-muted">Loading the asset…</p></div>;
    const s = d.submission;
    const sc = sectorContext(s);
    const au = authState(s);
    const g = evidenceGroups(s);
    const gaps = gapsOf(s);
    const classified = orgs.filter((o) => o.profile);
    const input = 'bg-card-muted border border-border rounded-lg px-2 py-1 text-xs text-foreground';
    return (
        <div className="border-2 border-purple/30 rounded-xl p-3 space-y-3 text-xs" aria-label={`Details of ${s.value}`}>
            <div className="flex items-start justify-between gap-2 flex-wrap">
                <div>
                    <p className="text-sm font-black text-foreground font-mono">{s.value} <span className="font-sans text-[11px] font-normal text-foreground-muted">{s.kind === 'domain' ? 'Domain' : 'IP address'}</span></p>
                    <div className="flex flex-wrap gap-1 mt-1"><Badge text="Enrichment complete" style="bg-card-muted text-foreground" /><Badge text={CNII_STATUS[s.status].label} style={CNII_STATUS[s.status].style} />{au.key !== 'not_applicable' && <Badge text={au.label} style={au.style} />}</div>
                </div>
                <div className="flex gap-2">
                    <button onClick={() => onRecheck(s.value)} className="flex items-center gap-1 text-[11px] font-bold text-purple"><RefreshCw className="w-3.5 h-3.5" /> Re-check</button>
                    <button onClick={onClose} className="text-foreground-muted" aria-label="Close details"><X className="w-4 h-4" /></button>
                </div>
            </div>
            {msg && <p role={msg.error ? 'alert' : 'status'} className={`font-semibold ${msg.error ? 'text-red' : 'text-foreground'}`}>{msg.text}</p>}

            <div className="grid md:grid-cols-2 gap-3">
                <div className={box}>
                    <p className="text-[10px] font-bold uppercase text-foreground-muted">Classification</p>
                    <p><span className="text-foreground-muted">CNII review:</span> {CNII_STATUS[s.status].label} — {reviewBasis(s)}</p>
                    <p><span className="text-foreground-muted">Sector:</span> {sc.text}</p>
                    <p><span className="text-foreground-muted">Organisation:</span> {s.status === 'confirmed' && d.organisation ? d.organisation.name : s.org_id ? `${s.org_id} (not confirmed)` : 'Unknown / Requires review'}</p>
                    <p><span className="text-foreground-muted">Network operator:</span> {networkContext(s)} <span className="text-foreground-muted">(registry data: operator of the network, not the owner)</span></p>
                    <p className="text-foreground">{s.reason}</p>
                </div>
                <div className={box}>
                    <p className="text-[10px] font-bold uppercase text-foreground-muted">Record history</p>
                    <p>Submitted by {s.submitted_by} on {fmtWat(s.submitted_at)}</p>
                    <p>DNS and registry checked {fmtWat(s.resolution.resolved_at)}</p>
                    {s.decided_by && <p>{s.status === 'rejected' ? 'Marked not CNII' : 'Confirmed'} by {s.decided_by} on {fmtWat(s.decided_at)}{s.decision_note ? `: ${s.decision_note}` : ''}</p>}
                    {s.authorisation && <p>Scan authorisation by {s.authorisation.approved_by} on {fmtWat(s.authorisation.approved_at)}{s.authorisation.revoked_at ? `; revoked by ${s.authorisation.revoked_by} on ${fmtWat(s.authorisation.revoked_at)}` : ''}</p>}
                    <p className="text-foreground-muted">Every submission, decision and authorisation is in the audit log (CNII_* actions).</p>
                </div>
            </div>

            {gaps.length > 0 && (
                <div className="border border-amber/40 bg-amber/5 rounded-lg p-3">
                    <p className="text-[10px] font-bold uppercase text-amber">Missing or conflicting information</p>
                    {gaps.map((x) => <p key={x}>• {x}</p>)}
                </div>
            )}

            <div className={box}>
                <p className="text-[10px] font-bold uppercase text-foreground-muted">Observed: addresses{s.kind === 'domain' ? ` ${s.value} resolves to` : ''}</p>
                {s.resolution.addresses.length === 0 ? <p className="text-foreground-muted">No address resolved.</p> : (
                    <div className="overflow-x-auto">
                        <table className="w-full min-w-[620px]">
                            <thead><tr className="text-left text-[10px] uppercase text-foreground-muted">{['Address', 'Type', 'Reverse DNS', 'Network (ASN / holder)', 'In authorised scope of'].map((h) => <th key={h} className="py-1 pr-2 font-bold">{h}</th>)}</tr></thead>
                            <tbody>{s.resolution.addresses.map((a) => (
                                <tr key={a.ip} className="border-t border-border/60"><td className="py-1 pr-2 font-mono font-bold">{a.ip}</td><td className="py-1 pr-2">{a.reserved ? 'Reserved — never scanned' : a.public ? 'Public' : 'Private'}</td><td className="py-1 pr-2">{a.ptr.slice(0, 2).join(', ') || '—'}</td><td className="py-1 pr-2">{a.holder ? `${a.asn ? `AS${String(a.asn).replace(/^AS/i, '')} ` : ''}${a.holder}` : 'No data'}</td><td className="py-1 pr-2">{a.covered_by.map((c) => c.org_id).join(', ') || 'None'}</td></tr>
                            ))}</tbody>
                        </table>
                    </div>
                )}
            </div>

            <div className={box}>
                <EvidenceList title="Observed facts" note="DNS and registry answers" items={g.facts} />
                <EvidenceList title="Platform records" note="authorised scope and CNII profiles" items={g.records} />
                <EvidenceList title="Human input" note="not verified until a manager confirms" items={g.human} />
                {s.suggestion && <div><p className="text-[10px] font-bold uppercase text-foreground-muted">Suggestion <span className="normal-case font-normal">— not evidence</span></p><p>Sector {s.suggestion.sectorId}{s.suggestion.subfield ? ` / ${s.suggestion.subfield}` : ''}: {s.suggestion.note}</p></div>}
                {!s.evidence.length && !s.suggestion && <p className="text-foreground-muted">No evidence recorded.</p>}
            </div>

            {s.status !== 'confirmed' && <AiPanel purpose="cnii_intake_classification" subjectId={s.id} title="AI classification help (a suggestion, not evidence)" />}

            {isManager && (
                <div className={box}>
                    <p className="text-[10px] font-bold uppercase text-foreground-muted">CNII review — manager decision</p>
                    <div className="flex flex-wrap gap-2 items-center">
                        <select className={input} value={org} onChange={(e) => setOrg(e.target.value)} aria-label="Operating organisation">
                            <option value="">{s.basis === 'manual_registration' && s.org_id ? `Registered organisation (${s.org_id})` : 'Operating organisation (CNII-classified)'}</option>
                            {classified.map((o) => <option key={o.slug} value={o.slug}>{o.name} — {o.profile!.sector_id} ({o.profile!.designation})</option>)}
                        </select>
                        <input className={`${input} flex-1 min-w-[220px]`} placeholder="Evidence or reason (e.g. letter reference, registrant)" value={note} onChange={(e) => setNote(e.target.value)} aria-label="Decision note" />
                        <button disabled={!!busy || (!org && !(s.basis === 'manual_registration' && s.org_id)) || note.trim().length < 5} onClick={() => void act('confirm', 'decision', { decision: 'confirm', ...(org ? { org_id: org } : {}), note }, () => 'Confirmed CNII. In-scope values were added to the organisation\'s inventory. Scanning still needs a separate authorisation.')} className="text-[11px] font-bold text-white bg-green rounded-lg px-3 py-1 disabled:opacity-50">{busy === 'confirm' ? 'Saving…' : 'Confirm CNII'}</button>
                        <button disabled={!!busy || note.trim().length < 5} onClick={() => void act('reject', 'decision', { decision: 'reject', note }, () => 'Marked not CNII.')} className="text-[11px] font-bold border border-border rounded-lg px-3 py-1 disabled:opacity-50">{busy === 'reject' ? 'Saving…' : 'Not CNII'}</button>
                    </div>
                </div>
            )}

            {s.status === 'confirmed' && (
                <div className={box}>
                    <div className="flex items-center justify-between flex-wrap gap-2">
                        <p className="text-[10px] font-bold uppercase text-foreground-muted">Scan authorisation</p>
                        {isManager && <Link href={`/admin/cnii/authorisations?id=${s.id}`} className="text-[11px] font-bold text-purple">Manage on CNII Scan Authorisations →</Link>}
                    </div>
                    <p><Badge text={au.label} style={au.style} /> {au.key === 'authorised' && s.authorisation ? `${scanTypes(s.authorisation)} until ${fmtWat(s.authorisation.expires_at)} (ref ${s.authorisation.reference})` : au.key === 'vms_scope' ? 'Its authorised VMS scope entry governs what may be scanned.' : au.key === 'awaiting' ? 'Confirmed as CNII is not permission to scan: a manager must authorise it.' : ''}</p>
                </div>
            )}

            {s.status === 'confirmed' && (
                <div className={box}>
                    <div className="flex items-center justify-between flex-wrap gap-2">
                        <p className="text-[10px] font-bold uppercase text-foreground-muted">Assessments{running ? ' · assessment running, refreshing every 15 s' : ''}</p>
                        <div className="flex gap-2 items-center flex-wrap">
                            {canScan && <button disabled={!!busy} onClick={() => void act('assess', 'assess', {}, (r) => ((r.results as { target: string; ok: boolean; status?: string; error?: string }[]) ?? []).map((x) => `${x.target}: ${x.ok ? `assessment ${(x.status ?? '').replace(/_/g, ' ')}` : x.error}`).join(' · ') || 'Nothing to assess')} className="flex items-center gap-1 text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1 disabled:opacity-50"><Play className="w-3.5 h-3.5" /> {busy === 'assess' ? 'Starting…' : 'Run Full Assessment'}</button>}
                            {isManager && <>
                                <input type="number" min={1} max={60} value={days} onChange={(e) => setDays(Math.min(60, Math.max(1, Number(e.target.value) || 1)))} className={`${input} w-16`} aria-label="Days to repeat" />
                                <button disabled={!!busy} onClick={() => void act('schedule', 'schedule', { days }, (r) => `Every 48 h until ${fmtWat(String(r.ends_at))}: ${((r.schedules as { target: string; existing: boolean; error?: string }[]) ?? []).map((x) => `${x.target} ${x.error ?? (x.existing ? 'already scheduled' : 'scheduled')}`).join(' · ')}`)} className="flex items-center gap-1 text-[11px] font-bold border border-border rounded-lg px-3 py-1 disabled:opacity-50"><CalendarClock className="w-3.5 h-3.5" /> Repeat every 2 days</button>
                            </>}
                        </div>
                    </div>
                    {d.assessments.length === 0 ? <p className="text-foreground-muted">No assessment yet. Assessments run only on values inside an authorised scope.</p> : d.assessments.map((a) => (
                        <div key={a.id} className="border-t border-border pt-1">
                            <p><span className="font-mono font-bold">{a.target}</span> <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${ASSESSMENT_STATUS_STYLE[a.status]}`}>{a.status === 'in_progress' ? 'Assessment running' : `Assessment ${ASSESSMENT_STATUS_LABEL[a.status].toLowerCase()}`}</span> <span className="text-foreground-muted">requested {fmtWat(a.requested_at)} by {a.requested_by}</span></p>
                            <p className="text-foreground-muted">{a.steps.map((st) => `${st.label}: ${STEP_STATUS_LABEL[st.status]}${['completed', 'findings_detected', 'pending', 'running'].includes(st.status) ? '' : ` (${st.detail})`}`).join(' · ')}</p>
                        </div>
                    ))}
                    {d.schedules.map((sc2) => <p key={sc2.id} className="text-foreground-muted">Repeats for {sc2.targets.join(', ')}: {sc2.enabled ? `next ${fmtWat(sc2.next_run_at)}` : 'stopped'}{sc2.ends_at ? `, ends ${fmtWat(sc2.ends_at)}` : ''}{sc2.last_result ? ` — ${sc2.last_result}` : ''}</p>)}
                </div>
            )}

            {s.status === 'confirmed' && (
                <div className={box}>
                    <p className="text-[10px] font-bold uppercase text-foreground-muted">Findings <span className="normal-case font-normal space-x-1">{sevLine(d.severity)}</span></p>
                    {d.findings.length === 0 ? <p className="text-foreground-muted">No findings recorded. This is not proof the asset is secure: check above which checks ran, were inconclusive or did not run.</p> : (
                        <div className="overflow-x-auto">
                            <table className="w-full min-w-[760px]">
                                <thead><tr className="text-left text-[10px] uppercase text-foreground-muted">{['Severity', 'Finding', 'Endpoint', 'Status', 'Evidence', 'Remediation', 'Last seen'].map((h) => <th key={h} className="py-1 pr-2 font-bold">{h}</th>)}</tr></thead>
                                <tbody>{d.findings.map((f) => (
                                    <tr key={f.id} className="border-t border-border/60 align-top">
                                        <td className={`py-1 pr-2 font-bold uppercase ${SEV_STYLE[f.scanner_severity] ?? ''}`}>{f.scanner_severity}{f.priority ? <span className="text-foreground-muted font-normal normal-case"> {f.priority}</span> : null}</td>
                                        <td className="py-1 pr-2"><a href={`/admin/vms/findings?id=${f.id}`} className="font-semibold text-purple">{f.title}</a><p className="text-foreground-muted font-mono">{[f.rule_id, ...f.cve_ids].filter((x, i, arr) => arr.indexOf(x) === i).join(', ')}</p></td>
                                        <td className="py-1 pr-2 font-mono">{f.asset_value}{f.port ? `:${f.port}` : ''}</td>
                                        <td className="py-1 pr-2">{f.status.replace(/_/g, ' ')}</td>
                                        <td className="py-1 pr-2 text-foreground-muted">{f.evidence_class.replace(/_/g, ' ')}{f.latest_evidence?.matched_at ? ` · ${f.latest_evidence.matched_at}` : ''}</td>
                                        <td className="py-1 pr-2 text-foreground-muted max-w-xs">{f.remediation ?? '—'}</td>
                                        <td className="py-1 pr-2 text-foreground-muted">{fmtWat(f.last_seen)}</td>
                                    </tr>
                                ))}</tbody>
                            </table>
                        </div>
                    )}
                </div>
            )}
            {d.note && s.status !== 'confirmed' && <p className="text-foreground-muted">{d.note}</p>}
        </div>
    );
}
