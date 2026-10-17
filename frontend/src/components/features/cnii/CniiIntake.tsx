'use client';

// CNII Watch intake (phase P17): submit a domain or IP; the backend resolves it, records the
// evidence and links it to a designated CNII organisation only from authorised scope — otherwise it
// stays a candidate with the reason until a manager confirms or rejects it. Confirmed values inside
// that organisation's scope are assessed with the existing Full Assessment (scope, exclusions and
// workers apply). Every figure here comes from the backend; nothing is filled in.

import { useCallback, useEffect, useState } from 'react';
import { Plus, RefreshCw, ShieldCheck, Play, CalendarClock } from 'lucide-react';
import { cniiGet, apiSend, timeAgo, type CniiProfile } from '@/lib/cnii-types';
import { SECTOR_BY_ID } from '@/lib/cnii-sectors';
import { ASSESSMENT_STATUS_LABEL, ASSESSMENT_STATUS_STYLE, STEP_STATUS_LABEL, fmtWat, type VmsAssessment } from '@/lib/vms';
import { AiPanel } from '@/components/shared/AiPanel';

type Status = 'confirmed' | 'candidate' | 'rejected';
interface Address { ip: string; ptr: string[]; asn: string | null; holder: string | null; public: boolean; reserved: boolean; covered_by: { org_id: string; scope: string }[] }
interface Submission {
    id: string; value: string; kind: 'domain' | 'ip'; status: Status; basis: string | null; reason: string; org_id: string | null; sector_id: string | null; subfield: string | null;
    ips: string[]; resolution: { resolved_at: string; errors: string[]; truncated: boolean; addresses: Address[] };
    evidence: { kind: string; detail: string; source: string; strength: 'trusted' | 'supporting' | 'context' }[];
    suggestion: { sectorId: string; subfield: string; note: string } | null; decided_by: string | null; decided_at: string | null; submitted_by: string; submitted_at: string; updated_at: string;
    open_by_severity?: Record<string, number>; last_assessment_at?: string | null;
}
interface Finding { id: string; title: string; rule_id: string; cve_ids: string[]; scanner_severity: string; priority: string | null; status: string; asset_value: string; port: number | null; evidence_class: string; remediation: string | null; first_seen: string; last_seen: string; latest_evidence: { matched_at: string | null; observed_at: string } | null }
interface Schedule { id: string; targets: string[]; interval_hours: number; next_run_at: string; ends_at: string | null; enabled: boolean; last_run_at: string | null; last_result: string | null }
interface Detail { submission: Submission; organisation: { slug: string; name: string } | null; assessments: VmsAssessment[]; findings: Finding[]; severity: Record<string, number>; schedules: Schedule[]; note: string | null }
export interface IntakeOrg { slug: string; name: string; profile: CniiProfile | null }

const DOMAIN = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
/** Client-side check only; the backend validates again. */
export function intakeInputError(v: string): string | null {
    const s = v.trim();
    if (!s) return 'Enter a domain or IP address';
    if (/[/\s]|^\w+:\/\/|\*/.test(s)) return 'A domain or IP only — no URL, path, wildcard or range';
    if (IPV4.test(s) || (s.includes(':') && /^[0-9a-f:.]+$/i.test(s))) return null;
    return DOMAIN.test(s.replace(/\.$/, '')) ? null : 'Not a valid domain name or IP address';
}
const STATUS_STYLE: Record<Status, string> = { confirmed: 'bg-green/10 text-green', candidate: 'bg-amber/10 text-amber', rejected: 'bg-card-muted text-foreground-muted' };
const STATUS_TEXT: Record<Status, string> = { confirmed: 'Confirmed CNII', candidate: 'Unverified candidate', rejected: 'Not CNII' };
const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_STYLE: Record<string, string> = { critical: 'text-red', high: 'text-red/80', medium: 'text-amber', low: 'text-blue', info: 'text-foreground-muted' };
const sevLine = (s: Record<string, number> | undefined) => SEV.filter((k) => s?.[k]).map((k) => <span key={k} className={`font-bold ${SEV_STYLE[k]}`}>{s![k]} {k}</span>);

export function CniiIntake({ orgs, isManager, canScan }: { orgs: IntakeOrg[]; isManager: boolean; canScan: boolean }) {
    const [value, setValue] = useState('');
    const [busy, setBusy] = useState(false);
    const [msg, setMsg] = useState<string | null>(null);
    const [list, setList] = useState<Submission[] | null>(null);
    const [listErr, setListErr] = useState<string | null>(null);
    const [tab, setTab] = useState<Status | 'all'>('all');
    const [sel, setSel] = useState<string | null>(null);
    const [tick, setTick] = useState(0);
    const reload = useCallback(() => setTick((t) => t + 1), []);

    useEffect(() => {
        let active = true;
        void cniiGet<{ submissions: Submission[] }>('/intake').then((r) => { if (active) { setList(r.ok ? r.data.submissions : null); setListErr(r.ok ? null : r.error); } });
        return () => { active = false; };
    }, [tick]);

    async function submit(v: string) {
        const err = intakeInputError(v);
        if (err) { setMsg(err); return; }
        setBusy(true);
        const r = await apiSend<{ submission: Submission; created: boolean }>('/api/cnii/intake', 'POST', { value: v.trim() });
        setBusy(false);
        if (!r.ok) { setMsg(r.error); return; }
        setMsg(`${r.data.submission.value}: ${STATUS_TEXT[r.data.submission.status]} — ${r.data.submission.reason}${r.data.created ? '' : ' (existing submission re-checked)'}`);
        setValue('');
        setSel(r.data.submission.id);
        reload();
    }

    const shown = (list ?? []).filter((s) => tab === 'all' || s.status === tab);
    const count = (s: Status) => (list ?? []).filter((x) => x.status === s).length;
    const input = 'bg-card-muted border border-border rounded-lg px-3 py-2 text-xs text-foreground';
    return (
        <section className="bg-card border border-border rounded-xl p-4 space-y-3">
            <div className="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <h2 className="text-sm font-bold text-foreground flex items-center gap-2"><ShieldCheck className="w-4 h-4" /> Asset intake and watch list</h2>
                    <p className="text-[11px] text-foreground-muted max-w-3xl">Submit a domain or IP. It is resolved and checked against authorised scope and CNII profiles; it joins the watch list only when a designated CNII organisation holds it in authorised scope, or a manager confirms it. Registry data and AI give hints, never ownership.</p>
                </div>
                <form onSubmit={(e) => { e.preventDefault(); void submit(value); }} className="flex gap-2">
                    <input className={input} placeholder="portal.example.gov.ng or 196.x.x.x" value={value} onChange={(e) => setValue(e.target.value)} aria-label="Domain or IP address to submit" maxLength={253} />
                    <button disabled={busy} className="flex items-center gap-1.5 text-[11px] font-bold text-white bg-purple rounded-lg px-3 disabled:opacity-50"><Plus className="w-3.5 h-3.5" /> {busy ? 'Checking…' : 'Submit'}</button>
                </form>
            </div>
            {msg && <p role="status" className="text-xs text-foreground">{msg}</p>}
            {listErr && <p role="alert" className="text-xs text-red font-semibold">{listErr}</p>}
            {list && (
                <>
                    <div className="flex gap-1 bg-card-muted rounded-lg p-1 w-fit text-[11px] font-bold">
                        {(['all', 'confirmed', 'candidate', 'rejected'] as const).map((t) => <button key={t} onClick={() => setTab(t)} className={`px-2.5 py-1 rounded-md ${tab === t ? 'bg-blue text-white' : 'text-foreground-muted'}`}>{t === 'all' ? `All (${list.length})` : `${STATUS_TEXT[t]} (${count(t)})`}</button>)}
                    </div>
                    {shown.length === 0 ? <p className="text-xs text-foreground-muted">Nothing here yet.</p> : (
                        <div className="overflow-x-auto">
                            <table className="w-full text-xs min-w-[760px]">
                                <thead><tr className="text-left text-[10px] uppercase text-foreground-muted border-b border-border">{['Asset', 'Status', 'Sector / organisation', 'Addresses', 'Open findings', 'Last assessment'].map((h) => <th key={h} className="py-1.5 pr-3">{h}</th>)}</tr></thead>
                                <tbody>
                                    {shown.map((s) => (
                                        <tr key={s.id} onClick={() => setSel(s.id)} className={`border-b border-border/60 cursor-pointer align-top ${sel === s.id ? 'bg-purple/5' : ''}`}>
                                            <td className="py-1.5 pr-3 font-mono font-bold text-foreground">{s.value}<span className="text-foreground-muted font-sans font-normal"> {s.kind}</span></td>
                                            <td className="py-1.5 pr-3"><span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${STATUS_STYLE[s.status]}`}>{STATUS_TEXT[s.status]}</span>{s.status !== 'confirmed' && <p className="text-[10px] text-foreground-muted max-w-xs">{s.reason}</p>}</td>
                                            <td className="py-1.5 pr-3">{s.status === 'confirmed' ? `${s.sector_id ?? '—'}${s.subfield ? ` / ${s.subfield}` : ''} · ${s.org_id}` : '—'}</td>
                                            <td className="py-1.5 pr-3 font-mono text-foreground-muted">{s.ips.slice(0, 3).join(', ') || 'none resolved'}{s.ips.length > 3 ? ` +${s.ips.length - 3}` : ''}</td>
                                            <td className="py-1.5 pr-3 space-x-1">{s.status === 'confirmed' ? (sevLine(s.open_by_severity).length ? sevLine(s.open_by_severity) : <span className="text-foreground-muted">none recorded</span>) : '—'}</td>
                                            <td className="py-1.5 pr-3 text-foreground-muted">{s.last_assessment_at ? timeAgo(s.last_assessment_at) : 'never'}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </>
            )}
            {sel && <IntakeDetail key={sel} id={sel} orgs={orgs} isManager={isManager} canScan={canScan} onChanged={reload} onRecheck={(v) => void submit(v)} />}
        </section>
    );
}

function IntakeDetail({ id, orgs, isManager, canScan, onChanged, onRecheck }: { id: string; orgs: IntakeOrg[]; isManager: boolean; canScan: boolean; onChanged: () => void; onRecheck: (v: string) => void }) {
    const [d, setD] = useState<Detail | null>(null);
    const [err, setErr] = useState<string | null>(null);
    const [msg, setMsg] = useState<string | null>(null);
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
    // Poll while an assessment is in progress (the backend derives status from the scan jobs).
    useEffect(() => {
        if (!running) return;
        const t = setInterval(() => setTick((x) => x + 1), 15_000);
        return () => clearInterval(t);
    }, [running]);

    async function act(path: string, body: unknown, ok: (data: Record<string, unknown>) => string) {
        const r = await apiSend<Record<string, unknown>>(`/api/cnii/intake/${id}/${path}`, 'POST', body);
        setMsg(r.ok ? ok(r.data) : r.error);
        setTick((x) => x + 1);
        onChanged();
    }
    if (err) return <p role="alert" className="text-xs text-red">{err}</p>;
    if (!d) return <p className="text-xs text-foreground-muted">Loading…</p>;
    const s = d.submission;
    const classified = orgs.filter((o) => o.profile);
    const input = 'bg-card-muted border border-border rounded-lg px-2 py-1 text-xs text-foreground';
    const box = 'border border-border rounded-lg p-3 space-y-1';
    return (
        <div className="border-t border-border pt-3 space-y-3 text-xs">
            <div className="flex items-center justify-between gap-2 flex-wrap">
                <p className="text-sm font-black text-foreground font-mono">{s.value} <span className={`font-sans text-[10px] font-bold px-1.5 py-0.5 rounded ${STATUS_STYLE[s.status]}`}>{STATUS_TEXT[s.status]}</span></p>
                <button onClick={() => onRecheck(s.value)} className="flex items-center gap-1 text-[11px] font-bold text-purple"><RefreshCw className="w-3.5 h-3.5" /> Re-check DNS and evidence</button>
            </div>
            <p className="text-foreground">{s.reason}</p>
            <p className="text-foreground-muted">Submitted by {s.submitted_by} {timeAgo(s.submitted_at)}; resolved {fmtWat(s.resolution.resolved_at)}{s.decided_by ? `; decided by ${s.decided_by} ${timeAgo(s.decided_at)}` : ''}.
                {s.status === 'confirmed' && d.organisation ? ` Operated by ${d.organisation.name} — ${SECTOR_BY_ID[s.sector_id ?? ''] ? s.sector_id : '—'}${s.subfield ? ` / ${s.subfield}` : ''} (${s.basis === 'authorised_scope' ? 'from authorised scope' : 'confirmed by a manager'}).` : ''}</p>
            {msg && <p role="status" className="font-semibold text-foreground">{msg}</p>}

            <div className={box}>
                <p className="text-[10px] font-bold uppercase text-foreground-muted">Addresses{s.kind === 'domain' ? ` ${s.value} resolves to` : ''}</p>
                {s.resolution.errors.map((e) => <p key={e} className="text-amber">DNS: {e}</p>)}
                {s.resolution.addresses.length === 0 ? <p className="text-foreground-muted">No address resolved.</p> : s.resolution.addresses.map((a) => (
                    <p key={a.ip}><span className="font-mono font-bold">{a.ip}</span> <span className="text-foreground-muted">· {a.reserved ? 'reserved (never assessed)' : a.public ? 'public' : 'private'}{a.ptr.length ? ` · PTR ${a.ptr.slice(0, 2).join(', ')}` : ''}{a.holder ? ` · ${a.asn} ${a.holder}` : ''}{a.covered_by.length ? ` · in scope of ${a.covered_by.map((c) => c.org_id).join(', ')}` : ' · in no organisation\'s scope'}</span></p>
                ))}
                {s.resolution.truncated && <p className="text-foreground-muted">More addresses than shown; only the first 16 are kept.</p>}
            </div>

            <div className={box}>
                <p className="text-[10px] font-bold uppercase text-foreground-muted">Evidence</p>
                {s.evidence.map((e, i) => <p key={i}><span className={`text-[10px] font-bold uppercase ${e.strength === 'trusted' ? 'text-green' : e.strength === 'supporting' ? 'text-amber' : 'text-foreground-muted'}`}>{e.strength}</span> {e.detail} <span className="text-foreground-muted">({e.source})</span></p>)}
                {s.suggestion && <p className="text-foreground-muted">Keyword hint: {s.suggestion.sectorId}{s.suggestion.subfield ? ` / ${s.suggestion.subfield}` : ''} — {s.suggestion.note}</p>}
            </div>

            {s.status !== 'confirmed' && <AiPanel purpose="cnii_intake_classification" subjectId={s.id} title="AI classification help (suggestion only)" />}

            {isManager && (
                <div className={box}>
                    <p className="text-[10px] font-bold uppercase text-foreground-muted">Manager decision</p>
                    <div className="flex flex-wrap gap-2 items-center">
                        <select className={input} value={org} onChange={(e) => setOrg(e.target.value)} aria-label="Operating organisation">
                            <option value="">Organisation (CNII-classified)</option>
                            {classified.map((o) => <option key={o.slug} value={o.slug}>{o.name} — {o.profile!.sector_id} ({o.profile!.designation})</option>)}
                        </select>
                        <input className={`${input} flex-1 min-w-[220px]`} placeholder="Evidence or reason (e.g. letter ref, registrant)" value={note} onChange={(e) => setNote(e.target.value)} aria-label="Decision note" />
                        <button disabled={!org || note.trim().length < 5} onClick={() => void act('decision', { decision: 'confirm', org_id: org, note }, () => 'Confirmed and linked; in-scope values were added to the organisation\'s inventory')} className="text-[11px] font-bold text-white bg-green rounded-lg px-3 py-1 disabled:opacity-50">Confirm CNII</button>
                        <button disabled={note.trim().length < 5} onClick={() => void act('decision', { decision: 'reject', note }, () => 'Marked not CNII')} className="text-[11px] font-bold border border-border rounded-lg px-3 py-1 disabled:opacity-50">Not CNII</button>
                    </div>
                </div>
            )}

            {s.status === 'confirmed' && (
                <div className={box}>
                    <div className="flex items-center justify-between flex-wrap gap-2">
                        <p className="text-[10px] font-bold uppercase text-foreground-muted">Assessments{running ? ' · refreshing every 15 s' : ''}</p>
                        <div className="flex gap-2 items-center">
                            {canScan && <button onClick={() => void act('assess', {}, (r) => ((r.results as { target: string; ok: boolean; status?: string; error?: string }[]) ?? []).map((x) => `${x.target}: ${x.ok ? x.status : x.error}`).join(' · '))} className="flex items-center gap-1 text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1"><Play className="w-3.5 h-3.5" /> Run Full Assessment</button>}
                            {isManager && <>
                                <input type="number" min={1} max={60} value={days} onChange={(e) => setDays(Math.min(60, Math.max(1, Number(e.target.value) || 1)))} className={`${input} w-16`} aria-label="Days to repeat" />
                                <button onClick={() => void act('schedule', { days }, (r) => `Every 48 h until ${fmtWat(String(r.ends_at))}: ${((r.schedules as { target: string; existing: boolean; error?: string }[]) ?? []).map((x) => `${x.target} ${x.error ?? (x.existing ? 'already scheduled' : 'scheduled')}`).join(' · ')}`)} className="flex items-center gap-1 text-[11px] font-bold border border-border rounded-lg px-3 py-1"><CalendarClock className="w-3.5 h-3.5" /> Repeat every 2 days</button>
                            </>}
                        </div>
                    </div>
                    {d.assessments.length === 0 ? <p className="text-foreground-muted">No assessment yet.</p> : d.assessments.map((a) => (
                        <div key={a.id} className="border-t border-border pt-1">
                            <p><span className="font-mono font-bold">{a.target}</span> <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${ASSESSMENT_STATUS_STYLE[a.status]}`}>{ASSESSMENT_STATUS_LABEL[a.status]}</span> <span className="text-foreground-muted">requested {fmtWat(a.requested_at)} by {a.requested_by}</span></p>
                            <p className="text-foreground-muted">{a.steps.map((st) => `${st.label}: ${STEP_STATUS_LABEL[st.status]}${st.status === 'completed' || st.status === 'findings_detected' || st.status === 'pending' || st.status === 'running' ? '' : ` (${st.detail})`}`).join(' · ')}</p>
                        </div>
                    ))}
                    {d.schedules.map((sc) => <p key={sc.id} className="text-foreground-muted">Schedule {sc.targets.join(', ')}: {sc.enabled ? `next ${fmtWat(sc.next_run_at)}` : 'stopped'}{sc.ends_at ? `, ends ${fmtWat(sc.ends_at)}` : ''}{sc.last_result ? ` — ${sc.last_result}` : ''}</p>)}
                </div>
            )}

            {s.status === 'confirmed' && (
                <div className={box}>
                    <p className="text-[10px] font-bold uppercase text-foreground-muted">Findings on {s.value}{s.ips.length ? ' and its addresses' : ''} <span className="normal-case font-normal space-x-1">{sevLine(d.severity)}</span></p>
                    {d.findings.length === 0 ? <p className="text-foreground-muted">No findings recorded. This does not mean the asset is secure: see which checks ran, were inconclusive or did not run above.</p> : (
                        <div className="overflow-x-auto">
                            <table className="w-full min-w-[760px]">
                                <thead><tr className="text-left text-[10px] uppercase text-foreground-muted">{['Severity', 'Finding', 'Endpoint', 'Status', 'Evidence', 'Remediation', 'Last seen'].map((h) => <th key={h} className="py-1 pr-2">{h}</th>)}</tr></thead>
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
            {d.note && <p className="text-foreground-muted">{d.note}</p>}
        </div>
    );
}
