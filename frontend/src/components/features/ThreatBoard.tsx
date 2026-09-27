'use client';

import { Fragment, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { RefreshCw, ShieldOff, ArrowUpRight, CheckCircle2, UserPlus, Loader2, ChevronDown, ChevronRight } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Threat Management — distinct threats derived from live Wazuh alerts (GET /api/threats), one
// per rule + source IP (or rule + agent when the alert has no IP). Actions are real: Contain
// blocks the source IP at the firewall, Escalate opens a case, Resolve / Assign record the
// analyst's decision. Nothing is sample data.

type Status = 'active' | 'contained' | 'resolved' | 'monitoring';
type Severity = 'critical' | 'high' | 'medium';

interface Threat {
    id: string; name: string; type: string; source: string; severity: Severity; status: Status; recurred: boolean;
    rule_id: string; rule_level: number; source_ip: string | null; assets: string[]; alert_count: number;
    first_seen: string; last_seen: string; mitre_technique_id: string | null; mitre_technique: string | null; mitre_tactic: string | null;
    assigned_to: string | null; case_id: string | null; case_number: string | null; decided_at: string | null;
}
interface Summary { active: number; contained: number; resolved_this_week: number; critical_unresolved: number }
interface TeamMember { name: string; email: string }

const STATUS_STYLE: Record<Status, string> = {
    active: 'bg-red-500/10 text-red-500 border-red-500/30',
    contained: 'bg-amber-500/10 text-amber-600 border-amber-500/30',
    resolved: 'bg-green/10 text-green border-green/30',
    monitoring: 'bg-blue/10 text-blue border-blue/30',
};
const SEV_STYLE: Record<Severity, string> = {
    critical: 'bg-red-500/10 text-red-500 border-red-500/30',
    high: 'bg-orange/10 text-orange border-orange/30',
    medium: 'bg-amber-500/10 text-amber-600 border-amber-500/30',
};
const wat = (iso: string) => (iso ? new Intl.DateTimeFormat('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }).format(new Date(iso)) + ' WAT' : '—');

type Feedback = { threatId: string; ok: boolean; neutral?: boolean; text: string };

export function ThreatBoard() {
    const [range, setRange] = useState<'24h' | '7d' | '30d'>('7d');
    const [nonce, setNonce] = useState(0);
    const [loaded, setLoaded] = useState<{ key: string; threats: Threat[]; summary: Summary | null; store: string; checkedAt: string; error?: string } | null>(null);
    const [team, setTeam] = useState<TeamMember[]>([]);
    const [statusF, setStatusF] = useState<'all' | Status>('all');
    const [typeF, setTypeF] = useState('all');
    const [sevF, setSevF] = useState<'all' | Severity>('all');
    const [sourceF, setSourceF] = useState('all');
    const [expanded, setExpanded] = useState<string | null>(null);
    const [busy, setBusy] = useState<string | null>(null);
    const [feedback, setFeedback] = useState<Feedback | null>(null);

    const key = `${range}|${nonce}`;
    useEffect(() => {
        let active = true;
        const [r] = key.split('|');
        apiFetch(apiUrl(`/api/threats?range=${r}`), { cache: 'no-store' })
            .then(async (res) => {
                const d = await res.json().catch(() => null);
                if (!active) return;
                if (!res.ok || !d) {
                    setLoaded({ key, threats: [], summary: null, store: '', checkedAt: d?.checked_at ?? new Date().toISOString(), error: res.status === 401 ? 'Sign in with a NovrSOC analyst account to view threats.' : d?.error ?? `HTTP ${res.status}` });
                    return;
                }
                setLoaded({ key, threats: d.threats ?? [], summary: d.summary ?? null, store: d.store, checkedAt: d.checked_at });
            })
            .catch(() => { if (active) setLoaded({ key, threats: [], summary: null, store: '', checkedAt: new Date().toISOString(), error: 'Could not reach the backend' }); });
        return () => { active = false; };
    }, [key]);

    useEffect(() => {
        let active = true;
        apiFetch(apiUrl('/api/communications/recipients'), { cache: 'no-store' })
            .then((r) => (r.ok ? r.json() : null))
            .then((d) => { if (active) setTeam(Array.isArray(d?.analysts) ? d.analysts.map((a: TeamMember) => ({ name: a.name, email: a.email })) : []); })
            .catch(() => {});
        return () => { active = false; };
    }, []);

    const current = loaded?.key === key ? loaded : null;
    const threats = useMemo(() => current?.threats ?? [], [current]);
    const types = useMemo(() => [...new Set(threats.map((t) => t.type))].sort(), [threats]);
    const sources = useMemo(() => [...new Set(threats.map((t) => t.source))].sort(), [threats]);
    const filtered = threats.filter((t) =>
        (statusF === 'all' || t.status === statusF) && (typeF === 'all' || t.type === typeF)
        && (sevF === 'all' || t.severity === sevF) && (sourceF === 'all' || t.source === sourceF));

    async function act(t: Threat, action: 'contain' | 'escalate' | 'resolve' | 'assign', body: Record<string, unknown> = {}) {
        setBusy(`${t.id}:${action}`);
        setFeedback(null);
        try {
            const res = await apiFetch(apiUrl(`/api/threats/${encodeURIComponent(t.id)}/${action}`), {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
            });
            const d = await res.json().catch(() => ({}));
            const text = d?.message ?? d?.error ?? `HTTP ${res.status}`;
            setFeedback({ threatId: t.id, ok: !!d?.success, neutral: d?.outcome === 'skipped', text: d?.outcome === 'skipped' ? `Not done — ${text}` : text });
            if (d?.success) setNonce((n) => n + 1);
        } catch {
            setFeedback({ threatId: t.id, ok: false, text: 'Could not reach the backend' });
        } finally {
            setBusy(null);
        }
    }

    const s = current?.summary;
    const select = 'bg-card border border-border rounded-lg px-2.5 py-1.5 text-xs font-bold text-foreground';
    const btn = 'flex items-center gap-1.5 text-[11px] font-bold rounded-lg px-3 py-1.5 border disabled:opacity-50';

    return (
        <div className="space-y-4">
            <div className="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <h1 className="text-lg font-black text-foreground">Threat Management</h1>
                    <p className="text-xs text-foreground-muted">Distinct threats from live Wazuh alerts (level 7+), one per rule and source. {current && !current.error ? `Checked ${wat(current.checkedAt)}.` : ''}</p>
                </div>
                <button onClick={() => setNonce((n) => n + 1)} className="flex items-center gap-1.5 text-[11px] font-bold text-foreground-muted hover:text-foreground border border-border rounded-lg px-3 py-1.5">
                    <RefreshCw className={`w-3.5 h-3.5 ${current === null ? 'animate-spin' : ''}`} /> Refresh
                </button>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {[
                    { label: 'Active Threats', value: s?.active, cls: 'text-red-500' },
                    { label: 'Contained', value: s?.contained, cls: 'text-amber-600' },
                    { label: 'Resolved This Week', value: s?.resolved_this_week, cls: 'text-green' },
                    { label: 'Critical Unresolved', value: s?.critical_unresolved, cls: (s?.critical_unresolved ?? 0) > 0 ? 'text-red-500' : 'text-foreground' },
                ].map((k) => (
                    <div key={k.label} className="bg-card border border-border rounded-xl p-4">
                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{k.label}</p>
                        <p className={`text-2xl font-black mt-1 ${k.cls}`}>{typeof k.value === 'number' ? k.value : '—'}</p>
                    </div>
                ))}
            </div>

            <div className="flex flex-wrap items-center gap-2">
                <select value={statusF} onChange={(e) => setStatusF(e.target.value as typeof statusF)} aria-label="Status" className={select}>
                    <option value="all">All statuses</option>
                    {(['active', 'monitoring', 'contained', 'resolved'] as const).map((x) => <option key={x} value={x}>{x.charAt(0).toUpperCase() + x.slice(1)}</option>)}
                </select>
                <select value={typeF} onChange={(e) => setTypeF(e.target.value)} aria-label="Type" className={select}>
                    <option value="all">All types</option>
                    {types.map((x) => <option key={x} value={x}>{x}</option>)}
                </select>
                <select value={sevF} onChange={(e) => setSevF(e.target.value as typeof sevF)} aria-label="Severity" className={select}>
                    <option value="all">All severities</option>
                    {(['critical', 'high', 'medium'] as const).map((x) => <option key={x} value={x}>{x.charAt(0).toUpperCase() + x.slice(1)}</option>)}
                </select>
                <select value={sourceF} onChange={(e) => setSourceF(e.target.value)} aria-label="Source" className={select}>
                    <option value="all">All sources</option>
                    {sources.map((x) => <option key={x} value={x}>{x}</option>)}
                </select>
                <select value={range} onChange={(e) => setRange(e.target.value as typeof range)} aria-label="Date range" className={select}>
                    <option value="24h">Last 24 hours</option>
                    <option value="7d">Last 7 days</option>
                    <option value="30d">Last 30 days</option>
                </select>
            </div>

            {current?.store === 'memory' && (
                <p className="text-[11px] bg-amber-500/10 border border-amber-500/30 text-amber-600 rounded-lg px-3 py-2">
                    Analyst decisions (contained, resolved, assigned) are kept in memory until backend/sql/2026-09-threat-triage.sql is run in Supabase — they are lost on restart.
                </p>
            )}

            <div className="bg-card border border-border rounded-xl overflow-x-auto">
                {current === null ? (
                    <div className="p-4 space-y-2">{Array.from({ length: 5 }).map((_, i) => <div key={i} className="h-10 bg-card-muted rounded animate-pulse" />)}</div>
                ) : current.error ? (
                    <p role="alert" className="text-sm font-bold text-red-500 text-center py-10 px-4">Could not load threats: {current.error}</p>
                ) : filtered.length === 0 ? (
                    <p className="text-xs text-foreground-muted text-center py-10">{threats.length === 0 ? 'No threats in this period.' : 'No threats match these filters.'}</p>
                ) : (
                    <table className="w-full text-xs min-w-[900px]">
                        <thead>
                            <tr className="text-left text-[10px] uppercase tracking-wider text-foreground-muted border-b border-border">
                                {['', 'Threat', 'Type', 'Source', 'Severity', 'Status', 'Assets', 'First seen', 'Last seen', 'MITRE'].map((h, i) => <th key={i} className="px-3 py-2.5 font-bold whitespace-nowrap">{h}</th>)}
                            </tr>
                        </thead>
                        <tbody>
                            {filtered.map((t) => {
                                const open = expanded === t.id;
                                return (
                                    <Fragment key={t.id}>
                                        <tr className="border-b border-border/60 align-top hover:bg-card-muted/30 cursor-pointer" onClick={() => setExpanded(open ? null : t.id)}>
                                            <td className="px-3 py-2.5">{open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}</td>
                                            <td className="px-3 py-2.5 max-w-[280px]">
                                                <p className="font-bold text-foreground line-clamp-2">{t.name}</p>
                                                <p className="text-[10px] font-mono text-foreground-muted">{t.id} · {t.alert_count.toLocaleString()} alert{t.alert_count === 1 ? '' : 's'}</p>
                                            </td>
                                            <td className="px-3 py-2.5 text-foreground whitespace-nowrap">{t.type}</td>
                                            <td className="px-3 py-2.5 text-foreground-muted whitespace-nowrap">{t.source}</td>
                                            <td className="px-3 py-2.5"><span className={`text-[9px] font-bold px-2 py-0.5 rounded-full border uppercase ${SEV_STYLE[t.severity]}`}>{t.severity}</span></td>
                                            <td className="px-3 py-2.5 whitespace-nowrap">
                                                <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full border capitalize ${STATUS_STYLE[t.status]}`}>{t.status}</span>
                                                {t.recurred && <span className="block text-[9px] text-red-500 mt-0.5">Fired again after decision</span>}
                                            </td>
                                            <td className="px-3 py-2.5 text-foreground">{t.source_ip && <span className="block font-mono text-[10px]">{t.source_ip}</span>}{t.assets.join(', ')}</td>
                                            <td className="px-3 py-2.5 text-foreground-muted whitespace-nowrap">{wat(t.first_seen)}</td>
                                            <td className="px-3 py-2.5 text-foreground-muted whitespace-nowrap">{wat(t.last_seen)}</td>
                                            <td className="px-3 py-2.5 whitespace-nowrap">
                                                {t.mitre_technique_id
                                                    ? <a href={`https://attack.mitre.org/techniques/${t.mitre_technique_id.replace('.', '/')}/`} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()} className="font-mono text-blue hover:underline" title={t.mitre_technique ?? undefined}>{t.mitre_technique_id}</a>
                                                    : <span className="text-foreground-muted">—</span>}
                                            </td>
                                        </tr>
                                        {open && (
                                            <tr className="border-b border-border bg-card-muted/20">
                                                <td />
                                                <td colSpan={9} className="px-3 py-3 space-y-2.5">
                                                    <p className="text-[11px] text-foreground-muted">
                                                        Rule {t.rule_id} (level {t.rule_level}){t.mitre_technique ? ` · ${t.mitre_tactic ?? ''} — ${t.mitre_technique}` : ''}
                                                        {' · '}Assigned: <strong className="text-foreground">{t.assigned_to ?? 'Unassigned'}</strong>
                                                        {t.case_number && t.case_id && <> · Case <Link href={`/admin/secops/cases?id=${t.case_id}`} className="font-bold text-purple hover:underline">{t.case_number}</Link></>}
                                                        {t.decided_at && ` · Decision ${wat(t.decided_at)}`}
                                                    </p>
                                                    <div className="flex flex-wrap items-center gap-2">
                                                        <button disabled={busy !== null || t.status === 'contained'} onClick={() => act(t, 'contain')} title={t.source_ip ? `Block ${t.source_ip} at the firewall` : 'No source IP — contain the host from its case'}
                                                            className={`${btn} text-amber-600 border-amber-500/30 bg-amber-500/5`}>
                                                            {busy === `${t.id}:contain` ? <Loader2 size={12} className="animate-spin" /> : <ShieldOff size={12} />} Contain
                                                        </button>
                                                        <button disabled={busy !== null} onClick={() => act(t, 'escalate')} className={`${btn} text-white border-transparent`} style={{ backgroundColor: '#CC2B2B' }}>
                                                            {busy === `${t.id}:escalate` ? <Loader2 size={12} className="animate-spin" /> : <ArrowUpRight size={12} />} {t.case_number ? 'Open case' : 'Escalate to case'}
                                                        </button>
                                                        <button disabled={busy !== null || t.status === 'resolved'} onClick={() => act(t, 'resolve')} className={`${btn} text-green border-green/30 bg-green/5`}>
                                                            {busy === `${t.id}:resolve` ? <Loader2 size={12} className="animate-spin" /> : <CheckCircle2 size={12} />} Resolve
                                                        </button>
                                                        <label className="flex items-center gap-1.5 text-[11px] text-foreground-muted">
                                                            <UserPlus size={12} />
                                                            <select value="" disabled={busy !== null || team.length === 0} onChange={(e) => e.target.value && act(t, 'assign', { analyst_id: e.target.value })} aria-label="Assign analyst" className={select}>
                                                                <option value="">{team.length === 0 ? 'No team members' : 'Assign to…'}</option>
                                                                {team.map((m) => <option key={m.email} value={m.email}>{m.name}</option>)}
                                                            </select>
                                                        </label>
                                                    </div>
                                                    {feedback?.threatId === t.id && (
                                                        <p role="status" className={`text-[11px] font-bold ${feedback.ok ? 'text-green' : feedback.neutral ? 'text-foreground-muted' : 'text-red-500'}`}>{feedback.text}</p>
                                                    )}
                                                </td>
                                            </tr>
                                        )}
                                    </Fragment>
                                );
                            })}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    );
}
