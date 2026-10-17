'use client';

// One CNII sector (phase P9): its organisations with measured figures and data gaps, and an
// on-demand AI briefing grounded in those records. The briefing is advice: it changes nothing,
// marks every statement's basis, and lists what data was missing.

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { ArrowLeft, Sparkles, AlertTriangle } from 'lucide-react';
import { SECTOR_BY_ID } from '@/lib/cnii-sectors';
import { cniiGet, apiSend, timeAgo, type CniiProfile, type OrgStats } from '@/lib/cnii-types';

interface OrgEntry { profile: CniiProfile; name: string; stats: OrgStats; gaps: string[] }
interface WatchItem { id: string; value: string; kind: string; org_id: string; subfield: string | null; basis: string; ips: string[]; updated_at: string; authorisation?: { revoked_at: string | null; expires_at: string } | null }
interface RegisteredItem { id: string; value: string; org_id: string; reason: string; updated_at: string }
interface Briefing {
    period: string; headline: string; posture_summary: string;
    statements: { statement: string; basis: 'platform_record' | 'source_claim' | 'ai_assessment'; evidence_refs: string[] }[];
    emerging_risks: { risk: string; confirmed: boolean; evidence_refs: string[] }[];
    organisation_actions: { org_id: string; action: string; priority: 'high' | 'medium' | 'low'; requires_approval: boolean; evidence_refs: string[] }[];
    data_gaps: string[]; confidence: string; invalid_refs?: string[];
}
const BASIS: Record<string, string> = { platform_record: 'Platform record', source_claim: 'Source claim', ai_assessment: 'AI assessment' };

export function CniiSector({ sectorId }: { sectorId: string }) {
    const meta = SECTOR_BY_ID[sectorId];
    const [orgs, setOrgs] = useState<OrgEntry[] | null>(null);
    const [watch, setWatch] = useState<WatchItem[] | null>(null);
    const [registered, setRegistered] = useState<RegisteredItem[] | null>(null);
    const [allOrgs, setAllOrgs] = useState<{ slug: string; name: string; profile: CniiProfile | null }[]>([]);
    const [manual, setManual] = useState({ open: false, org_id: '', sector_id: sectorId, ip: '', justification: '' });
    const [manualMsg, setManualMsg] = useState<string | null>(null);
    const [reloadKey, setReloadKey] = useState(0);
    const [error, setError] = useState<string | null>(null);
    const [brief, setBrief] = useState<{ content: Briefing; model: string; created_at: string } | null>(null);
    const [briefing, setBriefing] = useState(false);
    const [briefErr, setBriefErr] = useState<string | null>(null);

    useEffect(() => {
        if (!meta) return;
        let active = true;
        void cniiGet<{ organisations: OrgEntry[]; watchlist?: WatchItem[] | null; registered?: RegisteredItem[] | null }>(`/sectors/${sectorId}`).then((r) => {
            if (!active) return;
            setOrgs(r.ok ? r.data.organisations : null);
            setWatch(r.ok ? r.data.watchlist ?? null : null);
            setRegistered(r.ok ? r.data.registered ?? null : null);
            setError(r.ok ? null : r.error);
        });
        return () => { active = false; };
    }, [sectorId, meta, reloadKey]);
    useEffect(() => {
        if (!manual.open || allOrgs.length) return;
        let active = true;
        void cniiGet<{ organisations: { slug: string; name: string; profile: CniiProfile | null }[] }>('/organisations').then((r) => { if (active && r.ok) setAllOrgs(r.data.organisations); });
        return () => { active = false; };
    }, [manual.open, allOrgs.length]);

    async function addManual() {
        const r = await apiSend<{ registered: boolean; note: string | null }>('/api/cnii/intake/manual', 'POST', { org_id: manual.org_id, sector_id: manual.sector_id, ip: manual.ip.trim(), justification: manual.justification.trim() });
        setManualMsg(r.ok ? (r.data.registered ? `${manual.ip} registered, not verified: a manager must confirm it, and scanning needs a separate authorisation.` : r.data.note) : r.error);
        if (r.ok) { setManual({ ...manual, ip: '', justification: '' }); setReloadKey((k) => k + 1); }
    }

    async function generate(period: '7d' | '30d') {
        setBriefing(true); setBriefErr(null);
        const r = await apiSend<{ artifact: { content: Briefing; model: string; created_at: string } }>('/api/ai/generate', 'POST', { purpose: 'cnii_sector_briefing', subject_id: `${sectorId}:${period}` });
        setBriefing(false);
        if (r.ok) setBrief(r.data.artifact); else setBriefErr(r.error);
    }

    if (!meta) return <p className="text-xs text-foreground-muted">Unknown sector. <Link href="/admin/cnii" className="text-purple font-bold">Back to CNII Watch</Link></p>;
    const Icon = meta.icon;
    return (
        <div className="space-y-4">
            <Link href="/admin/cnii" className="text-[11px] text-foreground-muted flex items-center gap-1"><ArrowLeft className="w-3 h-3" /> CNII Watch</Link>
            <div className="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <h1 className="text-lg font-black text-foreground flex items-center gap-2"><Icon className="w-5 h-5" style={{ color: meta.color }} /> {meta.label}</h1>
                    <p className="text-xs text-foreground-muted max-w-3xl">{meta.description}</p>
                    <p className="text-[11px] text-foreground-muted mt-1">Frameworks: {meta.compliance.join(', ')}</p>
                </div>
                <div className="flex gap-2">
                    {(['7d', '30d'] as const).map((p) => (
                        <button key={p} disabled={briefing} onClick={() => void generate(p)} className="flex items-center gap-1.5 text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5 disabled:opacity-50"><Sparkles className="w-3.5 h-3.5" /> Briefing ({p})</button>
                    ))}
                </div>
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {briefErr && <p role="alert" className="text-xs text-red font-semibold">{briefErr}</p>}
            {briefing && <p className="text-xs text-foreground-muted">Writing the briefing from this sector&apos;s records…</p>}

            {brief && (
                <div className="bg-card border border-purple/30 rounded-xl p-4 space-y-3 text-xs">
                    <div>
                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">AI briefing · {brief.content.period} · {brief.model} · confidence {brief.content.confidence} · advice only</p>
                        <p className="text-sm font-bold text-foreground mt-1">{brief.content.headline}</p>
                        <p className="text-foreground mt-1">{brief.content.posture_summary}</p>
                    </div>
                    {brief.content.data_gaps.length > 0 && (
                        <div className="rounded-lg p-2 border border-amber/30 bg-amber/10 text-amber">
                            <p className="font-bold flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5" /> Data gaps</p>
                            <ul className="list-disc ml-5">{brief.content.data_gaps.map((g, i) => <li key={i}>{g}</li>)}</ul>
                        </div>
                    )}
                    <ul className="space-y-1">{brief.content.statements.map((s, i) => <li key={i}><span className="text-[10px] font-bold uppercase text-foreground-muted mr-1">{BASIS[s.basis]}</span>{s.statement}</li>)}</ul>
                    {brief.content.emerging_risks.length > 0 && (
                        <div><p className="font-bold text-foreground">Emerging risks</p><ul className="list-disc ml-5">{brief.content.emerging_risks.map((r, i) => <li key={i}>{r.risk} <span className={r.confirmed ? 'text-red' : 'text-amber'}>({r.confirmed ? 'confirmed' : 'unconfirmed'})</span></li>)}</ul></div>
                    )}
                    {brief.content.organisation_actions.length > 0 && (
                        <div><p className="font-bold text-foreground">Suggested actions (for people to decide)</p><ul className="list-disc ml-5">{brief.content.organisation_actions.map((a, i) => <li key={i}><span className="font-semibold">{a.org_id}</span>: {a.action} · {a.priority}{a.requires_approval ? ' · needs approval' : ''}</li>)}</ul></div>
                    )}
                    {brief.content.invalid_refs?.length ? <p className="text-foreground-muted">References the model gave that are not in the records were removed: {brief.content.invalid_refs.join(', ')}</p> : null}
                </div>
            )}

            {orgs && orgs.length === 0 && <p className="text-xs text-foreground-muted">No organisation is classified into this sector yet.</p>}
            <div className="bg-card border border-border rounded-xl p-4 space-y-2 text-xs">
                <div className="flex items-center justify-between">
                    <h2 className="text-sm font-bold text-foreground">Manually add asset</h2>
                    <button onClick={() => setManual({ ...manual, open: !manual.open })} className="text-[11px] font-bold text-purple">{manual.open ? 'Close' : 'Manually Add Asset'}</button>
                </div>
                {manual.open && (
                    <>
                        <p className="text-foreground-muted">Registers an IP against an organisation and sector with your justification. It is <span className="font-bold">not verified</span>: it does not appear as confirmed, does not designate the operator, and does not authorise any scan.</p>
                        <div className="flex flex-wrap gap-2 items-center">
                            <select className="bg-card-muted border border-border rounded-lg px-2 py-1" value={manual.org_id} onChange={(e) => setManual({ ...manual, org_id: e.target.value })} aria-label="Organisation">
                                <option value="">Organisation</option>
                                {allOrgs.map((o) => <option key={o.slug} value={o.slug}>{o.name}{o.profile ? ` — ${o.profile.sector_id} (${o.profile.designation})` : ' — not classified'}</option>)}
                            </select>
                            <select className="bg-card-muted border border-border rounded-lg px-2 py-1" value={manual.sector_id} onChange={(e) => setManual({ ...manual, sector_id: e.target.value })} aria-label="Sector">
                                {Object.keys(SECTOR_BY_ID).map((id) => <option key={id} value={id}>{id}</option>)}
                            </select>
                            <input className="bg-card-muted border border-border rounded-lg px-2 py-1 font-mono" placeholder="IP address" value={manual.ip} onChange={(e) => setManual({ ...manual, ip: e.target.value })} aria-label="IP address" />
                            <input className="bg-card-muted border border-border rounded-lg px-2 py-1 flex-1 min-w-[240px]" placeholder="Justification / evidence (10+ characters)" value={manual.justification} onChange={(e) => setManual({ ...manual, justification: e.target.value })} aria-label="Justification" />
                            <button disabled={!manual.org_id || !manual.ip.trim() || manual.justification.trim().length < 10} onClick={() => void addManual()} className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1 disabled:opacity-50">Register</button>
                        </div>
                    </>
                )}
                {manualMsg && <p role="status" className="font-semibold">{manualMsg}</p>}
                {registered && registered.length > 0 && (
                    <div>
                        <p className="text-[10px] font-bold uppercase text-foreground-muted">Registered, not verified ({registered.length})</p>
                        {registered.map((r) => <p key={r.id}><span className="font-mono font-bold">{r.value}</span> <span className="text-amber font-bold text-[10px] uppercase">unverified</span> <span className="text-foreground-muted">· {r.org_id} · {timeAgo(r.updated_at)}</span></p>)}
                    </div>
                )}
            </div>
            {watch && watch.length > 0 && (
                <div className="bg-card border border-border rounded-xl p-4">
                    <h2 className="text-sm font-bold text-foreground mb-1">Confirmed watch-list assets ({watch.length})</h2>
                    <p className="text-[11px] text-foreground-muted mb-2">Submitted through intake and linked to an organisation in this sector by authorised scope or a manager&apos;s confirmation. Open one from the CNII overview for its assessments and findings.</p>
                    {watch.map((w) => <p key={w.id} className="text-xs"><span className="font-mono font-bold">{w.value}</span> <span className="text-foreground-muted">· {w.org_id}{w.subfield ? ` / ${w.subfield}` : ''} · {w.ips.slice(0, 3).join(', ')}{w.ips.length > 3 ? ` +${w.ips.length - 3}` : ''} · {w.basis === 'authorised_scope' ? 'from authorised scope' : 'confirmed by a manager'} · {timeAgo(w.updated_at)}</span></p>)}
                </div>
            )}
            {orgs && orgs.length > 0 && (
                <div className="bg-card border border-border rounded-xl p-4 overflow-x-auto">
                    <table className="w-full text-xs">
                        <thead><tr className="text-left text-foreground-muted"><th className="py-1 pr-3">Organisation</th><th className="pr-3">Assets</th><th className="pr-3">Confirmed P1/P2</th><th className="pr-3">Unconfirmed</th><th className="pr-3">KEV</th><th className="pr-3">New matches</th><th className="pr-3">Last collection</th><th>Gaps</th></tr></thead>
                        <tbody>
                            {orgs.map((o) => (
                                <tr key={o.profile.org_id} className="border-t border-border align-top">
                                    <td className="py-1.5 pr-3"><Link href={`/admin/cnii/org/${encodeURIComponent(o.profile.org_id)}`} className="font-semibold text-purple">{o.name}</Link><p className="text-foreground-muted">{o.profile.subfield ?? ''} {o.profile.designation}</p></td>
                                    <td className="pr-3">{o.stats.assets}{o.stats.probable_assets ? <span className="text-foreground-muted"> ({o.stats.probable_assets} probable)</span> : null}</td>
                                    <td className="pr-3 font-bold text-red">{o.stats.confirmed_p1_p2}</td>
                                    <td className="pr-3 text-amber">{o.stats.unconfirmed_open}</td>
                                    <td className="pr-3">{o.stats.kev_open}</td>
                                    <td className="pr-3">{o.stats.new_matches}</td>
                                    <td className="pr-3">{o.stats.last_collection ? `${timeAgo(o.stats.last_collection.at)} (${o.stats.last_collection.status})` : 'never'}</td>
                                    <td className="text-amber">{o.gaps.join('; ') || <span className="text-foreground-muted">none</span>}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}
