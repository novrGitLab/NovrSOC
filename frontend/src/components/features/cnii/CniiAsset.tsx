'use client';

// One CNII asset (phase P9): how it is authorised, what each passive source reported (with
// confidence and how often), its findings with the kind of evidence behind each — a third-party
// version match is shown as unconfirmed, never as a confirmed vulnerability — indicator matches,
// services our own scanner saw, and its change history. The AI assessment is advice only.

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { ArrowLeft, Sparkles } from 'lucide-react';
import { getAdminUser } from '@/lib/admin-auth';
import { cniiGet, apiSend, timeAgo, permits, isUnconfirmed, AUTH_STYLE, AUTH_LABEL, EVIDENCE_LABEL, PRIORITY_STYLE, type Authorisation, type CniiObservation, type CniiFinding } from '@/lib/cnii-types';
import { fmtWat, describeEvent, EVENT_LABEL, type VmsEvent, type VmsService } from '@/lib/vms';

interface Detail {
    asset: { id: string; value: string; asset_type: string; exposure: string; confidence: string; criticality: string; ips: string[]; discovery_sources: string[]; first_seen: string; last_seen: string };
    authorisation: Authorisation; observations: CniiObservation[]; findings: CniiFinding[];
    indicator_matches: { id: string; status: string; matched_field: string; first_matched_at: string; ti_indicators: { type: string; value: string; max_confidence: number | null; malware_families: string[]; source_count: number } | null }[];
    services: VmsService[]; events: VmsEvent[];
}
interface Assessment { summary: string; exposure: string; priority_actions: { action: string; rationale: string; requires_approval: boolean }[]; uncertainties: string[]; confidence: string }

export function CniiAsset({ org, id }: { org: string; id: string }) {
    const role = getAdminUser().role;
    const send = ['super_admin', 'soc_manager', 'analyst'].includes(role) ? org : undefined;
    const [d, setD] = useState<Detail | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [ai, setAi] = useState<Assessment | null>(null);
    const [aiErr, setAiErr] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);

    useEffect(() => {
        let active = true;
        void cniiGet<Detail>(`/assets/${id}`, send).then((r) => { if (active) { setD(r.ok ? r.data : null); setError(r.ok ? null : r.error); } });
        return () => { active = false; };
    }, [id, send]);

    async function assess() {
        setBusy(true); setAiErr(null);
        const r = await apiSend<{ artifact: { content: Assessment } }>('/api/ai/generate', 'POST', { purpose: 'asset_assessment', subject_id: id }, send);
        setBusy(false);
        if (r.ok) setAi(r.data.artifact.content); else setAiErr(r.error);
    }

    if (error) return <p role="alert" className="text-xs text-red font-semibold">{error}</p>;
    if (!d) return <p className="text-xs text-foreground-muted">Loading…</p>;
    const a = d.asset;
    return (
        <div className="space-y-4 text-xs">
            <Link href={`/admin/cnii/org/${encodeURIComponent(org)}`} className="text-[11px] text-foreground-muted flex items-center gap-1"><ArrowLeft className="w-3 h-3" /> Organisation</Link>
            <div className="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <h1 className="text-lg font-black text-foreground font-mono">{a.value}</h1>
                    <p className="text-foreground-muted">{a.asset_type} · {a.exposure} · criticality {a.criticality} · {a.confidence}{a.ips.length ? ` · ${a.ips.join(', ')}` : ''} · first seen {fmtWat(a.first_seen)} · sources {a.discovery_sources.join(', ')}</p>
                </div>
                <button disabled={busy} onClick={() => void assess()} className="flex items-center gap-1.5 text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5 disabled:opacity-50"><Sparkles className="w-3.5 h-3.5" /> AI assessment</button>
            </div>
            <div className="bg-card border border-border rounded-xl p-4">
                <span className={`px-1.5 py-0.5 rounded font-bold ${AUTH_STYLE[d.authorisation.status]}`}>{AUTH_LABEL[d.authorisation.status]}</span>
                <span className="ml-2 text-foreground">{d.authorisation.scope ? `${d.authorisation.scope} · ` : ''}{d.authorisation.status === 'authorised' ? `allows ${permits(d.authorisation)} · until ${fmtWat(d.authorisation.expires_at)}` : d.authorisation.status === 'not_authorised' ? 'No scope entry covers this asset: nothing may be collected about it.' : 'The scope entry that covered it no longer does; nothing new is collected.'}</span>
            </div>
            {aiErr && <p role="alert" className="text-red font-semibold">{aiErr}</p>}
            {ai && (
                <div className="bg-card border border-purple/30 rounded-xl p-4 space-y-2">
                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">AI assessment · confidence {ai.confidence} · advice only</p>
                    <p className="text-foreground">{ai.summary}</p>
                    <p className="text-foreground-muted">{ai.exposure}</p>
                    <ul className="list-disc ml-5">{ai.priority_actions.map((p, i) => <li key={i}>{p.action}{p.requires_approval ? ' (needs approval)' : ''}: <span className="text-foreground-muted">{p.rationale}</span></li>)}</ul>
                    {ai.uncertainties.length > 0 && <p className="text-amber">Uncertain: {ai.uncertainties.join('; ')}</p>}
                </div>
            )}

            <div className="bg-card border border-border rounded-xl p-4 overflow-x-auto">
                <h2 className="text-sm font-bold text-foreground mb-2">Findings ({d.findings.length})</h2>
                <p className="text-foreground-muted mb-2">Status changes, cases and remediation are made in Vulnerability Management by someone working in this organisation.</p>
                {d.findings.length === 0 ? <p className="text-foreground-muted">None.</p> : (
                    <table className="w-full">
                        <thead><tr className="text-left text-foreground-muted"><th className="py-1 pr-3">Priority</th><th className="pr-3">Finding</th><th className="pr-3">Evidence</th><th className="pr-3">Status</th><th>Seen</th></tr></thead>
                        <tbody>
                            {d.findings.map((f) => (
                                <tr key={f.id} className="border-t border-border align-top">
                                    <td className="py-1.5 pr-3"><span className={`px-1.5 py-0.5 rounded font-bold ${PRIORITY_STYLE[f.priority ?? 'P4']}`}>{f.priority ?? '—'}</span></td>
                                    <td className="pr-3"><span className="font-semibold text-foreground">{f.title}</span><p className="text-foreground-muted">{String((f.risk_factors as { rule?: unknown }).rule ?? '')}</p></td>
                                    <td className={`pr-3 ${isUnconfirmed(f.evidence_class) ? 'text-amber font-semibold' : 'text-foreground'}`}>{EVIDENCE_LABEL[f.evidence_class] ?? f.evidence_class}<p className="text-foreground-muted font-normal">{f.detected_by.join(', ')}</p></td>
                                    <td className="pr-3">{f.status.replace(/_/g, ' ')}</td>
                                    <td>{timeAgo(f.last_seen)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            <div className="bg-card border border-border rounded-xl p-4 overflow-x-auto">
                <h2 className="text-sm font-bold text-foreground mb-2">What passive sources reported ({d.observations.length})</h2>
                {d.observations.length === 0 ? <p className="text-foreground-muted">Nothing yet.</p> : (
                    <table className="w-full">
                        <thead><tr className="text-left text-foreground-muted"><th className="py-1 pr-3">Kind</th><th className="pr-3">Detail</th><th className="pr-3">Source</th><th className="pr-3">Confidence</th><th>First / last seen</th></tr></thead>
                        <tbody>
                            {d.observations.map((o) => (
                                <tr key={o.id} className="border-t border-border align-top">
                                    <td className="py-1.5 pr-3">{o.kind.replace(/_/g, ' ')}</td>
                                    <td className="pr-3 font-mono break-all">{o.key}</td>
                                    <td className="pr-3">{o.source}</td>
                                    <td className="pr-3">{o.confidence}</td>
                                    <td>{timeAgo(o.first_seen)} / {timeAgo(o.last_seen)} ({o.seen_count}×)</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            {d.indicator_matches.length > 0 && (
                <div className="bg-card border border-border rounded-xl p-4">
                    <h2 className="text-sm font-bold text-foreground mb-2">Threat indicator matches</h2>
                    <ul className="space-y-1">{d.indicator_matches.map((m) => <li key={m.id}><span className="font-mono">{m.ti_indicators?.value}</span> ({m.ti_indicators?.type}) · {m.ti_indicators?.source_count ?? 0} source(s){m.ti_indicators?.malware_families?.length ? ` · ${m.ti_indicators.malware_families.join(', ')}` : ''} · {m.status}</li>)}</ul>
                </div>
            )}

            {d.services.length > 0 && (
                <div className="bg-card border border-border rounded-xl p-4">
                    <h2 className="text-sm font-bold text-foreground mb-2">Services seen by our scanner</h2>
                    <ul>{d.services.map((s) => <li key={s.id}>{s.port}/{s.protocol} {[s.service, s.product, s.version].filter(Boolean).join(' ')} · {s.status}</li>)}</ul>
                </div>
            )}

            {d.events.length > 0 && (
                <div className="bg-card border border-border rounded-xl p-4">
                    <h2 className="text-sm font-bold text-foreground mb-2">History</h2>
                    <ul className="space-y-0.5">{d.events.map((e) => <li key={e.id}>{fmtWat(e.at)} · {EVENT_LABEL[e.event] ?? e.event} {describeEvent(e)}</li>)}</ul>
                </div>
            )}
        </div>
    );
}
