'use client';

// Threat Intelligence — AI Intelligence Analyst (phase P25). Questions about stored intelligence,
// answered only from records the platform holds (POST /api/ti/analyst/ask). Each statement says
// whether it is a fact in the platform's records, a claim a source made, or the model's
// inference, and cites the records it relies on; citations to records that were not sent are
// removed by the backend and counted here. Briefings and 7/30-day reports use the same rules.
// The AI never takes an action and never changes a record.

import { useState } from 'react';
import Link from 'next/link';
import { Sparkles, Send, AlertTriangle, ShieldCheck } from 'lucide-react';
import { PageHeader, Segmented, Notice, btn, type Msg } from '@/components/features/vms/kit';
import { Card, SectionTitle, Skeleton } from '@/components/features/vms/ui';
import { vmsSend } from '@/components/features/vms/data';
import { AiPanel } from '@/components/shared/AiPanel';
import { fmtWat } from '@/lib/vms';
import { BasisBadge, type Basis } from './common';
import { AiThreatIntelligenceDemo } from './AiThreatIntelligenceDemo';

interface SourceRef { ref: string; type: string; id: string; label?: string }
interface Answer {
    question: string;
    artifact: {
        id: string | null; model: string; created_at: string; source_refs: SourceRef[];
        content: { answer: string; statements: { statement: string; basis: Basis; evidence_refs: string[] }[]; insufficient_evidence: boolean; suggested_follow_ups: string[]; confidence: 'low' | 'medium' | 'high'; invalid_refs?: string[] };
    };
}
const PROMPTS = [
    'What has been reported about threats to Nigeria in the last 30 days?',
    'Which indicators matched our environment recently, and what do the sources say about them?',
    'Which known exploited vulnerabilities affect our open findings?',
];

/** Where a cited record can be opened. */
function refHref(r: SourceRef): string | null {
    if (r.type === 'indicator' || r.type === 'related_indicator') return `/admin/ti/indicators?id=${r.id}`;
    if (r.type === 'match') return '/admin/ti/matches';
    if (r.type === 'kev' || r.type === 'finding') return '/admin/ti/vulnerabilities';
    if (r.type === 'source_report' || r.type === 'advisory') return '/admin/ti/map';
    if (r.type === 'feed') return '/admin/ti/sources';
    return null;
}

export function TiAnalyst() {
    const [question, setQuestion] = useState('');
    const [busy, setBusy] = useState(false);
    const [msg, setMsg] = useState<Msg>(null);
    const [history, setHistory] = useState<Answer[]>([]);
    const [period, setPeriod] = useState<'7d' | '30d'>('7d');

    async function ask(q: string) {
        const text = q.trim();
        if (text.length < 3) return;
        setBusy(true);
        setMsg(null);
        const r = await vmsSend<Answer>('POST', '/api/ti/analyst/ask', { question: text });
        setBusy(false);
        if (!r.ok) { setMsg({ ok: false, text: r.error }); return; }
        setHistory((h) => [r.data, ...h].slice(0, 20));
        setQuestion('');
    }

    return (
        <div className="space-y-5">
            <PageHeader title="AI Intelligence Analyst" icon={Sparkles}
                description="Ask about the intelligence the platform holds. Answers use only stored records, label every statement as fact, source claim or inference, and cite their records." />

            <Card>
                <form onSubmit={(e) => { e.preventDefault(); void ask(question); }} className="space-y-2">
                    <label htmlFor="ti-question" className="text-xs font-semibold text-foreground">Your question</label>
                    <textarea id="ti-question" value={question} onChange={(e) => setQuestion(e.target.value)} maxLength={1000} rows={3}
                        placeholder="e.g. What do we know about 203.0.113.5? Is AsyncRAT active against Nigerian banks?"
                        className="w-full text-sm rounded-xl border border-border bg-card px-3 py-2 outline-none focus-visible:ring-2 focus-visible:ring-purple/60" />
                    <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex flex-wrap gap-1.5">{PROMPTS.map((p) => <button key={p} type="button" className={btn('ghost')} onClick={() => void ask(p)} disabled={busy}>{p}</button>)}</div>
                        <button type="submit" className={btn('primary', 'md')} disabled={busy || question.trim().length < 3}><Send className="w-3.5 h-3.5" /> Ask</button>
                    </div>
                </form>
                <p className="mt-3 flex items-start gap-1.5 text-[11px] text-foreground-muted"><ShieldCheck className="w-3.5 h-3.5 mt-px shrink-0" aria-hidden />The analyst reads records; it never takes an action. Content from feeds is treated as data, never as instructions. Sharing markings limit what the model may read.</p>
                <Notice msg={msg} />
            </Card>

            {busy && <Card><Skeleton className="h-28" /></Card>}

            {history.map((h, i) => {
                const c = h.artifact.content;
                const refs = new Map(h.artifact.source_refs.map((r) => [r.ref, r]));
                return (
                    <Card key={`${h.artifact.created_at}-${i}`} aria-label={`Answer to: ${h.question}`}>
                        <p className="text-[11px] text-foreground-muted">You asked · {fmtWat(h.artifact.created_at)}</p>
                        <p className="text-sm font-semibold text-foreground mt-0.5">{h.question}</p>
                        {c.insufficient_evidence && (
                            <p className="mt-3 flex items-start gap-1.5 rounded-xl border border-orange/40 bg-orange/10 p-2.5 text-xs text-foreground"><AlertTriangle className="w-4 h-4 text-orange shrink-0" aria-hidden />The stored intelligence does not fully answer this. What follows is limited to what the records show.</p>
                        )}
                        <p className="text-sm text-foreground mt-3 leading-relaxed">{c.answer}</p>
                        {c.statements.length > 0 && (
                            <ul className="mt-3 space-y-2">
                                {c.statements.map((s, j) => (
                                    <li key={j} className="rounded-xl border border-border p-2.5">
                                        <div className="flex items-start gap-2"><BasisBadge basis={s.basis} /><p className="text-xs text-foreground">{s.statement}</p></div>
                                        {s.evidence_refs.length > 0 && (
                                            <div className="mt-1.5 flex flex-wrap gap-1">
                                                {s.evidence_refs.map((ref) => {
                                                    const r = refs.get(ref);
                                                    const href = r ? refHref(r) : null;
                                                    const label = r?.label ? `${r.type}: ${r.label}` : ref;
                                                    return href ? <Link key={ref} href={href} className="text-[10px] font-mono rounded-md border border-border px-1.5 py-0.5 hover:border-purple/50">{label.slice(0, 70)}</Link> : <span key={ref} className="text-[10px] font-mono rounded-md border border-border px-1.5 py-0.5">{label.slice(0, 70)}</span>;
                                                })}
                                            </div>
                                        )}
                                    </li>
                                ))}
                            </ul>
                        )}
                        <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-foreground-muted">
                            <span>Confidence: <span className="font-semibold text-foreground">{c.confidence}</span></span>
                            <span>{h.artifact.source_refs.length} record(s) given to the model</span>
                            <span>Model: {h.artifact.model}</span>
                            {c.invalid_refs?.length ? <span className="text-orange">{c.invalid_refs.length} citation(s) to records that were not given were removed</span> : null}
                        </div>
                        {c.suggested_follow_ups.length > 0 && (
                            <div className="mt-3 flex flex-wrap gap-1.5">{c.suggested_follow_ups.slice(0, 4).map((f) => <button key={f} type="button" className={btn('secondary')} onClick={() => void ask(f)} disabled={busy}>{f}</button>)}</div>
                        )}
                    </Card>
                );
            })}

            <Card>
                <SectionTitle title="Executive AI Briefing" hint="Real AI, grounded in the period's stored records only — the platform's actual capability, not a demo" action={<Segmented label="Period" value={period} onChange={setPeriod} options={[['7d', '7 days'], ['30d', '30 days']] as const} />} />
                <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                    <AiPanel key={`b-${period}`} purpose="threat_briefing" subjectId={period} title={`Threat report — ${period === '7d' ? '7' : '30'} days`} />
                    <AiPanel key={`n-${period}`} purpose="nigeria_briefing" subjectId={period} title={`Nigeria briefing — ${period === '7d' ? '7' : '30'} days`} />
                </div>
            </Card>

            <div>
                <h2 className="text-sm font-black text-foreground mb-3">AI Threat Intelligence &amp; Behavioral Analysis</h2>
                <AiThreatIntelligenceDemo />
            </div>
        </div>
    );
}
