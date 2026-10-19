'use client';

// AI panel (phase P3) — asks the backend for an AI analysis of one record
// (POST /api/ai/generate) and shows the latest one (GET /api/ai/artifacts). The output is
// labelled as an AI assessment, shows the records it cites, flags any citation the backend had to
// remove, and takes analyst feedback. It never changes the record. When AI is unavailable it
// says so; nothing is shown in its place.

import { useEffect, useState } from 'react';
import { Sparkles, ThumbsUp, ThumbsDown, AlertTriangle } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { loadJson } from '@/lib/alerts';

interface Artifact {
    id: string | null; purpose: string; content: Record<string, unknown> & { invalid_refs?: string[] }; model: string; created_at: string;
    status?: string; feedback?: string | null; feedback_by?: string | null;
}

const SUBJECT: Record<string, string> = {
    alert_summary: 'alert', case_summary: 'case', case_handover: 'case', incident_report: 'case',
    finding_explanation: 'finding', remediation_plan: 'finding', rescan_interpretation: 'finding', asset_assessment: 'asset',
    indicator_assessment: 'indicator', threat_briefing: 'report', weekly_insights: 'report',
    cnii_intake_classification: 'cnii_submission',
};
const LABEL = (k: string) => k.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase());
const MAIN_FIELDS = ['action', 'step', 'event', 'observation', 'title', 'task', 'control', 'finding', 'item', 'name'];
const fmt = (iso: string) => new Intl.DateTimeFormat('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }).format(new Date(iso)) + ' WAT';

function Refs({ refs }: { refs: unknown }) {
    if (!Array.isArray(refs) || !refs.length) return null;
    return <span className="ml-1 text-[9px] font-mono text-foreground-muted">[{refs.join(', ')}]</span>;
}

function Value({ v }: { v: unknown }) {
    if (v === null || v === undefined || v === '') return <span className="text-foreground-muted">—</span>;
    if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') return <span>{String(v)}</span>;
    if (Array.isArray(v)) {
        if (!v.length) return <span className="text-foreground-muted">None</span>;
        return (
            <ul className="list-disc pl-4 space-y-1">
                {v.map((item, i) => {
                    if (typeof item !== 'object' || item === null) return <li key={i}>{String(item)}</li>;
                    const o = item as Record<string, unknown>;
                    const main = MAIN_FIELDS.find((f) => typeof o[f] === 'string');
                    return (
                        <li key={i}>
                            {main && <span className="font-semibold">{String(o[main])}</span>}
                            {o.requires_approval === true && <span className="ml-1 text-[9px] font-bold text-amber uppercase">needs approval</span>}
                            {Object.entries(o).filter(([k]) => k !== main && !['evidence_refs', 'ref', 'evidence_ref', 'requires_approval'].includes(k)).map(([k, x]) => (
                                <span key={k} className="block text-foreground-muted">{LABEL(k)}: {typeof x === 'object' ? JSON.stringify(x) : String(x)}</span>
                            ))}
                            <Refs refs={o.evidence_refs ?? (o.ref ? [o.ref] : o.evidence_ref ? [o.evidence_ref] : null)} />
                        </li>
                    );
                })}
            </ul>
        );
    }
    return (
        <div className="space-y-0.5">
            {Object.entries(v as Record<string, unknown>).map(([k, x]) => <p key={k}><span className="text-foreground-muted">{LABEL(k)}:</span> <Value v={x} /></p>)}
        </div>
    );
}

export function AiPanel({ purpose, subjectId, title, purposes }: { purpose: string; subjectId: string; title: string; purposes?: { value: string; label: string }[] }) {
    const [chosen, setChosen] = useState(purpose);
    const [artifact, setArtifact] = useState<Artifact | null>(null);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const subjectType = SUBJECT[chosen] ?? 'alert';

    // Callers key this component by record id, so a new record starts from a clean state.
    useEffect(() => {
        let active = true;
        void loadJson<{ artifacts: Artifact[] }>(`/api/ai/artifacts?subject_type=${subjectType}&subject_id=${encodeURIComponent(subjectId)}`).then((r) => {
            if (active) setArtifact(r.ok ? r.data.artifacts.find((a) => a.purpose === chosen) ?? null : null);
        });
        return () => { active = false; };
    }, [subjectType, subjectId, chosen]);

    async function run() {
        setBusy(true);
        setError(null);
        try {
            const r = await apiFetch(apiUrl('/api/ai/generate'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ purpose: chosen, subject_id: subjectId }) });
            const d = await r.json().catch(() => null);
            if (!r.ok) { setError(d?.error ?? `AI unavailable (HTTP ${r.status})`); return; }
            setArtifact(d.artifact);
        } catch {
            setError('Could not reach the backend');
        } finally {
            setBusy(false);
        }
    }

    async function feedback(status: 'accepted' | 'rejected') {
        if (!artifact?.id) return;
        const note = status === 'rejected' ? window.prompt('What is wrong with it? (optional)') : null;
        const r = await apiFetch(apiUrl(`/api/ai/artifacts/${artifact.id}/feedback`), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status, feedback: note ?? undefined }) });
        const d = await r.json().catch(() => null);
        if (r.ok && d?.artifact) setArtifact({ ...artifact, ...d.artifact });
    }

    const { invalid_refs: invalid, ...content } = artifact?.content ?? {};
    return (
        <div className="border border-purple/30 rounded-xl p-3 space-y-2 bg-purple/5">
            <div className="flex items-center justify-between gap-2 flex-wrap">
                <p className="text-xs font-black text-foreground flex items-center gap-1.5"><Sparkles className="w-3.5 h-3.5 text-purple" /> {title}</p>
                <div className="flex items-center gap-2">
                    {purposes && purposes.length > 1 && (
                        <select aria-label="Analysis type" value={chosen} onChange={(e) => { setArtifact(null); setError(null); setChosen(e.target.value); }} className="bg-card border border-border rounded px-2 py-1 text-[11px]">
                            {purposes.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
                        </select>
                    )}
                    <button disabled={busy} onClick={() => void run()} className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1 disabled:opacity-50">
                        {busy ? 'Analysing…' : artifact ? 'Regenerate' : 'Generate'}
                    </button>
                </div>
            </div>
            {error && <p role="alert" className="text-[11px] text-amber font-semibold">{error}</p>}
            {artifact && (
                <div className="space-y-2 text-[11px] text-foreground">
                    <p className="text-[10px] text-foreground-muted">AI-generated assessment ({artifact.model}, {fmt(artifact.created_at)}). Advice only — verify against the cited records before acting.</p>
                    {invalid && invalid.length > 0 && (
                        <p className="text-[10px] text-amber flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> {invalid.length} citation(s) to records that were not provided were removed: {invalid.join(', ')}</p>
                    )}
                    {Object.entries(content).map(([k, v]) => (
                        <div key={k}>
                            <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{LABEL(k)}</p>
                            <div className="mt-0.5"><Value v={v} /></div>
                        </div>
                    ))}
                    {artifact.id && (
                        <div className="flex items-center gap-2 pt-1">
                            {artifact.status && artifact.status !== 'draft' ? (
                                <span className="text-[10px] text-foreground-muted">Marked {artifact.status}{artifact.feedback_by ? ` by ${artifact.feedback_by}` : ''}{artifact.feedback ? ` — ${artifact.feedback}` : ''}</span>
                            ) : (
                                <>
                                    <button onClick={() => void feedback('accepted')} className="flex items-center gap-1 text-[10px] font-bold border border-border rounded px-2 py-0.5"><ThumbsUp className="w-3 h-3" /> Useful</button>
                                    <button onClick={() => void feedback('rejected')} className="flex items-center gap-1 text-[10px] font-bold border border-border rounded px-2 py-0.5"><ThumbsDown className="w-3 h-3" /> Wrong</button>
                                </>
                            )}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
