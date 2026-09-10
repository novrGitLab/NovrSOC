'use client';

import { useEffect, useState } from 'react';
import { ClipboardCheck, RotateCcw } from 'lucide-react';
import { ExportButton } from '@/components/shared/ExportButton';

// Structured vendor security assessment — the questionnaire half of the vendor review, as
// opposed to the automated attack-surface scoring the rest of the page does from DNS/TLS/breach
// signals. The two answer different questions: the automated score says what's observable from
// outside, this says what the vendor attests to about its own controls.
//
// Answers persist in localStorage, keyed per vendor. That's deliberate and worth being clear
// about: there is no assessment table in Supabase, and routes/vendor-assessments.ts only
// proxies to APP_BACKEND_URL (the external legacy backend), which isn't reachable in this
// deployment — so a "Save" button here would silently fail or need a schema that doesn't exist
// yet. Per-browser persistence is honest about that; wire it to a real table before promising
// the answers are shared or retained anywhere else.

interface Question { id: string; text: string }
interface Domain { id: string; name: string; questions: Question[] }

const ASSESSMENT_DOMAINS: Domain[] = [
    {
        id: 'data_security',
        name: 'Data Security',
        questions: [
            { id: 'ds1', text: 'Is data encrypted at rest and in transit?' },
            { id: 'ds2', text: 'Are encryption keys properly managed?' },
            { id: 'ds3', text: 'Is sensitive data classified and labeled?' },
        ],
    },
    {
        id: 'access_control',
        name: 'Access Control',
        questions: [
            { id: 'ac1', text: 'Is multi-factor authentication enforced?' },
            { id: 'ac2', text: 'Are access rights reviewed regularly?' },
            { id: 'ac3', text: 'Is the least-privilege principle applied?' },
        ],
    },
    {
        id: 'incident_response',
        name: 'Incident Response',
        questions: [
            { id: 'ir1', text: 'Is there a documented incident response plan?' },
            { id: 'ir2', text: 'Are staff trained on incident procedures?' },
            { id: 'ir3', text: 'Are incidents reported within 24 hours?' },
        ],
    },
    {
        id: 'compliance',
        name: 'Compliance',
        questions: [
            { id: 'cp1', text: 'Is the vendor NDPA compliant?' },
            { id: 'cp2', text: 'Are third-party audits conducted annually?' },
            { id: 'cp3', text: 'Are compliance certificates available?' },
        ],
    },
    {
        id: 'business_continuity',
        name: 'Business Continuity',
        questions: [
            { id: 'bc1', text: 'Is there a tested business continuity plan?' },
            { id: 'bc2', text: 'Are regular backups performed and tested?' },
            { id: 'bc3', text: 'Is RTO/RPO defined and achievable?' },
        ],
    },
];

const SCORE_OPTIONS = [
    { value: 0, label: 'Not implemented' },
    { value: 1, label: 'Partially implemented' },
    { value: 2, label: 'Implemented' },
    { value: 3, label: 'Fully implemented with evidence' },
];

const TOTAL_QUESTIONS = ASSESSMENT_DOMAINS.reduce((n, d) => n + d.questions.length, 0);
const MAX_SCORE = TOTAL_QUESTIONS * 3;

function ratingFor(pct: number): { label: string; text: string; bar: string } {
    if (pct >= 90) return { label: 'Low Risk', text: 'text-green', bar: 'bg-green' };
    if (pct >= 70) return { label: 'Medium Risk', text: 'text-amber', bar: 'bg-amber' };
    if (pct >= 50) return { label: 'High Risk', text: 'text-orange', bar: 'bg-orange' };
    return { label: 'Critical Risk', text: 'text-red', bar: 'bg-red' };
}

export function VendorAssessmentQuestionnaire({ vendorId, vendorName }: { vendorId: string; vendorName: string }) {
    const storageKey = `novrsoc.vendor-assessment.${vendorId}`;
    const [answers, setAnswers] = useState<Record<string, number>>({});
    const [hydrated, setHydrated] = useState(false);

    // Read after mount, never during render — this page is prerendered, so localStorage doesn't
    // exist when the server HTML is produced. Seeding useState from it instead would either
    // throw during prerender or make the server and client markup disagree.
    //
    // react-hooks/set-state-in-effect is disabled here deliberately: the rule targets effects
    // that derive state React already has, but this one subscribes to an external store
    // (localStorage) at mount, which is the case the rule's own docs carve out. The alternative
    // that satisfies it — useSyncExternalStore — is a lot of machinery for a one-shot read.
    useEffect(() => {
        try {
            const raw = localStorage.getItem(storageKey);
            // eslint-disable-next-line react-hooks/set-state-in-effect -- one-shot hydrate from localStorage; see above
            if (raw) setAnswers(JSON.parse(raw) as Record<string, number>);
        } catch {
            // Private mode, blocked site data, or corrupt JSON — start from a blank assessment.
        }
        setHydrated(true);
    }, [storageKey]);

    useEffect(() => {
        if (!hydrated) return;
        try {
            localStorage.setItem(storageKey, JSON.stringify(answers));
        } catch {
            // Persisting is best-effort; the assessment still works for this session.
        }
    }, [answers, hydrated, storageKey]);

    const setAnswer = (qid: string, value: number) => setAnswers((prev) => ({ ...prev, [qid]: value }));
    const reset = () => setAnswers({});

    const answered = Object.keys(answers).length;
    const totalScore = Object.values(answers).reduce((a, b) => a + b, 0);
    // Scored against the whole questionnaire, not just what's been answered — a part-finished
    // assessment shouldn't read as "Low Risk" because the three answered questions scored well.
    const pct = Math.round((totalScore / MAX_SCORE) * 100);
    const rating = ratingFor(pct);
    const complete = answered === TOTAL_QUESTIONS;

    return (
        <div id="vendor-assessment-report" className="bg-card border border-border rounded-xl p-5 space-y-5">
            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="flex items-start gap-2.5">
                    <div className="w-8 h-8 rounded-lg bg-purple/10 flex items-center justify-center flex-shrink-0">
                        <ClipboardCheck className="w-4 h-4 text-purple" />
                    </div>
                    <div>
                        <p className="text-sm font-black text-foreground">Security Assessment — {vendorName}</p>
                        <p className="text-[11px] text-foreground-muted">
                            {TOTAL_QUESTIONS} controls across {ASSESSMENT_DOMAINS.length} domains, scored 0–3
                        </p>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    <button onClick={reset} className="flex items-center gap-1.5 text-[11px] font-bold text-foreground-muted border border-border rounded-lg px-3 py-2 hover:text-foreground transition-colors">
                        <RotateCcw size={12} /> Reset
                    </button>
                    <ExportButton elementId="vendor-assessment-report" filename={`vendor-assessment-${vendorId}`} title={`Security Assessment — ${vendorName}`} />
                </div>
            </div>

            {/* Progress + running score */}
            <div className="bg-card-muted/50 border border-border rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between text-xs flex-wrap gap-2">
                    <span className="text-foreground-muted">
                        Progress: <span className="font-bold text-foreground">{answered}/{TOTAL_QUESTIONS}</span> answered
                    </span>
                    <span className="text-foreground-muted">
                        Score: <span className="font-bold text-foreground">{totalScore}/{MAX_SCORE}</span> ({pct}%)
                    </span>
                    <span className={`text-[10px] font-black uppercase ${rating.text}`}>
                        {complete ? rating.label : `${rating.label} (incomplete)`}
                    </span>
                </div>
                <div className="h-2 bg-border rounded-full overflow-hidden">
                    <div className={`h-full ${rating.bar} transition-all`} style={{ width: `${Math.round((answered / TOTAL_QUESTIONS) * 100)}%` }} />
                </div>
                {!complete && (
                    <p className="text-[10px] text-foreground-muted">
                        Rating is provisional until every control is answered — unanswered controls score zero.
                    </p>
                )}
            </div>

            {/* Domains */}
            <div className="space-y-5">
                {ASSESSMENT_DOMAINS.map((domain) => {
                    const domainMax = domain.questions.length * 3;
                    const domainScore = domain.questions.reduce((sum, q) => sum + (answers[q.id] ?? 0), 0);
                    const domainPct = Math.round((domainScore / domainMax) * 100);
                    const domainRating = ratingFor(domainPct);

                    return (
                        <div key={domain.id} className="border border-border rounded-xl overflow-hidden">
                            <div className="flex items-center justify-between gap-3 px-4 py-2.5 bg-card-muted/40 border-b border-border flex-wrap">
                                <p className="text-xs font-black text-foreground">{domain.name}</p>
                                <span className={`text-[11px] font-bold ${domainRating.text}`}>
                                    {domainScore}/{domainMax} · {domainPct}%
                                </span>
                            </div>
                            <div className="divide-y divide-border">
                                {domain.questions.map((q) => (
                                    <div key={q.id} className="px-4 py-3">
                                        <p className="text-xs text-foreground mb-2">{q.text}</p>
                                        <div className="flex flex-wrap gap-1.5">
                                            {SCORE_OPTIONS.map((opt) => {
                                                const selected = answers[q.id] === opt.value;
                                                return (
                                                    <button
                                                        key={opt.value}
                                                        onClick={() => setAnswer(q.id, opt.value)}
                                                        className={`text-[10px] font-bold px-2.5 py-1.5 rounded-lg border transition-colors ${
                                                            selected
                                                                ? 'bg-purple text-white border-purple'
                                                                : 'bg-card text-foreground-muted border-border hover:border-purple hover:text-purple'
                                                        }`}
                                                    >
                                                        {opt.value} · {opt.label}
                                                    </button>
                                                );
                                            })}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    );
                })}
            </div>

            <p className="text-[10px] text-foreground-muted">
                Answers are saved in this browser only. They are not yet persisted to Supabase or
                shared with other users.
            </p>
        </div>
    );
}
