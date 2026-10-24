'use client';

// Shared pieces for the Threat Intelligence pages (phase P25): sharing markings, the basis of an
// AI statement, source citations with their timestamps, freshness and server-side paging. Every
// value shown comes from /api/ti; a source's claim is always labelled as that source's.

import type { ReactNode } from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { fmtWat } from '@/lib/vms';
import { btn } from '@/components/features/vms/kit';
import { StatusPill, type Tone } from '@/components/features/vms/ui';
import { TLP_LABEL, FEED_NAME, ago, type Tlp } from '@/lib/ti';

const TLP_STYLE: Record<Tlp, string> = {
    clear: 'border-border text-foreground bg-card',
    green: 'border-green/40 text-green bg-green/10',
    amber: 'border-orange/40 text-orange bg-orange/10',
    'amber+strict': 'border-orange/60 text-orange bg-orange/15',
    red: 'border-red/50 text-red bg-red/10',
};
const TLP_MEANING: Record<Tlp, string> = {
    clear: 'May be shared freely.',
    green: 'May be shared within the community, not publicly.',
    amber: 'Limited to recipients\' organisations and their clients, on a need-to-know basis.',
    'amber+strict': 'Limited to the recipient organisation only.',
    red: 'For the named recipients only. Never shared outside the platform.',
};
/** A sharing marking, with what it means on hover. */
export function TlpBadge({ tlp }: { tlp: Tlp | null | undefined }) {
    const t = tlp ?? 'amber';
    return <span title={TLP_MEANING[t]} className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-bold tracking-wide whitespace-nowrap ${TLP_STYLE[t]}`}>{TLP_LABEL[t]}</span>;
}

export type Basis = 'platform_record' | 'source_claim' | 'ai_assessment';
const BASIS: Record<Basis, { label: string; tone: Tone; hint: string }> = {
    platform_record: { label: 'Fact', tone: 'good', hint: 'Shown by a record in the platform' },
    source_claim: { label: 'Source claim', tone: 'warning', hint: 'Stated by a feed or report — not confirmed by NovrSOC' },
    ai_assessment: { label: 'AI inference', tone: 'neutral', hint: 'The model\'s own reasoning' },
};
/** Fact, source claim or inference — the three are never mixed. */
export function BasisBadge({ basis }: { basis: Basis }) {
    const b = BASIS[basis] ?? BASIS.ai_assessment;
    return <span title={b.hint}><StatusPill tone={b.tone} label={b.label} /></span>;
}

/** "ThreatFox #1001 · 3 h ago" with the exact time on hover. */
export function Citation({ feed, sourceRef, at, now }: { feed: string; sourceRef?: string | null; at?: string | null; now: number }) {
    return (
        <span className="text-[11px] text-foreground-muted">
            <span className="font-semibold text-foreground">{FEED_NAME[feed] ?? feed}</span>
            {sourceRef ? <span className="font-mono"> #{sourceRef.length > 24 ? `${sourceRef.slice(0, 24)}…` : sourceRef}</span> : null}
            {at ? <span title={fmtWat(at)}> · {ago(at, now)}</span> : null}
        </span>
    );
}

/** A freshness state for a source: current, stale (no success within its window), failing or off. */
export function Freshness({ lastSuccess, stale, failing, configured, retired, enabled, now }: { lastSuccess: string | null; stale?: boolean; failing?: boolean; configured?: boolean; retired?: boolean; enabled?: boolean; now: number }) {
    if (retired) return <StatusPill tone="neutral" label="Retired" />;
    if (configured === false) return <StatusPill tone="neutral" label="Not configured" />;
    if (enabled === false) return <StatusPill tone="neutral" label="Switched off" />;
    if (failing) return <StatusPill tone="critical" label={`Failing · last success ${ago(lastSuccess, now)}`} />;
    if (stale) return <StatusPill tone="warning" label={`Stale · ${ago(lastSuccess, now)}`} />;
    return <StatusPill tone="good" label={`Current · ${ago(lastSuccess, now)}`} />;
}

/** Server-side paging: "1–50 of 1,234" with previous / next. */
export function Pager({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (p: number) => void }) {
    const pages = Math.max(1, Math.ceil(total / pageSize));
    const from = total ? (page - 1) * pageSize + 1 : 0;
    const to = Math.min(total, page * pageSize);
    return (
        <nav className="flex items-center justify-between gap-2 pt-3 text-[11px] text-foreground-muted" aria-label="Pages">
            <span className="tabular-nums">{from.toLocaleString('en-GB')}–{to.toLocaleString('en-GB')} of {total.toLocaleString('en-GB')}</span>
            <span className="flex items-center gap-1">
                <button type="button" className={btn('ghost')} disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page"><ChevronLeft className="w-3.5 h-3.5" /></button>
                <span className="tabular-nums">Page {page} of {pages}</span>
                <button type="button" className={btn('ghost')} disabled={page >= pages} onClick={() => onPage(page + 1)} aria-label="Next page"><ChevronRight className="w-3.5 h-3.5" /></button>
            </span>
        </nav>
    );
}

/** A small labelled value in a detail panel. */
export function Field({ label, children }: { label: string; children: ReactNode }) {
    return (
        <div className="min-w-0">
            <dt className="text-[10px] font-bold uppercase tracking-wider text-foreground-muted">{label}</dt>
            <dd className="mt-0.5 text-xs text-foreground break-words">{children}</dd>
        </div>
    );
}

/** The data limitations a page states, as a short list. */
export function Limitations({ items }: { items: string[] }) {
    if (!items.length) return null;
    return (
        <ul className="mt-3 space-y-1 text-[11px] text-foreground-muted list-disc pl-4">
            {items.map((l) => <li key={l}>{l}</li>)}
        </ul>
    );
}
