'use client';

// VMS design system, part 2 (redesign, phase P20): page headers, buttons, KPI cards, severity /
// priority / risk indicators (colour always paired with text), empty / error / notice states,
// segmented filters and search, a drawer, a confirmation dialog, a timeline, CSV export and an
// evidence viewer. Primitives (cards, tooltips, tones, count-up) live in ./ui.

import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import Link from 'next/link';
import { X, Search, Download, RefreshCw, Inbox, Copy, ChevronDown, ChevronRight, type LucideIcon } from 'lucide-react';
import { toCsv } from '@/lib/vmsFormat';
import { CountUp, Unavailable, ToneIcon, type Tone } from './ui';

// ── Page structure ─────────────────────────────────────────────────────────────────────────────
export function PageHeader({ title, description, icon: Icon, actions }: { title: string; description?: ReactNode; icon?: LucideIcon; actions?: ReactNode }) {
    return (
        <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
                <h1 className="text-xl font-black tracking-tight text-foreground flex items-center gap-2">{Icon && <Icon className="w-5 h-5 text-purple dark:text-[var(--vz-prog-4)]" aria-hidden />}{title}</h1>
                {description && <p className="text-xs text-foreground-muted mt-1 max-w-3xl leading-relaxed">{description}</p>}
            </div>
            {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </div>
    );
}

const BTN = {
    primary: 'bg-purple text-white hover:bg-purple-hover disabled:opacity-50 disabled:cursor-not-allowed',
    secondary: 'border border-border bg-card text-foreground hover:bg-card-muted disabled:opacity-50 disabled:cursor-not-allowed',
    danger: 'bg-red text-white hover:bg-red-hover disabled:opacity-50 disabled:cursor-not-allowed',
    ghost: 'text-foreground-muted hover:text-foreground hover:bg-card-muted disabled:opacity-50 disabled:cursor-not-allowed',
} as const;
/** Button classes, so links and buttons look the same. */
export const btn = (variant: keyof typeof BTN = 'secondary', size: 'sm' | 'md' = 'sm') =>
    `inline-flex items-center justify-center gap-1.5 rounded-lg font-semibold whitespace-nowrap transition-colors outline-none focus-visible:ring-2 focus-visible:ring-purple/60 ${size === 'sm' ? 'text-[11px] px-2.5 py-1.5' : 'text-xs px-3.5 py-2'} ${BTN[variant]}`;

/** A headline figure. null → "Unavailable" with the reason, never 0. */
export function KpiCard({ label, value, text, suffix, reason, hint, tone, href, icon: Icon, sub }: {
    /** `text` shows a short value that is not a number (a time, a version) instead of `value`. */
    label: string; value?: number | null; text?: string; suffix?: string; reason?: string; hint?: string; tone?: Tone; href?: string; icon?: LucideIcon; sub?: ReactNode;
}) {
    const body = (
        <>
            <div className="flex items-start justify-between gap-2">
                <p className="text-[11px] font-semibold text-foreground-muted leading-tight">{label}</p>
                {tone && tone !== 'neutral' ? <ToneIcon tone={tone} /> : Icon ? <Icon className="w-4 h-4 text-foreground-muted shrink-0" aria-hidden /> : null}
            </div>
            <div className="mt-2 text-[26px] leading-none font-black tracking-tight text-foreground tabular-nums">
                {text !== undefined ? <span className="text-lg">{text}</span> : value === null || value === undefined ? <Unavailable reason={reason ?? 'Could not be read'} /> : <CountUp value={value} suffix={suffix} />}
            </div>
            {(sub || hint) && <div className="mt-2 text-[11px] text-foreground-muted leading-snug">{sub ?? hint}</div>}
        </>
    );
    const cls = 'block bg-card border border-border rounded-2xl p-4 shadow-[0_1px_2px_rgba(0,0,0,0.04)] transition-colors';
    return href
        ? <Link href={href} title={hint} className={`${cls} hover:border-purple/40 focus-visible:ring-2 focus-visible:ring-purple/60 outline-none`}>{body}</Link>
        : <div title={hint} className={cls}>{body}</div>;
}

// ── Severity, priority, risk ───────────────────────────────────────────────────────────────────
export const SEVERITY_META: Record<string, { label: string; color: string; rank: number }> = {
    critical: { label: 'Critical', color: 'var(--vz-sev-critical)', rank: 0 },
    high: { label: 'High', color: 'var(--vz-sev-high)', rank: 1 },
    medium: { label: 'Medium', color: 'var(--vz-sev-medium)', rank: 2 },
    low: { label: 'Low', color: 'var(--vz-sev-low)', rank: 3 },
    info: { label: 'Info', color: 'var(--vz-sev-info)', rank: 4 },
};
export const SEVERITY_KEYS = ['critical', 'high', 'medium', 'low', 'info'] as const;
export const PRIORITY_META: Record<string, { label: string; color: string; hint: string }> = {
    P1: { label: 'P1', color: 'var(--vz-sev-critical)', hint: 'Fix within 2 days' },
    P2: { label: 'P2', color: 'var(--vz-sev-high)', hint: 'Fix within 7 days' },
    P3: { label: 'P3', color: 'var(--vz-sev-medium)', hint: 'Fix within 30 days' },
    P4: { label: 'P4', color: 'var(--vz-sev-low)', hint: 'Fix within 90 days' },
};
/** Scanner severity: a coloured square and the word. */
export function SeverityBadge({ severity }: { severity: string | null | undefined }) {
    const m = SEVERITY_META[severity ?? ''] ?? { label: severity ?? '—', color: 'var(--vz-neutral)' };
    return (
        <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-foreground whitespace-nowrap">
            <span className="w-2.5 h-2.5 rounded-[3px] shrink-0" style={{ background: m.color }} aria-hidden />{m.label}
        </span>
    );
}
/** Risk priority (lib/riskScore.ts on the backend): a solid chip with its label. */
export function PriorityBadge({ priority }: { priority: string | null | undefined }) {
    const m = PRIORITY_META[priority ?? ''];
    if (!m) return <span className="text-[11px] text-foreground-muted">—</span>;
    return <span title={m.hint} className="inline-flex items-center justify-center min-w-[26px] text-[10px] font-black px-1.5 py-0.5 rounded-md text-white" style={{ background: m.color }}>{m.label}</span>;
}
export const riskColor = (score: number) => (score >= 80 ? 'var(--vz-sev-critical)' : score >= 60 ? 'var(--vz-sev-high)' : score >= 35 ? 'var(--vz-sev-medium)' : 'var(--vz-sev-low)');
/** A 0–100 risk score with a proportional bar. */
export function RiskScore({ score, wide = false }: { score: number | null | undefined; wide?: boolean }) {
    if (score === null || score === undefined) return <span className="text-[11px] text-foreground-muted">—</span>;
    return (
        <span className="inline-flex items-center gap-2" aria-label={`Risk score ${Math.round(score)} of 100`}>
            <span className="text-[12px] font-bold tabular-nums text-foreground w-6 text-right">{Math.round(score)}</span>
            <span className={`${wide ? 'w-20' : 'w-10'} h-1.5 rounded-full bg-card-muted overflow-hidden`} aria-hidden><span className="block h-full rounded-full" style={{ width: `${Math.min(100, score)}%`, background: riskColor(score) }} /></span>
        </span>
    );
}
/** Small neutral tag (source, exposure, KEV…). `strong` uses the critical tone for KEV-like facts. */
export function Tag({ children, strong = false, title }: { children: ReactNode; strong?: boolean; title?: string }) {
    return <span title={title} className={`inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded ${strong ? 'text-white' : 'bg-card-muted text-foreground-muted'}`} style={strong ? { background: 'var(--vz-critical)' } : undefined}>{children}</span>;
}

// ── States ─────────────────────────────────────────────────────────────────────────────────────
export function EmptyState({ title, body, action, icon: Icon = Inbox, compact = false }: { title: string; body?: ReactNode; action?: ReactNode; icon?: LucideIcon; compact?: boolean }) {
    return (
        <div className={`flex flex-col items-center justify-center text-center ${compact ? 'py-6' : 'py-12'} px-4`}>
            <span className="w-10 h-10 rounded-full bg-card-muted flex items-center justify-center mb-3"><Icon className="w-5 h-5 text-foreground-muted" aria-hidden /></span>
            <p className="text-sm font-bold text-foreground">{title}</p>
            {body && <div className="text-xs text-foreground-muted mt-1 max-w-md leading-relaxed">{body}</div>}
            {action && <div className="mt-3">{action}</div>}
        </div>
    );
}
export function ErrorState({ error, onRetry, status }: { error: string; onRetry?: () => void; status?: number }) {
    const forbidden = status === 403;
    return (
        <div role="alert" className="flex items-start gap-3 rounded-xl border border-border bg-card p-4">
            <ToneIcon tone={forbidden ? 'warning' : 'critical'} className="w-5 h-5 mt-0.5" />
            <div className="flex-1 min-w-0">
                <p className="text-sm font-bold text-foreground">{forbidden ? 'Not available for your role' : status === 503 ? 'Not set up yet' : 'Could not load this data'}</p>
                <p className="text-xs text-foreground-muted mt-0.5 break-words">{error}</p>
            </div>
            {onRetry && !forbidden && <button onClick={onRetry} className={btn('secondary')}><RefreshCw className="w-3.5 h-3.5" aria-hidden /> Retry</button>}
        </div>
    );
}
export type Msg = { ok: boolean; text: string } | null;
/** The result of an action: success or failure, announced to screen readers. */
export function Notice({ msg }: { msg: Msg }) {
    if (!msg) return null;
    return <p role={msg.ok ? 'status' : 'alert'} className="flex items-center gap-1.5 text-xs font-semibold text-foreground"><ToneIcon tone={msg.ok ? 'good' : 'critical'} className="w-3.5 h-3.5" />{msg.text}</p>;
}

// ── Filters ────────────────────────────────────────────────────────────────────────────────────
export function Segmented<V extends string>({ options, value, onChange, label }: { options: readonly (readonly [V, string])[]; value: V; onChange: (v: V) => void; label: string }) {
    return (
        <div role="group" aria-label={label} className="inline-flex flex-wrap gap-0.5 bg-card border border-border rounded-lg p-0.5">
            {options.map(([v, l]) => (
                <button key={v} type="button" aria-pressed={value === v} onClick={() => onChange(v)}
                    className={`text-[11px] font-semibold px-2.5 py-1 rounded-md transition-colors outline-none focus-visible:ring-2 focus-visible:ring-purple/60 ${value === v ? 'bg-purple text-white' : 'text-foreground-muted hover:text-foreground'}`}>{l}</button>
            ))}
        </div>
    );
}
export function Toggle({ on, onChange, children }: { on: boolean; onChange: (v: boolean) => void; children: ReactNode }) {
    return (
        <button type="button" aria-pressed={on} onClick={() => onChange(!on)}
            className={`text-[11px] font-semibold px-2.5 py-1.5 rounded-lg border transition-colors outline-none focus-visible:ring-2 focus-visible:ring-purple/60 ${on ? 'bg-purple text-white border-purple' : 'bg-card border-border text-foreground-muted hover:text-foreground'}`}>{children}</button>
    );
}
export function Select<V extends string>({ value, onChange, options, label }: { value: V; onChange: (v: V) => void; options: readonly (readonly [V, string])[]; label: string }) {
    return (
        <label className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-foreground-muted">
            <span className="sr-only sm:not-sr-only">{label}</span>
            <select aria-label={label} value={value} onChange={(e) => onChange(e.target.value as V)} className="bg-card border border-border rounded-lg px-2 py-1.5 text-[11px] text-foreground outline-none focus:ring-2 focus:ring-purple/40">
                {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
        </label>
    );
}
/** Search box that submits on Enter (the backend or the page filters). */
export function SearchBox({ value, onSubmit, placeholder, label }: { value: string; onSubmit: (v: string) => void; placeholder: string; label: string }) {
    const [text, setText] = useState(value);
    return (
        <form role="search" onSubmit={(e) => { e.preventDefault(); onSubmit(text.trim()); }} className="flex items-center gap-1.5 bg-card border border-border rounded-lg px-2.5 py-1.5 focus-within:ring-2 focus-within:ring-purple/40">
            <Search className="w-3.5 h-3.5 text-foreground-muted" aria-hidden />
            <input aria-label={label} value={text} onChange={(e) => setText(e.target.value)} placeholder={placeholder} className="bg-transparent text-[12px] text-foreground outline-none w-44 placeholder:text-foreground-muted" />
            {text && <button type="button" aria-label="Clear search" onClick={() => { setText(''); onSubmit(''); }} className="text-foreground-muted hover:text-foreground"><X className="w-3.5 h-3.5" /></button>}
        </form>
    );
}

// ── Overlays ───────────────────────────────────────────────────────────────────────────────────
function useEscape(open: boolean, onClose: () => void) {
    useEffect(() => {
        if (!open) return;
        const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
        window.addEventListener('keydown', h);
        return () => window.removeEventListener('keydown', h);
    }, [open, onClose]);
}
/** Side panel for a record's detail. Escape or the backdrop closes it; focus moves into it. */
export function Drawer({ open, onClose, title, subtitle, children, width = 'max-w-2xl' }: { open: boolean; onClose: () => void; title: ReactNode; subtitle?: ReactNode; children: ReactNode; width?: string }) {
    useEscape(open, onClose);
    const ref = useRef<HTMLDivElement>(null);
    const id = useId();
    useEffect(() => { if (open) ref.current?.focus(); }, [open]);
    if (!open) return null;
    return (
        <div className="fixed inset-0 z-50 flex justify-end">
            <div className="absolute inset-0 bg-black/40 motion-safe:animate-[vzfade_200ms_ease-out]" onClick={onClose} aria-hidden />
            <div ref={ref} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby={id} className={`relative h-full w-full ${width} bg-surface border-l border-border shadow-2xl flex flex-col outline-none`}>
                <div className="flex items-start justify-between gap-3 px-5 py-4 border-b border-border bg-card">
                    <div className="min-w-0"><h2 id={id} className="text-base font-black text-foreground break-words">{title}</h2>{subtitle && <div className="text-[11px] text-foreground-muted mt-0.5">{subtitle}</div>}</div>
                    <button onClick={onClose} aria-label="Close" className="p-1.5 rounded-lg text-foreground-muted hover:bg-card-muted hover:text-foreground"><X className="w-4 h-4" /></button>
                </div>
                <div className="flex-1 overflow-y-auto p-5 space-y-5">{children}</div>
            </div>
        </div>
    );
}
/**
 * Confirmation for a consequential action. With `reason`, the text is passed to onConfirm and, when
 * required, must be filled in first (e.g. risk acceptance). Nothing happens until it is confirmed.
 */
export function ConfirmDialog({ open, title, body, confirmLabel, tone = 'primary', reason, onConfirm, onCancel }: {
    open: boolean; title: string; body: ReactNode; confirmLabel: string; tone?: 'primary' | 'danger'; reason?: { label: string; required: boolean }; onConfirm: (reason: string) => void | Promise<void>; onCancel: () => void;
}) {
    useEscape(open, onCancel);
    const [text, setText] = useState('');
    const [busy, setBusy] = useState(false);
    const id = useId();
    if (!open) return null;
    const blocked = busy || (!!reason?.required && !text.trim());
    return (
        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
            <div className="absolute inset-0 bg-black/50" onClick={onCancel} aria-hidden />
            <div role="alertdialog" aria-modal="true" aria-labelledby={id} className="relative w-full max-w-md bg-card border border-border rounded-2xl shadow-2xl p-5 space-y-3">
                <h2 id={id} className="text-sm font-black text-foreground">{title}</h2>
                <div className="text-xs text-foreground-muted leading-relaxed">{body}</div>
                {reason && (
                    <label className="block text-[11px] font-semibold text-foreground">{reason.label}{reason.required ? ' (required)' : ' (optional)'}
                        <textarea autoFocus value={text} onChange={(e) => setText(e.target.value)} rows={3} maxLength={2000} className="mt-1 block w-full bg-card-muted border border-border rounded-lg px-2.5 py-2 text-xs text-foreground outline-none focus:ring-2 focus:ring-purple/40" />
                    </label>
                )}
                <div className="flex justify-end gap-2 pt-1">
                    <button onClick={onCancel} className={btn('secondary', 'md')}>Cancel</button>
                    <button disabled={blocked} onClick={async () => { setBusy(true); try { await onConfirm(text.trim()); } finally { setBusy(false); setText(''); } }} className={btn(tone === 'danger' ? 'danger' : 'primary', 'md')}>{busy ? 'Working…' : confirmLabel}</button>
                </div>
            </div>
        </div>
    );
}

// ── Timeline ───────────────────────────────────────────────────────────────────────────────────
export interface TimelineItem { id: string; at: string; title: ReactNode; meta?: ReactNode; body?: ReactNode; tone?: Tone }
const DOT: Record<Tone, string> = { good: 'var(--vz-good)', warning: 'var(--vz-warning)', serious: 'var(--vz-serious)', critical: 'var(--vz-critical)', neutral: 'var(--vz-neutral)' };
export function Timeline({ items, empty = 'No history yet.' }: { items: TimelineItem[]; empty?: string }) {
    if (!items.length) return <p className="text-xs text-foreground-muted">{empty}</p>;
    return (
        <ol className="relative border-l border-border ml-1.5 space-y-3">
            {items.map((i) => (
                <li key={i.id} className="pl-4 relative">
                    <span className="absolute -left-[5px] top-1.5 w-2.5 h-2.5 rounded-full ring-2 ring-card" style={{ background: i.tone ? DOT[i.tone] : 'var(--vz-prog-3)' }} aria-hidden />
                    <p className="text-xs font-semibold text-foreground">{i.title}</p>
                    {i.meta && <p className="text-[11px] text-foreground-muted">{i.meta}</p>}
                    {i.body && <div className="text-[11px] text-foreground mt-0.5 break-words">{i.body}</div>}
                </li>
            ))}
        </ol>
    );
}

// ── Export ─────────────────────────────────────────────────────────────────────────────────────
export function downloadText(filename: string, text: string, type = 'text/csv;charset=utf-8') {
    const url = URL.createObjectURL(new Blob(['﻿', text], { type }));
    const a = Object.assign(document.createElement('a'), { href: url, download: filename });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}
/** Exports exactly the rows given (what is filtered on screen), never a sample. */
export function ExportCsvButton({ filename, rows, columns, label = 'Export CSV' }: { filename: string; rows: Record<string, unknown>[] | null | undefined; columns: { key: string; header: string }[]; label?: string }) {
    return (
        <button disabled={!rows?.length} onClick={() => rows && downloadText(filename, toCsv(rows, columns))} className={btn('secondary')} title={rows?.length ? `${rows.length} row(s)` : 'Nothing to export'}>
            <Download className="w-3.5 h-3.5" aria-hidden /> {label}
        </button>
    );
}

// ── Evidence ───────────────────────────────────────────────────────────────────────────────────
export interface EvidenceItem { id: string; title: ReactNode; meta?: ReactNode; content: unknown; truncated?: boolean }
/** Evidence exactly as stored (redacted by the backend), collapsible, with copy. */
export function EvidenceViewer({ items, empty = 'No evidence recorded.' }: { items: EvidenceItem[]; empty?: string }) {
    const [open, setOpen] = useState<Record<string, boolean>>({});
    const [copied, setCopied] = useState<string | null>(null);
    if (!items.length) return <p className="text-xs text-foreground-muted">{empty}</p>;
    return (
        <div className="space-y-2">
            {items.map((e, i) => {
                const text = typeof e.content === 'string' ? e.content : JSON.stringify(e.content, null, 2);
                const isOpen = open[e.id] ?? i === 0;
                return (
                    <div key={e.id} className="border border-border rounded-xl bg-card overflow-hidden">
                        <div className="flex items-center gap-2 px-3 py-2">
                            <button onClick={() => setOpen({ ...open, [e.id]: !isOpen })} aria-expanded={isOpen} className="flex-1 min-w-0 flex items-center gap-1.5 text-left">
                                {isOpen ? <ChevronDown className="w-3.5 h-3.5 shrink-0" aria-hidden /> : <ChevronRight className="w-3.5 h-3.5 shrink-0" aria-hidden />}
                                <span className="text-xs font-semibold text-foreground truncate">{e.title}</span>
                            </button>
                            <span className="text-[10px] text-foreground-muted shrink-0 hidden sm:inline">{e.meta}</span>
                            <button onClick={() => { void navigator.clipboard?.writeText(text).then(() => { setCopied(e.id); setTimeout(() => setCopied(null), 1500); }); }} aria-label="Copy evidence" className="p-1 rounded text-foreground-muted hover:text-foreground"><Copy className="w-3.5 h-3.5" /></button>
                            {copied === e.id && <span className="text-[10px] text-foreground-muted" role="status">Copied</span>}
                        </div>
                        {isOpen && <pre className="text-[10.5px] leading-relaxed font-mono whitespace-pre-wrap break-all text-foreground bg-card-muted px-3 py-2 max-h-72 overflow-y-auto border-t border-border">{text}{e.truncated ? '\n… truncated by the worker' : ''}</pre>}
                    </div>
                );
            })}
        </div>
    );
}

// ── Formatting ─────────────────────────────────────────────────────────────────────────────────
export const nf = new Intl.NumberFormat('en-GB');
export { relTime, fmtDay, toCsv } from '@/lib/vmsFormat';
