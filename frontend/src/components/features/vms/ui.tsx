'use client';

// VMS design-system primitives (redesign, phase P20). Shared by the VMS pages so they read as one
// product: cards, section headers, numbers that count up (respecting prefers-reduced-motion),
// skeletons, status pills (icon + label — never colour alone), an "unavailable" marker that is
// visibly different from zero, and an accessible hover/focus tooltip.

import { useEffect, useRef, useState, useSyncExternalStore, type ReactNode, type CSSProperties } from 'react';
import { CheckCircle2, AlertTriangle, XCircle, MinusCircle, Info } from 'lucide-react';

// ── Motion ─────────────────────────────────────────────────────────────────────────────────────
const query = '(prefers-reduced-motion: reduce)';
function subscribe(cb: () => void) {
    if (typeof window === 'undefined' || !window.matchMedia) return () => undefined;
    const m = window.matchMedia(query);
    m.addEventListener('change', cb);
    return () => m.removeEventListener('change', cb);
}
/** True when the viewer asked for reduced motion (false during server render). */
export function useReducedMotion(): boolean {
    return useSyncExternalStore(subscribe, () => (typeof window !== 'undefined' && !!window.matchMedia && window.matchMedia(query).matches), () => false);
}

// ── Theme tokens for SVG charts ───────────────────────────────────────────────────────────────
// SVG presentation attributes (stroke="…", fill="…", which Recharts writes) do not resolve CSS
// var(), so chart colours are read from the computed tokens and re-read when the theme class on
// <html> changes (next-themes toggles .dark).
function subscribeTheme(cb: () => void) {
    if (typeof window === 'undefined' || typeof MutationObserver === 'undefined') return () => undefined;
    const mo = new MutationObserver(cb);
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['class', 'style', 'data-theme'] });
    return () => mo.disconnect();
}
/** The current values of CSS custom properties (e.g. '--vz-sev-high'), resolved for the active theme. */
export function useCssTokens<K extends string>(names: readonly K[]): Record<K, string> {
    const key = names.join('|');
    const snapshot = useSyncExternalStore(
        subscribeTheme,
        () => { const cs = getComputedStyle(document.documentElement); return key.split('|').map((n) => cs.getPropertyValue(n).trim()).join('|'); },
        () => '',
    );
    const values = snapshot.split('|');
    return Object.fromEntries(names.map((n, i) => [n, values[i] || 'currentColor'])) as Record<K, string>;
}

const fmt = new Intl.NumberFormat('en-GB');
/** A number that eases from its previous value to the new one; instant under reduced motion. */
export function CountUp({ value, suffix = '', className = '' }: { value: number; suffix?: string; className?: string }) {
    const reduced = useReducedMotion();
    const [shown, setShown] = useState(value);
    const from = useRef(value);
    useEffect(() => {
        if (reduced) { from.current = value; return; }
        const start = performance.now();
        const a = from.current;
        let raf = 0;
        const step = (t: number) => {
            const k = Math.min(1, (t - start) / 650);
            const eased = 1 - Math.pow(1 - k, 3);
            setShown(Math.round(a + (value - a) * eased));
            if (k < 1) raf = requestAnimationFrame(step); else from.current = value;
        };
        raf = requestAnimationFrame(step);
        return () => cancelAnimationFrame(raf);
    }, [value, reduced]);
    return <span className={className}>{fmt.format(reduced ? value : shown)}{suffix}</span>;
}

// ── Layout ─────────────────────────────────────────────────────────────────────────────────────
export function Card({ children, className = '', as: As = 'section', ...rest }: { children: ReactNode; className?: string; as?: 'section' | 'div'; 'aria-label'?: string; 'aria-busy'?: boolean }) {
    return <As {...rest} className={`bg-card border border-border rounded-2xl p-5 shadow-[0_1px_2px_rgba(0,0,0,0.04)] transition-colors ${className}`}>{children}</As>;
}

export function SectionTitle({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
    return (
        <div className="flex items-start justify-between gap-3 mb-4">
            <div>
                <h2 className="text-[13px] font-bold tracking-tight text-foreground">{title}</h2>
                {hint && <p className="text-[11px] text-foreground-muted mt-0.5 leading-relaxed">{hint}</p>}
            </div>
            {action}
        </div>
    );
}

/** A loading placeholder. Pulses only when motion is allowed. */
export function Skeleton({ className = '', style }: { className?: string; style?: CSSProperties }) {
    return <div aria-hidden style={style} className={`rounded-lg bg-card-muted motion-safe:animate-pulse ${className}`} />;
}

/** A value that could not be read: visibly not zero, with the reason on hover/focus. */
export function Unavailable({ reason }: { reason: string }) {
    return (
        <Tip label={reason}>
            <span className="inline-flex items-center gap-1 text-foreground-muted text-sm font-semibold" tabIndex={0}>
                <MinusCircle className="w-4 h-4" aria-hidden /> Unavailable
            </span>
        </Tip>
    );
}

// ── Status ─────────────────────────────────────────────────────────────────────────────────────
export type Tone = 'good' | 'warning' | 'serious' | 'critical' | 'neutral';
const TONE: Record<Tone, { icon: typeof CheckCircle2; color: string }> = {
    good: { icon: CheckCircle2, color: 'var(--vz-good)' },
    warning: { icon: AlertTriangle, color: 'var(--vz-warning)' },
    serious: { icon: AlertTriangle, color: 'var(--vz-serious)' },
    critical: { icon: XCircle, color: 'var(--vz-critical)' },
    neutral: { icon: Info, color: 'var(--foreground-muted)' },
};
/** A state with an icon and a label: the colour never carries the meaning alone. */
export function StatusPill({ tone, label }: { tone: Tone; label: string }) {
    const { icon: Icon, color } = TONE[tone];
    return (
        <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-foreground whitespace-nowrap">
            <Icon className="w-3.5 h-3.5 shrink-0" style={{ color }} aria-hidden />
            {label}
        </span>
    );
}
export function ToneIcon({ tone, className = 'w-4 h-4' }: { tone: Tone; className?: string }) {
    const { icon: Icon, color } = TONE[tone];
    return <Icon className={`shrink-0 ${className}`} style={{ color }} aria-hidden />;
}

// ── Tooltip ────────────────────────────────────────────────────────────────────────────────────
/** Hover/focus tooltip. It enhances; the same information is always visible elsewhere or in text. */
export function Tip({ label, children, className = '', style }: { label: ReactNode; children: ReactNode; className?: string; style?: CSSProperties }) {
    const [open, setOpen] = useState(false);
    return (
        <span style={style} className={`relative inline-flex ${className}`} onMouseEnter={() => setOpen(true)} onMouseLeave={() => setOpen(false)} onFocus={() => setOpen(true)} onBlur={() => setOpen(false)}>
            {children}
            {open && (
                <span role="tooltip" className="pointer-events-none absolute z-30 bottom-full left-1/2 -translate-x-1/2 mb-2 w-max max-w-[260px] rounded-lg border border-border bg-card px-2.5 py-1.5 text-[11px] leading-snug text-foreground shadow-lg">
                    {label}
                </span>
            )}
        </span>
    );
}

/** Segmented bar: proportional segments with a 2px surface gap, each focusable with a tooltip. */
export function SegmentBar({ segments, height = 'h-3', label }: { segments: { key: string; label: string; value: number; color: string }[]; height?: string; label: string }) {
    const total = segments.reduce((n, s) => n + s.value, 0);
    if (!total) return <div className={`${height} rounded-full bg-card-muted`} role="img" aria-label={`${label}: none`} />;
    return (
        <div className={`flex ${height} w-full gap-[2px]`} role="img" aria-label={`${label}: ${segments.filter((s) => s.value).map((s) => `${s.label} ${s.value}`).join(', ')}`}>
            {segments.filter((s) => s.value > 0).map((s, i, arr) => (
                <Tip key={s.key} label={<><span className="font-semibold">{s.label}</span>: {fmt.format(s.value)} ({Math.round((s.value / total) * 100)}%)</>} className="h-full" style={{ flexGrow: s.value, flexBasis: 0, minWidth: 4 }}>
                    <span
                        tabIndex={0}
                        aria-label={`${s.label}: ${s.value}`}
                        className={`block h-full w-full outline-none focus-visible:ring-2 focus-visible:ring-purple ${i === 0 ? 'rounded-l-full' : ''} ${i === arr.length - 1 ? 'rounded-r-full' : ''} transition-[filter] hover:brightness-110`}
                        style={{ background: s.color }}
                    />
                </Tip>
            ))}
        </div>
    );
}
