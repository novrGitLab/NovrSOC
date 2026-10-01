'use client';

import { useEffect, useState, useSyncExternalStore, type ReactNode } from 'react';
import Link from 'next/link';
import { AlertTriangle, Database, Loader2, PlugZap } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { getAdminUser } from '@/lib/admin-auth';

// Shared building blocks for the Email Security module (Overview, DMARC SaaS, Phish ID,
// Messaging Suite). Every page renders one of four honest states: loading, setup required
// (tables not created), error, or real data — and "not available" is never drawn as zero.

export const API = '/api/email-security';

// ── Data ───────────────────────────────────────────────────────────────────────────────────

interface Loaded<T> { key: string; data: T | null; error: string | null; setup: string | null }

/** GET `${API}${path}`; pass a changing `nonce` to reload. null path = don't fetch. */
export function useEmailApi<T>(path: string | null, nonce = 0) {
    const key = `${path}|${nonce}`;
    const [loaded, setLoaded] = useState<Loaded<T> | null>(null);
    useEffect(() => {
        if (!path) return;
        let active = true;
        apiFetch(apiUrl(`${API}${path}`), { cache: 'no-store' })
            .then(async (r) => {
                const d = await r.json().catch(() => null);
                if (!active) return;
                if (r.ok && d) setLoaded({ key, data: d as T, error: null, setup: null });
                else setLoaded({ key, data: null, error: d?.error ?? `HTTP ${r.status}`, setup: d?.setup_required ? d.error : null });
            })
            .catch(() => { if (active) setLoaded({ key, data: null, error: 'Could not reach the NovrSOC backend.', setup: null }); });
        return () => { active = false; };
    }, [key, path]);
    const cur = loaded?.key === key ? loaded : null;
    return { data: cur?.data ?? null, error: cur?.error ?? null, setup: cur?.setup ?? null, loading: !!path && cur === null };
}

export type SendResult<T = Record<string, unknown>> = { ok: boolean; status: number; data: T | null; error: string | null };

export async function send<T = Record<string, unknown>>(method: string, path: string, body?: unknown): Promise<SendResult<T>> {
    try {
        const isForm = typeof FormData !== 'undefined' && body instanceof FormData;
        const r = await apiFetch(apiUrl(`${API}${path}`), {
            method,
            headers: body === undefined || isForm ? undefined : { 'Content-Type': 'application/json' },
            body: body === undefined ? undefined : isForm ? body : JSON.stringify(body),
        });
        const d = await r.json().catch(() => null);
        return { ok: r.ok, status: r.status, data: d as T, error: r.ok ? null : d?.error ?? `HTTP ${r.status}` };
    } catch {
        return { ok: false, status: 0, data: null, error: 'Could not reach the NovrSOC backend.' };
    }
}

const noop = () => () => {};
/** The signed-in role, for hiding controls the backend would refuse anyway. */
export function useRole(): string {
    return useSyncExternalStore(noop, () => getAdminUser().role, () => '');
}
export const isManager = (role: string) => role === 'super_admin' || role === 'soc_manager';
export const isAnalyst = (role: string) => isManager(role) || role === 'analyst';

// ── Formatting ─────────────────────────────────────────────────────────────────────────────

const WAT = new Intl.DateTimeFormat('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
export const wat = (iso: string | null | undefined) => (iso && !Number.isNaN(Date.parse(iso)) ? `${WAT.format(new Date(iso))} WAT` : '—');
export const day = (iso: string | null | undefined) => (iso && !Number.isNaN(Date.parse(iso)) ? new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }).format(new Date(iso)) : '—');
export const label = (s: string | null | undefined) => (s ? s.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase()) : '—');
export const n = (v: number | null | undefined) => (typeof v === 'number' ? v.toLocaleString() : '—');

// ── Badges ─────────────────────────────────────────────────────────────────────────────────

const TONES = {
    red: 'bg-red-500/10 text-red-500 border-red-500/30',
    orange: 'bg-orange/10 text-orange border-orange/30',
    amber: 'bg-amber-500/10 text-amber-600 border-amber-500/30',
    green: 'bg-green/10 text-green border-green/30',
    blue: 'bg-blue/10 text-blue border-blue/30',
    purple: 'bg-purple/10 text-purple border-purple/30',
    grey: 'bg-card-muted text-foreground-muted border-border',
} as const;
export type Tone = keyof typeof TONES;

export function Badge({ tone, children, title }: { tone: Tone; children: ReactNode; title?: string }) {
    return <span title={title} className={`inline-block text-[9px] font-bold px-2 py-0.5 rounded-full border uppercase tracking-wide whitespace-nowrap ${TONES[tone]}`}>{children}</span>;
}

const SEV_TONE: Record<string, Tone> = { critical: 'red', high: 'orange', medium: 'amber', low: 'blue', informational: 'grey' };
export const SevBadge = ({ s }: { s: string }) => <Badge tone={SEV_TONE[s] ?? 'grey'}>{s === 'informational' ? 'info' : s}</Badge>;

const STATUS_TONE: Record<string, Tone> = {
    new: 'red', investigating: 'amber', resolved: 'green', false_positive: 'grey', suppressed: 'grey',
    discovered: 'blue', under_investigation: 'amber', suspicious: 'orange', confirmed_phishing: 'red',
    healthy: 'green', warning: 'amber', critical: 'red', error: 'red', pending: 'grey',
    pass: 'green', warn: 'amber', fail: 'red', missing: 'red', not_found: 'grey',
    connected: 'green', not_connected: 'grey', requires_configuration: 'amber', auth_error: 'red', permission_error: 'red', sync_error: 'amber',
    known: 'green', unknown: 'grey',
};
export const StatusBadge = ({ s }: { s: string | null | undefined }) => <Badge tone={STATUS_TONE[s ?? ''] ?? 'grey'}>{label(s ?? 'unknown')}</Badge>;

// ── Layout ─────────────────────────────────────────────────────────────────────────────────

export function PageHeader({ title, subtitle, actions, back }: { title: string; subtitle?: ReactNode; actions?: ReactNode; back?: { href: string; label: string } }) {
    return (
        <div className="flex items-start justify-between gap-3 flex-wrap">
            <div className="min-w-0">
                {back && <Link href={back.href} className="text-[11px] font-bold text-foreground-muted hover:text-purple">← {back.label}</Link>}
                <h1 className="text-lg font-black text-foreground break-words">{title}</h1>
                {subtitle && <p className="text-xs text-foreground-muted mt-0.5">{subtitle}</p>}
            </div>
            {actions && <div className="flex items-center gap-2 flex-wrap">{actions}</div>}
        </div>
    );
}

export function Panel({ title, action, children, className = '' }: { title?: ReactNode; action?: ReactNode; children: ReactNode; className?: string }) {
    return (
        <section className={`bg-card border border-border rounded-xl ${className}`}>
            {(title || action) && (
                <div className="flex items-center justify-between gap-2 px-4 py-3 border-b border-border">
                    <h2 className="text-xs font-black text-foreground uppercase tracking-wider">{title}</h2>
                    {action}
                </div>
            )}
            <div className="p-4">{children}</div>
        </section>
    );
}

/** A KPI. `value === null` means "not available" and shows `hint` instead of a number. */
export function Kpi({ label: l, value, hint, tone, suffix = '' }: { label: string; value: number | string | null | undefined; hint?: string; tone?: 'danger' | 'warn' | 'good'; suffix?: string }) {
    const color = tone === 'danger' ? 'text-red-500' : tone === 'warn' ? 'text-amber-600' : tone === 'good' ? 'text-green' : 'text-foreground';
    const missing = value === null || value === undefined;
    return (
        <div className="bg-card border border-border rounded-xl p-4 min-w-0">
            <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider truncate">{l}</p>
            {missing ? (
                <>
                    <p className="text-sm font-bold text-foreground-muted mt-1.5">Not available</p>
                    {hint && <p className="text-[10px] text-foreground-muted mt-0.5">{hint}</p>}
                </>
            ) : (
                <p className={`text-2xl font-black mt-1 ${color}`}>{typeof value === 'number' ? value.toLocaleString() : value}{suffix}</p>
            )}
        </div>
    );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string; count?: number | null }[]; value: T; onChange: (t: T) => void }) {
    return (
        <div role="tablist" className="flex gap-1 border-b border-border overflow-x-auto">
            {tabs.map((t) => (
                <button key={t.id} role="tab" aria-selected={value === t.id} onClick={() => onChange(t.id)}
                    className={`px-3 py-2 text-xs font-bold whitespace-nowrap border-b-2 -mb-px transition-colors ${value === t.id ? 'border-purple text-purple' : 'border-transparent text-foreground-muted hover:text-foreground'}`}>
                    {t.label}{typeof t.count === 'number' ? <span className="ml-1.5 text-[10px] font-bold text-foreground-muted">{t.count}</span> : null}
                </button>
            ))}
        </div>
    );
}

// ── States ─────────────────────────────────────────────────────────────────────────────────

export function Loading({ rows = 4 }: { rows?: number }) {
    return <div className="space-y-2" aria-busy="true">{Array.from({ length: rows }).map((_, i) => <div key={i} className="h-9 bg-card-muted rounded animate-pulse" />)}</div>;
}

export function Empty({ title, body, action, icon }: { title: string; body?: ReactNode; action?: ReactNode; icon?: ReactNode }) {
    return (
        <div className="text-center py-10 px-4">
            <div className="mx-auto w-10 h-10 rounded-full bg-card-muted flex items-center justify-center text-foreground-muted mb-3">{icon ?? <PlugZap size={18} />}</div>
            <p className="text-sm font-bold text-foreground">{title}</p>
            {body && <p className="text-xs text-foreground-muted mt-1 max-w-md mx-auto">{body}</p>}
            {action && <div className="mt-4 flex justify-center">{action}</div>}
        </div>
    );
}

export function SetupNotice({ message }: { message: string }) {
    return (
        <div role="status" className="flex gap-3 bg-amber-500/10 border border-amber-500/30 rounded-xl p-4">
            <Database size={18} className="text-amber-600 shrink-0 mt-0.5" />
            <div>
                <p className="text-sm font-bold text-foreground">Email Security is not set up yet</p>
                <p className="text-xs text-foreground-muted mt-0.5">{message}</p>
            </div>
        </div>
    );
}

export function ErrorNote({ message }: { message: string }) {
    return (
        <p role="alert" className="flex items-start gap-2 text-xs text-red-500 bg-red-500/5 border border-red-500/30 rounded-lg px-3 py-2">
            <AlertTriangle size={14} className="shrink-0 mt-px" /> {message}
        </p>
    );
}

/** Loading / setup / error wrapper for a fetched section. */
export function Gate({ state, children, rows }: { state: { loading: boolean; error: string | null; setup: string | null }; children: ReactNode; rows?: number }) {
    if (state.loading) return <Loading rows={rows} />;
    if (state.setup) return <SetupNotice message={state.setup} />;
    if (state.error) return <ErrorNote message={state.error} />;
    return <>{children}</>;
}

// ── Controls ───────────────────────────────────────────────────────────────────────────────

export const inputCls = 'bg-card border border-border rounded-lg px-3 py-2 text-xs text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-purple focus:ring-2 focus:ring-purple/10';
export const selectCls = 'bg-card border border-border rounded-lg px-2.5 py-1.5 text-xs font-bold text-foreground';

export function Button({ children, onClick, busy, disabled, variant = 'secondary', type = 'button', title }: {
    children: ReactNode; onClick?: () => void; busy?: boolean; disabled?: boolean; variant?: 'primary' | 'secondary' | 'danger'; type?: 'button' | 'submit'; title?: string;
}) {
    const cls = variant === 'primary' ? 'bg-purple text-white border-purple hover:opacity-90'
        : variant === 'danger' ? 'bg-card text-red-500 border-red-500/40 hover:bg-red-500/5'
        : 'bg-card text-foreground border-border hover:bg-card-muted';
    return (
        <button type={type} onClick={onClick} disabled={disabled || busy} title={title}
            className={`inline-flex items-center gap-1.5 text-[11px] font-bold rounded-lg px-3 py-1.5 border disabled:opacity-50 disabled:cursor-not-allowed ${cls}`}>
            {busy && <Loader2 size={12} className="animate-spin" />}{children}
        </button>
    );
}

export function Feedback({ result }: { result: { ok: boolean; text: string } | null }) {
    if (!result) return null;
    return <p role="status" className={`text-[11px] font-bold ${result.ok ? 'text-green' : 'text-red-500'}`}>{result.text}</p>;
}

export function KeyValue({ rows }: { rows: [string, ReactNode][] }) {
    return (
        <dl className="grid grid-cols-[minmax(110px,max-content)_1fr] gap-x-4 gap-y-1.5 text-xs">
            {rows.map(([k, v]) => (
                <div key={k} className="contents">
                    <dt className="text-foreground-muted">{k}</dt>
                    <dd className="text-foreground break-words min-w-0">{v ?? '—'}</dd>
                </div>
            ))}
        </dl>
    );
}

export const th = 'px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-wider text-foreground-muted whitespace-nowrap';
export const td = 'px-3 py-2.5 align-top';
