'use client';

import { createContext, useContext, useState, type ReactNode } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEmailApi, StatusBadge, useOrgName } from './shared';

// Email Security shell: one place that loads the organisation's domains and mail-provider
// connections for every Email Security page, derives setup progress from that BACKEND data
// (nothing is stored in the browser, so setup is always resumable and always true), and renders
// the module header — organisation, overall status, setup progress.

export interface VerificationState { state: string; checked_at: string; detail: string }
export interface DomainRow {
    id: string; domain: string; status: string; dmarc_policy: string | null; spf_status: string | null; dkim_status: string | null; dmarc_status: string | null;
    health_score: number | null; sending_sources: number; last_checked: string | null; last_error: string | null; dkim_selectors: string[];
    verification: VerificationState | null; last_report_at: string | null;
}
export interface ProviderRow {
    provider: 'microsoft365' | 'google_workspace' | 'gateway'; label: string; permissions: string[]; missing_config: string[]; status: string;
    connection: null | { tenant_id: string | null; tenant_name: string | null; admin_email: string | null; last_sync: string | null; last_success_sync: string | null; last_event_at: string | null; last_error: string | null; connected_by: string | null; connected_at: string | null };
}

// ── Setup derivation (pure) ──────────────────────────────────────────────────────────────

export type DomainReadiness = 'ready' | 'attention' | 'incomplete';
const AUTH_OK = new Set(['pass', 'warn']);
export const isVerified = (d: DomainRow) => d.verification?.state === 'verified';
export const authConfigured = (d: DomainRow) => !!d.last_checked && AUTH_OK.has(d.spf_status ?? '') && AUTH_OK.has(d.dmarc_status ?? '');

export function domainReadiness(d: DomainRow): { state: DomainReadiness; reason: string } {
    if (!isVerified(d)) {
        const v = d.verification?.state;
        if (v === 'incorrect_value' || v === 'dns_error') return { state: 'attention', reason: v === 'dns_error' ? 'Verification lookup failed' : 'Verification record has the wrong value' };
        return { state: 'incomplete', reason: 'Domain not verified yet' };
    }
    if (!authConfigured(d)) return { state: 'attention', reason: !d.last_checked ? 'Not inspected yet' : d.dmarc_status === 'missing' || d.dmarc_status === 'fail' ? 'DMARC needs attention' : 'SPF needs attention' };
    if (d.dmarc_status !== 'pass' || d.spf_status !== 'pass') return { state: 'attention', reason: d.dmarc_policy === 'none' ? 'DMARC is monitor-only (p=none)' : 'Authentication has warnings' };
    return { state: 'ready', reason: 'Verified and authenticated' };
}

export interface SetupStep { id: 'domain' | 'verify' | 'auth' | 'provider' | 'finish'; title: string; done: boolean }
export interface SetupState { steps: SetupStep[]; completed: number; total: number; percent: number; status: 'not_configured' | 'requires_configuration' | 'active' }

export function deriveSetup(domains: DomainRow[], providers: ProviderRow[]): SetupState {
    const domain = domains.length > 0;
    const verify = domains.some(isVerified);
    const auth = domains.some((d) => isVerified(d) && authConfigured(d));
    const provider = providers.some((p) => p.status === 'connected');
    const steps: SetupStep[] = [
        { id: 'domain', title: 'Add domain', done: domain },
        { id: 'verify', title: 'Verify domain', done: verify },
        { id: 'auth', title: 'Configure email authentication', done: auth },
        { id: 'provider', title: 'Connect email provider', done: provider },
        { id: 'finish', title: 'Finish setup', done: domain && verify && auth && provider },
    ];
    const completed = steps.filter((s) => s.done).length;
    return {
        steps, completed, total: steps.length, percent: Math.round((completed / steps.length) * 100),
        status: completed === 0 ? 'not_configured' : completed === steps.length ? 'active' : 'requires_configuration',
    };
}

// ── Context ──────────────────────────────────────────────────────────────────────────────

interface Ctx {
    domains: DomainRow[]; providers: ProviderRow[]; setup: SetupState;
    loading: boolean; error: string | null; notSetUp: string | null; reload: () => void;
}
const EmailSecurityContext = createContext<Ctx | null>(null);
export function useEmailSecurity(): Ctx {
    const c = useContext(EmailSecurityContext);
    if (!c) throw new Error('useEmailSecurity must be used inside the Email Security layout');
    return c;
}

export function EmailSecurityShell({ children }: { children: ReactNode }) {
    const [nonce, setNonce] = useState(0);
    const d = useEmailApi<{ domains: DomainRow[] }>('/dmarc/domains', nonce);
    const p = useEmailApi<{ connections: ProviderRow[] }>('/messaging/connections', nonce);
    const domains = d.data?.domains ?? [];
    const providers = p.data?.connections ?? [];
    const setup = deriveSetup(domains, providers);
    const ctx: Ctx = {
        domains, providers, setup,
        loading: d.loading || p.loading,
        error: d.error ?? p.error,
        notSetUp: d.setup ?? p.setup,
        reload: () => setNonce((n) => n + 1),
    };
    const org = useOrgName();
    const path = usePathname();
    const onSetup = path?.startsWith('/admin/email/setup');
    const status = ctx.notSetUp ? 'not_configured' : setup.status;

    return (
        <EmailSecurityContext.Provider value={ctx}>
            <div className="space-y-4">
                <div className="flex items-center justify-between gap-3 flex-wrap border-b border-border pb-3">
                    <div className="flex items-center gap-2 min-w-0 flex-wrap text-xs">
                        <span className="font-black uppercase tracking-wider text-foreground">Email Security</span>
                        {org && <><span className="text-foreground-muted" aria-hidden>/</span><span className="font-bold text-foreground truncate">{org}</span></>}
                        {!ctx.loading && <StatusBadge s={status} title="Overall Email Security status" />}
                    </div>
                    {!ctx.loading && !ctx.notSetUp && status !== 'active' && (
                        <div className="flex items-center gap-3 text-xs">
                            <div className="flex items-center gap-2" aria-label={`Setup ${setup.percent}% complete`}>
                                <div className="w-28 h-1.5 rounded-full bg-card-muted overflow-hidden"><div className="h-full bg-purple" style={{ width: `${setup.percent}%` }} /></div>
                                <span className="font-bold text-foreground-muted whitespace-nowrap">Setup {setup.completed}/{setup.total}</span>
                            </div>
                            {!onSetup && <Link href="/admin/email/setup" className="font-bold text-purple hover:underline whitespace-nowrap">{setup.completed ? 'Resume setup' : 'Start setup'} →</Link>}
                        </div>
                    )}
                </div>
                {children}
            </div>
        </EmailSecurityContext.Provider>
    );
}
