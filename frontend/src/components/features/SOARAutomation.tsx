'use client';

import { useEffect, useState } from 'react';
import { CheckCircle2, XCircle, MinusCircle } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// SOAR Automation — a report of what the SOAR engine did, not a place to work cases (that's
// Cases). Everything is read from Supabase via /api/soar: counts from /stats, per-tier case
// lists from /cases with each action's real outcome from soar_log, and the recent engine log.
// An action shows as done only when the engine logged SUCCESS/REQUESTED for it; a skipped or
// failed one shows the logged reason.

type Tier = 1 | 2 | 3;
type Range = '24h' | '7d' | '30d' | 'all';

interface Stats {
    total: number; resolved: number; auto_closed: number; tier1: number; tier2: number; tier3: number;
    auto_rate: number; containment_done: number; cases_created_today: number; engine_active: boolean;
    last_engine_case_at: string | null;
}
interface Outcome { done: boolean; detail: string | null }
interface TierCase {
    id: string; case_number: string; title: string; agent_name: string | null; source_ip: string | null;
    severity: string; status: string; created_at: string; resolved_at: string | null; assigned_to: string | null;
    ip_blocked: Outcome; agent_isolated: Outcome; email_sent: boolean; ciso_notified: boolean; enriched: boolean;
    close_reason: string | null;
}
interface LogEntry {
    id: string; tier: number; action: string; result: string | null; executed_at: string;
    cases: { case_number: string; title: string } | null;
}

const RANGE_MS: Record<Range, number | null> = { '24h': 864e5, '7d': 7 * 864e5, '30d': 30 * 864e5, all: null };

const wat = (iso: string | null) =>
    iso ? new Date(iso).toLocaleString('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }) : '—';

function Flag({ ok, title }: { ok: boolean | null; title?: string | null }) {
    if (ok === null) return <MinusCircle size={14} className="text-foreground-muted" aria-label="Not applicable" />;
    return ok
        ? <span title={title ?? 'Done'}><CheckCircle2 size={14} className="text-emerald-500" aria-label="Done" /></span>
        : <span title={title ?? 'Not done'}><XCircle size={14} className="text-foreground-muted" aria-label={title ?? 'Not done'} /></span>;
}

// An outcome with no log entry means the action didn't apply (e.g. no public source IP to
// block), which is different from a skip or failure — shown as "—" rather than ✗.
const outcomeFlag = (o: Outcome) => <Flag ok={o.detail === null ? null : o.done} title={o.detail} />;

export function SOARAutomation() {
    const [stats, setStats] = useState<Stats | null>(null);
    const [statsError, setStatsError] = useState<string | null>(null);
    const [log, setLog] = useState<LogEntry[] | null>(null);
    const [tier, setTier] = useState<Tier>(1);
    const [range, setRange] = useState<Range>('7d');
    const [loaded, setLoaded] = useState<{ key: string; cases: TierCase[]; total: number; error?: string } | null>(null);

    useEffect(() => {
        apiFetch(apiUrl('/api/soar/stats'), { cache: 'no-store' })
            .then(async (r) => {
                const d = await r.json();
                if (!r.ok) throw new Error(d?.error ?? `HTTP ${r.status}`);
                setStats(d as Stats);
            })
            .catch((e: unknown) => setStatsError(e instanceof Error ? e.message : 'Could not load stats'));
        apiFetch(apiUrl('/api/soar/log?limit=15'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((d) => setLog(Array.isArray(d?.entries) ? d.entries : []))
            .catch(() => setLog([]));
    }, []);

    // The tier list is stored with the tier+range it was fetched for, and loading is derived by
    // comparing keys — no setState at the top of the effect, and no stale list shown under a
    // newly selected tab.
    const key = `${tier}|${range}`;
    useEffect(() => {
        const [t, r] = key.split('|') as [string, Range];
        const params = new URLSearchParams({ tier: t, limit: '100' });
        const ms = RANGE_MS[r];
        if (ms !== null) params.set('since', new Date(Date.now() - ms).toISOString());
        apiFetch(apiUrl(`/api/soar/cases?${params}`), { cache: 'no-store' })
            .then(async (res) => {
                const d = await res.json();
                if (!res.ok) throw new Error(d?.error ?? `HTTP ${res.status}`);
                setLoaded({ key, cases: d.cases ?? [], total: d.total ?? 0 });
            })
            .catch((e: unknown) => setLoaded({ key, cases: [], total: 0, error: e instanceof Error ? e.message : 'Could not load cases' }));
    }, [key]);

    const current = loaded?.key === key ? loaded : null;

    const summary = [
        { label: 'Total cased', value: stats?.total },
        { label: 'Tier 1 (fully auto)', value: stats?.tier1 },
        { label: 'Tier 2 (auto + analyst)', value: stats?.tier2 },
        { label: 'Tier 3 (critical auto)', value: stats?.tier3 },
        { label: 'Auto-close rate', value: stats ? `${stats.auto_rate}%` : undefined, sub: stats ? `${stats.auto_closed} of ${stats.resolved} resolved` : undefined },
    ];

    return (
        <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-2">
                <div>
                    <h1 className="text-lg font-black text-foreground">SOAR Automation</h1>
                    <p className="text-xs text-foreground-muted">What the SOAR engine did with each case, by tier. Cases are worked on the Cases page.</p>
                </div>
                <div className="flex items-center gap-2 text-[11px]">
                    <span className={`w-2 h-2 rounded-full ${stats?.engine_active ? 'bg-green-500' : 'bg-foreground-muted'}`} />
                    <span className="text-foreground-muted">
                        {stats === null
                            ? statsError ? 'Engine status unavailable' : 'Checking engine…'
                            : stats.last_engine_case_at
                                ? `Last engine case ${wat(stats.last_engine_case_at)} WAT${stats.engine_active ? '' : ' — none in 24h'}`
                                : 'No case from the engine yet — see infra/soar/README.md to deploy it'}
                    </span>
                </div>
            </div>

            {statsError && <p className="text-xs text-red-500">Could not load SOAR statistics: {statsError}</p>}

            <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
                {summary.map((s) => (
                    <div key={s.label} className="bg-card border border-border rounded-xl p-4">
                        <div className="text-2xl font-black text-foreground">{s.value ?? '—'}</div>
                        <div className="text-[11px] text-foreground-muted mt-0.5">{s.label}</div>
                        {s.sub && <div className="text-[10px] text-foreground-muted/70 mt-0.5">{s.sub}</div>}
                    </div>
                ))}
            </div>

            <div className="bg-card border border-border rounded-xl">
                <div className="flex flex-wrap items-center justify-between gap-3 p-4 border-b border-border">
                    <div className="flex items-center gap-1 bg-card-muted rounded-lg p-1" role="tablist">
                        {([1, 2, 3] as Tier[]).map((t) => (
                            <button
                                key={t}
                                role="tab"
                                aria-selected={tier === t}
                                onClick={() => setTier(t)}
                                className={`text-xs font-bold px-3 py-1.5 rounded-md ${tier === t ? 'bg-card text-foreground shadow-xs' : 'text-foreground-muted hover:text-foreground'}`}
                            >
                                Tier {t}
                            </button>
                        ))}
                    </div>
                    <select
                        value={range}
                        onChange={(e) => setRange(e.target.value as Range)}
                        aria-label="Date range"
                        className="bg-card border border-border rounded-lg px-2.5 py-1.5 text-xs font-bold text-foreground"
                    >
                        <option value="24h">Last 24 hours</option>
                        <option value="7d">Last 7 days</option>
                        <option value="30d">Last 30 days</option>
                        <option value="all">All time</option>
                    </select>
                </div>

                <p className="px-4 pt-3 text-[11px] text-foreground-muted">
                    {tier === 1 && 'Level 7–9 alerts. Enriched, then closed automatically.'}
                    {tier === 2 && 'Level 10–12 alerts. Enriched, source IP blocked, SOC emailed. An analyst reviews and resolves.'}
                    {tier === 3 && 'Level 13+ alerts. Enriched, IP blocked, agent isolated for selected techniques, CISO emailed.'}
                </p>

                <div className="overflow-x-auto p-4">
                    {current === null ? (
                        <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-8 bg-card-muted rounded animate-pulse" />)}</div>
                    ) : current.error ? (
                        <p className="text-xs text-red-500 py-4">Could not load tier {tier} cases: {current.error}</p>
                    ) : current.cases.length === 0 ? (
                        <p className="text-xs text-foreground-muted py-6 text-center">No tier {tier} cases in this period.</p>
                    ) : (
                        <table className="w-full text-xs min-w-[720px]">
                            <thead>
                                <tr className="text-left text-[10px] uppercase tracking-wider text-foreground-muted border-b border-border">
                                    <th className="py-2 pr-3 font-bold">Case</th>
                                    <th className="py-2 pr-3 font-bold">Title</th>
                                    {tier === 1 ? (
                                        <>
                                            <th className="py-2 pr-3 font-bold">Agent</th>
                                            <th className="py-2 pr-3 font-bold">Severity</th>
                                            <th className="py-2 pr-3 font-bold">Created</th>
                                            <th className="py-2 pr-3 font-bold">Closed</th>
                                            <th className="py-2 font-bold">Reason</th>
                                        </>
                                    ) : (
                                        <>
                                            <th className="py-2 pr-3 font-bold text-center">IP blocked</th>
                                            {tier === 3 && <th className="py-2 pr-3 font-bold text-center">Agent isolated</th>}
                                            <th className="py-2 pr-3 font-bold text-center">{tier === 2 ? 'Email sent' : 'CISO notified'}</th>
                                            <th className="py-2 pr-3 font-bold">{tier === 2 ? 'Analyst' : 'Status'}</th>
                                            <th className="py-2 font-bold">Resolved</th>
                                        </>
                                    )}
                                </tr>
                            </thead>
                            <tbody>
                                {current.cases.map((c) => (
                                    <tr key={c.id} className="border-b border-border/60 last:border-0">
                                        <td className="py-2 pr-3 font-mono font-bold text-foreground whitespace-nowrap">{c.case_number}</td>
                                        <td className="py-2 pr-3 text-foreground max-w-[280px] truncate" title={c.title}>{c.title}</td>
                                        {tier === 1 ? (
                                            <>
                                                <td className="py-2 pr-3 text-foreground-muted">{c.agent_name || '—'}</td>
                                                <td className="py-2 pr-3 capitalize text-foreground-muted">{c.severity}</td>
                                                <td className="py-2 pr-3 text-foreground-muted whitespace-nowrap">{wat(c.created_at)}</td>
                                                <td className="py-2 pr-3 text-foreground-muted whitespace-nowrap">{wat(c.resolved_at)}</td>
                                                <td className="py-2 text-foreground-muted">{c.close_reason ?? (c.status === 'resolved' ? 'Closed' : `Still ${c.status}`)}</td>
                                            </>
                                        ) : (
                                            <>
                                                <td className="py-2 pr-3"><div className="flex justify-center">{outcomeFlag(c.ip_blocked)}</div></td>
                                                {tier === 3 && <td className="py-2 pr-3"><div className="flex justify-center">{outcomeFlag(c.agent_isolated)}</div></td>}
                                                <td className="py-2 pr-3"><div className="flex justify-center"><Flag ok={tier === 2 ? c.email_sent : c.ciso_notified} /></div></td>
                                                <td className="py-2 pr-3 text-foreground-muted">{tier === 2 ? c.assigned_to || 'Unassigned' : <span className="capitalize">{c.status}</span>}</td>
                                                <td className="py-2 text-foreground-muted whitespace-nowrap">{c.resolved_at ? wat(c.resolved_at) : 'Open'}</td>
                                            </>
                                        )}
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                    {current && current.total > current.cases.length && (
                        <p className="text-[10px] text-foreground-muted mt-2">Showing the newest {current.cases.length} of {current.total}.</p>
                    )}
                    {current && tier > 1 && current.cases.length > 0 && (
                        <p className="text-[10px] text-foreground-muted mt-2">
                            ✓ done · ✗ skipped or failed (hover for the logged reason) · — not applicable (no public source IP or technique not in the isolation list).
                        </p>
                    )}
                </div>
            </div>

            <div className="bg-card border border-border rounded-xl p-5">
                <h2 className="font-bold text-sm text-foreground mb-3">Recent engine actions</h2>
                {log === null ? (
                    <p className="text-xs text-foreground-muted">Loading…</p>
                ) : log.length === 0 ? (
                    <p className="text-xs text-foreground-muted">The engine hasn&apos;t logged any actions yet.</p>
                ) : (
                    <div className="space-y-1">
                        {log.map((e) => (
                            <div key={e.id} className="grid grid-cols-[auto_auto_1fr] sm:grid-cols-[110px_90px_1fr_1fr] gap-x-3 gap-y-0.5 text-xs py-1.5 border-b border-border last:border-0">
                                <span className="font-mono text-foreground-muted whitespace-nowrap">{wat(e.executed_at)}</span>
                                <span className="font-mono font-bold text-foreground">{e.cases?.case_number ?? '—'}</span>
                                <span className="text-foreground">{e.action}</span>
                                <span className={`col-span-3 sm:col-span-1 ${/^(SUCCESS|REQUESTED)/.test(e.result ?? '') ? 'text-emerald-500' : /^(FAILED|ERROR)/.test(e.result ?? '') ? 'text-red-500' : 'text-foreground-muted'}`}>
                                    {e.result ?? '—'}
                                </span>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}
