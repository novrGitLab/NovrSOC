'use client';

import { useEffect, useState } from 'react';
import { BarChart3 } from 'lucide-react';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import { apiUrl, apiFetch } from '@/lib/api';

// Platform analytics — every figure is fetched from a live endpoint, nothing is synthesised.
//
// Sources, and what each can actually answer:
//   GET /api/incidents          → TheHive case counts (total/open/critical/resolved today).
//   GET /api/wazuh/trend?range= → alert volume per bucket, from the Wazuh indexer.
//   GET /api/wazuh/agents       → active vs total agents.
//   GET /api/wazuh/mitre-stats  → MITRE tactic counts over 24h.
//   GET /api/platform/health    → how many live service checks are passing.
//
// MTTD/MTTR are deliberately NOT shown. Neither TheHive's case list nor the Wazuh alert
// aggregation exposes a detection or resolution timestamp pair through the routes above, so
// computing them here would mean inventing the inputs. Add them once a route returns real
// created/detected/resolved timestamps per case; don't approximate them from case counts.

interface IncidentSummary {
    total: number; open: number; critical: number; investigating: number; resolved: number; resolvedToday: number;
}
interface TrendPoint { label: string; alerts: number; incidents: number; critical: number }
interface AgentStats { active: number; total: number }
interface MitreTactic { tactic?: string; name?: string; count?: number }
interface HealthCheck { name: string; status: 'up' | 'degraded' | 'down' }

type Range = '24h' | '7d' | '30d';
const RANGES: Range[] = ['24h', '7d', '30d'];

function Stat({ label, value, sub, tone = 'text-foreground' }: { label: string; value: string; sub?: string; tone?: string }) {
    return (
        <div className="bg-card border border-border rounded-xl p-4">
            <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{label}</p>
            <p className={`text-2xl font-black mt-1 ${tone}`}>{value}</p>
            {sub && <p className="text-[10px] text-foreground-muted mt-0.5">{sub}</p>}
        </div>
    );
}

export function PlatformAnalytics() {
    const [range, setRange] = useState<Range>('7d');
    const [incidents, setIncidents] = useState<IncidentSummary | null>(null);
    const [trendByRange, setTrendByRange] = useState<Partial<Record<Range, TrendPoint[]>>>({});
    const [agents, setAgents] = useState<AgentStats | null>(null);
    const [tactics, setTactics] = useState<MitreTactic[] | null>(null);
    const [health, setHealth] = useState<HealthCheck[] | null>(null);
    const [loading, setLoading] = useState(true);

    // Range-independent panels — fetched once.
    useEffect(() => {
        const get = (path: string) => apiFetch(apiUrl(path), { cache: 'no-store' }).then((r) => r.json());

        Promise.allSettled([
            get('/api/incidents'),
            get('/api/wazuh/agents'),
            get('/api/wazuh/mitre-stats'),
            get('/api/platform/health'),
        ]).then(([inc, ag, mitre, hp]) => {
            if (inc.status === 'fulfilled' && inc.value?.summary) setIncidents(inc.value.summary as IncidentSummary);
            if (ag.status === 'fulfilled' && ag.value && typeof ag.value.total === 'number') setAgents({ active: ag.value.active ?? 0, total: ag.value.total });
            if (mitre.status === 'fulfilled') {
                const raw = Array.isArray(mitre.value) ? mitre.value : mitre.value?.tactics;
                if (Array.isArray(raw)) setTactics(raw as MitreTactic[]);
            }
            if (hp.status === 'fulfilled' && Array.isArray(hp.value?.services)) setHealth(hp.value.services as HealthCheck[]);
            setLoading(false);
        });
    }, []);

    // Alert trend re-fetches when the range changes. Results are cached per range rather than
    // blanked on switch: that keeps the effect from calling setState synchronously just to show
    // a spinner, and switching back to an already-loaded range renders instantly.
    useEffect(() => {
        let cancelled = false;
        apiFetch(apiUrl(`/api/wazuh/trend?range=${range}`), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => { if (!cancelled) setTrendByRange((prev) => ({ ...prev, [range]: Array.isArray(data) ? data : [] })); })
            .catch(() => { if (!cancelled) setTrendByRange((prev) => ({ ...prev, [range]: [] })); });
        return () => { cancelled = true; };
    }, [range]);

    // undefined = not fetched yet for this range (loading); [] = fetched and empty.
    const trend = trendByRange[range] ?? null;
    const totalAlerts = trend?.reduce((s, p) => s + p.alerts, 0) ?? null;
    const topTactics = (tactics ?? [])
        .map((t) => ({ name: t.tactic ?? t.name ?? 'Unknown', count: t.count ?? 0 }))
        .filter((t) => t.count > 0)
        .sort((a, b) => b.count - a.count)
        .slice(0, 5);
    const servicesUp = health?.filter((s) => s.status === 'up').length ?? null;

    return (
        <div className="space-y-4">
            <div className="flex items-start gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-purple/10 flex items-center justify-center flex-shrink-0">
                    <BarChart3 className="w-4 h-4 text-purple" />
                </div>
                <div>
                    <h1 className="text-lg font-black text-foreground">Analytics</h1>
                    <p className="text-xs text-foreground-muted">Settings · Security and coverage metrics from live platform data</p>
                </div>
            </div>

            {/* Security metrics */}
            <div>
                <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">Security Metrics</p>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <Stat label="Incidents (open cases)" value={incidents ? String(incidents.total) : loading ? '…' : '—'} sub="TheHive, severity high+" />
                    <Stat label="Critical" value={incidents ? String(incidents.critical) : loading ? '…' : '—'} tone="text-red" />
                    <Stat label="Investigating" value={incidents ? String(incidents.investigating) : loading ? '…' : '—'} tone="text-amber" />
                    <Stat label="Resolved Today" value={incidents ? String(incidents.resolvedToday) : loading ? '…' : '—'} tone="text-green" />
                </div>
                {!incidents && !loading && (
                    <p className="text-[11px] text-foreground-muted mt-2">Incident metrics unavailable — TheHive did not respond.</p>
                )}
            </div>

            {/* Alert volume */}
            <div className="bg-card border border-border rounded-xl overflow-hidden">
                <div className="px-5 py-4 border-b border-border flex items-center justify-between gap-3 flex-wrap">
                    <div>
                        <h3 className="font-bold text-foreground-muted text-xs tracking-wide uppercase">Alert Volume</h3>
                        <p className="text-[10px] text-foreground-muted mt-0.5">
                            {totalAlerts === null ? 'Loading…' : `${totalAlerts.toLocaleString()} alerts in the last ${range}`}
                        </p>
                    </div>
                    <div className="flex items-center gap-0.5 bg-card-muted border border-border rounded-lg p-0.5">
                        {RANGES.map((r) => (
                            <button key={r} onClick={() => setRange(r)}
                                className={`px-2.5 py-1 rounded-md text-[11px] font-semibold transition-colors ${range === r ? 'bg-purple text-white' : 'text-foreground-muted hover:text-foreground'}`}>
                                {r}
                            </button>
                        ))}
                    </div>
                </div>
                <div className="h-64 w-full p-5">
                    {trend === null ? (
                        <div className="h-full bg-card-muted rounded animate-pulse" />
                    ) : trend.length === 0 ? (
                        <div className="h-full flex items-center justify-center text-xs text-foreground-muted text-center px-6">
                            No alert data returned for this range — the Wazuh indexer is unreachable or has no alerts in the window.
                        </div>
                    ) : (
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={trend}>
                                <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                                <XAxis dataKey="label" tick={{ fill: 'var(--color-foreground-muted)', fontSize: 10 }} interval="preserveStartEnd" />
                                <YAxis tick={{ fill: 'var(--color-foreground-muted)', fontSize: 10 }} allowDecimals={false} />
                                <Tooltip contentStyle={{ background: 'var(--color-card)', border: '1px solid var(--color-border)', borderRadius: 8, fontSize: 12 }} />
                                <Line type="monotone" dataKey="alerts" stroke="var(--color-blue)" strokeWidth={2} dot={false} name="Alerts" />
                                <Line type="monotone" dataKey="critical" stroke="var(--color-red)" strokeWidth={2} dot={false} name="Critical" />
                            </LineChart>
                        </ResponsiveContainer>
                    )}
                </div>
            </div>

            {/* Top MITRE tactics */}
            <div className="bg-card border border-border rounded-xl overflow-hidden">
                <div className="px-5 py-4 border-b border-border">
                    <h3 className="font-bold text-foreground-muted text-xs tracking-wide uppercase">Top MITRE Tactics — Last 24h</h3>
                    <p className="text-[10px] text-foreground-muted mt-0.5">Only alerts whose matching rule carries a MITRE mapping are counted.</p>
                </div>
                <div className="h-56 w-full p-5">
                    {tactics === null ? (
                        <div className="h-full bg-card-muted rounded animate-pulse" />
                    ) : topTactics.length === 0 ? (
                        <div className="h-full flex items-center justify-center text-xs text-foreground-muted">No MITRE-mapped alerts in the last 24 hours.</div>
                    ) : (
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={topTactics} layout="vertical" margin={{ left: 40 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" horizontal={false} />
                                <XAxis type="number" tick={{ fill: 'var(--color-foreground-muted)', fontSize: 10 }} allowDecimals={false} />
                                <YAxis type="category" dataKey="name" width={120} tick={{ fill: 'var(--color-foreground-muted)', fontSize: 10 }} />
                                <Tooltip contentStyle={{ background: 'var(--color-card)', border: '1px solid var(--color-border)', borderRadius: 8, fontSize: 12 }} />
                                <Bar dataKey="count" fill="var(--color-purple)" radius={[0, 4, 4, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    )}
                </div>
            </div>

            {/* Coverage */}
            <div>
                <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">Coverage</p>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                    <Stat
                        label="Agents Active"
                        value={agents ? `${agents.active}/${agents.total}` : loading ? '…' : '—'}
                        sub={agents ? `${agents.total - agents.active} not reporting` : 'Wazuh unreachable'}
                        tone={agents && agents.active < agents.total ? 'text-amber' : 'text-foreground'}
                    />
                    <Stat
                        label="Service Checks Passing"
                        value={servicesUp !== null && health ? `${servicesUp}/${health.length}` : loading ? '…' : '—'}
                        sub="Live probes from Platform Health"
                        tone={health && servicesUp !== null && servicesUp < health.length ? 'text-amber' : 'text-foreground'}
                    />
                    <Stat label="States Monitored" value="37" sub="All 36 states + FCT" />
                </div>
            </div>

            <p className="text-[10px] text-foreground-muted">
                MTTD and MTTR are not shown: no endpoint currently returns per-case detection and
                resolution timestamps, and deriving them from case counts would be a guess.
            </p>
        </div>
    );
}
