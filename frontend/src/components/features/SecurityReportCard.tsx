'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Info, CheckCircle2, AlertTriangle } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { SlaTrendChart, type SlaPoint } from './SlaTrendChart';
import { POSTURE_STYLE, TrendMark, type Posture } from './SecurityAssessmentAdmin';

// Security Assessment — one organisation's report card (GET /api/client/security-assessment).
// Rendered in the client portal and, for staff, as a preview under the admin Security
// Assessment page (?org=<slug>). Every figure comes from the real cases table; anything not yet
// measurable (detection time, the engagement components) says "Not tracked yet" and why.

interface ClosedCase { id: string; case_number: string; title: string; severity: string; close_time_hrs: number; within_sla: boolean; resolved_at: string }
interface EngagementComponent { key: string; label: string; max: number; value: number | null; reason: string }
interface ReportCard {
    org_id: string; org_name: string; detection_time_hrs: null; response_time_hrs: number | null; response_sample: number;
    close_time_hrs: number | null; open_cases: number; closed_this_month: number; resolved_30d: number;
    sla_rate: number | null; posture: Posture; trend: 'improving' | 'stable' | 'declining' | null;
    monthly: SlaPoint[]; last_closed: ClosedCase[];
    engagement: { score: number | null; components: EngagementComponent[] };
    orgs: { slug: string; name: string }[];
    definitions: { sla_target_hours: Record<string, number>; detection_time: string };
}

const BRAND = { blue: '#2B3BCC', red: '#CC2B2B', purple: '#6B1FA8', muted: '#7A8099' };
const SEV: Record<string, string> = { critical: BRAND.red, high: '#E8730C', medium: '#D4A017', low: BRAND.blue };
const engagementLabel = (s: number) => (s >= 80 ? 'Highly Active' : s >= 55 ? 'Active' : s >= 30 ? 'Moderate' : 'Passive');
const wat = (iso: string) => new Intl.DateTimeFormat('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }).format(new Date(iso)) + ' WAT';

function Tile({ label, value, note }: { label: string; value: string; note?: string }) {
    return (
        <div className="bg-card border border-border rounded-xl p-4">
            <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{label}</p>
            <p className="text-2xl font-black text-foreground mt-1">{value}</p>
            {note && <p className="text-[10px] text-foreground-muted mt-0.5">{note}</p>}
        </div>
    );
}

// Open vs closed-this-month as two labelled bars (one measure each, same scale).
function OpenClosedBars({ open, closed }: { open: number; closed: number }) {
    const max = Math.max(open, closed, 1);
    const rows = [
        { label: 'Open now', value: open, colour: BRAND.red },
        { label: 'Closed this month', value: closed, colour: BRAND.blue },
    ];
    return (
        <div className="space-y-3" role="img" aria-label={`Open cases ${open}, closed this month ${closed}`}>
            {rows.map((r) => (
                <div key={r.label}>
                    <div className="flex justify-between text-xs mb-1"><span className="text-foreground">{r.label}</span><span className="font-bold text-foreground">{r.value}</span></div>
                    <div className="h-2.5 bg-card-muted rounded-full overflow-hidden">
                        <div className="h-full rounded-full" style={{ width: `${(r.value / max) * 100}%`, backgroundColor: r.colour, minWidth: r.value > 0 ? 6 : 0 }} />
                    </div>
                </div>
            ))}
        </div>
    );
}

export function SecurityReportCard({ mode }: { mode: 'client' | 'staff' }) {
    const router = useRouter();
    const org = useSearchParams().get('org') ?? '';
    const [loaded, setLoaded] = useState<{ org: string; data: ReportCard | null; error?: string; unauthorised?: boolean } | null>(null);

    useEffect(() => {
        let active = true;
        const q = org ? `?org=${encodeURIComponent(org)}` : '';
        apiFetch(apiUrl(`/api/client/security-assessment${q}`), { cache: 'no-store' })
            .then(async (r) => {
                const d = await r.json().catch(() => null);
                if (!active) return;
                if (r.status === 401 || r.status === 403) { setLoaded({ org, data: null, unauthorised: true }); return; }
                if (!r.ok || !d) { setLoaded({ org, data: null, error: d?.error ?? `HTTP ${r.status}` }); return; }
                setLoaded({ org, data: d as ReportCard });
            })
            .catch(() => { if (active) setLoaded({ org, data: null, error: 'Could not reach the backend' }); });
        return () => { active = false; };
    }, [org]);

    const current = loaded?.org === org ? loaded : null;

    if (current?.unauthorised) {
        return (
            <div className="bg-card border border-dashed border-border rounded-xl p-12 text-center max-w-2xl mx-auto">
                <h1 className="font-bold text-sm text-foreground mb-1">Security report card unavailable</h1>
                <p className="text-xs text-foreground-muted">
                    {mode === 'client'
                        ? 'Client portal sign-in isn’t connected to NovrSOC’s data yet. Your SOC team can share your report card with you in the meantime.'
                        : 'You need a NovrSOC staff account to view client report cards.'}
                </p>
            </div>
        );
    }
    if (current?.error) {
        return <div role="alert" className="bg-red-500/5 border border-red-500/30 rounded-xl p-6 text-center text-sm font-bold text-red-500">Could not load the report card: {current.error}</div>;
    }
    const d = current?.data ?? null;
    if (!d) return <div className="space-y-3">{Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-24 bg-card-muted/60 rounded-xl animate-pulse" />)}</div>;

    const posture = POSTURE_STYLE[d.posture];
    const engaged = d.engagement.score;

    return (
        <div className="space-y-5">
            {/* Header */}
            <div className="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">Security report card</p>
                    <div className="flex items-center gap-2 mt-1">
                        <h1 className="text-xl font-black text-foreground">{d.org_name}</h1>
                        <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border ${posture.cls}`}>{posture.label}</span>
                    </div>
                    <p className="text-xs text-foreground-muted mt-0.5 flex items-center gap-2">SLA trend this month: <TrendMark trend={d.trend} /></p>
                </div>
                {mode === 'staff' && d.orgs.length > 1 && (
                    <select value={d.org_id} onChange={(e) => router.replace(`?org=${encodeURIComponent(e.target.value)}`)} aria-label="Client organisation"
                        className="border border-border bg-card rounded-lg px-2.5 py-1.5 text-xs font-bold text-foreground">
                        {d.orgs.map((o) => <option key={o.slug} value={o.slug}>{o.name}</option>)}
                    </select>
                )}
            </div>

            {/* 1 — Response metrics */}
            <section>
                <h2 className="text-sm font-bold text-foreground mb-2">Response metrics</h2>
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                    <Tile label="Avg Detection Time" value="—" note="Not tracked yet" />
                    <Tile label="Avg Response Time" value={d.response_time_hrs === null ? '—' : `${d.response_time_hrs}h`} note={d.response_time_hrs === null ? 'No alerts cased in 30 days' : `Alert → case · ${d.response_sample} case${d.response_sample === 1 ? '' : 's'}, 30 days`} />
                    <Tile label="Avg Close Time" value={d.close_time_hrs === null ? '—' : `${d.close_time_hrs}h`} note="Last 30 days" />
                    <Tile label="SLA Compliance" value={d.sla_rate === null ? '—' : `${d.sla_rate}%`} note={d.sla_rate === null ? 'No cases resolved in 30 days' : `${d.resolved_30d} resolved, 30 days`} />
                </div>
            </section>

            {/* 2 — Case activity */}
            <section className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div className="bg-card border border-border rounded-xl p-4">
                    <h2 className="text-sm font-bold text-foreground mb-3">Case activity</h2>
                    <OpenClosedBars open={d.open_cases} closed={d.closed_this_month} />
                </div>
                <div className="lg:col-span-2 bg-card border border-border rounded-xl p-4 overflow-x-auto">
                    <h2 className="text-sm font-bold text-foreground mb-3">Last 10 closed cases</h2>
                    {d.last_closed.length === 0 ? (
                        <p className="text-xs text-foreground-muted py-4 text-center">No cases closed in the last six months.</p>
                    ) : (
                        <table className="w-full text-xs min-w-[520px]">
                            <thead><tr className="text-left text-[10px] uppercase tracking-wider text-foreground-muted border-b border-border">
                                {['Case', 'Title', 'Severity', 'Close Time', 'Outcome'].map((h) => <th key={h} className="py-2 pr-3 font-bold">{h}</th>)}
                            </tr></thead>
                            <tbody>
                                {d.last_closed.map((c) => (
                                    <tr key={c.id} className="border-b border-border/60 last:border-0">
                                        <td className="py-2 pr-3 font-mono font-bold text-foreground whitespace-nowrap">{c.case_number}</td>
                                        <td className="py-2 pr-3 text-foreground max-w-[240px] truncate" title={c.title}>{c.title}</td>
                                        <td className="py-2 pr-3"><span className="text-[9px] font-bold px-2 py-0.5 rounded-full uppercase text-white" style={{ backgroundColor: SEV[c.severity] ?? BRAND.muted }}>{c.severity}</span></td>
                                        <td className="py-2 pr-3 text-foreground whitespace-nowrap">{c.close_time_hrs}h</td>
                                        <td className="py-2">
                                            {c.within_sla
                                                ? <span className="inline-flex items-center gap-1 text-green font-bold"><CheckCircle2 size={12} /> Within SLA</span>
                                                : <span className="inline-flex items-center gap-1 font-bold" style={{ color: BRAND.red }}><AlertTriangle size={12} /> Over SLA</span>}
                                            <span className="block text-[10px] text-foreground-muted">Resolved {wat(c.resolved_at)}</span>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>
            </section>

            {/* 3 — Engagement */}
            <section className="bg-card border border-border rounded-xl p-4">
                <h2 className="text-sm font-bold text-foreground">How active is your team?</h2>
                <p className="text-[11px] text-foreground-muted mb-3">Engagement score, 0–100</p>
                {engaged === null ? (
                    <p className="text-xs text-foreground bg-card-muted rounded-lg px-3 py-2 mb-3">Not tracked yet — none of the three components below is measured, so there is no score to show.</p>
                ) : (
                    <div className="mb-3">
                        <div className="flex justify-between text-xs mb-1"><span className="font-bold text-foreground">{engagementLabel(engaged)}</span><span className="font-bold text-foreground">{engaged}/100</span></div>
                        <div className="h-3 bg-card-muted rounded-full overflow-hidden"><div className="h-full rounded-full" style={{ width: `${engaged}%`, backgroundColor: BRAND.purple }} /></div>
                    </div>
                )}
                <div className="space-y-2.5">
                    {d.engagement.components.map((c) => (
                        <div key={c.key}>
                            <div className="flex justify-between text-[11px] mb-1"><span className="text-foreground">{c.label}</span><span className="text-foreground-muted">{c.value === null ? `— / ${c.max}` : `${c.value} / ${c.max}`}</span></div>
                            <div className="h-1.5 bg-card-muted rounded-full overflow-hidden">
                                {c.value !== null && <div className="h-full rounded-full" style={{ width: `${(c.value / c.max) * 100}%`, backgroundColor: BRAND.purple }} />}
                            </div>
                            {c.value === null && <p className="text-[10px] text-foreground-muted mt-0.5">{c.reason}</p>}
                        </div>
                    ))}
                </div>
            </section>

            {/* 4 — Trend */}
            <section className="bg-card border border-border rounded-xl p-4">
                <h2 className="text-sm font-bold text-foreground">SLA compliance — last 6 months</h2>
                <p className="text-[10px] text-foreground-muted mb-3">Share of cases resolved within target, by month (WAT)</p>
                <SlaTrendChart data={d.monthly} height={240} />
            </section>

            <div className="flex gap-2 text-[11px] text-foreground-muted bg-card border border-border rounded-xl p-3">
                <Info size={14} className="shrink-0 mt-px" />
                <p>
                    SLA targets (time to resolve): {Object.entries(d.definitions.sla_target_hours).map(([k, v]) => `${k} ${v}h`).join(' · ')}.
                    Cases closed automatically by NovrSOC&apos;s automation are not counted. Detection time is not tracked yet: {d.definitions.detection_time.replace(/^Not tracked — /, '')}
                </p>
            </div>
        </div>
    );
}
