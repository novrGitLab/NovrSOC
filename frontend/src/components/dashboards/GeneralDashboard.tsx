'use client';

import { useState, useEffect, useCallback, useSyncExternalStore } from 'react';
import Link from 'next/link';
import {
    Monitor, Siren, ShieldAlert, Shield, Clock, Laptop, Server, ChevronRight, Building2, Timer, Zap, Activity,
    CheckCircle, Bell,
} from 'lucide-react';
import { KpiCard, type KpiCardProps } from '../shared/KpiCard';
import { ChartWrapper } from '../shared/ChartWrapper';
import { DashboardNigeriaMap } from './DashboardNigeriaMap';
import { apiUrl, apiFetch } from '@/lib/api';
import { fetchAlertStats, loadJson, watTime, type AlertStats } from '@/lib/alerts';
import { AlertFeedStatus } from '@/components/shared/AlertFeedStatus';
import { usePolling } from '@/lib/usePolling';
import { getAdminUser } from '@/lib/admin-auth';
import { getOrgContext, subscribeOrgContext } from '@/lib/orgContext';
import { platformHealthDisplay, honestCountDisplay, openCasesDisplay } from '@/lib/dashboardKpis';

const Card = ({ children, className = '' }: { children: React.ReactNode; className?: string }) => (
    <div className={`bg-card border border-border rounded-xl overflow-hidden shadow-sm ${className}`}>
        <div className="h-[3px] bg-grey-100" />
        {children}
    </div>
);

const SectionHeader = ({ title, badge }: { title: string; badge?: string }) => (
    <div className="flex items-center gap-2 mb-1">
        <div className="flex items-center gap-2 border-l-2 border-amber pl-2">
            <h3 className="text-xs font-black text-foreground uppercase tracking-widest">{title}</h3>
        </div>
        {badge && <span className="text-[9px] font-bold px-2 py-0.5 bg-blue/10 text-blue border border-blue/30 rounded-full uppercase tracking-wide">{badge}</span>}
    </div>
);

const WidgetCard = ({ title, linkHref, linkLabel, children }: { title: string; linkHref?: string; linkLabel?: string; children: React.ReactNode }) => (
    <div className="bg-card border border-border rounded-xl p-5 h-full flex flex-col">
        <div className="flex items-center justify-between mb-4">
            <h3 className="font-bold text-sm text-foreground">{title}</h3>
            {linkHref && <Link href={linkHref} className="text-xs text-purple font-medium hover:underline flex-shrink-0">{linkLabel ?? 'View all →'}</Link>}
        </div>
        <div className="flex-1">{children}</div>
    </div>
);

/* ── Case Queue Widget (Row 2, right) — open cases from /api/cases ── */
export interface QueueIncident {
    id: string;
    name: string;
    asset: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    status: 'Open' | 'Investigating' | 'Contained' | 'Resolved';
    openedAt: string;
    ruleId?: string;
}

const SEVERITY_CONFIG: Record<string, { bg: string; text: string; border: string }> = {
    critical: { bg: 'bg-red-500/10', text: 'text-red-500', border: 'border-red-500/30' },
    high: { bg: 'bg-orange/10', text: 'text-orange', border: 'border-orange/30' },
    medium: { bg: 'bg-amber-500/10', text: 'text-amber-500', border: 'border-amber-500/30' },
    low: { bg: 'bg-blue/10', text: 'text-blue', border: 'border-blue/30' },
};

const STATUS_CONFIG: Record<string, { bg: string; text: string }> = {
    Open: { bg: 'bg-red-500/10 text-red-500', text: 'Open' },
    Investigating: { bg: 'bg-amber-500/10 text-amber-500', text: 'Investigating' },
    Contained: { bg: 'bg-blue/10 text-blue', text: 'Contained' },
    Resolved: { bg: 'bg-emerald-500/10 text-emerald-500', text: 'Resolved' },
};

export function IncidentQueueWidget({ incidents, loading }: { incidents: QueueIncident[] | null; loading: boolean }) {
    const rows = (incidents ?? []).slice(0, 6);

    return (
        <div className="bg-card border border-border rounded-2xl shadow-xs overflow-hidden">
            {/* Header */}
            <div className="p-4 sm:px-5 sm:py-4 border-b border-border flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                    <h3 className="text-sm font-bold text-foreground tracking-tight">Active Case Queue</h3>
                    <span className="text-[11px] font-semibold text-foreground-muted bg-card-muted px-2 py-0.5 rounded-full border border-border">
                        {rows.length} Active
                    </span>
                </div>
                <Link
                    href="/admin/secops/cases"
                    className="flex items-center gap-1 text-xs font-bold text-orange hover:text-orange-hover transition-colors"
                >
                    View all
                    <ChevronRight size={14} />
                </Link>
            </div>

            {/* Content Body */}
            <div className="p-2 sm:p-3">
                {loading ? (
                    <div className="space-y-2 p-2">
                        {Array.from({ length: 5 }).map((_, i) => (
                            <div key={i} className="h-10 bg-card-muted/60 rounded-xl animate-pulse" />
                        ))}
                    </div>
                ) : rows.length === 0 ? (
                    <div className="text-center py-8">
                        <div className="w-10 h-10 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center mx-auto mb-2.5">
                            <CheckCircle size={18} className="text-emerald-500" />
                        </div>
                        <p className="text-xs font-semibold text-foreground">No open cases</p>
                        <p className="text-[11px] text-foreground-muted mt-0.5">Nothing is waiting for an analyst.</p>
                    </div>
                ) : (
                    <div>
                        {/* Table Column Labels */}
                        <div className="grid grid-cols-12 gap-3 px-3 py-2 text-[10px] font-bold text-foreground-muted uppercase tracking-wider border-b border-border/60">
                            <span className="col-span-2">Severity</span>
                            <span className="col-span-6">Case & Host</span>
                            <span className="col-span-2 text-center">Status</span>
                            <span className="col-span-2 text-right">Opened</span>
                        </div>

                        {/* List Items */}
                        <div className="divide-y divide-border/40">
                            {rows.map((inc) => {
                                const sev = SEVERITY_CONFIG[inc.severity?.toLowerCase()] || SEVERITY_CONFIG.low;
                                const stat = STATUS_CONFIG[inc.status] || STATUS_CONFIG.Open;

                                return (
                                    <Link
                                        key={inc.id}
                                        href="/admin/secops/cases"
                                        className="grid grid-cols-12 gap-3 items-center px-3 py-3 rounded-xl hover:bg-card-muted/50 transition-colors group"
                                    >
                                        {/* Severity Tag */}
                                        <div className="col-span-2 flex items-center">
                                            <span className={`inline-flex items-center justify-center text-[10px] font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-md border ${sev.bg} ${sev.text} ${sev.border}`}>
                                                {inc.severity}
                                            </span>
                                        </div>

                                        {/* Incident Name & Asset */}
                                        <div className="col-span-6 min-w-0">
                                            <p className="text-xs font-semibold text-foreground truncate group-hover:text-orange transition-colors">
                                                {inc.name}
                                            </p>
                                            <div className="flex items-center gap-1.5 mt-0.5 text-[11px] text-foreground-muted truncate">
                                                {inc.asset.includes('DESKTOP') ? (
                                                    <Laptop size={11} className="flex-shrink-0" />
                                                ) : (
                                                    <Server size={11} className="flex-shrink-0" />
                                                )}
                                                <span className="font-mono text-[10px]">{inc.asset}</span>
                                            </div>
                                        </div>

                                        {/* Status */}
                                        <div className="col-span-2 flex justify-center">
                                            <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${stat.bg}`}>
                                                {inc.status}
                                            </span>
                                        </div>

                                        {/* Opened (WAT) */}
                                        <div className="col-span-2 flex items-center justify-end gap-1 font-mono text-[11px] text-foreground-muted">
                                            <Clock size={11} className="text-foreground-muted/80" />
                                            <span>{inc.openedAt}</span>
                                        </div>
                                    </Link>
                                );
                            })}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}

/* ── MITRE ATT&CK Widget (Row 3, left) ──
 * All 14 MITRE ATT&CK Enterprise tactics (this used to list 8, silently dropping Reconnaissance,
 * Resource Development, Defense Evasion, Discovery, Collection and Impact — Defense Evasion and
 * Discovery are among the most common tactics Wazuh rules map to, so the dropped six were not an
 * edge case). GET /api/wazuh/mitre-stats already aggregates by whatever rule.mitre.tactic values
 * the last 24h of alerts carry; only the fixed row list here needs to cover every one of them. */
const MITRE_TACTICS = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
    'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
    'Exfiltration', 'Impact',
];

function MITREWidget({ tactics, source }: { tactics: Record<string, number> | null; source: string | null }) {
    const data = tactics ?? {};
    const maxCount = Math.max(...Object.values(data), 1);
    return (
        <WidgetCard title="MITRE ATT&CK" linkHref="/admin/secops/mitre" linkLabel="View MITRE Intelligence →">
            <div className="flex items-center justify-end mb-2 -mt-2">
                <span className="text-[9px] bg-purple/10 text-purple px-2 py-0.5 rounded-full font-bold uppercase">{source === 'wazuh' ? 'Last 24h' : source === 'demo' ? 'Demo' : 'No data'}</span>
            </div>
            <div className="space-y-2">
                {MITRE_TACTICS.map((tactic) => {
                    const count = data[tactic] ?? 0;
                    const pct = Math.round((count / maxCount) * 100);
                    const color = count === 0 ? 'bg-card-muted' : count < 5 ? 'bg-orange/30' : count < 20 ? 'bg-orange' : 'bg-red';
                    return (
                        <div key={tactic} className="flex items-center gap-3">
                            <span className="text-[10px] text-foreground-muted w-32 flex-shrink-0 truncate">{tactic}</span>
                            <div className="flex-1 bg-card-muted rounded-full h-2">
                                <div className={`h-2 rounded-full transition-all ${color}`} style={{ width: `${pct}%` }} />
                            </div>
                            <span className="text-[10px] font-bold text-foreground w-6 text-right">{count}</span>
                        </div>
                    );
                })}
            </div>
        </WidgetCard>
    );
}

/* ── Threat Intel Snapshot Widget (Row 3, right) ──
 * Was GET /api/org-cti/stats — a process-lifetime, in-memory accumulator (lib/orgCtiStore.ts)
 * that resets on every deploy, and its platform-wide half was wired to a backend
 * (/api/threat-intel/stats) that no longer exists, so it always rendered "Not connected". Both
 * halves now come from GET /api/ti/overview (the persistent Threat Intelligence pipeline, phase
 * P25): indicators.active / indicators.new_last_24h are genuinely platform-wide (every org sees
 * the same two numbers, same as the TI Overview page itself); matches.new / matches.total are
 * this organisation's own ti_matches rows, so they move with the organisation switcher. */
interface TiSummary { indicatorsActive: number; indicatorsNew24h: number; matchesNew: number; matchesTotal: number }

function ThreatIntelWidget({ ti, failure }: { ti: TiSummary | null; failure: string | null }) {
    return (
        <WidgetCard title="Threat Intelligence" linkHref="/admin/ti" linkLabel="Open Threat Intelligence →">
            {failure ? (
                <p className="text-xs text-foreground-muted text-center py-6">{failure}</p>
            ) : (
                <>
                    <div className="bg-card-muted rounded-lg p-3 mb-4">
                        <div className="text-[10px] text-foreground-muted uppercase tracking-wider mb-2">Platform-wide</div>
                        <div className="flex gap-4">
                            <div><div className="text-lg font-black text-foreground">{ti ? ti.indicatorsActive.toLocaleString() : '—'}</div><div className="text-[10px] text-foreground-muted">Active indicators</div></div>
                            <div><div className="text-lg font-black text-blue">{ti ? ti.indicatorsNew24h.toLocaleString() : '—'}</div><div className="text-[10px] text-foreground-muted">New (24h)</div></div>
                        </div>
                    </div>
                    <div className="border-t border-border pt-3">
                        <div className="text-[10px] text-foreground-muted uppercase tracking-wider mb-2">Your Organisation</div>
                        <div className="flex gap-4">
                            <div><div className="text-lg font-black text-red">{ti ? ti.matchesNew.toLocaleString() : '—'}</div><div className="text-[10px] text-foreground-muted">New matches</div></div>
                            <div><div className="text-lg font-black text-purple">{ti ? ti.matchesTotal.toLocaleString() : '—'}</div><div className="text-[10px] text-foreground-muted">Total matches</div></div>
                        </div>
                    </div>
                </>
            )}
        </WidgetCard>
    );
}

/* ── SOAR Activity Widget (Row 4, left) ──────────────────────────────────────────────
 * Every figure comes from GET /api/soar/stats (Supabase case counts).
 * This previously rendered four hardcoded values — "6 playbooks", three zeros and a 0%
 * automation rate — under a note naming a third-party workflow engine. The numbers were not
 * measured and the engine name is not something to surface in the product, so both are gone.
 * A count that can't be read renders as "—", never as 0: zero is a finding, unknown is not. */
function SOARWidget() {
    const [status, setStatus] = useState<{
        cases_created_today?: number;
        auto_resolved_today?: number;
        open_cases?: number;
        escalated_open?: number;
        engine_active?: boolean;
    } | null>(null);
    const [failed, setFailed] = useState(false);

    useEffect(() => {
        apiFetch(apiUrl('/api/soar/stats'), { cache: 'no-store' })
            .then(async (r) => { if (!r.ok) throw new Error(); setStatus(await r.json()); })
            .catch(() => setFailed(true));
    }, []);

    const show = (v: number | undefined) => (typeof v === 'number' ? v.toLocaleString() : '—');

    return (
        <WidgetCard title="SOAR Automation" linkHref="/admin/secops/soar" linkLabel="View workflows →">
            <div className="grid grid-cols-2 gap-3">
                {[
                    { label: 'Cases Created Today', value: show(status?.cases_created_today), color: 'text-blue' },
                    { label: 'Auto-Resolved Today', value: show(status?.auto_resolved_today), color: 'text-green' },
                    { label: 'Open Cases', value: show(status?.open_cases), color: 'text-purple' },
                    { label: 'Escalated', value: show(status?.escalated_open), color: 'text-red' },
                ].map((s) => (
                    <div key={s.label} className="bg-card-muted rounded-lg p-3">
                        <div className={`text-xl font-black ${s.color}`}>{s.value}</div>
                        <div className="text-[10px] text-foreground-muted mt-0.5">{s.label}</div>
                    </div>
                ))}
            </div>
            <div className="mt-3 flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full flex-shrink-0 ${status?.engine_active ? 'bg-green' : 'bg-card-muted'}`} />
                <span className="text-[10px] text-foreground-muted">
                    {failed
                        ? 'Automation status unavailable — could not reach the backend.'
                        : status?.engine_active
                            ? 'SOAR engine active — a Wazuh alert was cased in the last 24 hours.'
                            : 'No case from the SOAR engine in 24 hours — see SOAR Automation.'}
                </span>
            </div>
        </WidgetCard>
    );
}

/* ── Compliance Scores Widget (Row 4, right) — real /api/compliance data ── */
interface FrameworkScore { shortName: string; score: number; assessed: number }
function ComplianceWidget({ frameworks, loading, failure }: { frameworks: FrameworkScore[] | null; loading: boolean; failure: string | null }) {
    const FW_COLOR: Record<string, string> = { NDPA: 'bg-purple', 'ISO 27001': 'bg-blue', CBN: 'bg-orange', 'PCI-DSS': 'bg-green', NCC: 'bg-red' };
    const shown = (frameworks ?? []).filter((f) => ['NDPA', 'ISO 27001', 'CBN', 'PCI-DSS', 'NCC'].includes(f.shortName));
    return (
        <WidgetCard title="Compliance" linkHref="/admin/compliance" linkLabel="Full report →">
            {loading ? (
                <div className="space-y-3">{Array.from({ length: 5 }).map((_, i) => <div key={i} className="h-6 bg-card-muted rounded animate-pulse" />)}</div>
            ) : failure ? (
                <p className="text-xs text-foreground-muted text-center py-6">{failure}</p>
            ) : (
                <div className="space-y-3">
                    {shown.map((f) => (
                        <div key={f.shortName}>
                            <div className="flex justify-between items-center mb-1">
                                <span className="text-xs font-medium text-foreground">{f.shortName}</span>
                                <span className="text-xs font-bold text-foreground">{f.assessed > 0 ? `${f.score}%` : 'Not assessed'}</span>
                            </div>
                            <div className="bg-card-muted rounded-full h-2">
                                <div className={`h-2 rounded-full transition-all ${FW_COLOR[f.shortName] ?? 'bg-blue'}`} style={{ width: `${f.score}%` }} />
                            </div>
                        </div>
                    ))}
                </div>
            )}
            <Link href="/admin/compliance" className="block mt-4 pt-3 border-t border-border text-xs text-orange font-bold hover:underline">
                + Set up compliance assessment →
            </Link>
        </WidgetCard>
    );
}

/* ── Recent Alerts Feed (Row 5, full width) — stored alerts, GET /api/alerts (phase R2) ── */
interface FeedAlert { id: string; severity: string; rule_description: string | null; agent_name: string | null; agent_ip: string | null; event_time: string }
const FEED_SEV_STYLE: Record<string, string> = {
    critical: 'bg-red text-white', high: 'bg-orange/10 text-orange',
    medium: 'bg-amber/10 text-amber', low: 'bg-card-muted text-foreground-muted',
};

function AlertsFeed({ alerts, failure, loading }: { alerts: FeedAlert[]; failure: string | null; loading: boolean }) {
    return (
        <Card>
            <div className="p-5">
                <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                        <h3 className="font-bold text-sm text-foreground">Recent Alerts</h3>
                    </div>
                    <Link href="/admin/secops/alerts" className="text-xs text-purple font-medium hover:underline">View all alerts →</Link>
                </div>

                {loading ? (
                    <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <div key={i} className="h-8 bg-card-muted rounded animate-pulse" />)}</div>
                ) : failure ? (
                    <p className="text-xs text-red-500 text-center py-8">{failure}</p>
                ) : alerts.length === 0 ? (
                    <p className="text-xs text-foreground-muted text-center py-8">No data — no alerts stored for this organisation.</p>
                ) : (
                    <div className="overflow-x-auto scrollbar-thin">
                        <table className="w-full text-left">
                            <thead>
                                <tr className="bg-grey-800">
                                    {['Time', 'Severity', 'Alert', 'Agent', 'Agent IP', ''].map((h) => (
                                        <th key={h} className="px-4 py-2.5 text-[10px] font-semibold text-white uppercase tracking-widest whitespace-nowrap">{h}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border text-xs">
                                {alerts.slice(0, 10).map((a) => (
                                    <tr key={a.id} className="hover:bg-card-muted transition-colors">
                                        <td className="px-4 py-3 text-foreground-muted font-mono whitespace-nowrap">{watTime(a.event_time)}</td>
                                        <td className="px-4 py-3"><span className={`text-[10px] font-bold px-2 py-1 rounded-full ${FEED_SEV_STYLE[a.severity] ?? 'bg-card-muted text-foreground-muted'}`}>{a.severity?.toUpperCase()}</span></td>
                                        <td className="px-4 py-3 text-foreground font-medium max-w-xs truncate">{a.rule_description ?? '—'}</td>
                                        <td className="px-4 py-3 text-foreground-muted whitespace-nowrap">{a.agent_name ?? '—'}</td>
                                        <td className="px-4 py-3 text-foreground font-mono whitespace-nowrap">{a.agent_ip || '—'}</td>
                                        <td className="px-4 py-3 whitespace-nowrap"><Link href="/admin/secops/alerts" className="text-[10px] text-purple font-medium hover:underline">Investigate</Link></td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </Card>
    );
}

/* ── Onboarded Clients Widget (kept from the previous dashboard — real /api/customers + per-client Wazuh data) ── */
interface OnboardedClient { id: string; slug: string | null; name: string; industry: string | null; status: string; agentsTotal: number | null; activeIncidents: number | null; wazuhGroup: string | null; setupComplete?: boolean }

// null = that figure could not be read for this client (no access, or Wazuh / the alert store
// unavailable): shown as "—", never as 0.
interface ClientLiveData { endpoints: number | null; alerts: number | null }

function clientStatusBadge(orgStatus: string, endpoints: number | null): { label: string; classes: string } {
    if (orgStatus !== 'active') return { label: 'Inactive', classes: 'text-foreground-muted bg-card-muted border-border' };
    if (endpoints === null) return { label: 'Unknown', classes: 'text-foreground-muted bg-card-muted border-border' };
    if (endpoints > 0) return { label: 'Active', classes: 'text-blue bg-blue/10 border-blue/30' };
    return { label: 'Pending', classes: 'text-amber bg-grey-100 border-amber/30' };
}

const OnboardedClientsWidget = ({ clients, loading, failure }: { clients: OnboardedClient[] | null; loading: boolean; failure: string | null }) => {
    const rows = (clients ?? []).slice(0, 5);
    const [liveData, setLiveData] = useState<Record<string, ClientLiveData>>({});

    useEffect(() => {
        if (!clients || clients.length === 0) return;
        // Each client's own figures, read as that organisation (X-Org-Id; the backend checks the
        // viewer may see it and audits the access). No fallback to another group or organisation.
        const fetchClient = async (slug: string): Promise<ClientLiveData> => {
            const init = { cache: 'no-store' as const, signal: AbortSignal.timeout(10000), headers: { 'X-Org-Id': slug } };
            const json = (r: Response) => (r.ok ? r.json() : null);
            const [agentsRes, statsRes] = await Promise.all([
                apiFetch(apiUrl('/api/wazuh/agents'), init).then(json).catch(() => null),
                apiFetch(apiUrl('/api/alerts/stats?range=7d'), init).then(json).catch(() => null),
            ]);
            return {
                endpoints: typeof agentsRes?.total === 'number' ? agentsRes.total : null,
                alerts: typeof statsRes?.total === 'number' ? statsRes.total : null,
            };
        };
        rows.forEach(async (c) => {
            const result = c.slug ? await fetchClient(c.slug) : { endpoints: null, alerts: null };
            setLiveData(prev => ({ ...prev, [c.id]: result }));
        });
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [clients]);

    return (
        <Card>
            <div className="p-4">
                <div className="flex items-center justify-between mb-3">
                    <div>
                        <SectionHeader title="Onboarded Clients" badge={clients ? `${clients.length} ${clients.length === 1 ? 'Client' : 'Clients'}` : undefined} />
                        <p className="text-[10px] text-foreground-muted">Client portfolio and monitoring status</p>
                    </div>
                    <Link href="/admin/customers" className="text-[10px] font-semibold text-blue hover:underline">View All →</Link>
                </div>
                {loading ? (
                    <div className="space-y-2 py-2">{Array.from({ length: 2 }).map((_, i) => <div key={i} className="h-6 bg-card-muted rounded animate-pulse" />)}</div>
                ) : failure ? (
                    <p className="text-xs text-foreground-muted text-center py-6">{failure}</p>
                ) : rows.length === 0 ? (
                    <div className="py-8 text-center">
                        <p className="text-[11px] text-foreground-muted mb-3">No clients onboarded yet. Go to Customers to add your first client.</p>
                        <Link href="/admin/customers" className="inline-block text-[10px] font-bold px-3 py-1.5 bg-orange hover:bg-orange-hover text-white rounded-lg transition-colors">Onboard First Client</Link>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-xs">
                            <thead>
                                <tr className="bg-card-muted border-b border-border">
                                    {['Client Name', 'Industry', 'Endpoints', 'Alerts (7d)', 'Status'].map(h => (
                                        <th key={h} className="text-left py-2 px-3 text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{h}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {rows.map(c => {
                                    const live = liveData[c.id];
                                    const endpoints = live ? live.endpoints : null;
                                    const alerts = live ? live.alerts : null;
                                    const badge = clientStatusBadge(c.status, endpoints);
                                    return (
                                        <tr key={c.id} className="border-b border-border hover:bg-card-muted transition-colors">
                                            <td className="py-2 px-3 font-semibold text-foreground">{c.name === 'Cybernovr' ? '🛡️' : '🏢'} {c.name}</td>
                                            <td className="py-2 px-3 text-foreground-muted">{c.industry ?? '—'}</td>
                                            <td className="py-2 px-3 text-foreground-muted">{live ? endpoints?.toLocaleString() ?? '—' : '…'}</td>
                                            <td className="py-2 px-3 font-bold text-foreground">{live ? alerts?.toLocaleString() ?? '—' : '…'}</td>
                                            <td className="py-2 px-3"><span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${badge.classes}`}>{badge.label}</span></td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </Card>
    );
};

/* ── Main ── */
export const GeneralDashboard = () => {
    // The organisation being viewed (lib/orgContext.ts, 2026 redesign Stage 2) — every org-scoped
    // fetch below re-runs when a staff session switches organisation. super_admin-only is read
    // once (getAdminUser decodes the token locally; never used for authorization, only to decide
    // which calls this role can expect to succeed — the backend enforces every one regardless).
    const org = useSyncExternalStore(subscribeOrgContext, getOrgContext, () => '');
    const [role] = useState<string>(() => (typeof window === 'undefined' ? '' : getAdminUser().role));
    const isSuperAdmin = role === 'super_admin';

    const [wazuhStatus, setWazuhStatus] = useState<{ connected: boolean; agent_count: number | null; active_agents: number | null; disconnected_agents: number | null; error?: string } | null>(null);
    const [platformHealth, setPlatformHealth] = useState<{ overall: string; services: Array<{ name: string; status: string; latency_ms: number }>; error?: string } | null>(null);
    const [alertStats, setAlertStats] = useState<AlertStats | null>(null);
    const [alertsState, setAlertsState] = useState<{ loaded: boolean; notConnected: boolean; error: string | null }>({ loaded: false, notConnected: false, error: null });
    const [incidentKpis, setIncidentKpis] = useState<{ total: number; critical: number } | null>(null);
    const [incidentsFailed, setIncidentsFailed] = useState(false);
    const [incidentQueue, setIncidentQueue] = useState<QueueIncident[] | null>(null);
    const [incidentsLoading, setIncidentsLoading] = useState(true);
    const [mitreTactics, setMitreTactics] = useState<Record<string, number> | null>(null);
    const [mitreSource, setMitreSource] = useState<string | null>(null);
    const [ti, setTi] = useState<TiSummary | null>(null);
    const [tiFailure, setTiFailure] = useState<string | null>(null);
    const [frameworks, setFrameworks] = useState<FrameworkScore[] | null>(null);
    const [frameworksLoading, setFrameworksLoading] = useState(true);
    const [frameworksFailure, setFrameworksFailure] = useState<string | null>(null);
    const [feedAlerts, setFeedAlerts] = useState<FeedAlert[]>([]);
    const [feedFailure, setFeedFailure] = useState<string | null>(null);
    const [feedLoading, setFeedLoading] = useState(true);
    const [customerCount, setCustomerCount] = useState<number | null>(null);
    const [customersFailed, setCustomersFailed] = useState(false);

    useEffect(() => {
        apiFetch(apiUrl('/api/wazuh/status'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(r => r.json())
            .then(data => setWazuhStatus({ connected: !!data?.connected, agent_count: data?.agent_count ?? null, active_agents: data?.active_agents ?? null, disconnected_agents: data?.disconnected_agents ?? null, error: data?.error }))
            .catch(() => setWazuhStatus({ connected: false, agent_count: null, active_agents: null, disconnected_agents: null, error: 'Could not reach the backend' }));
    }, [org]);

    // Platform-wide, super_admin only (backend: requireRole('super_admin')) — every other role
    // would always get a 403 here, which used to render as a red "0%" rather than "unavailable
    // for your role". Not fetched at all for anyone else, same reasoning as HeaderStatus.tsx.
    useEffect(() => {
        if (!isSuperAdmin) return;
        apiFetch(apiUrl('/api/platform/health'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(async r => { const data = await r.json(); if (!r.ok) throw new Error(data?.error ?? `HTTP ${r.status}`); setPlatformHealth({ overall: data?.overall ?? 'unknown', services: Array.isArray(data?.services) ? data.services : [] }); })
            .catch((e: unknown) => setPlatformHealth({ overall: 'unknown', services: [], error: e instanceof Error ? e.message : 'Could not reach the backend' }));
    }, [isSuperAdmin]);

    // Alert counts come from the stored, org-scoped alert table (phase R2). A failure leaves them
    // null, shown as "—" with the reason — never 0.
    const loadAlertStats = useCallback(() => fetchAlertStats('24h').then((r) => {
        setAlertStats(r.ok ? r.data : null);
        setAlertsState({ loaded: true, notConnected: !r.ok && r.notConnected, error: r.ok ? null : r.error });
    }), []);
    useEffect(() => { void loadAlertStats(); }, [loadAlertStats, org]);

    useEffect(() => {
        // Real cases (analyst queue: auto-closed tier-1 excluded), newest first; unresolved only.
        // A failed load leaves the KPI null (shown as "—"), never a false "0 open cases".
        const STATUS_LABEL: Record<string, QueueIncident['status']> = { open: 'Open', investigating: 'Investigating', contained: 'Contained', resolved: 'Resolved' };
        apiFetch(apiUrl('/api/cases?exclude_auto_closed=true&limit=50'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(async r => { const data = await r.json(); if (!r.ok) throw new Error(data?.error ?? `HTTP ${r.status}`); return data; })
            .then(data => {
                setIncidentKpis({ total: data?.summary?.active ?? 0, critical: data?.summary?.critical ?? 0 });
                const rows = (Array.isArray(data?.cases) ? data.cases : []) as Array<{ id: string; title: string; agent_name: string | null; severity: QueueIncident['severity']; status: string; created_at: string; rule_id: string | null }>;
                setIncidentQueue(rows.filter(c => c.status !== 'resolved').map(c => ({
                    id: c.id,
                    name: c.title,
                    asset: c.agent_name || '—',
                    severity: c.severity,
                    status: STATUS_LABEL[c.status] ?? 'Open',
                    openedAt: new Date(c.created_at).toLocaleString('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }),
                    ruleId: c.rule_id ?? undefined,
                })));
            })
            .catch(() => { setIncidentKpis(null); setIncidentQueue([]); setIncidentsFailed(true); })
            .finally(() => setIncidentsLoading(false));
    }, [org]);

    useEffect(() => {
        apiFetch(apiUrl('/api/wazuh/mitre-stats'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(r => r.json())
            .then(data => { setMitreTactics(data?.tactics ?? {}); setMitreSource(data?.source ?? 'unavailable'); })
            .catch(() => { setMitreTactics({}); setMitreSource('unavailable'); });
    }, [org]);

    // GET /api/ti/overview (phase P25, persistent) — replaces the in-memory org-cti store.
    useEffect(() => {
        apiFetch(apiUrl('/api/ti/overview'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(async r => { const data = await r.json(); if (!r.ok) throw new Error(data?.error ?? `HTTP ${r.status}`); return data; })
            .then(data => {
                setTi({
                    indicatorsActive: data?.indicators?.active ?? 0, indicatorsNew24h: data?.indicators?.new_last_24h ?? 0,
                    matchesNew: data?.matches?.new ?? 0, matchesTotal: data?.matches?.total ?? 0,
                });
                setTiFailure(null);
            })
            .catch((e: unknown) => { setTi(null); setTiFailure(e instanceof Error ? e.message : 'Could not reach the backend'); });
    }, [org]);

    useEffect(() => {
        apiFetch(apiUrl('/api/compliance'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(async r => {
                const data = await r.json().catch(() => null);
                if (!r.ok) throw new Error(r.status === 403 ? 'Compliance is not available for your role' : (data?.error ?? `HTTP ${r.status}`));
                setFrameworks(Array.isArray(data) ? data : []);
            })
            .catch((e: unknown) => { setFrameworks(null); setFrameworksFailure(e instanceof Error ? e.message : 'Could not reach the backend'); })
            .finally(() => setFrameworksLoading(false));
    }, [org]);

    const loadFeed = useCallback(() => loadJson<{ alerts: FeedAlert[] }>('/api/alerts?limit=10').then((r) => {
        setFeedAlerts(r.ok ? r.data.alerts : []);
        setFeedFailure(r.ok ? null : r.notConnected ? 'Not connected — the alert store is unavailable.' : `Alerts unavailable — ${r.error}`);
        setFeedLoading(false);
    }), []);
    useEffect(() => { void loadFeed(); }, [loadFeed]);
    // Stored-alert KPIs and the feed stay current while the dashboard is on screen.
    usePolling(() => Promise.all([loadAlertStats(), loadFeed()]), 60_000);

    const [clients, setClients] = useState<OnboardedClient[] | null>(null);
    const [clientsLoading, setClientsLoading] = useState(true);
    useEffect(() => {
        apiFetch(apiUrl('/api/customers'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(async r => { const data = await r.json(); if (!r.ok) throw new Error(data?.error ?? `HTTP ${r.status}`); return data; })
            .then(data => { setClients(Array.isArray(data?.customers) ? data.customers : []); setCustomerCount(Array.isArray(data?.customers) ? data.customers.length : 0); })
            .catch(() => { setClients(null); setCustomerCount(null); setCustomersFailed(true); })
            .finally(() => setClientsLoading(false));
    }, [org]);

    const [trendData, setTrendData] = useState<{ label: string; alerts: number; incidents: number; critical: number }[] | null>(null);
    const [trendLoading, setTrendLoading] = useState(true);
    const [trendRange, setTrendRange] = useState<'24h' | '7d' | '30d'>('7d');
    useEffect(() => {
        apiFetch(apiUrl(`/api/wazuh/trend?range=${trendRange}`), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(r => r.json())
            .then(data => setTrendData(Array.isArray(data) && data.length > 0 ? data : null))
            .catch(() => setTrendData(null))
            .finally(() => setTrendLoading(false));
    }, [trendRange]);

    const trendBars = trendData
        ? (() => {
            const maxAlerts = Math.max(...trendData.map(d => d.alerts), 1);
            return trendData.map(d => ({ heightPct: Math.max(4, Math.round((d.alerts / maxAlerts) * 100)), label: d.label, title: `${d.alerts} alerts, ${d.incidents} high severity, ${d.critical} critical`, critical: d.critical > 0 }));
        })()
        : [];

    const health = platformHealthDisplay(isSuperAdmin, platformHealth);
    const openCases = openCasesDisplay(incidentKpis, incidentsFailed);
    const clientsProtected = honestCountDisplay(customerCount, customersFailed, 'organisations');

    const criticalAlertsCount = alertStats ? alertStats.by_severity.critical : null;
    const level7PlusCount = alertStats ? alertStats.by_severity.critical + alertStats.by_severity.high + alertStats.by_severity.medium : null;
    const alertsUnavailable = !alertsState.loaded ? 'checking…' : alertsState.notConnected ? 'not connected' : 'unavailable';

    const kpiCards: KpiCardProps[] = [
        // Registered / online / offline, from /api/wazuh/status. When the manager can't be reached
        // the card says so instead of showing 0 agents, which would read as "nothing monitored".
        {
            label: 'Agents',
            value: wazuhStatus?.connected && wazuhStatus.agent_count !== null ? wazuhStatus.agent_count.toLocaleString() : '—',
            trend: '', type: 'purple', icon: Monitor,
            subValue: wazuhStatus === null ? 'checking…' : wazuhStatus.connected
                ? `${wazuhStatus.active_agents ?? '—'} online · ${wazuhStatus.disconnected_agents ?? '—'} offline`
                : 'Agent inventory unavailable',
        },
        { label: 'Open Cases', value: openCases.value, trend: '', type: 'orange', icon: Siren, subValue: openCases.sub },
        { label: 'Critical Alerts', value: criticalAlertsCount !== null ? String(criticalAlertsCount) : '—', trend: '', type: 'red', icon: ShieldAlert, subValue: alertStats ? 'last 24 hours' : alertsUnavailable },
        { label: 'Alerts Level 7+', value: level7PlusCount !== null ? String(level7PlusCount) : '—', trend: '', type: 'orange', icon: Shield, subValue: alertStats ? 'last 24 hours' : alertsUnavailable },
        { label: 'Clients Protected', value: clientsProtected.value, trend: '', type: 'blue', icon: Building2, subValue: clientsProtected.sub },
        { label: 'Mean Time to Detect', value: '—', trend: '', type: 'purple', icon: Timer, subValue: 'no data yet' },
        { label: 'Mean Time to Respond', value: '—', trend: '', type: 'blue', icon: Zap, subValue: 'no data yet' },
        { label: 'Platform Health', value: health.pct, trend: '', type: health.type, icon: Activity, subValue: health.sub },
    ];

    return (
        <div className="space-y-6">
            {/* Header bar */}
            <div className="flex items-center justify-between flex-wrap gap-3">
                <div>
                    <p className="text-xs text-foreground-muted">{new Date().toLocaleString('en-GB', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'Africa/Lagos' })} WAT</p>
                </div>
                <Link href="/admin/secops/alerts" className="flex items-center gap-2 border border-border rounded-lg px-3 py-2 text-xs font-bold text-foreground-muted hover:text-foreground hover:border-grey-300 transition-colors">
                    <Bell size={14} /> {criticalAlertsCount ?? '—'} critical
                </Link>
            </div>

            <AlertFeedStatus loaded={alertsState.loaded} notConnected={alertsState.notConnected} error={alertsState.error} lastReceivedAt={alertStats?.last_received_at ?? null} staleAfterMinutes={alertStats?.stale_after_minutes} />


            {/* Row 1: KPI cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {kpiCards.map((kpi, idx) => <KpiCard key={idx} {...kpi} />)}
            </div>

            {/* Row 2: Nigeria map (60%) + Case queue (40%) */}
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-4 items-stretch">
                <div className="lg:col-span-5"><DashboardNigeriaMap /></div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-5 gap-4 items-stretch">
                 <div className="lg:col-span-5"><IncidentQueueWidget incidents={incidentQueue} loading={incidentsLoading} /></div>
            </div>

            {/* Row 3: MITRE (40%) + Threat Intel (60%) */}
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-4 items-stretch">
                <div className="lg:col-span-2"><MITREWidget tactics={mitreTactics} source={mitreSource} /></div>
                <div className="lg:col-span-3"><ThreatIntelWidget ti={ti} failure={tiFailure} /></div>
            </div>

            {/* Row 4: SOAR (50%) + Compliance (50%) */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 items-stretch">
                <SOARWidget />
                <ComplianceWidget frameworks={frameworks} loading={frameworksLoading} failure={frameworksFailure} />
            </div>

            {/* Row 5: Recent alerts feed */}
            <AlertsFeed alerts={feedAlerts} failure={feedFailure} loading={feedLoading} />

            <OnboardedClientsWidget clients={clients} loading={clientsLoading} failure={customersFailed ? 'Client list unavailable' : null} />

            <ChartWrapper title="Security Posture & Alert Activity Trends">
                <div className="flex items-center gap-2 mb-3">
                    {([['24h', 'Last 24 Hours'], ['7d', 'Last 7 Days'], ['30d', 'Last 30 Days']] as const).map(([val, label]) => (
                        <button key={val} onClick={() => { setTrendLoading(true); setTrendRange(val); }}
                            className={`text-[10px] font-bold px-2.5 py-1 rounded border transition-colors ${trendRange === val ? 'bg-grey-100 text-white border-amber' : 'bg-card border-border text-foreground-muted hover:text-foreground'}`}>
                            {label}
                        </button>
                    ))}
                </div>
                {trendLoading ? (
                    <div className="w-full h-full flex items-end gap-2 pt-4">
                        {Array.from({ length: 12 }).map((_, i) => (
                            <div key={i} className="flex-1 flex flex-col items-center">
                                <div style={{ height: `${30 + (i % 5) * 10}%` }} className="w-full rounded-t bg-card-muted animate-pulse" />
                            </div>
                        ))}
                    </div>
                ) : trendBars.length === 0 ? (
                    <div className="w-full h-full flex items-center justify-center">
                        <p className="text-xs text-foreground-muted">No trend data for this range yet.</p>
                    </div>
                ) : (
                    <div className="w-full h-full flex items-end gap-2 pt-4">
                        {trendBars.map((bar, i) => (
                            <div key={i} className="flex-1 flex flex-col items-center group" title={bar.title}>
                                <div style={{ height: `${bar.heightPct}%`, backgroundColor: bar.critical ? '#EF4444' : '#D97706' }} className="w-full rounded-t opacity-70 group-hover:opacity-100 transition-all duration-200" />
                                <span className="text-[9px] text-foreground-muted mt-1.5 font-medium">{bar.label}</span>
                            </div>
                        ))}
                    </div>
                )}
            </ChartWrapper>
        </div>
    );
};
