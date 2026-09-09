'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import {
    Monitor, Siren, ShieldAlert, Shield, Clock, Laptop, Server, ChevronRight, Building2, Timer, Zap, Activity,
    CheckCircle, Bell,
} from 'lucide-react';
import { KpiCard, type KpiCardProps } from '../shared/KpiCard';
import { ChartWrapper } from '../shared/ChartWrapper';
import { getPortalContext } from '@/lib/portal-context';
import { GlobalThreatMap } from '../geo/GlobalThreatMap';
import { NigeriaThreatMap, type FeedAdvisory } from '../geo/NigeriaThreatMap';
import { apiUrl, apiFetch } from '@/lib/api';

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

/* ── Incident Queue Widget (Row 2, right) ── */
export interface QueueIncident {
    id: string;
    name: string;
    asset: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    status: 'Open' | 'Investigating' | 'Contained' | 'Resolved';
    slaTime: string;
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
                    <h3 className="text-sm font-bold text-foreground tracking-tight">Active Incident Queue</h3>
                    <span className="text-[11px] font-semibold text-foreground-muted bg-card-muted px-2 py-0.5 rounded-full border border-border">
                        {rows.length} Active
                    </span>
                </div>
                <Link
                    href="/admin/secops/incidents"
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
                        <p className="text-xs font-semibold text-foreground">Zero Active Incidents</p>
                        <p className="text-[11px] text-foreground-muted mt-0.5">All monitored endpoints are operating within normal baseline.</p>
                    </div>
                ) : (
                    <div>
                        {/* Table Column Labels */}
                        <div className="grid grid-cols-12 gap-3 px-3 py-2 text-[10px] font-bold text-foreground-muted uppercase tracking-wider border-b border-border/60">
                            <span className="col-span-2">Severity</span>
                            <span className="col-span-6">Incident & Target Host</span>
                            <span className="col-span-2 text-center">Status</span>
                            <span className="col-span-2 text-right">SLA Target</span>
                        </div>

                        {/* List Items */}
                        <div className="divide-y divide-border/40">
                            {rows.map((inc) => {
                                const sev = SEVERITY_CONFIG[inc.severity?.toLowerCase()] || SEVERITY_CONFIG.low;
                                const stat = STATUS_CONFIG[inc.status] || STATUS_CONFIG.Open;

                                return (
                                    <Link
                                        key={inc.id}
                                        href={`/admin/secops/incidents`}
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

                                        {/* SLA Remaining */}
                                        <div className="col-span-2 flex items-center justify-end gap-1 font-mono text-[11px] text-foreground-muted">
                                            <Clock size={11} className="text-foreground-muted/80" />
                                            <span>{inc.slaTime || '02:00:00'}</span>
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

/* ── MITRE ATT&CK Widget (Row 3, left) ── */
const MITRE_TACTICS = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Credential Access', 'Lateral Movement', 'Exfiltration', 'Command and Control'];

function MITREWidget({ tactics, source }: { tactics: Record<string, number> | null; source: string | null }) {
    const data = tactics ?? {};
    const maxCount = Math.max(...Object.values(data), 1);
    return (
        <WidgetCard title="MITRE ATT&CK" linkHref="/admin/threat/mitre" linkLabel="View full MITRE dashboard →">
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

/* ── Threat Intel Snapshot Widget (Row 3, right) ── */
interface CtiStats { total_iocs: number; iocs_last_24h: number; active_campaigns: number; exploitable_cves_this_week: number; sources_active: number }
interface OrgCtiSummary { malicious: number; suspicious: number; total: number }

function ThreatIntelWidget({ ctiStats, orgCti }: { ctiStats: CtiStats | null; orgCti: OrgCtiSummary | null }) {
    return (
        <WidgetCard title="Threat Intelligence" linkHref="/admin/threat/cti" linkLabel="Open IOC Lookup →">
            <div className="grid grid-cols-3 gap-3 mb-4">
                {[
                    { label: 'Total IOCs', value: ctiStats?.total_iocs ?? 0, color: 'text-blue' },
                    { label: 'Last 24h', value: ctiStats?.iocs_last_24h ?? 0, color: 'text-orange' },
                    { label: 'Sources Active', value: ctiStats?.sources_active ?? 0, color: 'text-green' },
                ].map((s) => (
                    <div key={s.label} className="bg-card-muted rounded-lg p-3 text-center">
                        <div className={`text-lg font-black ${s.color}`}>{s.value.toLocaleString()}</div>
                        <div className="text-[9px] text-foreground-muted mt-0.5">{s.label}</div>
                    </div>
                ))}
            </div>
            <div className="border-t border-border pt-3">
                <div className="text-[10px] text-foreground-muted uppercase tracking-wider mb-2">Your Organisation IOCs</div>
                <div className="flex gap-4">
                    <div><div className="text-lg font-black text-red">{orgCti?.malicious ?? 0}</div><div className="text-[10px] text-foreground-muted">Malicious</div></div>
                    <div><div className="text-lg font-black text-amber">{orgCti?.suspicious ?? 0}</div><div className="text-[10px] text-foreground-muted">Suspicious</div></div>
                    <div><div className="text-lg font-black text-purple">{orgCti?.total ?? 0}</div><div className="text-[10px] text-foreground-muted">Total</div></div>
                </div>
            </div>
        </WidgetCard>
    );
}

/* ── SOAR Activity Widget (Row 4, left) — no Shuffle API wired yet, honestly labeled ── */
function SOARWidget() {
    return (
        <WidgetCard title="SOAR Automation" linkHref="/admin/secops/soar" linkLabel="View workflows →">
            <div className="grid grid-cols-2 gap-3">
                {[
                    { label: 'Playbooks Available', value: 6, color: 'text-purple' },
                    { label: 'Cases Auto-Created', value: 0, color: 'text-blue' },
                    { label: 'IPs Auto-Blocked', value: 0, color: 'text-red' },
                    { label: 'Automation Rate', value: '0%', color: 'text-green' },
                ].map((s) => (
                    <div key={s.label} className="bg-card-muted rounded-lg p-3">
                        <div className={`text-xl font-black ${s.color}`}>{s.value}</div>
                        <div className="text-[10px] text-foreground-muted mt-0.5">{s.label}</div>
                    </div>
                ))}
            </div>
            <div className="mt-3 flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-card-muted flex-shrink-0" />
                <span className="text-[10px] text-foreground-muted">Shuffle workflow not yet connected — see SOAR Automation for setup.</span>
            </div>
        </WidgetCard>
    );
}

/* ── Compliance Scores Widget (Row 4, right) — real /api/compliance data ── */
interface FrameworkScore { shortName: string; score: number; assessed: number }
function ComplianceWidget({ frameworks, loading }: { frameworks: FrameworkScore[] | null; loading: boolean }) {
    const FW_COLOR: Record<string, string> = { NDPA: 'bg-purple', 'ISO 27001': 'bg-blue', CBN: 'bg-orange', 'PCI-DSS': 'bg-green', NCC: 'bg-red' };
    const shown = (frameworks ?? []).filter((f) => ['NDPA', 'ISO 27001', 'CBN', 'PCI-DSS', 'NCC'].includes(f.shortName));
    return (
        <WidgetCard title="Compliance" linkHref="/admin/compliance" linkLabel="Full report →">
            {loading ? (
                <div className="space-y-3">{Array.from({ length: 5 }).map((_, i) => <div key={i} className="h-6 bg-card-muted rounded animate-pulse" />)}</div>
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

/* ── Recent Alerts Feed (Row 5, full width) — real /api/threats/alerts ── */
interface FeedAlert { id: string; severity: string; rule_description: string; agent_name: string; source_ip: string | null; detected_at: string }
const FEED_SEV_STYLE: Record<string, string> = {
    critical: 'bg-red text-white', high: 'bg-orange/10 text-orange',
    medium: 'bg-amber/10 text-amber', low: 'bg-card-muted text-foreground-muted',
};

function AlertsFeed({ alerts, source, loading }: { alerts: FeedAlert[]; source: 'wazuh' | 'mock' | 'demo' | null; loading: boolean }) {
    return (
        <Card>
            <div className="p-5">
                <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                        <h3 className="font-bold text-sm text-foreground">Live Alert Feed</h3>
                        {source === 'wazuh' && (
                            <div className="flex items-center gap-1.5 bg-green/10 border border-green/30 rounded-full px-2.5 py-1">
                                <span className="relative flex h-1.5 w-1.5"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green opacity-60" /><span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-green" /></span>
                                <span className="text-[10px] font-bold text-green">LIVE</span>
                            </div>
                        )}
                        {source === 'demo' && (
                            <div className="flex items-center gap-1.5 bg-purple/10 border border-purple/30 rounded-full px-2.5 py-1">
                                <div className="w-1.5 h-1.5 rounded-full bg-purple" />
                                <span className="text-[10px] font-bold text-purple">DEMO</span>
                            </div>
                        )}
                        {source === 'mock' && (
                            <div className="flex items-center gap-1.5 bg-amber/10 border border-amber/30 rounded-full px-2.5 py-1">
                                <div className="w-1.5 h-1.5 rounded-full bg-amber" />
                                <span className="text-[10px] font-bold text-amber">DEMO DATA</span>
                            </div>
                        )}
                    </div>
                    <Link href="/admin/secops/threats" className="text-xs text-purple font-medium hover:underline">View all alerts →</Link>
                </div>

                {loading ? (
                    <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <div key={i} className="h-8 bg-card-muted rounded animate-pulse" />)}</div>
                ) : alerts.length === 0 ? (
                    <p className="text-xs text-foreground-muted text-center py-8">No recent alerts.</p>
                ) : (
                    <div className="overflow-x-auto scrollbar-thin">
                        <table className="w-full text-left">
                            <thead>
                                <tr className="bg-grey-800">
                                    {['Time', 'Severity', 'Alert', 'Agent', 'Source IP', ''].map((h) => (
                                        <th key={h} className="px-4 py-2.5 text-[10px] font-semibold text-white uppercase tracking-widest whitespace-nowrap">{h}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border text-xs">
                                {alerts.slice(0, 10).map((a) => (
                                    <tr key={a.id} className="hover:bg-card-muted transition-colors">
                                        <td className="px-4 py-3 text-foreground-muted font-mono whitespace-nowrap">{a.detected_at}</td>
                                        <td className="px-4 py-3"><span className={`text-[10px] font-bold px-2 py-1 rounded-full ${FEED_SEV_STYLE[a.severity] ?? 'bg-card-muted text-foreground-muted'}`}>{a.severity?.toUpperCase()}</span></td>
                                        <td className="px-4 py-3 text-foreground font-medium max-w-xs truncate">{a.rule_description}</td>
                                        <td className="px-4 py-3 text-foreground-muted whitespace-nowrap">{a.agent_name}</td>
                                        <td className="px-4 py-3 text-foreground font-mono whitespace-nowrap">{a.source_ip || '—'}</td>
                                        <td className="px-4 py-3 whitespace-nowrap"><Link href="/admin/secops/threats" className="text-[10px] text-purple font-medium hover:underline">Investigate</Link></td>
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
interface OnboardedClient { id: string; name: string; industry: string | null; status: string; agentsTotal: number; activeIncidents: number; wazuhGroup: string | null; setupComplete?: boolean }

/* Orgs created but never taken through the onboarding wizard have no Wazuh group or contacts,
   so their widgets render empty with no explanation. Surface them with a direct link to finish. */
function IncompleteSetupPrompt({ clients }: { clients: OnboardedClient[] | null }) {
    const incomplete = (clients ?? []).filter((c) => c.setupComplete === false);
    if (incomplete.length === 0) return null;

    return (
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex items-start justify-between gap-4 flex-wrap">
            <div>
                <p className="text-sm text-amber-800 font-medium">
                    {incomplete.length === 1
                        ? `${incomplete[0].name} hasn’t finished onboarding`
                        : `${incomplete.length} organisations haven’t finished onboarding`}
                </p>
                <p className="text-xs text-amber-700 mt-1">
                    Until setup is complete there’s no Wazuh group mapping, so endpoints and incidents won’t attribute to
                    {incomplete.length === 1 ? ' this client' : ' these clients'}.
                </p>
            </div>
            <div className="flex flex-wrap gap-2">
                {incomplete.slice(0, 3).map((c) => (
                    <a
                        key={c.id}
                        href={`/admin/settings/organisations/${c.id}/setup`}
                        className="text-[11px] font-bold px-3 py-1.5 bg-amber-600 hover:bg-amber-700 text-white rounded-lg transition-colors whitespace-nowrap"
                    >
                        Complete Setup{incomplete.length > 1 ? ` — ${c.name}` : ''}
                    </a>
                ))}
            </div>
        </div>
    );
}
interface ClientLiveData { endpoints: number; incidents: number }

function clientStatusBadge(orgStatus: string, endpoints: number): { label: string; classes: string } {
    if (orgStatus !== 'active') return { label: 'Inactive', classes: 'text-foreground-muted bg-card-muted border-border' };
    if (endpoints > 0) return { label: 'Active', classes: 'text-blue bg-blue/10 border-blue/30' };
    return { label: 'Pending', classes: 'text-amber bg-grey-100 border-amber/30' };
}

const OnboardedClientsWidget = ({ clients, loading }: { clients: OnboardedClient[] | null; loading: boolean }) => {
    const rows = (clients ?? []).slice(0, 5);
    const [liveData, setLiveData] = useState<Record<string, ClientLiveData>>({});

    useEffect(() => {
        if (!clients || clients.length === 0) return;
        const fetchGroup = async (group: string | null) => {
            const [agentsRes, incidentsRes] = await Promise.all([
                apiFetch(apiUrl(`/api/wazuh/agents${group ? `?group=${encodeURIComponent(group)}` : ''}`), { cache: 'no-store', signal: AbortSignal.timeout(10000) }).then(r => r.json()).catch(() => null),
                apiFetch(apiUrl(`/api/wazuh/incidents${group ? `?group=${encodeURIComponent(group)}` : ''}`), { cache: 'no-store', signal: AbortSignal.timeout(10000) }).then(r => r.json()).catch(() => null),
            ]);
            return {
                endpoints: typeof agentsRes?.total === 'number' ? agentsRes.total : 0,
                incidents: typeof incidentsRes?.kpis?.total === 'number' ? incidentsRes.kpis.total : 0,
            };
        };
        clients.forEach(async (c) => {
            let result = await fetchGroup(c.wazuhGroup);
            if (result.endpoints === 0 && c.wazuhGroup && c.wazuhGroup !== 'default') {
                result = await fetchGroup('default');
            }
            setLiveData(prev => ({ ...prev, [c.id]: result }));
        });
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
                                    {['Client Name', 'Industry', 'Endpoints', 'Incidents (24h)', 'Status'].map(h => (
                                        <th key={h} className="text-left py-2 px-3 text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{h}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {rows.map(c => {
                                    const live = liveData[c.id];
                                    const endpoints = live?.endpoints ?? c.agentsTotal;
                                    const incidents = live?.incidents ?? c.activeIncidents;
                                    const badge = clientStatusBadge(c.status, endpoints);
                                    return (
                                        <tr key={c.id} className="border-b border-border hover:bg-card-muted transition-colors">
                                            <td className="py-2 px-3 font-semibold text-foreground">{c.name === 'Cybernovr' ? '🛡️' : '🏢'} {c.name}</td>
                                            <td className="py-2 px-3 text-foreground-muted">{c.industry ?? '—'}</td>
                                            <td className="py-2 px-3 text-foreground-muted">{endpoints.toLocaleString()}</td>
                                            <td className="py-2 px-3 font-bold text-foreground">{incidents}</td>
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
    const [wazuhStatus, setWazuhStatus] = useState<{ connected: boolean; agent_count: number; active_agents: number } | null>(null);
    const [platformHealth, setPlatformHealth] = useState<{ overall: string; services: Array<{ name: string; status: string; latency_ms: number }> } | null>(null);
    const [criticalAlertsCount, setCriticalAlertsCount] = useState<number | null>(null);
    const [openIncidentsCount, setOpenIncidentsCount] = useState<number | null>(null);
    const [incidentKpis, setIncidentKpis] = useState<{ total: number; critical: number } | null>(null);
    const [incidentQueue, setIncidentQueue] = useState<QueueIncident[] | null>(null);
    const [incidentsLoading, setIncidentsLoading] = useState(true);
    const [mitreTactics, setMitreTactics] = useState<Record<string, number> | null>(null);
    const [mitreSource, setMitreSource] = useState<string | null>(null);
    const [ctiStats, setCtiStats] = useState<CtiStats | null>(null);
    const [orgCti, setOrgCti] = useState<OrgCtiSummary | null>(null);
    const [frameworks, setFrameworks] = useState<FrameworkScore[] | null>(null);
    const [frameworksLoading, setFrameworksLoading] = useState(true);
    const [feedAlerts, setFeedAlerts] = useState<FeedAlert[]>([]);
    const [feedSource, setFeedSource] = useState<'wazuh' | 'mock' | 'demo' | null>(null);
    const [feedLoading, setFeedLoading] = useState(true);
    const [customerCount, setCustomerCount] = useState<number | null>(null);

    useEffect(() => {
        apiFetch(apiUrl('/api/wazuh/status'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(r => r.json())
            .then(data => setWazuhStatus({ connected: !!data?.connected, agent_count: data?.agent_count ?? 0, active_agents: data?.active_agents ?? 0 }))
            .catch(() => setWazuhStatus({ connected: false, agent_count: 0, active_agents: 0 }));
    }, []);

    useEffect(() => {
        apiFetch(apiUrl('/api/platform/health'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(r => r.json())
            .then(data => setPlatformHealth({ overall: data?.overall ?? 'unknown', services: Array.isArray(data?.services) ? data.services : [] }))
            .catch(() => setPlatformHealth({ overall: 'unknown', services: [] }));
    }, []);

    useEffect(() => {
        const group = getPortalContext().wazuhGroup;
        const params = new URLSearchParams({ minLevel: '7', range: '24h' });
        if (group) params.set('group', group);
        apiFetch(apiUrl(`/api/wazuh/alerts-indexer?${params.toString()}`), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(r => r.json())
            .then(data => {
                setCriticalAlertsCount(typeof data?.criticalCount === 'number' ? data.criticalCount : 0);
                setOpenIncidentsCount(typeof data?.openIncidentsCount === 'number' ? data.openIncidentsCount : 0);
            })
            .catch(() => { setCriticalAlertsCount(0); setOpenIncidentsCount(0); });
    }, []);

    useEffect(() => {
        apiFetch(apiUrl('/api/wazuh/incidents'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(r => r.json())
            .then(data => {
                setIncidentKpis({ total: data?.kpis?.total ?? 0, critical: data?.kpis?.critical ?? 0 });
                setIncidentQueue(Array.isArray(data?.incidents) ? data.incidents : []);
            })
            .catch(() => { setIncidentKpis({ total: 0, critical: 0 }); setIncidentQueue([]); })
            .finally(() => setIncidentsLoading(false));
    }, []);

    useEffect(() => {
        apiFetch(apiUrl('/api/wazuh/mitre-stats'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(r => r.json())
            .then(data => { setMitreTactics(data?.tactics ?? {}); setMitreSource(data?.source ?? 'unavailable'); })
            .catch(() => { setMitreTactics({}); setMitreSource('unavailable'); });
    }, []);

    useEffect(() => {
        apiFetch(apiUrl('/api/threat-intel/stats'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(r => r.json())
            .then(data => setCtiStats(data))
            .catch(() => {});
    }, []);

    useEffect(() => {
        apiFetch(apiUrl('/api/org-cti/stats'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(r => r.json())
            .then(data => setOrgCti({ malicious: data?.malicious ?? 0, suspicious: data?.suspicious ?? 0, total: data?.total_iocs ?? 0 }))
            .catch(() => {});
    }, []);

    useEffect(() => {
        // Cybernovr is the single pre-launch tenant everywhere else in this codebase defaults
        // to (see lib/orgCtiStore.ts, routes/orgCTI.ts) — orgId=1 here for the same reason.
        apiFetch(apiUrl('/api/compliance?orgId=1'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(r => r.json())
            .then(data => setFrameworks(Array.isArray(data) ? data : []))
            .catch(() => setFrameworks([]))
            .finally(() => setFrameworksLoading(false));
    }, []);

    useEffect(() => {
        apiFetch(apiUrl('/api/threats/alerts?limit=10'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(r => r.json())
            .then(data => {
                setFeedAlerts(Array.isArray(data?.alerts) ? data.alerts : []);
                setFeedSource(data?.source === 'wazuh' ? 'wazuh' : data?.source === 'demo' ? 'demo' : 'mock');
            })
            .catch(() => { setFeedAlerts([]); setFeedSource('mock'); })
            .finally(() => setFeedLoading(false));
    }, []);

    const [nigeriaAdvisories, setNigeriaAdvisories] = useState<FeedAdvisory[] | null>(null);
    useEffect(() => {
        apiFetch(apiUrl('/api/advisories'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(r => r.json())
            .then(data => setNigeriaAdvisories(Array.isArray(data?.advisories) ? data.advisories : []))
            .catch(() => setNigeriaAdvisories([]));
    }, []);

    const [clients, setClients] = useState<OnboardedClient[] | null>(null);
    const [clientsLoading, setClientsLoading] = useState(true);
    useEffect(() => {
        apiFetch(apiUrl('/api/customers'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(r => r.json())
            .then(data => { setClients(Array.isArray(data?.customers) ? data.customers : []); setCustomerCount(Array.isArray(data?.customers) ? data.customers.length : 0); })
            .catch(() => { setClients([]); setCustomerCount(0); })
            .finally(() => setClientsLoading(false));
    }, []);

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

    const servicesUp = platformHealth?.services.filter(s => s.status === 'up').length ?? 0;
    const servicesTotal = platformHealth?.services.length ?? 0;
    const platformHealthPct = platformHealth?.overall === 'operational' ? '100%' : platformHealth?.overall === 'degraded' ? `${Math.round((servicesUp / Math.max(servicesTotal, 1)) * 100)}%` : '0%';
    const platformHealthType: KpiCardProps['type'] = platformHealth?.overall === 'operational' ? 'green' : platformHealth?.overall === 'degraded' ? 'orange' : 'red';

    const kpiCards: KpiCardProps[] = [
        { label: 'Assets Monitored', value: (wazuhStatus?.agent_count ?? 0).toLocaleString(), trend: '', type: 'purple', icon: Monitor, subValue: `${wazuhStatus?.active_agents ?? 0} active` },
        { label: 'Active Incidents', value: String(incidentKpis?.total ?? 0), trend: '', type: 'orange', icon: Siren, subValue: `${incidentKpis?.critical ?? 0} critical` },
        { label: 'Critical Alerts', value: criticalAlertsCount !== null ? String(criticalAlertsCount) : '0', trend: '', type: 'red', icon: ShieldAlert, subValue: 'last 24 hours' },
        { label: 'Open Incidents', value: openIncidentsCount !== null ? String(openIncidentsCount) : '0', trend: '', type: 'orange', icon: Shield, subValue: 'last 24 hours' },
        { label: 'Clients Protected', value: customerCount !== null ? String(customerCount) : '0', trend: '', type: 'blue', icon: Building2, subValue: 'organisations' },
        { label: 'Mean Time to Detect', value: '—', trend: '', type: 'purple', icon: Timer, subValue: 'no data yet' },
        { label: 'Mean Time to Respond', value: '—', trend: '', type: 'blue', icon: Zap, subValue: 'no data yet' },
        { label: 'Platform Health', value: platformHealthPct, trend: '', type: platformHealthType, icon: Activity, subValue: `${servicesUp}/${servicesTotal} services up` },
    ];

    return (
        <div className="space-y-6">
            {/* Header bar */}
            <div className="flex items-center justify-between flex-wrap gap-3">
                <div>
                    <p className="text-xs text-foreground-muted">{new Date().toLocaleString('en-GB', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'Africa/Lagos' })} WAT</p>
                </div>
                <Link href="/admin/secops/threats" className="flex items-center gap-2 border border-border rounded-lg px-3 py-2 text-xs font-bold text-foreground-muted hover:text-foreground hover:border-grey-300 transition-colors">
                    <Bell size={14} /> {criticalAlertsCount ?? 0} critical
                </Link>
            </div>

            <IncompleteSetupPrompt clients={clients} />

            {/* Row 1: KPI cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {kpiCards.map((kpi, idx) => <KpiCard key={idx} {...kpi} />)}
            </div>

            {/* Row 2: Nigeria map (60%) + Incident queue (40%) */}
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-4 items-stretch">
                <div className="lg:col-span-5"><NigeriaThreatMap advisories={nigeriaAdvisories} /></div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-5 gap-4 items-stretch">
                 <div className="lg:col-span-5"><IncidentQueueWidget incidents={incidentQueue} loading={incidentsLoading} /></div>
            </div>

            {/* Row 3: MITRE (40%) + Threat Intel (60%) */}
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-4 items-stretch">
                <div className="lg:col-span-2"><MITREWidget tactics={mitreTactics} source={mitreSource} /></div>
                <div className="lg:col-span-3"><ThreatIntelWidget ctiStats={ctiStats} orgCti={orgCti} /></div>
            </div>

            {/* Row 4: SOAR (50%) + Compliance (50%) */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 items-stretch">
                <SOARWidget />
                <ComplianceWidget frameworks={frameworks} loading={frameworksLoading} />
            </div>

            {/* Row 5: Recent alerts feed */}
            <AlertsFeed alerts={feedAlerts} source={feedSource} loading={feedLoading} />

            {/* Supplementary — kept from the previous dashboard, still real data */}
            <GlobalThreatMap />

            <OnboardedClientsWidget clients={clients} loading={clientsLoading} />

            <ChartWrapper title="Security Posture & Incident Activity Trends">
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
