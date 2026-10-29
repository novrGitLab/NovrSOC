'use client';

import { useState, useEffect, useCallback, useSyncExternalStore } from 'react';
import Link from 'next/link';
import {
    Monitor, Siren, ShieldAlert, Shield, Clock, Laptop, Server, ChevronRight, Building2, Activity,
    CheckCircle, Bell, ClipboardCheck, Bug, Target, Flame, Bot, ListChecks,
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RTooltip, Legend, ResponsiveContainer } from 'recharts';
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
import { buildPriorityItems, filterMyCases, priorityFailedSources as computePriorityFailedSources, type PriorityItem } from '@/lib/priorityQueue';

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

const WidgetCard = ({ title, icon: Icon, linkHref, linkLabel, children }: { title: string; icon?: React.ElementType; linkHref?: string; linkLabel?: string; children: React.ReactNode }) => (
    <div className="bg-card border border-border rounded-xl p-5 h-full flex flex-col">
        <div className="flex items-center justify-between mb-4">
            <h3 className="font-bold text-sm text-foreground flex items-center gap-1.5">{Icon && <Icon size={14} className="text-foreground-muted" aria-hidden />}{title}</h3>
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
    assignedTo: string | null;
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
                <span className="text-[9px] bg-purple/10 text-purple px-2 py-0.5 rounded-full font-bold uppercase">{source === 'wazuh' ? 'Last 24h' : source === 'demo' ? 'Sample' : 'No data'}</span>
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

/* ── Priority Action Queue (R3.2) ──────────────────────────────────────────────────
 * Each item keeps its own real source and its own link — a critical/high case stays a case
 * (GET /api/cases), a pending response action stays an approval (GET /api/response-approvals),
 * an overdue finding stays a finding (GET /api/vms/findings/summary) — never merged into one
 * fabricated "incident" count. "No items" and "could not load every source" are shown
 * differently: a failed source is named, not silently folded into an empty queue. */
const QUEUE_KIND_LABEL: Record<PriorityItem['kind'], string> = { case: 'Case', approval: 'Approval', remediation: 'Overdue finding' };
const QUEUE_KIND_STYLE: Record<PriorityItem['kind'], string> = { case: 'bg-red-500/10 text-red-500', approval: 'bg-amber/10 text-amber', remediation: 'bg-orange/10 text-orange' };

function PriorityActionQueue({ items, loading, failedSources }: { items: PriorityItem[] | null; loading: boolean; failedSources: string[] }) {
    const rows = (items ?? []).slice(0, 8);
    return (
        <WidgetCard title="Priority Action Queue" icon={ListChecks}>
            {loading ? (
                <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-10 bg-card-muted rounded-lg animate-pulse" />)}</div>
            ) : rows.length === 0 ? (
                <div className="text-center py-8">
                    <CheckCircle size={20} className="text-green mx-auto mb-2" />
                    <p className="text-xs font-semibold text-foreground">Nothing needs attention right now</p>
                    <p className="text-[10px] text-foreground-muted mt-0.5">No critical cases, pending approvals, or overdue remediation.</p>
                </div>
            ) : (
                <ul className="divide-y divide-border">
                    {rows.map((item) => (
                        <li key={`${item.kind}-${item.id}`}>
                            <Link href={item.href} className="flex items-center gap-2.5 py-2 hover:bg-card-muted rounded-lg px-1 -mx-1 transition-colors">
                                <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded uppercase shrink-0 ${QUEUE_KIND_STYLE[item.kind]}`}>{QUEUE_KIND_LABEL[item.kind]}</span>
                                <div className="flex-1 min-w-0">
                                    <p className="text-xs font-semibold text-foreground truncate">{item.title}</p>
                                    <p className="text-[10px] text-foreground-muted truncate">{item.meta}</p>
                                </div>
                                {item.severity && <span className="text-[9px] font-bold uppercase text-foreground-muted shrink-0">{item.severity}</span>}
                            </Link>
                        </li>
                    ))}
                </ul>
            )}
            {failedSources.length > 0 && (
                <p className="text-[10px] text-amber mt-3 pt-3 border-t border-border flex items-center gap-1"><Flame size={10} aria-hidden /> Could not check: {failedSources.join(', ')} — the queue above may be incomplete.</p>
            )}
        </WidgetCard>
    );
}

/* ── Vulnerability & Asset Exposure (R3.2) ── GET /api/vms/overview + /api/vms/findings/summary ── */
interface VulnExposure { activeAssets: number; highRiskAssets: number; openCritical: number; openHigh: number; knownExploited: number; resolvedStates: number }
function VulnExposureWidget({ data, failure }: { data: VulnExposure | null; failure: string | null }) {
    return (
        <WidgetCard title="Vulnerability & Asset Exposure" icon={Bug} linkHref="/admin/vms/findings" linkLabel="Open VMS Findings →">
            {failure ? (
                <p className="text-xs text-foreground-muted text-center py-6">{failure}</p>
            ) : (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <div className="bg-card-muted rounded-lg p-3"><div className="text-lg font-black text-foreground">{data ? data.activeAssets.toLocaleString() : '—'}</div><div className="text-[10px] text-foreground-muted">Active assets</div></div>
                    <div className="bg-card-muted rounded-lg p-3"><div className="text-lg font-black text-orange">{data ? data.highRiskAssets.toLocaleString() : '—'}</div><div className="text-[10px] text-foreground-muted">High-risk assets</div></div>
                    <div className="bg-card-muted rounded-lg p-3"><div className="text-lg font-black text-red">{data ? (data.openCritical + data.openHigh).toLocaleString() : '—'}</div><div className="text-[10px] text-foreground-muted">Open critical + high</div></div>
                    <div className="bg-card-muted rounded-lg p-3"><div className="text-lg font-black text-purple">{data ? data.knownExploited.toLocaleString() : '—'}</div><div className="text-[10px] text-foreground-muted">Known exploited (KEV)</div></div>
                </div>
            )}
            <Link href="/admin/vms/attack-surface" className="block mt-3 pt-3 border-t border-border text-xs text-blue font-bold hover:underline">View Attack Surface →</Link>
        </WidgetCard>
    );
}

/* ── NovrAI compact entry point (R3.2) ── GET /api/novr-ai/status: a real NVIDIA/Gemini-backed
 * assistant already exists at /admin/novrail — this is a status-aware link to it, never a
 * decorative chatbot that pretends to analyse anything on its own. */
function NovrAiCard() {
    const [status, setStatus] = useState<{ configured: boolean; provider: string } | null>(null);
    useEffect(() => {
        apiFetch(apiUrl('/api/novr-ai/status'), { cache: 'no-store', signal: AbortSignal.timeout(8000) })
            .then((r) => r.json()).then((d) => setStatus({ configured: !!d?.configured, provider: d?.provider ?? 'none' })).catch(() => setStatus({ configured: false, provider: 'none' }));
    }, []);
    return (
        <Link href="/admin/novrail" className="bg-card border border-border rounded-xl p-4 flex items-center gap-3 hover:border-purple/40 transition-colors">
            <div className="w-9 h-9 rounded-lg bg-purple/10 flex items-center justify-center shrink-0"><Bot size={18} className="text-purple" aria-hidden /></div>
            <div className="flex-1 min-w-0">
                <p className="text-xs font-bold text-foreground">NovrAI Analyst</p>
                <p className="text-[10px] text-foreground-muted">{status === null ? 'Checking…' : status.configured ? `Available · ${status.provider}` : 'Not configured for this backend'}</p>
            </div>
            <ChevronRight size={14} className="text-foreground-muted shrink-0" aria-hidden />
        </Link>
    );
}

/* ── SOAR Activity Widget (Row 4, left) ──────────────────────────────────────────────
 * Every figure comes from GET /api/soar/stats (Supabase case counts).
 * This previously rendered four hardcoded values — "6 playbooks", three zeros and a 0%
 * automation rate — under a note naming a third-party workflow engine. The numbers were not
 * measured and the engine name is not something to surface in the product, so both are gone.
 * A count that can't be read renders as "—", never as 0: zero is a finding, unknown is not. */
function SOARWidget({ pendingApprovals }: { pendingApprovals: number | null }) {
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
        <WidgetCard title="SecOps & Automation" linkHref="/admin/secops/soar" linkLabel="View workflows →">
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
            {/* Every consequential action (block IP, isolate host) waits here for a manager's
             * decision — the SOAR engine (infra/soar/soar.py) requests, it never acts directly. */}
            <Link href="/admin/secops/approvals" className="flex items-center justify-between mt-3 bg-card-muted rounded-lg p-2.5 hover:bg-card transition-colors">
                <span className="text-[10px] font-semibold text-foreground-muted">Pending response approvals</span>
                <span className={`text-sm font-black ${pendingApprovals ? 'text-amber' : 'text-foreground'}`}>{pendingApprovals === null ? '—' : pendingApprovals.toLocaleString()}</span>
            </Link>
            <div className="mt-3 flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full flex-shrink-0 ${status?.engine_active ? 'bg-green' : 'bg-card-muted'}`} />
                <span className="text-[10px] text-foreground-muted">
                    {failed
                        ? 'Automation status unavailable — could not reach the backend.'
                        : status?.engine_active
                            ? 'SOAR engine active — a monitoring alert was cased in the last 24 hours.'
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
                const rows = (Array.isArray(data?.cases) ? data.cases : []) as Array<{ id: string; title: string; agent_name: string | null; severity: QueueIncident['severity']; status: string; created_at: string; rule_id: string | null; assigned_to: string | null }>;
                setIncidentQueue(rows.filter(c => c.status !== 'resolved').map(c => ({
                    id: c.id,
                    name: c.title,
                    asset: c.agent_name || '—',
                    severity: c.severity,
                    status: STATUS_LABEL[c.status] ?? 'Open',
                    openedAt: new Date(c.created_at).toLocaleString('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }),
                    ruleId: c.rule_id ?? undefined,
                    assignedTo: c.assigned_to ?? null,
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
    useEffect(() => {
        // apiFetch (lib/api.ts) reads the current organisation at call time and attaches it as
        // X-Org-Id, so this call is always correctly scoped — but without `org` in this effect's
        // deps it never re-ran on a switch, leaving the previous organisation's feed on screen
        // until the next 60s poll.
        void loadFeed();
    }, [loadFeed, org]);
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

    // Response approvals (phase P3, services/responseApprovals.ts) — consequential actions already
    // wait for a manager's decision before anything happens; this is a read of that existing queue,
    // not a new approval model. Feeds both the SOAR widget's count and the priority queue below.
    const [approvals, setApprovals] = useState<{ id: string; action: string; target: string; target_label: string | null; requested_at: string }[] | null>(null);
    const [approvalsFailed, setApprovalsFailed] = useState(false);
    useEffect(() => {
        apiFetch(apiUrl('/api/response-approvals?status=pending'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(async (r) => { const d = await r.json(); if (!r.ok) throw new Error(d?.error ?? `HTTP ${r.status}`); return d; })
            .then((d) => { setApprovals(Array.isArray(d?.approvals) ? d.approvals : []); setApprovalsFailed(false); })
            .catch(() => { setApprovals(null); setApprovalsFailed(true); });
    }, [org]);

    // Overdue remediation (GET /api/vms/findings?overdue=true, phase P5) — findings past their due
    // date and still open. Used both for the KPI count and the priority queue's individual rows.
    const [overdueFindings, setOverdueFindings] = useState<{ id: string; title: string; asset_value: string | null; scanner_severity: PriorityItem['severity']; priority: string | null }[] | null>(null);
    const [overdueFindingsFailed, setOverdueFindingsFailed] = useState(false);
    useEffect(() => {
        apiFetch(apiUrl('/api/vms/findings?overdue=true&status=open_all'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(async (r) => { const d = await r.json(); if (!r.ok) throw new Error(d?.error ?? `HTTP ${r.status}`); return d; })
            .then((d) => { setOverdueFindings(Array.isArray(d?.findings) ? d.findings : []); setOverdueFindingsFailed(false); })
            .catch(() => { setOverdueFindings(null); setOverdueFindingsFailed(true); });
    }, [org]);

    // Vulnerability & asset exposure (GET /api/vms/overview + /api/vms/findings/summary, phases P14/P5)
    // — both already-built, already org-scoped VMS endpoints; combined client-side, nothing new
    // on the backend. A failure on either leaves the whole card "—" rather than half-populated.
    const [vulnExposure, setVulnExposure] = useState<VulnExposure | null>(null);
    const [vulnExposureFailure, setVulnExposureFailure] = useState<string | null>(null);
    // The authoritative overdue total (findings/summary.overdue) — distinct from overdueFindings
    // below, which lists up to 1000 rows for the queue and would under-count on a very large org.
    const [overdueTotal, setOverdueTotal] = useState<number | null>(null);
    useEffect(() => {
        const get = (path: string) => apiFetch(apiUrl(path), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(async (r) => { const d = await r.json(); if (!r.ok) throw new Error(d?.error ?? `HTTP ${r.status}`); return d; });
        Promise.all([get('/api/vms/overview'), get('/api/vms/findings/summary')])
            .then(([overview, summary]) => {
                setVulnExposure({
                    activeAssets: overview?.assets?.active ?? 0,
                    highRiskAssets: overview?.high_risk_assets ?? 0,
                    openCritical: summary?.by_severity?.critical ?? 0,
                    openHigh: summary?.by_severity?.high ?? 0,
                    knownExploited: summary?.known_exploited_open ?? 0,
                    resolvedStates: summary?.by_status?.resolved ?? 0,
                });
                setOverdueTotal(typeof summary?.overdue === 'number' ? summary.overdue : null);
                setVulnExposureFailure(null);
            })
            .catch((e: unknown) => { setVulnExposure(null); setOverdueTotal(null); setVulnExposureFailure(e instanceof Error ? e.message : 'VMS is not available for this organisation'); });
    }, [org]);

    // "My Cases" — client-side filter of the already-fetched queue, not a separate backend call.
    const [myCasesOnly, setMyCasesOnly] = useState(false);
    const [currentUserName] = useState<string>(() => (typeof window === 'undefined' ? '' : getAdminUser().name));

    const [trendData, setTrendData] = useState<{ label: string; alerts: number; incidents: number; critical: number }[] | null>(null);
    // Distinct from trendData === null: an empty-but-successful response means zero alerts in
    // every bucket for this range (a real "nothing happened"), not that the trend couldn't be
    // read. The two used to be conflated (both rendered as the same "no data" message) — fixed
    // so a genuine outage/unreachable-backend reads differently from a quiet period.
    const [trendError, setTrendError] = useState<string | null>(null);
    const [trendLoading, setTrendLoading] = useState(true);
    const [trendRange, setTrendRange] = useState<'24h' | '7d' | '30d'>('7d');
    useEffect(() => {
        // This is org-scoped (scopeOf(req) in routes/wazuh.ts); `org` was missing from the deps
        // below, so switching organisation left the previous organisation's trend bars on screen
        // until the range buttons were next clicked.
        apiFetch(apiUrl(`/api/wazuh/trend?range=${trendRange}`), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(async (r) => {
                const data = await r.json().catch(() => null);
                if (!r.ok) { setTrendData(null); setTrendError((data && typeof data === 'object' && 'error' in data ? String(data.error) : null) ?? `HTTP ${r.status}`); return; }
                if (!Array.isArray(data)) { setTrendData(null); setTrendError('Unexpected response shape'); return; }
                setTrendData(data); // kept even when empty — an empty array is a real answer, not an error
                setTrendError(null);
            })
            .catch(() => { setTrendData(null); setTrendError('Could not reach the backend'); })
            .finally(() => setTrendLoading(false));
    }, [trendRange, org]);

    // Org switch: reset every organisation-scoped widget's state in the same render that notices
    // the change — not inside an effect, which would commit one frame of the previous
    // organisation's data before the reset took effect. This is React's documented pattern for
    // "adjusting state when a prop changes" (react.dev/learn/you-might-not-need-an-effect).
    const [resetForOrg, setResetForOrg] = useState(org);
    if (resetForOrg !== org) {
        setResetForOrg(org);
        setWazuhStatus(null);
        setAlertStats(null);
        setAlertsState({ loaded: false, notConnected: false, error: null });
        setIncidentKpis(null);
        setIncidentsFailed(false);
        setIncidentQueue(null);
        setIncidentsLoading(true);
        setMitreTactics(null);
        setMitreSource(null);
        setTi(null);
        setTiFailure(null);
        setFrameworks(null);
        setFrameworksLoading(true);
        setFrameworksFailure(null);
        setFeedAlerts([]);
        setFeedFailure(null);
        setFeedLoading(true);
        setClients(null);
        setClientsLoading(true);
        setCustomerCount(null);
        setCustomersFailed(false);
        setApprovals(null);
        setApprovalsFailed(false);
        setOverdueFindings(null);
        setOverdueFindingsFailed(false);
        setVulnExposure(null);
        setOverdueTotal(null);
        setVulnExposureFailure(null);
        setTrendData(null);
        setTrendError(null);
        setTrendLoading(true);
    }

    const health = platformHealthDisplay(isSuperAdmin, platformHealth);
    const openCases = openCasesDisplay(incidentKpis, incidentsFailed);
    const clientsProtected = honestCountDisplay(customerCount, customersFailed, 'organisations');

    const criticalAlertsCount = alertStats ? alertStats.by_severity.critical : null;
    const level7PlusCount = alertStats ? alertStats.by_severity.critical + alertStats.by_severity.high + alertStats.by_severity.medium : null;
    const alertsUnavailable = !alertsState.loaded ? 'checking…' : alertsState.notConnected ? 'not connected' : 'unavailable';

    // Priority Action Queue composition (src/lib/priorityQueue.ts, unit-tested there): critical/high
    // cases + pending response approvals + overdue remediation, kept as distinct, labelled rows
    // (never merged into one fabricated count). Every source here was already fetched above for
    // its own widget/KPI — nothing here issues an extra request. "My Cases" filters the case
    // queue (both here and the case widget below) the same way.
    const isManagerPlus = role === 'super_admin' || role === 'soc_manager';
    const casesForQueue = filterMyCases(incidentQueue, myCasesOnly, currentUserName);
    const priorityItemsFailedSources = computePriorityFailedSources(incidentsFailed, approvalsFailed, overdueFindingsFailed);
    const priorityItems: PriorityItem[] | null = (incidentsFailed && approvalsFailed && overdueFindingsFailed)
        ? null
        : buildPriorityItems(casesForQueue, approvals, overdueFindings, watTime);
    const priorityLoading = incidentsLoading || (approvals === null && !approvalsFailed) || (overdueFindings === null && !overdueFindingsFailed);

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
        {
            label: 'Pending Approvals', value: approvals ? String(approvals.length) : '—', trend: '', type: 'purple', icon: ClipboardCheck,
            subValue: approvals ? 'awaiting a decision' : approvalsFailed ? 'could not check' : 'checking…',
        },
        {
            label: 'Overdue Remediation', value: overdueTotal !== null ? String(overdueTotal) : '—', trend: '', type: 'red', icon: Target,
            subValue: overdueTotal !== null ? 'past due, still open' : vulnExposureFailure ? 'could not check' : 'checking…',
        },
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

            {/* Threat Intelligence — Nigeria map and the TI summary widget, both preserved as before */}
            <SectionHeader title="Threat Intelligence" />
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-4 items-stretch">
                <div className="lg:col-span-5"><DashboardNigeriaMap /></div>
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-4 items-stretch">
                <div className="lg:col-span-2"><MITREWidget tactics={mitreTactics} source={mitreSource} /></div>
                <div className="lg:col-span-3"><ThreatIntelWidget ti={ti} failure={tiFailure} /></div>
            </div>

            {/* Priority Action Queue (left) + Case queue (right), with an analyst-only "My Cases" filter */}
            <SectionHeader title="Priority Action Queue & Case Status" />
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-4 items-stretch">
                <div className="lg:col-span-2"><PriorityActionQueue items={priorityItems} loading={priorityLoading} failedSources={priorityItemsFailedSources} /></div>
                <div className="lg:col-span-3">
                    {role === 'analyst' && (
                        <div className="flex justify-end mb-2">
                            <button onClick={() => setMyCasesOnly((v) => !v)}
                                className={`text-[10px] font-bold px-2.5 py-1 rounded border transition-colors ${myCasesOnly ? 'bg-grey-100 text-white border-amber' : 'bg-card border-border text-foreground-muted hover:text-foreground'}`}>
                                My Cases Only
                            </button>
                        </div>
                    )}
                    <IncidentQueueWidget incidents={casesForQueue} loading={incidentsLoading} />
                </div>
            </div>

            {/* Vulnerability & Asset Exposure */}
            <SectionHeader title="Vulnerability & Asset Exposure" />
            <VulnExposureWidget data={vulnExposure} failure={vulnExposureFailure} />

            {/* SecOps & Automation (50%) + Compliance (50%) */}
            <SectionHeader title="SecOps, Automation & Compliance" />
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 items-stretch">
                <SOARWidget pendingApprovals={approvals ? approvals.length : null} />
                <ComplianceWidget frameworks={frameworks} loading={frameworksLoading} failure={frameworksFailure} />
            </div>

            {/* NovrAI entry point — only the status-aware link to the real, already-built assistant */}
            <NovrAiCard />

            {/* Recent alerts feed */}
            <AlertsFeed alerts={feedAlerts} failure={feedFailure} loading={feedLoading} />

            {isManagerPlus && (
                <OnboardedClientsWidget clients={clients} loading={clientsLoading} failure={customersFailed ? 'Client list unavailable' : null} />
            )}

            <ChartWrapper title="Security Posture & Alert Activity Trends" live={!trendError}>
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
                ) : trendError ? (
                    <div className="w-full h-full flex items-center justify-center">
                        <p className="text-xs text-red font-semibold">Trend data unavailable: {trendError}</p>
                    </div>
                ) : !trendData || trendData.length === 0 ? (
                    <div className="w-full h-full flex items-center justify-center">
                        <p className="text-xs text-foreground-muted">No alerts recorded in this range — a real zero, not a failed read.</p>
                    </div>
                ) : (
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={trendData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                            <XAxis dataKey="label" tick={{ fill: 'var(--foreground-muted)', fontSize: 10 }} tickLine={false} axisLine={{ stroke: 'var(--border)' }} />
                            <YAxis allowDecimals={false} tick={{ fill: 'var(--foreground-muted)', fontSize: 10 }} tickLine={false} axisLine={false} width={32} />
                            <RTooltip contentStyle={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 11 }} />
                            <Legend wrapperStyle={{ fontSize: 10 }} />
                            {/* Grouped, not stacked: incidents/critical are sub-counts within alerts (not
                                disjoint), so stacking them would double-count and misrepresent the total. */}
                            <Bar dataKey="alerts" name="Alerts" fill="#D97706" radius={[2, 2, 0, 0]} isAnimationActive={false} />
                            <Bar dataKey="incidents" name="High severity" fill="#F59E0B" radius={[2, 2, 0, 0]} isAnimationActive={false} />
                            <Bar dataKey="critical" name="Critical" fill="#EF4444" radius={[2, 2, 0, 0]} isAnimationActive={false} />
                        </BarChart>
                    </ResponsiveContainer>
                )}
            </ChartWrapper>
        </div>
    );
};
