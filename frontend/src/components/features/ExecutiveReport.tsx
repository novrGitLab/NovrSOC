'use client';

import { useState, useEffect } from 'react';
import { apiUrl, apiFetch } from '@/lib/api';
import { exportPageAsPDF } from '@/lib/exportPDF';

// Board/CISO-facing summary — real data only, composed from endpoints already built
// elsewhere (compliance, cases, alerts, Wazuh agents). No fabricated "Overall Score: 74" or "vs last
// month" trend arrow — this backend has no historical snapshot mechanism to compare against,
// so a trend number here would be invented, not measured. The overall score is a genuine
// average of assessed compliance frameworks; "Not yet assessed" is the honest state until at
// least one framework has real control assessments.

interface Framework { shortName: string; score: number; assessed: number }
interface CaseKpis { active: number; critical: number }
interface AgentCounts { total: number; active: number; disconnected: number }

export function ExecutiveReport() {
    const [frameworks, setFrameworks] = useState<Framework[] | null>(null);
    const [caseKpis, setCaseKpis] = useState<CaseKpis | null>(null);
    const [agents, setAgents] = useState<AgentCounts | null>(null);
    const [criticalAlerts, setCriticalAlerts] = useState<number | null>(null);
    const [customerCount, setCustomerCount] = useState<number | null>(null);

    useEffect(() => {
        apiFetch(apiUrl('/api/compliance?orgId=1'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then((r) => r.json()).then((d) => setFrameworks(Array.isArray(d) ? d : [])).catch(() => setFrameworks([]));
        apiFetch(apiUrl('/api/cases?limit=1'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then((r) => r.json()).then((d) => setCaseKpis(d?.summary ? { active: d.summary.active, critical: d.summary.critical } : null)).catch(() => setCaseKpis(null));
        // Endpoint counts from the Wazuh manager — the same source as every other agent figure.
        // An unreachable manager leaves this null ("—"), not 0: zero endpoints is a finding.
        apiFetch(apiUrl('/api/wazuh/status'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then((r) => r.json())
            .then((d) => setAgents(d?.connected ? { total: d.agent_count ?? 0, active: d.active_agents ?? 0, disconnected: d.disconnected_agents ?? 0 } : null))
            .catch(() => setAgents(null));
        apiFetch(apiUrl('/api/wazuh/alerts-indexer?minLevel=7&range=24h'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then((r) => r.json()).then((d) => setCriticalAlerts(typeof d?.criticalCount === 'number' ? d.criticalCount : 0)).catch(() => setCriticalAlerts(0));
        apiFetch(apiUrl('/api/customers'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then((r) => r.json()).then((d) => setCustomerCount(Array.isArray(d?.customers) ? d.customers.length : 0)).catch(() => setCustomerCount(0));
    }, []);

    const assessedFrameworks = frameworks?.filter((f) => f.assessed > 0) ?? [];
    const overallScore = assessedFrameworks.length > 0 ? Math.round(assessedFrameworks.reduce((s, f) => s + f.score, 0) / assessedFrameworks.length) : null;
    const scoreLabel = overallScore === null ? '—' : String(overallScore);
    const scoreQualifier = overallScore === null ? 'Not yet assessed' : overallScore >= 80 ? 'Strong' : overallScore >= 60 ? 'Good' : overallScore >= 40 ? 'Needs attention' : 'At risk';

    return (
        <div id="executive-report" className="space-y-6">
            <div>
                <h1 className="text-2xl font-black text-foreground">Executive Security Report</h1>
                <p className="text-sm text-foreground-muted">
                    {new Date().toLocaleDateString('en-GB', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })} — Cybernovr Security Posture
                </p>
            </div>

            <div className="rounded-2xl p-8 text-white" style={{ background: 'linear-gradient(135deg, #520385, #2B3BCC)' }}>
                <div className="flex items-center justify-between flex-wrap gap-4">
                    <div>
                        <div className="text-sm font-medium opacity-80 mb-2">Overall Security Score</div>
                        <div className="text-7xl font-black">{scoreLabel}{overallScore !== null && <span className="text-2xl font-normal opacity-70">/100</span>}</div>
                        <div className="text-sm opacity-80 mt-2">{scoreQualifier}</div>
                    </div>
                    <div className="text-right">
                        <div className="text-xs opacity-70">Based on {assessedFrameworks.length} assessed framework{assessedFrameworks.length === 1 ? '' : 's'}</div>
                        <div className="text-xs opacity-70 mt-1">No historical trend data available yet</div>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                {[
                    { label: 'Endpoints Monitored', value: agents?.total ?? '—', sub: agents ? `${agents.active} online · ${agents.disconnected} offline` : 'Wazuh unreachable' },
                    { label: 'Open Cases', value: caseKpis?.active ?? '—' },
                    { label: 'Critical Cases (open)', value: caseKpis?.critical ?? '—' },
                    { label: 'Critical Alerts (24h)', value: criticalAlerts ?? '—' },
                    { label: 'Clients Protected', value: customerCount ?? '—' },
                ].map((s) => (
                    <div key={s.label} className="bg-card border border-border rounded-xl p-5">
                        <div className="text-3xl font-black text-foreground">{s.value}</div>
                        <div className="text-xs text-foreground-muted mt-1">{s.label}</div>
                        {'sub' in s && s.sub && <div className="text-[10px] text-foreground-muted/80 mt-0.5">{s.sub}</div>}
                    </div>
                ))}
            </div>

            <div className="bg-card border border-border rounded-xl p-5">
                <h2 className="font-bold text-sm text-foreground mb-4">Compliance Posture</h2>
                {frameworks === null ? (
                    <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-6 bg-card-muted rounded animate-pulse" />)}</div>
                ) : (
                    <div className="space-y-3">
                        {frameworks.map((f) => (
                            <div key={f.shortName}>
                                <div className="flex justify-between items-center mb-1">
                                    <span className="text-xs font-medium text-foreground">{f.shortName}</span>
                                    <span className="text-xs font-bold text-foreground">{f.assessed > 0 ? `${f.score}%` : 'Not assessed'}</span>
                                </div>
                                <div className="bg-card-muted rounded-full h-2"><div className="h-2 rounded-full bg-purple" style={{ width: `${f.score}%` }} /></div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            <div className="bg-card border border-border rounded-xl p-5">
                <h2 className="font-bold text-sm text-foreground mb-2">Top Risks</h2>
                {caseKpis === null ? (
                    <p className="text-xs text-foreground-muted">Case data unavailable.</p>
                ) : caseKpis.critical > 0 ? (
                    <p className="text-xs text-foreground-muted">{caseKpis.critical} critical-severity case{caseKpis.critical === 1 ? '' : 's'} open — see Cases for detail.</p>
                ) : (
                    <p className="text-xs text-foreground-muted">No critical cases open.</p>
                )}
                {agents && agents.disconnected > 0 && (
                    <p className="text-xs text-foreground-muted mt-1">{agents.disconnected} endpoint{agents.disconnected === 1 ? ' is' : 's are'} offline and not currently monitored.</p>
                )}
            </div>

            <button onClick={() => exportPageAsPDF('executive-report', 'executive-security-report', 'Executive Security Report')}
                className="bg-orange hover:bg-orange-hover text-white text-sm font-bold px-5 py-2.5 rounded-xl transition-colors">
                Export as PDF
            </button>
        </div>
    );
}
