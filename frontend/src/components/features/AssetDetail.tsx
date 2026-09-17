'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { ArrowLeft, Server, ShieldAlert, Package, Siren, Network, ClipboardCheck } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Asset detail — everything NovrSOC knows about one Wazuh agent.
//
// Each tab is backed by a different system, which is why they load independently rather than in
// one request: the agent record and packages come from the Wazuh Manager REST API, while
// vulnerabilities and alerts come from the Wazuh indexer. Those fail separately in practice (a
// real split confirmed on this deployment — the Manager on :55000 answering while the indexer on
// :9200 was unreachable), so one tab showing an error must not blank the other five.

interface Agent {
    id: string;
    name: string;
    ip: string | null;
    status: string;
    lastSeen?: string | null;
    lastKeepAlive?: string | null;
    os: string | { name?: string; full?: string; version?: string; arch?: string } | null;
    group?: string | string[];
    version?: string;
    manager?: string;
    dateAdd?: string;
    node_name?: string;
}

interface Vulnerability {
    cve: string;
    title: string;
    severity: string;
    cvss_score: number | null;
    package: string;
    version: string;
    fix: string;
    status: string;
}

interface ComplianceControl { framework: string; control: string; status: string; rationale: string }
interface ComplianceSummary {
    frameworks: Record<string, { failing: number; at_risk: number; controls: ComplianceControl[] }>;
    overall_impact: string;
    unmapped: number;
    note: string;
}

interface Pkg { name: string; version: string; architecture: string | null; vendor: string | null }
interface AgentAlert {
    id: string; timestamp: string; description: string; level: number;
    rule_id: string; severity: string; mitre_tactic: string | null; mitre_id: string | null; source_ip: string | null;
}

const TABS = [
    { id: 'overview', label: 'Overview', icon: Server },
    { id: 'vulns', label: 'Vulnerabilities', icon: ShieldAlert },
    { id: 'packages', label: 'Packages', icon: Package },
    { id: 'alerts', label: 'Recent Alerts', icon: Siren },
    { id: 'network', label: 'Network', icon: Network },
    { id: 'compliance', label: 'Compliance Impact', icon: ClipboardCheck },
] as const;
type TabId = (typeof TABS)[number]['id'];

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const SEVERITY_STYLE: Record<string, string> = {
    critical: 'bg-red-500/10 text-red-500 border-red-500/30',
    high: 'bg-orange/10 text-orange border-orange/30',
    medium: 'bg-amber-500/10 text-amber-500 border-amber-500/30',
    low: 'bg-card-muted text-foreground-muted border-border',
};

function osLabel(os: Agent['os']): string {
    if (!os) return 'Unknown';
    if (typeof os === 'string') return os;
    return os.full ?? os.name ?? 'Unknown';
}

function fmt(value: string | null | undefined): string {
    if (!value) return '—';
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? value : d.toLocaleString('en-GB', { timeZone: 'Africa/Lagos' }) + ' WAT';
}

export function AssetDetail({ agentId }: { agentId: string }) {
    const [tab, setTab] = useState<TabId>('overview');
    const [agent, setAgent] = useState<Agent | null>(null);
    const [agentError, setAgentError] = useState<string | null>(null);

    const [vulns, setVulns] = useState<Vulnerability[] | null>(null);
    const [compliance, setCompliance] = useState<ComplianceSummary | null>(null);
    const [vulnError, setVulnError] = useState<string | null>(null);

    const [packages, setPackages] = useState<Pkg[] | null>(null);
    const [pkgError, setPkgError] = useState<string | null>(null);

    const [alerts, setAlerts] = useState<AgentAlert[] | null>(null);
    const [alertError, setAlertError] = useState<string | null>(null);

    const get = useCallback((path: string) =>
        apiFetch(apiUrl(path), { cache: 'no-store' }).then(async (r) => {
            const json = await r.json();
            if (!r.ok) throw new Error(json?.error ?? `HTTP ${r.status}`);
            return json;
        }), []);

    useEffect(() => {
        get(`/api/wazuh/agents/${encodeURIComponent(agentId)}`)
            .then((d) => setAgent(d.agent ?? null))
            .catch((e) => setAgentError(e instanceof Error ? e.message : 'Agent unavailable'));

        get(`/api/wazuh/agents/${encodeURIComponent(agentId)}/vulnerabilities`)
            .then((d) => {
                setVulns(Array.isArray(d.vulnerabilities) ? d.vulnerabilities : []);
                setCompliance(d.compliance ?? null);
                // The route answers 200 with an `error` field when the index is unreachable, so
                // the other tabs survive — surface that rather than showing an empty list as if
                // the agent were clean.
                if (d.error) setVulnError(d.error);
            })
            .catch((e) => { setVulns([]); setVulnError(e instanceof Error ? e.message : 'Unavailable'); });

        get(`/api/wazuh/agents/${encodeURIComponent(agentId)}/packages`)
            .then((d) => { setPackages(Array.isArray(d.packages) ? d.packages : []); if (d.error) setPkgError(d.error); })
            .catch((e) => { setPackages([]); setPkgError(e instanceof Error ? e.message : 'Unavailable'); });

        get(`/api/wazuh/agents/${encodeURIComponent(agentId)}/alerts?limit=20`)
            .then((d) => { setAlerts(Array.isArray(d.alerts) ? d.alerts : []); if (d.error) setAlertError(d.error); })
            .catch((e) => { setAlerts([]); setAlertError(e instanceof Error ? e.message : 'Unavailable'); });
    }, [agentId, get]);

    // Packages carrying a known CVE on this agent, so the Packages tab can flag them. Matched on
    // exact package name as reported by both systems — a substring match would flag 'openssl' for
    // a CVE in 'openssl-legacy' and overstate the finding.
    const vulnerablePackages = new Set((vulns ?? []).map((v) => v.package).filter(Boolean));

    const sortedVulns = [...(vulns ?? [])].sort((a, b) => {
        const sa = SEVERITY_ORDER[a.severity?.toLowerCase()] ?? 9;
        const sb = SEVERITY_ORDER[b.severity?.toLowerCase()] ?? 9;
        if (sa !== sb) return sa - sb;
        return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
    });

    const frameworks = Object.entries(compliance?.frameworks ?? {});

    return (
        <div className="space-y-4">
            <Link href="/admin/infra/assets" className="flex items-center gap-1.5 text-xs font-bold text-blue hover:text-purple transition-colors w-fit">
                <ArrowLeft size={14} /> Back to Asset Inventory
            </Link>

            {/* Header */}
            <div className="bg-card border border-border rounded-xl p-5">
                {agentError ? (
                    <p className="text-sm text-red-500">Could not load this agent: {agentError}</p>
                ) : !agent ? (
                    <div className="h-14 bg-card-muted rounded animate-pulse" />
                ) : (
                    <div className="flex items-start justify-between gap-4 flex-wrap">
                        <div className="min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                                <h1 className="text-xl font-black text-foreground">{agent.name}</h1>
                                <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border uppercase ${
                                    agent.status === 'active' ? 'bg-blue/10 text-blue border-blue/30' : 'bg-card-muted text-foreground-muted border-border'
                                }`}>
                                    {agent.status}
                                </span>
                            </div>
                            <p className="text-xs text-foreground-muted mt-1 font-mono">
                                ID {agent.id} · {agent.ip ?? 'no IP'} · {osLabel(agent.os)}
                            </p>
                        </div>
                        <div className="text-right">
                            <p className="text-[10px] text-foreground-muted uppercase tracking-wider">Last seen</p>
                            <p className="text-xs font-bold text-foreground">{fmt(agent.lastSeen ?? agent.lastKeepAlive)}</p>
                        </div>
                    </div>
                )}
            </div>

            {/* Tabs */}
            <div className="flex gap-1 bg-card-muted rounded-lg p-1 w-fit overflow-x-auto max-w-full">
                {TABS.map((t) => {
                    const Icon = t.icon;
                    const badge = t.id === 'vulns' ? (vulns?.length ?? null) : t.id === 'alerts' ? (alerts?.length ?? null) : null;
                    return (
                        <button key={t.id} onClick={() => setTab(t.id)}
                            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-bold transition-colors whitespace-nowrap ${
                                tab === t.id ? 'bg-card text-purple shadow-sm' : 'text-foreground-muted hover:text-foreground'
                            }`}>
                            <Icon size={13} />
                            {t.label}
                            {badge !== null && badge > 0 && (
                                <span className="text-[9px] bg-red-500/10 text-red-500 px-1.5 rounded-full">{badge}</span>
                            )}
                        </button>
                    );
                })}
            </div>

            <div className="bg-card border border-border rounded-xl p-5">
                {tab === 'overview' && (
                    !agent ? <p className="text-xs text-foreground-muted">Loading…</p> : (
                        <div className="space-y-4">
                            <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-xs">
                                {[
                                    ['Hostname', agent.name],
                                    ['Agent ID', agent.id],
                                    ['IP address', agent.ip ?? '—'],
                                    ['Operating system', osLabel(agent.os)],
                                    ['Architecture', typeof agent.os === 'object' && agent.os?.arch ? agent.os.arch : '—'],
                                    ['Agent version', agent.version ?? '—'],
                                    ['Group', Array.isArray(agent.group) ? agent.group.join(', ') : (agent.group ?? 'default')],
                                    ['Manager', agent.manager ?? '—'],
                                    ['Enrolled', fmt(agent.dateAdd)],
                                ].map(([k, v]) => (
                                    <div key={String(k)}>
                                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{k}</p>
                                        <p className="text-foreground font-medium mt-0.5 break-all">{v}</p>
                                    </div>
                                ))}
                            </div>
                            <div className="border-t border-border pt-4 grid grid-cols-2 md:grid-cols-4 gap-3">
                                {[
                                    { label: 'Vulnerabilities', value: vulns?.length ?? null, tone: (vulns?.length ?? 0) > 0 ? 'text-red-500' : 'text-foreground' },
                                    { label: 'Packages', value: packages?.length ?? null, tone: 'text-foreground' },
                                    { label: 'Recent alerts', value: alerts?.length ?? null, tone: 'text-foreground' },
                                    { label: 'Compliance', value: null, tone: 'text-foreground', text: compliance?.overall_impact ?? '—' },
                                ].map((s) => (
                                    <div key={s.label} className="bg-card-muted/50 border border-border rounded-xl p-3">
                                        <div className={`text-lg font-black ${s.tone}`}>{s.text ?? (s.value === null ? '—' : s.value)}</div>
                                        <div className="text-[10px] text-foreground-muted mt-0.5">{s.label}</div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )
                )}

                {tab === 'vulns' && (
                    vulnError ? <p className="text-xs text-amber">{vulnError}</p>
                        : vulns === null ? <p className="text-xs text-foreground-muted">Loading…</p>
                            : sortedVulns.length === 0 ? <p className="text-xs text-foreground-muted">No vulnerabilities recorded for this agent. Wazuh&apos;s vulnerability detector must be enabled and have completed a scan for results to appear.</p>
                                : (
                                    <div className="overflow-x-auto scrollbar-thin">
                                        <table className="w-full text-left text-xs">
                                            <thead>
                                                <tr className="border-b border-border">
                                                    {['CVE', 'Severity', 'CVSS', 'Package', 'Version', 'Fix', 'Status'].map((c) => (
                                                        <th key={c} className="py-2 pr-4 text-[10px] font-semibold text-foreground-muted uppercase tracking-widest whitespace-nowrap">{c}</th>
                                                    ))}
                                                </tr>
                                            </thead>
                                            <tbody className="divide-y divide-border">
                                                {sortedVulns.map((v, i) => (
                                                    <tr key={`${v.cve}-${i}`}>
                                                        <td className="py-2 pr-4 font-mono text-foreground whitespace-nowrap">{v.cve || '—'}</td>
                                                        <td className="py-2 pr-4">
                                                            <span className={`text-[9px] font-black px-2 py-0.5 rounded-full border uppercase ${SEVERITY_STYLE[v.severity?.toLowerCase()] ?? SEVERITY_STYLE.low}`}>
                                                                {v.severity}
                                                            </span>
                                                        </td>
                                                        <td className="py-2 pr-4 text-foreground-muted">{v.cvss_score ?? '—'}</td>
                                                        <td className="py-2 pr-4 text-foreground">{v.package || '—'}</td>
                                                        <td className="py-2 pr-4 text-foreground-muted font-mono">{v.version || '—'}</td>
                                                        <td className="py-2 pr-4 text-foreground-muted">{v.fix || '—'}</td>
                                                        <td className="py-2 text-foreground-muted">{v.status}</td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                )
                )}

                {tab === 'packages' && (
                    pkgError ? <p className="text-xs text-amber">{pkgError}</p>
                        : packages === null ? <p className="text-xs text-foreground-muted">Loading…</p>
                            : packages.length === 0 ? <p className="text-xs text-foreground-muted">No package inventory available for this agent.</p>
                                : (
                                    <>
                                        <p className="text-[11px] text-foreground-muted mb-3">
                                            {packages.length} packages · {vulnerablePackages.size > 0
                                                ? `${packages.filter((p) => vulnerablePackages.has(p.name)).length} with a known CVE on this agent (highlighted)`
                                                : 'no package on this agent currently maps to a known CVE'}
                                        </p>
                                        <div className="overflow-x-auto scrollbar-thin max-h-[520px]">
                                            <table className="w-full text-left text-xs">
                                                <thead className="sticky top-0 bg-card">
                                                    <tr className="border-b border-border">
                                                        {['Package', 'Version', 'Architecture', 'Vendor'].map((c) => (
                                                            <th key={c} className="py-2 pr-4 text-[10px] font-semibold text-foreground-muted uppercase tracking-widest whitespace-nowrap">{c}</th>
                                                        ))}
                                                    </tr>
                                                </thead>
                                                <tbody className="divide-y divide-border">
                                                    {packages.map((p, i) => {
                                                        const vulnerable = vulnerablePackages.has(p.name);
                                                        return (
                                                            <tr key={`${p.name}-${i}`} className={vulnerable ? 'bg-red-500/5' : ''}>
                                                                <td className={`py-2 pr-4 ${vulnerable ? 'text-red-500 font-bold' : 'text-foreground'}`}>{p.name}</td>
                                                                <td className="py-2 pr-4 font-mono text-foreground-muted">{p.version}</td>
                                                                <td className="py-2 pr-4 text-foreground-muted">{p.architecture ?? '—'}</td>
                                                                <td className="py-2 text-foreground-muted truncate max-w-[220px]" title={p.vendor ?? ''}>{p.vendor ?? '—'}</td>
                                                            </tr>
                                                        );
                                                    })}
                                                </tbody>
                                            </table>
                                        </div>
                                    </>
                                )
                )}

                {tab === 'alerts' && (
                    alertError ? <p className="text-xs text-amber">{alertError}</p>
                        : alerts === null ? <p className="text-xs text-foreground-muted">Loading…</p>
                            : alerts.length === 0 ? <p className="text-xs text-foreground-muted">No alerts indexed for this agent.</p>
                                : (
                                    <div className="space-y-2">
                                        {alerts.map((a) => (
                                            <div key={a.id} className="border border-border rounded-xl p-3">
                                                <div className="flex items-start justify-between gap-3 flex-wrap">
                                                    <div className="min-w-0">
                                                        <div className="flex items-center gap-2 flex-wrap mb-1">
                                                            <span className={`text-[9px] font-black px-2 py-0.5 rounded-full border uppercase ${SEVERITY_STYLE[a.severity] ?? SEVERITY_STYLE.low}`}>
                                                                {a.severity}
                                                            </span>
                                                            <span className="text-[10px] text-foreground-muted">Level {a.level} · Rule {a.rule_id}</span>
                                                            {a.mitre_id && <span className="text-[9px] bg-purple/10 text-purple px-1.5 py-0.5 rounded-full">{a.mitre_id}</span>}
                                                        </div>
                                                        <p className="text-xs text-foreground">{a.description}</p>
                                                        {a.source_ip && <p className="text-[10px] text-foreground-muted font-mono mt-0.5">src {a.source_ip}</p>}
                                                    </div>
                                                    <span className="text-[10px] text-foreground-muted shrink-0">{fmt(a.timestamp)}</span>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )
                )}

                {tab === 'network' && (
                    <div className="space-y-3">
                        <p className="text-sm font-bold text-foreground">Per-agent network connections are not collected</p>
                        <p className="text-xs text-foreground-muted leading-relaxed max-w-2xl">
                            NovrSOC has a network view at <Link href="/admin/infra/topology" className="text-purple hover:underline">Infrastructure → Topology</Link>,
                            but it aggregates connection data across the whole estate from alert
                            records — it is not per-agent, and the Wazuh agents here do not ship
                            per-process socket inventory.
                        </p>
                        <p className="text-xs text-foreground-muted leading-relaxed max-w-2xl">
                            Populating this tab needs Sysmon (Windows) or osquery/audit rules (Linux)
                            enrolled on the agent so process-to-remote-IP data reaches the indexer.
                            Rather than showing a plausible-looking table with nothing real behind it,
                            this says what is missing.
                        </p>
                    </div>
                )}

                {tab === 'compliance' && (
                    !compliance ? <p className="text-xs text-foreground-muted">Loading…</p> : (
                        <div className="space-y-3">
                            <div className="flex items-center justify-between gap-3 flex-wrap">
                                <p className="text-sm font-bold text-foreground">Overall impact: {compliance.overall_impact}</p>
                                <span className="text-[10px] text-foreground-muted">
                                    {vulns?.length ?? 0} vulnerabilities assessed · {compliance.unmapped} below the mapping threshold
                                </span>
                            </div>

                            {frameworks.length === 0 ? (
                                <div className="text-center text-emerald-500 bg-emerald-500/5 border border-emerald-500/30 rounded-xl p-5 text-xs">
                                    No compliance controls are currently implicated by this agent&apos;s vulnerabilities.
                                </div>
                            ) : (
                                frameworks.map(([fw, data]) => (
                                    <div key={fw} className="border border-red-500/30 bg-red-500/5 rounded-xl p-4">
                                        <div className="flex justify-between items-center mb-2 gap-3 flex-wrap">
                                            <span className="font-bold text-sm text-red-500">{fw}</span>
                                            <span className="text-[10px] bg-red-500/10 text-red-500 px-2 py-0.5 rounded-full font-bold">
                                                {data.failing} failing · {data.at_risk} at risk
                                            </span>
                                        </div>
                                        <div className="space-y-1.5">
                                            {data.controls.map((c) => (
                                                <div key={c.control} className="text-xs flex items-start gap-2">
                                                    <span className="shrink-0">{c.status === 'FAIL' ? '❌' : '⚠️'}</span>
                                                    <div>
                                                        <p className="text-foreground">{c.control}</p>
                                                        <p className="text-[10px] text-foreground-muted">{c.rationale}</p>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                ))
                            )}

                            <p className="text-[10px] text-foreground-muted">{compliance.note}</p>
                        </div>
                    )
                )}
            </div>
        </div>
    );
}
