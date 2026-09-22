'use client';

import { useCallback, useEffect, useState } from 'react';
import { Shield, Swords, RefreshCw, ExternalLink } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// MITRE ATT&CK and D3FEND.
//
// ATT&CK techniques are real Wazuh detections, keyed on rule.mitre.id (T1055 etc.) — see
// routes/mitre.ts on why that field and not rule.mitre.technique.
//
// D3FEND statuses are tri-state on purpose. Countermeasures NovrSOC can verify from platform
// state report implemented/not implemented; everything else reports "unknown" and is excluded
// from the score. A coverage percentage built from assumptions is a number a CISO would act on.

const TIME_RANGES = [
    { label: '1h', value: '1h' }, { label: '6h', value: '6h' }, { label: '24h', value: '24h' },
    { label: '7d', value: '7d' }, { label: '30d', value: '30d' },
];

const SEVERITY_BADGE: Record<string, string> = {
    critical: 'bg-red-500/10 text-red-500 border-red-500/30',
    high: 'bg-orange/10 text-orange border-orange/30',
    medium: 'bg-amber-500/10 text-amber-500 border-amber-500/30',
    low: 'bg-blue/10 text-blue border-blue/30',
};
const SEVERITY_DOT: Record<string, string> = {
    critical: 'bg-red-500', high: 'bg-orange', medium: 'bg-amber-500', low: 'bg-blue',
};

// The 12 ATT&CK Enterprise tactics, in kill-chain order.
const TACTIC_COLOR: Record<string, string> = {
    'Initial Access': 'bg-red-500', 'Execution': 'bg-orange', 'Persistence': 'bg-amber-500',
    'Privilege Escalation': 'bg-yellow-500', 'Defense Evasion': 'bg-lime-500',
    'Credential Access': 'bg-green', 'Discovery': 'bg-teal-500', 'Lateral Movement': 'bg-cyan-500',
    'Collection': 'bg-blue', 'Command and Control': 'bg-indigo-500',
    'Exfiltration': 'bg-violet-500', 'Impact': 'bg-purple',
};

interface Technique {
    technique_id: string; technique_name: string; count: number;
    severity: string; max_level: number; tactics: string[];
    agents: Array<{ name: string; count: number }>; top_rules: string[];
}
interface TechniquesData {
    techniques: Technique[];
    tactics_summary: Array<{ tactic: string; technique_count: number; alert_count: number }>;
    agents_summary: Array<{ agent: string; technique_count: number; alert_count: number }>;
    total_techniques: number; total_alerts: number; error?: string;
}
interface Detail {
    technique_id: string;
    alerts: Array<{ timestamp: string; agent_name: string; description: string; level: number; severity: string; source_ip: string | null }>;
    total: number;
    agents: Array<{ name: string; count: number }>;
    rules: Array<{ name: string; count: number }>;
    error?: string;
}
interface CM { id: string; name: string; description: string; status: 'implemented' | 'not_implemented' | 'unknown'; basis: string }
interface DefendData {
    coverage: Array<{
        attack_technique: string; technique_name: string; countermeasures: CM[];
        coverage_score: number | null; implemented_count: number; verifiable_count: number;
        unknown_count: number; total_count: number;
    }>;
    uncovered_techniques: string[];
    overall_score: number | null;
    detected_count: number; covered_count: number;
    verifiable_count: number; unknown_count: number;
    scoring_note: string;
}
interface Agent { id: string; name: string }

const CM_STYLE: Record<CM['status'], { box: string; dot: string; label: string; text: string }> = {
    implemented: { box: 'bg-green/5 border-green/30', dot: 'bg-green', label: 'Implemented', text: 'text-green' },
    not_implemented: { box: 'bg-red-500/5 border-red-500/30', dot: 'bg-red-500', label: 'Not implemented', text: 'text-red-500' },
    unknown: { box: 'bg-card-muted/40 border-border', dot: 'bg-card-muted', label: 'Unknown', text: 'text-foreground-muted' },
};

function scoreTone(score: number | null): string {
    if (score === null) return 'text-foreground-muted';
    return score >= 70 ? 'text-green' : score >= 40 ? 'text-amber-500' : 'text-red-500';
}

export function MitreIntelligence() {
    const [tab, setTab] = useState<'attack' | 'defend'>('attack');
    const [range, setRange] = useState('24h');
    const [agentFilter, setAgentFilter] = useState('all');
    const [severityFilter, setSeverityFilter] = useState('all');
    const [tacticFilter, setTacticFilter] = useState('all');

    // Data is stored with the filter signature it was fetched for, and `loading` is derived by
    // comparing that to the current filters. This replaces a `setLoading(true)` at the top of
    // the fetch: calling setState synchronously inside an effect triggers a cascading render,
    // and deriving it also fixes a real bug — changing a filter now shows the spinner
    // immediately instead of briefly showing the previous filter's results as if they were
    // the new ones.
    const [loaded, setLoaded] = useState<{ key: string; payload: TechniquesData } | null>(null);
    const [agents, setAgents] = useState<Agent[]>([]);

    const [selected, setSelected] = useState<string | null>(null);
    const [detail, setDetail] = useState<Detail | null>(null);

    const [defendData, setDefendData] = useState<DefendData | null>(null);
    const [defendLoading, setDefendLoading] = useState(false);

    const filterKey = `${range}|${agentFilter}|${severityFilter}|${tacticFilter}`;

    const loadData = useCallback((key: string) => {
        const [r, agent, severity, tactic] = key.split('|');
        const params = new URLSearchParams({ range: r });
        if (agent !== 'all') params.set('agent_id', agent);
        if (severity !== 'all') params.set('severity', severity);
        if (tactic !== 'all') params.set('tactic', tactic);

        return apiFetch(apiUrl(`/api/mitre/techniques?${params}`), { cache: 'no-store' })
            .then((res) => res.json())
            .then((d) => setLoaded({ key, payload: d as TechniquesData }))
            // Stored against the same key so a failed fetch clears the spinner rather than
            // leaving it spinning forever.
            .catch(() => setLoaded({
                key,
                payload: {
                    techniques: [], tactics_summary: [], agents_summary: [],
                    total_techniques: 0, total_alerts: 0, error: 'Could not reach the backend',
                },
            }));
    }, []);

    useEffect(() => { void loadData(filterKey); }, [loadData, filterKey]);

    const data = loaded?.key === filterKey ? loaded.payload : null;
    const loading = data === null;

    useEffect(() => {
        apiFetch(apiUrl('/api/wazuh/agents'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((d) => setAgents(Array.isArray(d?.agents) ? d.agents : []))
            .catch(() => setAgents([]));
    }, []);

    // Loaded from the tab handler rather than an effect keyed on `tab`: the fetch belongs to the
    // user's click, and doing it here keeps setState out of an effect body.
    const openTab = (next: 'attack' | 'defend') => {
        setTab(next);
        if (next !== 'defend' || defendData || defendLoading) return;
        setDefendLoading(true);
        void apiFetch(apiUrl(`/api/mitre/defend?range=${range}`), { cache: 'no-store' })
            .then((r) => r.json())
            .then((d) => setDefendData(d as DefendData))
            .catch(() => setDefendData(null))
            .finally(() => setDefendLoading(false));
    };

    // Selection happens in a click handler, not an effect on `selected`, so the fetch is tied to
    // the user's action rather than to a state transition.
    const openTechnique = (id: string) => {
        setSelected(id);
        setDetail(null);
        void apiFetch(apiUrl(`/api/mitre/technique/${encodeURIComponent(id)}?range=${range}`), { cache: 'no-store' })
            .then((r) => r.json())
            .then((d) => setDetail(d as Detail))
            .catch(() => setDetail(null));
    };

    const tactics = [...new Set((data?.techniques ?? []).flatMap((t) => t.tactics))].filter(Boolean).sort();
    const maxAgentAlerts = Math.max(...(data?.agents_summary ?? []).map((a) => a.alert_count), 1);

    return (
        <div className="space-y-4">
            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="flex items-start gap-2.5">
                    <div className="w-8 h-8 rounded-lg bg-purple/10 flex items-center justify-center shrink-0">
                        <Shield className="w-4 h-4 text-purple" />
                    </div>
                    <div>
                        <h1 className="text-lg font-black text-foreground">MITRE Intelligence</h1>
                        <p className="text-xs text-foreground-muted">Security Operations · Techniques detected on endpoints and defensive coverage</p>
                    </div>
                </div>
                <div className="flex bg-card-muted rounded-lg p-1 gap-1">
                    {([['attack', 'ATT&CK', Swords], ['defend', 'D3FEND', Shield]] as const).map(([id, label, Icon]) => (
                        <button key={id} onClick={() => openTab(id)}
                            className={`flex items-center gap-1.5 px-4 py-2 rounded-md text-xs font-bold transition-colors ${
                                tab === id ? 'bg-card text-purple shadow-sm' : 'text-foreground-muted hover:text-foreground'
                            }`}>
                            <Icon size={13} /> {label}
                        </button>
                    ))}
                </div>
            </div>

            {tab === 'attack' && (
                <div className="space-y-4">
                    {/* Filters */}
                    <div className="bg-card border border-border rounded-xl p-4 flex flex-wrap gap-3 items-center">
                        <div className="flex items-center gap-0.5 bg-card-muted border border-border rounded-lg p-0.5">
                            {TIME_RANGES.map((r) => (
                                <button key={r.value} onClick={() => setRange(r.value)}
                                    className={`px-2.5 py-1 rounded-md text-[11px] font-semibold transition-colors ${
                                        range === r.value ? 'bg-purple text-white' : 'text-foreground-muted hover:text-foreground'
                                    }`}>
                                    {r.label}
                                </button>
                            ))}
                        </div>

                        <select value={agentFilter} onChange={(e) => setAgentFilter(e.target.value)} aria-label="Filter by endpoint"
                            className="bg-card border border-border rounded-lg px-2.5 py-1.5 text-xs font-bold text-foreground focus:outline-none">
                            <option value="all">All endpoints</option>
                            {agents.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
                        </select>

                        <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} aria-label="Filter by severity"
                            className="bg-card border border-border rounded-lg px-2.5 py-1.5 text-xs font-bold text-foreground focus:outline-none">
                            <option value="all">All severities</option>
                            {['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{s}</option>)}
                        </select>

                        <select value={tacticFilter} onChange={(e) => setTacticFilter(e.target.value)} aria-label="Filter by tactic"
                            className="bg-card border border-border rounded-lg px-2.5 py-1.5 text-xs font-bold text-foreground focus:outline-none">
                            <option value="all">All tactics</option>
                            {tactics.map((t) => <option key={t} value={t}>{t}</option>)}
                        </select>

                        <button onClick={() => void loadData(filterKey)} disabled={loading}
                            className="ml-auto flex items-center gap-1.5 bg-purple text-white text-xs font-bold px-3 py-1.5 rounded-lg hover:opacity-90 disabled:opacity-50 transition-opacity">
                            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> Refresh
                        </button>
                    </div>

                    {data?.error && (
                        <div className="bg-amber-500/5 border border-amber-500/30 rounded-xl p-4 text-xs text-amber-500">
                            {data.error} — techniques cannot be listed. This is an indexer problem, not an absence of attacks.
                        </div>
                    )}

                    {/* KPIs */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        {[
                            { label: 'Techniques detected', value: data?.total_techniques, tone: 'text-purple' },
                            { label: 'Total alerts', value: data?.total_alerts, tone: 'text-red-500' },
                            { label: 'Tactics seen', value: data?.tactics_summary?.length, tone: 'text-amber-500' },
                            { label: 'Endpoints affected', value: data?.agents_summary?.length, tone: 'text-blue' },
                        ].map((k) => (
                            <div key={k.label} className="bg-card border border-border rounded-xl p-4 text-center">
                                <div className={`text-2xl font-black ${k.tone}`}>
                                    {loading ? '…' : k.value === undefined ? '—' : k.value.toLocaleString()}
                                </div>
                                <div className="text-[10px] text-foreground-muted mt-0.5">{k.label}</div>
                            </div>
                        ))}
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                        {/* Technique list */}
                        <div className="lg:col-span-2 bg-card border border-border rounded-xl overflow-hidden">
                            <div className="px-5 py-4 border-b border-border flex items-center justify-between gap-3 flex-wrap">
                                <h3 className="text-sm font-black text-foreground">Detected Techniques</h3>
                                <span className="text-[10px] text-foreground-muted">
                                    {data?.total_techniques ?? 0} techniques · {(data?.total_alerts ?? 0).toLocaleString()} alerts
                                </span>
                            </div>

                            {loading ? (
                                <div className="p-5 space-y-2">{Array.from({ length: 5 }).map((_, i) => <div key={i} className="h-16 bg-card-muted rounded animate-pulse" />)}</div>
                            ) : (data?.techniques ?? []).length === 0 ? (
                                <div className="p-10 text-center">
                                    <p className="text-sm font-bold text-foreground mb-1">No techniques detected</p>
                                    <p className="text-xs text-foreground-muted max-w-sm mx-auto">
                                        No MITRE-mapped alerts matched these filters in the selected window. Only rules
                                        with a MITRE mapping appear here — this is not the full alert count.
                                    </p>
                                </div>
                            ) : (
                                <div className="divide-y divide-border">
                                    {(data?.techniques ?? []).map((tech) => (
                                        <button key={tech.technique_id} onClick={() => openTechnique(tech.technique_id)}
                                            className={`w-full flex items-start gap-3 px-5 py-4 text-left transition-colors hover:bg-card-muted/40 ${
                                                selected === tech.technique_id ? 'bg-purple/5' : ''
                                            }`}>
                                            <div className={`w-1.5 h-1.5 rounded-full mt-2 shrink-0 ${SEVERITY_DOT[tech.severity] ?? SEVERITY_DOT.low}`} />
                                            <div className="flex-1 min-w-0">
                                                <div className="flex items-center gap-2 mb-1 flex-wrap">
                                                    <code className="text-xs font-black text-purple">{tech.technique_id}</code>
                                                    <span className="text-xs font-bold text-foreground">{tech.technique_name}</span>
                                                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full border uppercase ${SEVERITY_BADGE[tech.severity] ?? SEVERITY_BADGE.low}`}>
                                                        {tech.severity}
                                                    </span>
                                                </div>
                                                <div className="flex gap-1 flex-wrap mb-1.5">
                                                    {tech.tactics.map((t) => (
                                                        <span key={t} className={`text-[8px] text-white px-1.5 py-0.5 rounded-full ${TACTIC_COLOR[t] ?? 'bg-card-muted'}`}>{t}</span>
                                                    ))}
                                                </div>
                                                {tech.top_rules[0] && <p className="text-[10px] text-foreground-muted truncate">{tech.top_rules[0]}</p>}
                                                <div className="flex items-center gap-1.5 mt-1.5 flex-wrap">
                                                    <span className="text-[9px] text-foreground-muted">Endpoints:</span>
                                                    {tech.agents.map((a) => (
                                                        <span key={a.name} className="text-[9px] bg-purple/10 text-purple px-1.5 py-0.5 rounded-full font-bold">
                                                            {a.name} ({a.count})
                                                        </span>
                                                    ))}
                                                </div>
                                            </div>
                                            <div className="text-right shrink-0">
                                                <div className="text-lg font-black text-foreground">{tech.count.toLocaleString()}</div>
                                                <div className="text-[9px] text-foreground-muted">alerts</div>
                                            </div>
                                        </button>
                                    ))}
                                </div>
                            )}
                        </div>

                        {/* Detail panel */}
                        <div className="bg-card border border-border rounded-xl overflow-hidden h-fit">
                            <div className="px-5 py-4 border-b border-border">
                                <h3 className="text-sm font-black text-foreground">
                                    {selected ? `Detail: ${selected}` : 'Technique detail'}
                                </h3>
                            </div>
                            {!selected ? (
                                <p className="p-6 text-center text-xs text-foreground-muted">Select a technique to see affected endpoints and recent alerts.</p>
                            ) : !detail ? (
                                <div className="p-5 space-y-2">{Array.from({ length: 3 }).map((_, i) => <div key={i} className="h-10 bg-card-muted rounded animate-pulse" />)}</div>
                            ) : (
                                <div className="p-5 space-y-4 max-h-[640px] overflow-y-auto scrollbar-thin">
                                    <div className="grid grid-cols-2 gap-2">
                                        <div className="bg-card-muted/50 rounded-xl p-3 text-center">
                                            <div className="text-xl font-black text-purple">{detail.total.toLocaleString()}</div>
                                            <div className="text-[9px] text-foreground-muted">Total alerts</div>
                                        </div>
                                        <div className="bg-card-muted/50 rounded-xl p-3 text-center">
                                            <div className="text-xl font-black text-foreground">{detail.agents.length}</div>
                                            <div className="text-[9px] text-foreground-muted">Endpoints</div>
                                        </div>
                                    </div>

                                    <div>
                                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">Affected endpoints</p>
                                        {detail.agents.length === 0 ? <p className="text-[11px] text-foreground-muted">None recorded.</p> : detail.agents.map((a) => (
                                            <div key={a.name} className="flex items-center justify-between py-1.5 border-b border-border last:border-0">
                                                <span className="text-xs font-bold text-foreground">{a.name}</span>
                                                <span className="text-[11px] text-foreground-muted">{a.count.toLocaleString()} alerts</span>
                                            </div>
                                        ))}
                                    </div>

                                    <div>
                                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">Detection rules</p>
                                        {detail.rules.slice(0, 4).map((r) => (
                                            <p key={r.name} className="text-[10px] text-foreground-muted py-1 border-b border-border last:border-0 leading-relaxed">{r.name}</p>
                                        ))}
                                    </div>

                                    <div>
                                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">Recent alerts</p>
                                        {detail.alerts.slice(0, 5).map((a, i) => (
                                            <div key={i} className="py-2 border-b border-border last:border-0">
                                                <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                                                    <span className="text-[9px] font-bold text-purple">{a.agent_name}</span>
                                                    <span className="text-[9px] text-foreground-muted">
                                                        {a.timestamp ? new Date(a.timestamp).toLocaleString('en-GB', { timeZone: 'Africa/Lagos' }) + ' WAT' : ''}
                                                    </span>
                                                </div>
                                                <p className="text-[10px] text-foreground-muted leading-relaxed">{a.description}</p>
                                                {a.source_ip && <p className="text-[9px] text-foreground-muted font-mono mt-0.5">src {a.source_ip}</p>}
                                            </div>
                                        ))}
                                    </div>

                                    <a href={`https://attack.mitre.org/techniques/${selected.replace('.', '/')}/`}
                                        target="_blank" rel="noopener noreferrer"
                                        className="flex items-center justify-center gap-1.5 text-xs text-purple font-bold hover:underline pt-1">
                                        View on MITRE ATT&amp;CK <ExternalLink size={12} />
                                    </a>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Tactics */}
                    {(data?.tactics_summary ?? []).length > 0 && (
                        <div className="bg-card border border-border rounded-xl p-5">
                            <h3 className="text-sm font-black text-foreground mb-3">Tactics Breakdown</h3>
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                {data!.tactics_summary.map((t) => (
                                    <button key={t.tactic} onClick={() => setTacticFilter(t.tactic)}
                                        className={`p-3 rounded-xl border text-left transition-colors ${
                                            tacticFilter === t.tactic ? 'border-purple bg-purple/5' : 'border-border hover:border-purple/40'
                                        }`}>
                                        <div className={`w-2 h-2 rounded-full mb-2 ${TACTIC_COLOR[t.tactic] ?? 'bg-card-muted'}`} />
                                        <div className="text-xs font-bold text-foreground leading-tight mb-1">{t.tactic}</div>
                                        <div className="text-[10px] text-foreground-muted">
                                            {t.technique_count} techniques · {t.alert_count.toLocaleString()} alerts
                                        </div>
                                    </button>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Endpoint comparison */}
                    {(data?.agents_summary ?? []).length > 0 && (
                        <div className="bg-card border border-border rounded-xl p-5">
                            <h3 className="text-sm font-black text-foreground mb-3">Endpoint Exposure Comparison</h3>
                            <div className="space-y-3">
                                {data!.agents_summary.map((a) => (
                                    <div key={a.agent}>
                                        <div className="flex items-center justify-between mb-1 gap-3 flex-wrap">
                                            <span className="text-xs font-bold text-foreground">{a.agent}</span>
                                            <span className="text-[10px] text-foreground-muted">
                                                {a.technique_count} techniques · {a.alert_count.toLocaleString()} alerts
                                            </span>
                                        </div>
                                        <div className="h-2 bg-card-muted rounded-full overflow-hidden">
                                            <div className="h-full bg-purple rounded-full transition-all"
                                                style={{ width: `${Math.round((a.alert_count / maxAgentAlerts) * 100)}%` }} />
                                        </div>
                                    </div>
                                ))}
                            </div>
                            <p className="text-[10px] text-foreground-muted mt-3">
                                Bars are relative to the busiest endpoint, not an absolute risk score.
                            </p>
                        </div>
                    )}
                </div>
            )}

            {tab === 'defend' && (
                <div className="space-y-4">
                    {defendLoading || !defendData ? (
                        <div className="space-y-3">{Array.from({ length: 3 }).map((_, i) => <div key={i} className="h-28 bg-card-muted rounded-xl animate-pulse" />)}</div>
                    ) : (
                        <>
                            <div className="bg-card border border-border rounded-xl p-5">
                                <div className="flex items-start justify-between gap-4 mb-4 flex-wrap">
                                    <div>
                                        <h3 className="text-sm font-black text-foreground">Defensive Coverage</h3>
                                        <p className="text-[11px] text-foreground-muted mt-0.5 max-w-xl leading-relaxed">
                                            D3FEND countermeasures for the ATT&amp;CK techniques detected in this window.
                                        </p>
                                    </div>
                                    <div className="text-right">
                                        <div className={`text-4xl font-black ${scoreTone(defendData.overall_score)}`}>
                                            {defendData.overall_score === null ? '—' : `${defendData.overall_score}%`}
                                        </div>
                                        <div className="text-[10px] text-foreground-muted">
                                            {defendData.overall_score === null ? 'not assessable' : 'of verifiable controls'}
                                        </div>
                                    </div>
                                </div>

                                {defendData.overall_score !== null && (
                                    <div className="h-3 bg-card-muted rounded-full overflow-hidden mb-4">
                                        <div className={`h-full rounded-full transition-all ${
                                            defendData.overall_score >= 70 ? 'bg-green' : defendData.overall_score >= 40 ? 'bg-amber-500' : 'bg-red-500'
                                        }`} style={{ width: `${defendData.overall_score}%` }} />
                                    </div>
                                )}

                                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                    {[
                                        { label: 'Techniques detected', value: defendData.detected_count },
                                        { label: 'With D3FEND mapping', value: defendData.covered_count },
                                        { label: 'Controls verifiable', value: defendData.verifiable_count },
                                        { label: 'Controls unknown', value: defendData.unknown_count },
                                    ].map((s) => (
                                        <div key={s.label} className="bg-card-muted/50 rounded-xl p-3 text-center">
                                            <div className="text-xl font-black text-foreground">{s.value}</div>
                                            <div className="text-[9px] text-foreground-muted">{s.label}</div>
                                        </div>
                                    ))}
                                </div>

                                <p className="text-[10px] text-foreground-muted mt-3 leading-relaxed">{defendData.scoring_note}</p>
                            </div>

                            {defendData.coverage.length === 0 ? (
                                <div className="bg-card border border-border rounded-xl p-8 text-center">
                                    <p className="text-sm font-bold text-foreground mb-1">Nothing to map yet</p>
                                    <p className="text-xs text-foreground-muted">No detected technique has a D3FEND mapping in this window.</p>
                                </div>
                            ) : defendData.coverage.map((item) => (
                                <div key={item.attack_technique} className="bg-card border border-border rounded-xl overflow-hidden">
                                    <div className="flex items-center justify-between gap-3 px-5 py-4 border-b border-border flex-wrap">
                                        <div className="flex items-center gap-2.5 flex-wrap">
                                            <code className="text-xs font-black text-red-500">{item.attack_technique}</code>
                                            <span className="text-sm font-bold text-foreground">{item.technique_name}</span>
                                        </div>
                                        <div className={`text-[11px] font-black px-3 py-1 rounded-full ${
                                            item.coverage_score === null ? 'bg-card-muted text-foreground-muted'
                                                : item.coverage_score >= 70 ? 'bg-green/10 text-green'
                                                    : item.coverage_score >= 40 ? 'bg-amber-500/10 text-amber-500' : 'bg-red-500/10 text-red-500'
                                        }`}>
                                            {item.coverage_score === null
                                                ? 'not assessable'
                                                : `${item.coverage_score}% of ${item.verifiable_count} verifiable`}
                                        </div>
                                    </div>
                                    <div className="p-4 space-y-2">
                                        {item.countermeasures.map((cm) => {
                                            const st = CM_STYLE[cm.status];
                                            return (
                                                <div key={cm.id} className={`flex items-start gap-3 p-3 rounded-xl border ${st.box}`}>
                                                    <div className={`w-2 h-2 rounded-full shrink-0 mt-1.5 ${st.dot}`} />
                                                    <div className="flex-1 min-w-0">
                                                        <div className="flex items-center gap-2 flex-wrap">
                                                            <code className="text-[9px] font-bold text-purple">{cm.id}</code>
                                                            <span className="text-xs font-bold text-foreground">{cm.name}</span>
                                                        </div>
                                                        <p className="text-[10px] text-foreground-muted mt-0.5">{cm.description}</p>
                                                        <p className="text-[10px] text-foreground-muted/80 mt-1 italic">{cm.basis}</p>
                                                    </div>
                                                    <span className={`text-[9px] font-bold shrink-0 ${st.text}`}>{st.label}</span>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>
                            ))}

                            {defendData.uncovered_techniques.length > 0 && (
                                <div className="bg-amber-500/5 border border-amber-500/30 rounded-xl p-5">
                                    <h3 className="text-sm font-bold text-amber-500 mb-2">Detected without a D3FEND mapping</h3>
                                    <div className="flex flex-wrap gap-2 mb-3">
                                        {defendData.uncovered_techniques.map((t) => (
                                            <a key={t} href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                                                target="_blank" rel="noopener noreferrer"
                                                className="text-[11px] bg-amber-500/10 text-amber-500 px-2 py-1 rounded-lg font-bold hover:bg-amber-500/20 transition-colors">
                                                {t}
                                            </a>
                                        ))}
                                    </div>
                                    <p className="text-[10px] text-foreground-muted leading-relaxed">
                                        These were detected but aren&apos;t in NovrSOC&apos;s D3FEND mapping table yet — it
                                        covers a curated subset, not all of D3FEND. Absence here means unmapped, not undefended.
                                        Look them up at d3fend.mitre.org.
                                    </p>
                                </div>
                            )}
                        </>
                    )}
                </div>
            )}
        </div>
    );
}
