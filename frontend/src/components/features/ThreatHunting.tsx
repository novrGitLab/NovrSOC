'use client';

import { useState } from 'react';
import { Plus, X, Download, Save, Play, RefreshCw, Crosshair } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Wired to the real Wazuh Indexer via POST /api/wazuh/hunt (routes/wazuh.ts). Saved Hunt
// Templates and Export Results are still frontend-only — a template just fills the query
// builder in, and Export just serializes whatever's in `results` state, neither needs its own
// endpoint.

const FIELDS = ['agent.name', 'rule.level', 'rule.groups', 'data.srcip', 'data.dstip', 'rule.description'] as const;
const OPERATORS = ['equals', 'contains', 'greater_than', 'less_than', 'exists'] as const;
const TIME_RANGES = [
    { label: 'Last 1h', value: '1h' },
    { label: 'Last 6h', value: '6h' },
    { label: 'Last 24h', value: '24h' },
    { label: 'Last 7d', value: '7d' },
] as const;

interface Condition { field: string; op: string; value: string }
interface HuntEvent { ts: string; agent: string; rule_id: string | number | null; level: number; srcip: string | null; description: string }

const HUNT_TEMPLATES: Array<{ name: string; description: string; filters: Condition[]; time_window: string }> = [
    { name: 'Failed Login Spike', description: 'Find accounts with multiple failed logins in short time', filters: [{ field: 'rule.groups', op: 'contains', value: 'authentication_failed' }], time_window: '1h' },
    { name: 'New User Created After Hours', description: 'User accounts created outside business hours (MITRE T1136)', filters: [{ field: 'rule.groups', op: 'contains', value: 'adduser' }, { field: 'rule.level', op: 'greater_than', value: '8' }], time_window: '24h' },
    { name: 'PowerShell Execution', description: 'PowerShell commands with encoded parameters (common malware pattern)', filters: [{ field: 'rule.description', op: 'contains', value: 'PowerShell' }, { field: 'rule.level', op: 'greater_than', value: '6' }], time_window: '24h' },
    { name: 'Outbound to Tor Exits', description: 'Any device communicating with known Tor exit nodes', filters: [{ field: 'rule.groups', op: 'contains', value: 'tor' }], time_window: '24h' },
    { name: 'File Created in Sensitive Directory', description: 'New files in system directories (/etc, System32, cron.d)', filters: [{ field: 'rule.groups', op: 'contains', value: 'syscheck' }, { field: 'rule.level', op: 'greater_than', value: '10' }], time_window: '24h' },
    { name: 'Lateral Movement Indicators', description: 'SMB, PsExec, WMI usage patterns (MITRE T1021)', filters: [{ field: 'rule.groups', op: 'contains', value: 'lateral_movement' }], time_window: '24h' },
    { name: 'DNS Tunneling Detection', description: 'Unusually long DNS queries or high DNS query volume', filters: [{ field: 'rule.groups', op: 'contains', value: 'dns' }, { field: 'rule.level', op: 'greater_than', value: '8' }], time_window: '24h' },
    { name: 'Credential Dumping', description: 'LSASS access, SAM database access (MITRE T1003)', filters: [{ field: 'rule.groups', op: 'contains', value: 'credential_access' }], time_window: '24h' },
];

export function ThreatHunting() {
    const [conditions, setConditions] = useState<Condition[]>([{ field: FIELDS[0], op: OPERATORS[0], value: '' }]);
    const [timeRange, setTimeRange] = useState<(typeof TIME_RANGES)[number]['value']>('24h');
    const [running, setRunning] = useState(false);
    const [results, setResults] = useState<HuntEvent[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [selected, setSelected] = useState<HuntEvent | null>(null);
    const [escalating, setEscalating] = useState(false);
    const [escalateResult, setEscalateResult] = useState<{ ok: boolean; message: string } | null>(null);

    // Adds the event's source IP to the shared IOC intelligence table AND opens a case
    // tagged 'threat-hunt' — see backend/src/routes/secops.ts's POST /hunting/escalate for both
    // writes.
    const addToThreats = async (event: HuntEvent) => {
        if (!event.srcip) {
            setEscalateResult({ ok: false, message: 'This event has no source IP to escalate.' });
            return;
        }
        setEscalating(true);
        setEscalateResult(null);
        try {
            const res = await apiFetch(apiUrl('/api/secops/hunting/escalate'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ioc_value: event.srcip,
                    ioc_type: 'ip',
                    finding: `${event.description}\nAgent: ${event.agent}\nRule: ${event.rule_id ?? '—'} (level ${event.level})`,
                    source_alert_id: event.rule_id != null ? String(event.rule_id) : undefined,
                }),
            });
            const data = await res.json();
            if (!res.ok || !data?.success) throw new Error(data?.error || `HTTP ${res.status}`);
            setEscalateResult({ ok: true, message: data.created === false ? `Added to threat intel — this IOC already has case ${data.case_number}.` : `Added to threat intel and case ${data.case_number} created.` });
        } catch (err) {
            setEscalateResult({ ok: false, message: err instanceof Error ? err.message : 'Failed to escalate' });
        } finally {
            setEscalating(false);
        }
    };

    const addCondition = () => setConditions((c) => [...c, { field: FIELDS[0], op: OPERATORS[0], value: '' }]);
    const updateCondition = (i: number, patch: Partial<Condition>) => setConditions((c) => c.map((cond, idx) => (idx === i ? { ...cond, ...patch } : cond)));
    const removeCondition = (i: number) => setConditions((c) => c.filter((_, idx) => idx !== i));

    const runHunt = async () => {
        setRunning(true);
        setResults(null);
        setError(null);
        try {
            const res = await apiFetch(apiUrl('/api/wazuh/hunt'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    conditions: conditions.filter((c) => c.op === 'exists' || c.value.trim()),
                    time_range: timeRange,
                    limit: 100,
                }),
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);
            const mapped: HuntEvent[] = (data.results ?? []).map((r: { timestamp?: string; agent?: string; rule_id?: string | number; rule_level?: number; rule_description?: string; source_ip?: string }) => ({
                ts: r.timestamp ?? '',
                agent: r.agent ?? 'Unknown',
                rule_id: r.rule_id ?? null,
                level: r.rule_level ?? 0,
                srcip: r.source_ip ?? null,
                description: r.rule_description ?? '',
            }));
            setResults(mapped);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Hunt query failed — check the Wazuh indexer connection');
            setResults([]);
        } finally {
            setRunning(false);
        }
    };

    const applyTemplate = (t: (typeof HUNT_TEMPLATES)[number]) => {
        setConditions(t.filters);
        setResults(null);
    };

    return (
        <div className="space-y-4">
            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div>
                    <h1 className="text-lg font-black text-foreground">Threat Hunting</h1>
                    <p className="text-xs text-foreground-muted">SecOps & Response · Search and query Wazuh events with custom filters.</p>
                </div>
                <div className="flex gap-2 flex-shrink-0">
                    <button className="flex items-center gap-2 border border-border text-foreground-muted text-xs font-bold px-4 py-2.5 rounded-lg hover:bg-card-muted transition-colors"><Save size={14} /> Save Hunt</button>
                    <button disabled={!results} className="flex items-center gap-2 border border-purple text-purple text-xs font-bold px-4 py-2.5 rounded-lg hover:bg-purple/5 disabled:opacity-50 transition-colors"><Download size={14} /> Export Results</button>
                </div>
            </div>

            {/* Query builder */}
            <div className="bg-card border border-border rounded-xl p-4 space-y-3">
                {conditions.map((cond, i) => (
                    <div key={i} className="flex flex-wrap items-center gap-2">
                        <select value={cond.field} onChange={(e) => updateCondition(i, { field: e.target.value })} className="bg-card-muted border border-border rounded-lg px-3 py-2 text-xs text-foreground focus:outline-none">
                            {FIELDS.map((f) => <option key={f} value={f}>{f}</option>)}
                        </select>
                        <select value={cond.op} onChange={(e) => updateCondition(i, { op: e.target.value })} className="bg-card-muted border border-border rounded-lg px-3 py-2 text-xs text-foreground focus:outline-none">
                            {OPERATORS.map((o) => <option key={o} value={o}>{o.replace('_', ' ')}</option>)}
                        </select>
                        {cond.op !== 'exists' && (
                            <input value={cond.value} onChange={(e) => updateCondition(i, { value: e.target.value })} placeholder="value"
                                className="flex-1 min-w-[140px] bg-card-muted border border-border rounded-lg px-3 py-2 text-xs text-foreground focus:outline-none focus:border-blue" />
                        )}
                        {conditions.length > 1 && (
                            <button onClick={() => removeCondition(i)} className="text-foreground-muted hover:text-red flex-shrink-0"><X size={14} /></button>
                        )}
                    </div>
                ))}
                <button onClick={addCondition} className="flex items-center gap-1.5 text-xs font-bold text-blue hover:text-purple transition-colors"><Plus size={12} /> Add Condition</button>

                <div className="flex flex-wrap items-center gap-3 pt-3 border-t border-border">
                    <div className="flex gap-1 bg-card-muted rounded-lg p-1">
                        {TIME_RANGES.map((tr) => (
                            <button key={tr.value} onClick={() => setTimeRange(tr.value)}
                                className={`px-2.5 py-1 rounded-md text-[11px] font-bold transition-colors ${timeRange === tr.value ? 'bg-card text-blue shadow-sm' : 'text-foreground-muted hover:text-foreground'}`}>
                                {tr.label}
                            </button>
                        ))}
                    </div>
                    <button onClick={runHunt} disabled={running} className="ml-auto flex items-center gap-2 bg-orange hover:bg-orange-hover text-white text-xs font-bold px-5 py-2 rounded-lg disabled:opacity-50 transition-colors">
                        {running ? <RefreshCw size={14} className="animate-spin" /> : <Play size={14} />}
                        {running ? 'Running…' : 'Run Hunt'}
                    </button>
                </div>
            </div>

            {error && (
                <div className="bg-red/10 border border-red/30 rounded-xl p-4 text-sm text-red">{error}</div>
            )}

            {/* Results */}
            {results && !error && (
                <div className="bg-card border border-border rounded-xl overflow-hidden">
                    <div className="px-4 py-3 border-b border-border flex items-center justify-between">
                        <p className="text-xs font-bold text-foreground">{results.length} events matched</p>
                    </div>
                    <div className="overflow-x-auto scrollbar-thin">
                        <table className="w-full text-left">
                            <thead>
                                <tr className="bg-grey-800">
                                    {['Timestamp', 'Agent', 'Rule', 'Level', 'Source IP', 'Description', ''].map((c) => (
                                        <th key={c} className="px-4 py-3 text-[10px] font-semibold text-white uppercase tracking-widest whitespace-nowrap">{c}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border text-sm">
                                {results.map((r, i) => (
                                    <tr key={i} className="hover:bg-card-muted cursor-pointer" onClick={() => { setSelected(r); setEscalateResult(null); }}>
                                        <td className="px-4 py-3 text-foreground-muted whitespace-nowrap">{r.ts}</td>
                                        <td className="px-4 py-3 font-medium text-foreground whitespace-nowrap">{r.agent}</td>
                                        <td className="px-4 py-3 font-mono text-foreground-muted">{r.rule_id ?? '—'}</td>
                                        <td className="px-4 py-3"><span className={`font-bold ${r.level >= 12 ? 'text-red' : r.level >= 8 ? 'text-amber' : 'text-blue'}`}>{r.level}</span></td>
                                        <td className="px-4 py-3 font-mono text-foreground-muted whitespace-nowrap">{r.srcip ?? '—'}</td>
                                        <td className="px-4 py-3 text-foreground-muted">{r.description}</td>
                                        <td className="px-4 py-3 whitespace-nowrap">
                                            <button className="text-[10px] font-bold text-blue hover:text-purple">Create Alert</button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* Saved templates */}
            <div>
                <p className="text-xs font-black text-foreground mb-3">Saved Hunt Templates</p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {HUNT_TEMPLATES.map((t) => (
                        <button key={t.name} onClick={() => applyTemplate(t)} className="text-left bg-card border border-border rounded-xl p-4 hover:border-blue/50 transition-colors">
                            <div className="flex items-center gap-2 mb-1">
                                <Crosshair size={14} className="text-purple flex-shrink-0" />
                                <p className="text-sm font-bold text-foreground">{t.name}</p>
                            </div>
                            <p className="text-xs text-foreground-muted mb-2">{t.description}</p>
                            <div className="flex flex-wrap gap-1">
                                {t.filters.map((f, i) => (
                                    <span key={i} className="text-[9px] font-mono px-1.5 py-0.5 bg-card-muted text-foreground-muted rounded">{f.field} {f.op} {f.value}</span>
                                ))}
                            </div>
                        </button>
                    ))}
                </div>
            </div>

            {selected && (
                <div className="fixed inset-0 bg-black/40 z-50 flex items-center justify-end" onClick={() => setSelected(null)}>
                    <div className="bg-card border-l border-border h-full w-full max-w-md p-6 overflow-y-auto scrollbar-thin" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="font-heading font-semibold text-sm text-foreground">Event Detail</h3>
                            <button onClick={() => setSelected(null)} className="text-foreground-muted hover:text-foreground"><X size={16} /></button>
                        </div>
                        <pre className="text-[11px] font-mono bg-card-muted rounded-lg p-4 overflow-x-auto text-foreground whitespace-pre-wrap">
{JSON.stringify(selected, null, 2)}
                        </pre>
                        <div className="flex flex-wrap gap-2 mt-4">
                            <button className="text-[10px] font-bold px-3 py-1.5 bg-blue hover:opacity-90 text-white rounded-lg transition-colors">Create Alert</button>
                            <button
                                onClick={() => addToThreats(selected)}
                                disabled={escalating}
                                className="text-[10px] font-bold px-3 py-1.5 border border-purple text-purple rounded-lg hover:bg-purple/5 disabled:opacity-50 transition-colors"
                            >
                                {escalating ? 'Adding…' : 'Add to Threats'}
                            </button>
                        </div>
                        {escalateResult && (
                            <div className={`mt-3 text-[11px] rounded-lg px-3 py-2 ${escalateResult.ok ? 'text-green bg-green/10 border border-green/30' : 'text-red bg-red/10 border border-red/30'}`}>
                                {escalateResult.message}
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
