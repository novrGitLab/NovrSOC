'use client';

import { useEffect, useState } from 'react';
import { CheckCircle2, XCircle } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// SOAR pipeline status. Everything here is real: the counts and the activity feed come from
// GET /api/incidents/automation-status (TheHive cases), and the alert figure from
// GET /api/wazuh/trend (the Wazuh indexer). Nothing is simulated to make the pipeline look busy
// — a quiet pipeline renders as quiet.
//
// Refreshes every 30s. Polling rather than a socket because the backend has no push channel,
// and 30s is well inside the useful window for a pipeline whose slowest stage (the 30-minute
// auto-close job) moves on a much longer cycle.

const REFRESH_MS = 30000;

interface SoarLogEntry {
    time: string;
    action: string;
    reason: string;
}

interface ActivityEntry {
    type: 'created' | 'resolved' | 'escalated';
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    time: string;
    case_id: string;
}

interface AutomationStatus {
    active: boolean;
    cases_created_today: number;
    auto_resolved_today: number;
    open_cases?: number;
    escalated_open?: number;
    avg_response_minutes: number | null;
    recent_log?: SoarLogEntry[];
    recent_activity?: ActivityEntry[];
}

const ACTIVITY_ICON: Record<ActivityEntry['type'], string> = {
    created: '📋',
    resolved: '✅',
    escalated: '🚨',
};

const ACTIVITY_STYLE: Record<ActivityEntry['type'], string> = {
    created: 'bg-blue/10 text-blue',
    resolved: 'bg-emerald-500/10 text-emerald-500',
    escalated: 'bg-red-500/10 text-red-500',
};

const SEVERITY_STYLE: Record<string, string> = {
    critical: 'bg-red-500/10 text-red-500',
    high: 'bg-orange/10 text-orange',
    medium: 'bg-amber-500/10 text-amber-500',
    low: 'bg-card-muted text-foreground-muted',
};

export function SOARAutomation() {
    const [status, setStatus] = useState<AutomationStatus | null>(null);
    const [alerts24h, setAlerts24h] = useState<number | null>(null);
    const [lastUpdated, setLastUpdated] = useState<string | null>(null);

    useEffect(() => {
        let cancelled = false;

        const load = () => {
            apiFetch(apiUrl('/api/incidents/automation-status'), { cache: 'no-store' })
                .then((r) => r.json())
                .then((data) => {
                    if (cancelled) return;
                    setStatus(data);
                    // Stamped from the response, not rendered inline from new Date() during
                    // render — that would differ between server and client markup and change on
                    // every unrelated re-render.
                    setLastUpdated(new Date().toLocaleTimeString('en-GB', { timeZone: 'Africa/Lagos' }));
                })
                .catch(() => {
                    if (!cancelled) setStatus({ active: false, cases_created_today: 0, auto_resolved_today: 0, avg_response_minutes: null });
                });

            // Wazuh alert volume is the pipeline's first stage and lives on a different service,
            // so it's a separate call rather than something automation-status fans out to.
            apiFetch(apiUrl('/api/wazuh/trend?range=24h'), { cache: 'no-store' })
                .then((r) => r.json())
                .then((data) => {
                    if (cancelled) return;
                    setAlerts24h(Array.isArray(data) ? data.reduce((s: number, p: { alerts?: number }) => s + (p.alerts ?? 0), 0) : null);
                })
                .catch(() => { if (!cancelled) setAlerts24h(null); });
        };

        load();
        const interval = setInterval(load, REFRESH_MS);
        return () => { cancelled = true; clearInterval(interval); };
    }, []);

    const activity = status?.recent_activity ?? [];

    const stages = [
        { label: 'Wazuh Alerts', window: '24h', count: alerts24h, icon: '🔍', tone: 'bg-blue/15 border-blue/30' },
        { label: 'Cases Created', window: 'today', count: status?.cases_created_today ?? null, icon: '📋', tone: 'bg-purple/15 border-purple/30' },
        { label: 'Auto-Resolved', window: 'today', count: status?.auto_resolved_today ?? null, icon: '✅', tone: 'bg-emerald-500/15 border-emerald-500/30' },
        { label: 'Escalated', window: 'open', count: status?.escalated_open ?? null, icon: '🚨', tone: 'bg-red-500/15 border-red-500/30' },
        { label: 'Analyst Open', window: 'now', count: status?.open_cases ?? null, icon: '👨‍💻', tone: 'bg-amber-500/15 border-amber-500/30' },
    ];

    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground">SOAR Automation</h1>
                <p className="text-xs text-foreground-muted">Automated case creation, status sync, and auto-resolution pipeline status.</p>
            </div>

            {/* Live pipeline */}
            <div className="bg-grey-900 rounded-2xl p-5 sm:p-6" style={{ backgroundColor: '#1C1F2E' }}>
                <div className="flex items-center gap-2 mb-4 flex-wrap">
                    <div className={`w-2 h-2 rounded-full ${status?.active ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`} />
                    <span className="text-white text-sm font-bold">
                        SOAR Pipeline — {status === null ? 'Checking…' : status.active ? 'Active' : 'Inactive'}
                    </span>
                    <span className="ml-auto text-[10px] text-white/40">
                        {lastUpdated ? `Updated ${lastUpdated} WAT · refreshes every 30s` : 'Loading…'}
                    </span>
                </div>

                <div className="flex items-center gap-2 overflow-x-auto pb-2">
                    {stages.map((stage, i) => (
                        <div key={stage.label} className="flex items-center gap-2 shrink-0">
                            <div className={`border rounded-xl p-3 text-center min-w-[116px] ${stage.tone}`}>
                                <div className="text-xl mb-1">{stage.icon}</div>
                                <div className="text-xl font-black text-white">{stage.count ?? '—'}</div>
                                <div className="text-[9px] text-white/50 mt-0.5">{stage.label}</div>
                                {/* Each stage names its own window — these are not all daily
                                    figures, and a bare number row would imply they are. */}
                                <div className="text-[8px] text-white/30 uppercase tracking-wider mt-0.5">{stage.window}</div>
                            </div>
                            {i < stages.length - 1 && <div className="text-white/30 text-lg shrink-0">→</div>}
                        </div>
                    ))}
                </div>
            </div>

            <div className={`rounded-xl p-4 flex items-center gap-3 border ${status?.active ? 'bg-green/10 border-green/30' : 'bg-red/10 border-red/30'}`}>
                {status?.active ? <CheckCircle2 size={20} className="text-green flex-shrink-0" /> : <XCircle size={20} className="text-red flex-shrink-0" />}
                <div>
                    <div className={`font-bold text-sm ${status?.active ? 'text-green' : 'text-red'}`}>
                        Automation pipeline: {status === null ? 'Checking…' : status.active ? 'Active' : 'Inactive'}
                    </div>
                    <div className="text-xs text-foreground-muted">
                        Wazuh-triggered case creation, status sync, and the 30-minute auto-resolve job for low/medium severity cases.
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                {[
                    { label: 'Cases Created Today', value: status?.cases_created_today ?? '—' },
                    { label: 'Auto-Resolved Today', value: status?.auto_resolved_today ?? '—' },
                    { label: 'Average Response Time', value: status?.avg_response_minutes != null ? `${status.avg_response_minutes}m` : '—' },
                ].map((s) => (
                    <div key={s.label} className="bg-card border border-border rounded-xl p-5">
                        <div className="text-3xl font-black text-foreground">{s.value}</div>
                        <div className="text-xs text-foreground-muted mt-1">{s.label}</div>
                    </div>
                ))}
            </div>

            {/* Live activity feed */}
            <div className="bg-card border border-border rounded-xl p-5">
                <div className="flex items-center justify-between mb-4 gap-3 flex-wrap">
                    <h2 className="font-bold text-sm text-foreground">Live Activity Feed</h2>
                    <div className="flex items-center gap-1.5">
                        <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
                        <span className="text-[10px] text-foreground-muted">Refreshes every 30s</span>
                    </div>
                </div>

                {activity.length === 0 ? (
                    <p className="text-xs text-foreground-muted text-center py-4">
                        {status === null ? 'Loading…' : 'No recent activity — pipeline is quiet'}
                    </p>
                ) : (
                    <div className="space-y-2">
                        {activity.map((a, i) => (
                            <div key={`${a.case_id}-${a.type}-${i}`} className="flex items-start gap-3 p-3 bg-card-muted/50 rounded-xl">
                                <div className={`w-7 h-7 rounded-full flex items-center justify-center shrink-0 text-xs ${ACTIVITY_STYLE[a.type]}`}>
                                    {ACTIVITY_ICON[a.type]}
                                </div>
                                <div className="flex-1 min-w-0">
                                    <p className="text-xs text-foreground font-medium truncate" title={a.title}>{a.title}</p>
                                    <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                                        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full uppercase ${SEVERITY_STYLE[a.severity] ?? SEVERITY_STYLE.low}`}>
                                            {a.severity}
                                        </span>
                                        <span className="text-[10px] text-foreground-muted">{a.time}</span>
                                    </div>
                                </div>
                                <span className={`text-[9px] font-bold px-2 py-1 rounded-full shrink-0 uppercase ${ACTIVITY_STYLE[a.type]}`}>
                                    {a.type}
                                </span>
                            </div>
                        ))}
                    </div>
                )}
                <p className="text-[10px] text-foreground-muted mt-3">
                    A &quot;resolved&quot; entry can&apos;t be distinguished from a manual resolve, and a
                    &quot;created&quot; entry doesn&apos;t record whether the webhook or an analyst opened the
                    case — TheHive stores no marker for either.
                </p>
            </div>

            <div className="bg-card border border-border rounded-xl p-5">
                <h2 className="font-bold text-sm text-foreground mb-4">Recent SOAR Activity</h2>
                {!status?.recent_log || status.recent_log.length === 0 ? (
                    <p className="text-xs text-foreground-muted">No SOAR activity yet today.</p>
                ) : (
                    <div className="space-y-1.5">
                        {status.recent_log.map((entry, i) => (
                            <div key={i} className="flex items-center gap-3 text-xs py-1.5 border-b border-border last:border-0">
                                <span className="font-mono text-foreground-muted w-12 shrink-0">{entry.time}</span>
                                <span className="font-bold text-foreground shrink-0">{entry.action}</span>
                                <span className="text-foreground-muted truncate">{entry.reason}</span>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            <div className="bg-card border border-border rounded-xl p-5">
                <h2 className="font-bold text-sm text-foreground mb-4">Active Workflows</h2>
                {[{ name: 'Wazuh Critical Alert Response', trigger: 'Wazuh webhook (level 9+)', action: 'Create case', status: 'configured', executions: 0 }].map((wf) => (
                    <div key={wf.name} className="flex items-center justify-between p-4 bg-card-muted rounded-xl border border-border flex-wrap gap-2">
                        <div>
                            <div className="font-semibold text-sm text-foreground">{wf.name}</div>
                            <div className="text-xs text-foreground-muted mt-1">Trigger: {wf.trigger} → Action: {wf.action}</div>
                        </div>
                        <div className="flex items-center gap-3">
                            <span className="text-xs font-bold px-2 py-1 rounded-full border text-blue bg-blue/10 border-blue/30">
                                Configured
                            </span>
                            <span className="text-xs text-foreground-muted">{wf.executions} executions</span>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}
