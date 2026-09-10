'use client';

import { useState, useEffect } from 'react';
import { CheckCircle2, AlertTriangle, Send } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Everything on this page is a real check. GET /api/platform/health (routes/platform.ts) runs
// five live probes per request — Wazuh Manager, Database (Supabase), Claude AI, MISP and
// TheHive — and returns the integration key/config state alongside them.
//
// This page used to pad that out with a hardcoded service list carrying invented uptime
// percentages (99.98%, 99.91%…), a twelve-row API table of made-up latencies, a synthetic sine
// wave posing as a 24h latency trend, and a fabricated incident history. All of that is gone.
// The rule for anything added back: if there's no poller actually measuring it, don't draw it.
//
// Note on uptime specifically: these probes measure a single request at page load, not a
// window, so there is no uptime figure to show. A percentage here would have to be invented,
// which is exactly what was removed — wire up a real poller with persisted samples first.

interface HealthCheck {
    name: string;
    status: 'up' | 'degraded' | 'down';
    latency_ms: number;
    // The check's own explanation where it has one — MISP distinguishes unconfigured,
    // unreachable, and reachable-but-rejecting-the-key, three states needing three different
    // fixes that a bare amber dot can't tell apart.
    detail?: string;
}

interface Integration {
    configured: boolean;
    removed?: boolean;
    detail?: string;
}

interface PlatformHealthResponse {
    overall: 'operational' | 'degraded' | 'outage';
    services: HealthCheck[];
    integrations?: Record<string, Integration>;
    checked_at: string;
}

const STATUS_DOT: Record<HealthCheck['status'], string> = {
    up: 'bg-green',
    degraded: 'bg-amber',
    down: 'bg-red',
};

const STATUS_LABEL: Record<HealthCheck['status'], string> = {
    up: 'text-green',
    degraded: 'text-amber',
    down: 'text-red',
};

export function PlatformHealth() {
    const [health, setHealth] = useState<PlatformHealthResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [loadError, setLoadError] = useState(false);
    const [testing, setTesting] = useState(false);
    const [testResult, setTestResult] = useState<Record<string, string> | null>(null);

    const runAlertTest = async () => {
        setTesting(true);
        setTestResult(null);
        try {
            const r = await apiFetch(apiUrl('/api/alerts/test'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: 'rayne@cybernovr.com' }),
            });
            const data = await r.json();
            setTestResult(data.results ?? { error: data.error || 'Unknown response' });
        } catch {
            setTestResult({ error: 'Test failed — check console' });
        } finally {
            setTesting(false);
        }
    };

    useEffect(() => {
        apiFetch(apiUrl('/api/platform/health'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data: PlatformHealthResponse) => {
                if (!Array.isArray(data?.services)) { setLoadError(true); return; }
                setHealth(data);
            })
            .catch(() => setLoadError(true))
            .finally(() => setLoading(false));
    }, []);

    const services = health?.services ?? [];
    const integrations = Object.entries(health?.integrations ?? {});
    const allOperational = health?.overall === 'operational';

    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground">Platform Health</h1>
                <p className="text-xs text-foreground-muted">Platform Administration · Live service checks and integration status. Super admin only.</p>
            </div>

            {loading ? (
                <div className="rounded-xl p-4 border border-border bg-card text-sm text-foreground-muted">Running live service checks…</div>
            ) : loadError ? (
                <div className="rounded-xl p-4 border border-red/30 bg-red/10 flex items-center gap-3">
                    <AlertTriangle size={20} className="text-red" />
                    <span className="text-sm font-black text-red">HEALTH CHECK UNREACHABLE — could not reach the backend</span>
                </div>
            ) : (
                <div className={`rounded-xl p-4 border flex items-center gap-3 ${allOperational ? 'bg-green/10 border-green/30' : 'bg-amber/10 border-amber/30'}`}>
                    {allOperational ? <CheckCircle2 size={20} className="text-green" /> : <AlertTriangle size={20} className="text-amber" />}
                    <span className={`text-sm font-black ${allOperational ? 'text-green' : 'text-amber'}`}>
                        {health?.overall === 'operational' ? 'ALL CHECKED SERVICES OPERATIONAL'
                            : health?.overall === 'outage' ? 'SERVICE OUTAGE DETECTED'
                                : 'DEGRADED PERFORMANCE DETECTED'}
                    </span>
                </div>
            )}

            <div className="bg-card border border-border rounded-xl p-4">
                <div className="flex items-center justify-between gap-4 flex-wrap">
                    <div>
                        <p className="text-sm font-bold text-foreground">Alert Communications</p>
                        <p className="text-[11px] text-foreground-muted">Send a live test alert through Slack and email to confirm both channels are working.</p>
                    </div>
                    <button
                        onClick={runAlertTest}
                        disabled={testing}
                        className="flex items-center gap-1.5 bg-primary text-white text-xs font-bold px-4 py-2.5 rounded-xl hover:opacity-90 transition-opacity disabled:opacity-50 shrink-0"
                    >
                        <Send size={13} /> {testing ? 'Sending...' : 'Test Alert Communications'}
                    </button>
                </div>

                {testResult && (
                    <div className="mt-4 bg-card-muted/60 rounded-xl p-4">
                        <div className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">Results</div>
                        {Object.entries(testResult).map(([channel, result]) => (
                            <div key={channel} className="flex items-center gap-2 text-xs py-1">
                                <div className={`w-2 h-2 rounded-full flex-shrink-0 ${result === 'sent' ? 'bg-green' : 'bg-red'}`} />
                                <span className="font-bold capitalize text-foreground">{channel}:</span>
                                <span className={result === 'sent' ? 'text-green' : 'text-red'}>{result}</span>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            <div>
                <div className="flex items-center justify-between mb-3 gap-3 flex-wrap">
                    <p className="text-xs font-black text-foreground">Service Checks</p>
                    {health?.checked_at && (
                        <p className="text-[10px] text-foreground-muted">Checked at {new Date(health.checked_at).toLocaleTimeString()}</p>
                    )}
                </div>
                {services.length === 0 ? (
                    <div className="bg-card border border-border rounded-xl p-6 text-center text-xs text-foreground-muted">
                        {loading ? 'Running checks…' : 'No service checks returned.'}
                    </div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                        {services.map((s) => (
                            <div key={s.name} className="bg-card border border-border rounded-xl p-4">
                                <div className="flex items-center justify-between mb-2 gap-2">
                                    <p className="text-sm font-bold text-foreground">{s.name}</p>
                                    <span className={`w-2 h-2 rounded-full flex-shrink-0 ${STATUS_DOT[s.status]}`} />
                                </div>
                                <div className="flex items-center justify-between text-xs">
                                    <span className={`font-bold uppercase ${STATUS_LABEL[s.status]}`}>{s.status}</span>
                                    <span className="text-foreground-muted">Latency: <span className="font-bold text-foreground">{s.latency_ms}ms</span></span>
                                </div>
                                {s.detail && <p className="text-[10px] text-foreground-muted mt-2 leading-snug">{s.detail}</p>}
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Integration key/config state, straight from the health response. This is a
                configuration report — whether the key is present and the right shape — not a
                liveness probe, and it's labelled that way so it isn't read as uptime. */}
            {integrations.length > 0 && (
                <div className="bg-card border border-border rounded-xl shadow-sm overflow-hidden">
                    <div className="px-6 py-4 border-b border-border">
                        <h3 className="font-bold text-foreground-muted text-xs tracking-wide uppercase">Integration Configuration</h3>
                        <p className="text-[10px] text-foreground-muted mt-0.5">Whether each integration&apos;s credentials are present — not a liveness check.</p>
                    </div>
                    <div className="divide-y divide-border">
                        {integrations.map(([key, cfg]) => (
                            <div key={key} className="flex items-start justify-between gap-4 px-6 py-3">
                                <div className="min-w-0">
                                    <p className="text-xs font-bold text-foreground uppercase">{key}</p>
                                    {cfg.detail && <p className="text-[10px] text-foreground-muted leading-snug mt-0.5">{cfg.detail}</p>}
                                </div>
                                <span className={`text-[10px] font-bold uppercase flex-shrink-0 ${cfg.removed ? 'text-foreground-muted' : cfg.configured ? 'text-green' : 'text-amber'}`}>
                                    {cfg.removed ? 'Removed' : cfg.configured ? 'Configured' : 'Not configured'}
                                </span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            <p className="text-[10px] text-foreground-muted">
                Uptime percentages, latency history and incident history are not shown: no poller
                persists samples yet, so any figure here would be invented rather than measured.
            </p>
        </div>
    );
}
