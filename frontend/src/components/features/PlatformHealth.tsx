'use client';

import { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import { CheckCircle2, AlertTriangle, Send } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Wazuh Manager, Database, and Claude AI are real — fetched from GET /api/platform/health
// (routes/platform.ts). Everything else here is still mock: no health-check job exists yet
// for the frontend/CDN, individual threat-intel provider APIs, or third-party webhooks — a
// real version of those needs a lightweight poller persisting latency samples somewhere
// queryable, not a per-page-load fetch. Rows backed by the real check are marked LIVE below;
// everything else stays marked MOCK rather than silently blending the two.

// `detail` carries the backend check's own explanation where it has one (MISP reports whether
// it's unconfigured, unreachable, or reachable-but-rejecting-the-key — three states that need
// three different fixes, and which a bare amber dot can't distinguish).
interface Service { name: string; url: string; status: 'operational' | 'degraded' | 'outage'; uptime: number; latency: number; live?: boolean; detail?: string }
// Vercel doesn't auto-expose its VERCEL_URL as a NEXT_PUBLIC_ var (that needs an explicit
// mapping in next.config.ts, which doesn't exist here), so NEXT_PUBLIC_VERCEL_URL is only ever
// populated if it's set by hand in the deployment's env vars. novr-soc.vercel.app is the
// fallback since that's the origin CORS was actually failing for (backend/src/index.ts's
// ALLOWED_ORIGINS lists it alongside the older socnovr.vercel.app).
const FRONTEND_URL_LABEL = process.env.NEXT_PUBLIC_VERCEL_URL || 'novr-soc.vercel.app';
const SERVICES: Service[] = [
    { name: 'NovrSOC Frontend', url: FRONTEND_URL_LABEL, status: 'operational', uptime: 99.98, latency: 124 },
    { name: 'NovrSOC Backend API', url: 'novrsoc-production-1fb6.up.railway.app', status: 'operational', uptime: 99.91, latency: 287 },
    { name: 'Supabase Database', url: 'bwtmjukbrtijnwusrrjb.supabase.co', status: 'operational', uptime: 99.99, latency: 45 },
    { name: 'Wazuh Manager', url: '169.58.242.174:55000', status: 'operational', uptime: 99.87, latency: 312 },
    { name: 'Wazuh Indexer', url: '169.58.242.174:9200', status: 'operational', uptime: 99.87, latency: 298 },
    // Real check — driven by GET /api/platform/health's MISP entry via REAL_CHECK_NAME_MAP
    // below, so the status/latency shown here are live, not the placeholder values.
    { name: 'MISP', url: '169.58.242.194', status: 'operational', uptime: 0, latency: 0 },
];

interface ApiStatus { name: string; last_check: string; status: 'up' | 'down'; latency: number; live?: boolean }
const API_STATUS: ApiStatus[] = [
    { name: 'IP Reputation Engine', last_check: '2 min ago', status: 'up', latency: 234 },
    { name: 'Global Threat Intelligence', last_check: '2 min ago', status: 'up', latency: 187 },
    { name: 'Multi-Engine Scanner', last_check: '2 min ago', status: 'up', latency: 892 },
    { name: 'Malicious URL Database', last_check: '2 min ago', status: 'up', latency: 143 },
    { name: 'Vulnerability Database', last_check: '5 min ago', status: 'up', latency: 997 },
    { name: 'Threat Classification', last_check: '2 min ago', status: 'up', latency: 156 },
    { name: 'URL Analysis Engine', last_check: '2 min ago', status: 'up', latency: 445 },
    { name: 'IP Intelligence API', last_check: '2 min ago', status: 'up', latency: 312 },
    { name: 'Email Service (SendGrid)', last_check: '10 min ago', status: 'up', latency: 201 },
    { name: 'Uptime Monitor', last_check: '5 min ago', status: 'up', latency: 178 },
    { name: 'Slack Webhook', last_check: '1 hr ago', status: 'up', latency: 92 },
    { name: 'Claude AI (PHISHID)', last_check: '2 min ago', status: 'up', latency: 340 },
];

interface PlatformHealthResponse {
    overall: 'operational' | 'degraded' | 'outage';
    services: Array<{ name: string; status: 'up' | 'degraded' | 'down'; latency_ms: number; detail?: string }>;
    checked_at: string;
}

// 24h latency trend — deterministic synthetic samples (avoids a fresh random walk on every
// render) for the aggregate backend API response time.
const LATENCY_TREND = Array.from({ length: 24 }).map((_, h) => ({
    hour: `${String(h).padStart(2, '0')}:00`,
    latency: Math.round(240 + 60 * Math.sin(h / 3) + (h % 5) * 8),
}));

const INCIDENT_HISTORY = [
    { date: '2026-08-19', service: 'Wazuh Indexer', duration: '4 min', cause: 'Indexer restart during patch' },
    { date: '2026-08-11', service: 'NovrSOC Backend API', duration: '11 min', cause: 'Railway deploy — brief cold start' },
];

const REAL_CHECK_NAME_MAP: Record<string, { serviceName?: string; apiName?: string }> = {
    'Wazuh Manager': { serviceName: 'Wazuh Manager' },
    'Database': { serviceName: 'Supabase Database' },
    'Claude AI': { apiName: 'Claude AI (PHISHID)' },
    'MISP': { serviceName: 'MISP' },
};

export function PlatformHealth() {
    const [services, setServices] = useState(SERVICES);
    const [apiStatus, setApiStatus] = useState(API_STATUS);
    const [checkedAt, setCheckedAt] = useState<string | null>(null);
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
                if (!Array.isArray(data?.services)) return;
                setCheckedAt(data.checked_at);
                for (const check of data.services) {
                    const mapped = REAL_CHECK_NAME_MAP[check.name];
                    if (!mapped) continue;
                    if (mapped.serviceName) {
                        setServices((prev) => prev.map((s) => s.name !== mapped.serviceName ? s : {
                            ...s, live: true, latency: check.latency_ms, detail: check.detail,
                            status: check.status === 'up' ? 'operational' : check.status === 'degraded' ? 'degraded' : 'outage',
                        }));
                    }
                    if (mapped.apiName) {
                        setApiStatus((prev) => prev.map((a) => a.name !== mapped.apiName ? a : {
                            ...a, live: true, latency: check.latency_ms,
                            status: check.status === 'up' ? 'up' : 'down',
                            last_check: 'just now',
                        }));
                    }
                }
            })
            .catch(() => {}); // real check unreachable — rows just keep their mock values, unmarked live
    }, []);

    const allOperational = services.every((s) => s.status === 'operational') && apiStatus.every((a) => a.status === 'up');

    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground">Platform Health</h1>
                <p className="text-xs text-foreground-muted">Platform Administration · NovrSOC&apos;s own uptime and API status monitoring. Super admin only.</p>
            </div>

            <div className={`rounded-xl p-4 border flex items-center gap-3 ${allOperational ? 'bg-green/10 border-green/30' : 'bg-red/10 border-red/30'}`}>
                {allOperational ? <CheckCircle2 size={20} className="text-green" /> : <AlertTriangle size={20} className="text-red" />}
                <span className={`text-sm font-black ${allOperational ? 'text-green' : 'text-red'}`}>
                    {allOperational ? 'ALL SYSTEMS OPERATIONAL' : 'DEGRADED PERFORMANCE DETECTED'}
                </span>
            </div>

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
                <div className="flex items-center justify-between mb-3">
                    <p className="text-xs font-black text-foreground">Services</p>
                    {checkedAt && <p className="text-[10px] text-foreground-muted">Live checks as of {new Date(checkedAt).toLocaleTimeString()}</p>}
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                    {services.map((s) => (
                        <div key={s.name} className="bg-card border border-border rounded-xl p-4">
                            <div className="flex items-center justify-between mb-2">
                                <p className="text-sm font-bold text-foreground flex items-center gap-1.5">
                                    {s.name}
                                    <span className={`text-[8px] font-bold px-1 py-0.5 rounded ${s.live ? 'bg-green/10 text-green' : 'bg-card-muted text-foreground-muted'}`}>{s.live ? 'LIVE' : 'MOCK'}</span>
                                </p>
                                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${s.status === 'operational' ? 'bg-green' : s.status === 'degraded' ? 'bg-amber' : 'bg-red'}`} />
                            </div>
                            <p className="text-[10px] text-foreground-muted font-mono mb-3 truncate">{s.url}</p>
                            <div className="flex items-center justify-between text-xs">
                                {/* Uptime is only meaningful for the rows carrying a historical
                                    figure — the live checks measure a single request, not a
                                    window, so a 0% there would be a lie rather than a datum. */}
                                <span className="text-foreground-muted">Uptime: <span className="font-bold text-foreground">{s.uptime > 0 ? `${s.uptime}%` : '—'}</span></span>
                                <span className="text-foreground-muted">Latency: <span className="font-bold text-foreground">{s.latency}ms</span></span>
                            </div>
                            {s.detail && <p className="text-[10px] text-amber mt-2 leading-snug">{s.detail}</p>}
                        </div>
                    ))}
                </div>
            </div>

            <div className="bg-card border border-border rounded-xl shadow-sm overflow-hidden">
                <div className="px-6 py-4 border-b border-border">
                    <h3 className="font-bold text-foreground-muted text-xs tracking-wide uppercase">API Integrations Status</h3>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 divide-y sm:divide-y-0 divide-border">
                    {apiStatus.map((a) => (
                        <div key={a.name} className="flex items-center justify-between px-6 py-3 border-b border-border sm:border-r">
                            <div className="min-w-0">
                                <p className="text-xs font-bold text-foreground truncate flex items-center gap-1.5">
                                    {a.name}
                                    <span className={`text-[8px] font-bold px-1 py-0.5 rounded flex-shrink-0 ${a.live ? 'bg-green/10 text-green' : 'bg-card-muted text-foreground-muted'}`}>{a.live ? 'LIVE' : 'MOCK'}</span>
                                </p>
                                <p className="text-[10px] text-foreground-muted">Checked {a.last_check} · {a.latency}ms</p>
                            </div>
                            <span className={`text-[10px] font-bold uppercase flex-shrink-0 ml-2 ${a.status === 'up' ? 'text-green' : 'text-red'}`}>{a.status}</span>
                        </div>
                    ))}
                </div>
            </div>

            <div className="bg-card border border-border rounded-xl shadow-sm overflow-hidden">
                <div className="px-6 py-4 border-b border-border">
                    <h3 className="font-bold text-foreground-muted text-xs tracking-wide uppercase">Backend API Latency — Last 24h</h3>
                </div>
                <div className="h-64 w-full p-5">
                    <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={LATENCY_TREND}>
                            <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                            <XAxis dataKey="hour" tick={{ fill: 'var(--color-foreground-muted)', fontSize: 10 }} interval={3} />
                            <YAxis tick={{ fill: 'var(--color-foreground-muted)', fontSize: 10 }} unit="ms" />
                            <Tooltip contentStyle={{ background: 'var(--color-card)', border: '1px solid var(--color-border)', borderRadius: 8, fontSize: 12 }} />
                            <Line type="monotone" dataKey="latency" stroke="var(--color-blue)" strokeWidth={2} dot={false} />
                        </LineChart>
                    </ResponsiveContainer>
                </div>
            </div>

            <div>
                <p className="text-xs font-black text-foreground mb-3">Incident History — Last 30 Days</p>
                {INCIDENT_HISTORY.length === 0 ? (
                    <div className="bg-card border border-border rounded-xl p-6 text-center text-xs text-foreground-muted">No service degradations in the last 30 days.</div>
                ) : (
                    <div className="bg-card border border-border rounded-xl overflow-hidden">
                        <div className="overflow-x-auto scrollbar-thin">
                            <table className="w-full text-left">
                                <thead>
                                    <tr className="bg-grey-800">
                                        {['Date', 'Service', 'Duration', 'Cause'].map((c) => (
                                            <th key={c} className="px-4 py-3 text-[10px] font-semibold text-white uppercase tracking-widest whitespace-nowrap">{c}</th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-border text-sm">
                                    {INCIDENT_HISTORY.map((h, i) => (
                                        <tr key={i}>
                                            <td className="px-4 py-3 text-foreground-muted whitespace-nowrap">{h.date}</td>
                                            <td className="px-4 py-3 font-medium text-foreground whitespace-nowrap">{h.service}</td>
                                            <td className="px-4 py-3 text-foreground-muted">{h.duration}</td>
                                            <td className="px-4 py-3 text-foreground-muted">{h.cause}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
