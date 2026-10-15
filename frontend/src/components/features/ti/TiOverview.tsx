'use client';

// Threat Information System overview (phase P6): indicator counts, this organisation's new matches,
// feed health with the last runs, and an AI threat briefing grounded in those records only.

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Crosshair, AlertTriangle, RefreshCw } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { loadJson } from '@/lib/alerts';
import { fmtWat } from '@/lib/vms';
import { AiPanel } from '@/components/shared/AiPanel';
import type { TiFeed, TiRun } from '@/lib/ti';

interface Overview {
    indicators: { active: number; new_last_24h: number; by_type: Record<string, number> };
    matches: { new: number; total: number };
    feeds: TiFeed[];
}

function Tile({ label, value, href }: { label: string; value: number | string; href?: string }) {
    const body = (
        <div className="bg-card border border-border rounded-xl p-4">
            <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{label}</p>
            <p className="text-2xl font-black text-foreground mt-1">{value}</p>
        </div>
    );
    return href ? <Link href={href}>{body}</Link> : body;
}

export function TiOverview() {
    const [data, setData] = useState<Overview | null>(null);
    const [runs, setRuns] = useState<TiRun[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [msg, setMsg] = useState<string | null>(null);
    const [busy, setBusy] = useState<string | null>(null);
    const [reload, setReload] = useState(0);
    const [period, setPeriod] = useState<'7d' | '30d'>('7d');

    useEffect(() => {
        let active = true;
        void Promise.all([loadJson<Overview>('/api/ti/overview'), loadJson<{ runs: TiRun[] }>('/api/ti/feeds')]).then(([o, f]) => {
            if (!active) return;
            setData(o.ok ? o.data : null);
            setError(o.ok ? null : o.error);
            setRuns(f.ok ? f.data.runs.slice(0, 20) : []);
        });
        return () => { active = false; };
    }, [reload]);

    async function run(id: string) {
        setBusy(id);
        setMsg(null);
        const r = await apiFetch(apiUrl(`/api/ti/feeds/${id}/run`), { method: 'POST' });
        const d = await r.json().catch(() => null);
        setBusy(null);
        setMsg(r.ok ? `${id}: ${d.counts.new} new, ${d.counts.updated} updated, ${d.counts.invalid} invalid` : `${id}: ${d?.error ?? `HTTP ${r.status}`}`);
        setReload((x) => x + 1);
    }

    return (
        <div className="space-y-5">
            <div>
                <h1 className="text-lg font-black text-foreground flex items-center gap-2"><Crosshair className="w-5 h-5" /> Threat Information System</h1>
                <p className="text-xs text-foreground-muted">Indicators from abuse.ch (ThreatFox, URLhaus, Feodo Tracker) and CISA KEV, matched against your alerts, assets, findings and cases. Labels and confidence are what each source reported.</p>
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {data && (
                <>
                    {data.feeds.some((f) => f.enabled && (f.failing || f.stale)) && (
                        <div className="rounded-xl p-3 border border-amber/30 bg-amber/10 text-xs text-amber font-semibold flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4" />
                            Coverage gap: {data.feeds.filter((f) => f.enabled && (f.failing || f.stale)).map((f) => f.name).join(', ')} {data.feeds.filter((f) => f.enabled && (f.failing || f.stale)).length === 1 ? 'is' : 'are'} failing or out of date. Matches from those sources may be missing.
                        </div>
                    )}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <Tile label="Active indicators" value={data.indicators.active} href="/admin/ti/indicators" />
                        <Tile label="New in 24 h" value={data.indicators.new_last_24h} href="/admin/ti/indicators" />
                        <Tile label="New matches in your environment" value={data.matches.new} href="/admin/ti/matches" />
                        <Tile label="All matches" value={data.matches.total} href="/admin/ti/matches" />
                    </div>
                    <p className="text-[11px] text-foreground-muted">By type: {Object.entries(data.indicators.by_type).map(([t, n]) => `${t} ${n}`).join(' · ')}</p>
                    <div className="bg-card border border-border rounded-xl p-4">
                        <h2 className="text-sm font-black text-foreground mb-2">Feeds</h2>
                        {msg && <p className="text-[11px] text-foreground-muted mb-2">{msg}</p>}
                        <table className="w-full text-xs">
                            <thead><tr className="text-left text-[10px] uppercase text-foreground-muted"><th className="py-1">Feed</th><th>Last success</th><th>Last run</th><th>State</th><th /></tr></thead>
                            <tbody>
                                {data.feeds.map((f) => (
                                    <tr key={f.id} className="border-t border-border">
                                        <td className="py-1.5 font-semibold">{f.name}</td>
                                        <td>{fmtWat(f.last_success_at)}</td>
                                        <td className="text-foreground-muted">{f.last_counts ? `${f.last_counts.fetched} fetched · ${f.last_counts.new} new · ${f.last_counts.invalid} invalid` : '—'}</td>
                                        <td className={f.failing ? 'text-red' : f.stale ? 'text-amber' : 'text-green'}>{!f.enabled ? 'off' : f.failing ? `failing: ${f.last_error}` : f.stale ? 'stale' : 'current'}</td>
                                        <td className="text-right"><button disabled={busy !== null} onClick={() => void run(f.id)} className="text-[11px] font-bold text-blue disabled:opacity-50 inline-flex items-center gap-1"><RefreshCw className={`w-3 h-3 ${busy === f.id ? 'animate-spin' : ''}`} /> Run now</button></td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                        <p className="text-[10px] text-foreground-muted mt-2">Run now is for SOC managers. Feeds run every 6 hours (KEV daily); ThreatFox and URLhaus need an abuse.ch Auth-Key on the server.</p>
                    </div>
                    {runs.length > 0 && (
                        <div className="bg-card border border-border rounded-xl p-4">
                            <h2 className="text-sm font-black text-foreground mb-2">Recent runs</h2>
                            {runs.map((r) => <p key={r.id} className="text-[11px] text-foreground-muted">{fmtWat(r.started_at)} · {r.feed_id} · <span className={r.status === 'failed' ? 'text-red' : ''}>{r.status}</span>{r.status === 'ok' ? ` · ${r.fetched} fetched, ${r.new} new, ${r.updated} updated, ${r.duplicates} duplicate, ${r.invalid} invalid` : r.error ? ` · ${r.error}` : ''}</p>)}
                        </div>
                    )}
                    <div className="space-y-2">
                        <div className="flex gap-1 bg-card border border-border rounded-lg p-1 w-fit">
                            {(['7d', '30d'] as const).map((p) => <button key={p} onClick={() => setPeriod(p)} className={`text-[11px] font-bold px-2.5 py-1 rounded-md ${period === p ? 'bg-blue text-white' : 'text-foreground-muted'}`}>Last {p === '7d' ? '7' : '30'} days</button>)}
                        </div>
                        <AiPanel key={period} purpose="threat_briefing" subjectId={period} title={`AI threat briefing — last ${period === '7d' ? '7' : '30'} days`} />
                    </div>
                </>
            )}
        </div>
    );
}
