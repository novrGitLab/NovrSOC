'use client';

// VMS overview (phase P4) — the attack-surface landing page: what is exposed, what changed in the
// last 7 days, recent scans and whether the scanner worker is alive. All from /api/vms/overview.
// "Connected" (phase P10) is the backend's record of authenticated worker requests (heartbeat or
// job poll) within its online window — never a guess from a process running.

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Radar, AlertTriangle } from 'lucide-react';
import { loadJson } from '@/lib/alerts';
import { VmsTrends } from './VmsTrends';
import {
    fmtWat, SCAN_STATUS_STYLE, SCAN_KIND_LABEL, describeEvent, EVENT_LABEL, SEVERITIES, SEVERITY_STYLE, ENGINE_STATE_LABEL, ENGINE_STATE_STYLE,
    type VmsScan, type VmsEvent, type VmsOperations, type VmsEndpointsResponse,
} from '@/lib/vms';

// P19: exposure, managed-endpoint coverage, scan activity and engine health, each from its own
// endpoint — a section whose source cannot be read is left out, never shown as zero.
interface FindingSummary { open: number; by_severity: Record<string, number>; known_exploited_open: number; overdue: number }
interface MostVulnerable { asset_id: string; value: string; open: number; by_severity: Record<string, number>; max_risk: number }

interface Overview {
    assets: { active: number; internet_facing: number; gone: number; open_services: number };
    last_7_days: { new_assets: number; changed_assets: number; gone_assets: number; new_services: number };
    active_scopes: number;
    recent_scans: VmsScan[];
    most_vulnerable_assets?: MostVulnerable[] | null;
    coverage?: { wazuh_endpoints: number; external_assets: number; assessed_last_30_days: number | null; assessments_last_30_days: number | null; checks_not_run_last_30_days: number | null };
    worker: {
        last_heartbeat_at: string | null; seen_recently: boolean;
        // Phase P10 (absent from an older backend):
        state?: 'online' | 'offline' | 'never'; source?: 'presence' | 'job_heartbeat' | 'none';
        online_workers?: number; online_window_seconds?: number; workers?: WorkerInfo[];
    };
}
interface WorkerInfo {
    worker_id: string; online: boolean; kinds: string[]; tools: Record<string, boolean>; version: string | null;
    last_seen_at: string; last_heartbeat_at: string | null; last_claim_at: string | null; last_job_at: string | null;
}

/** Tools a worker needs for the kinds it runs, that it reported as missing. */
function missingTools(w: WorkerInfo): string[] {
    const need: Record<string, string[]> = { discovery: ['subfinder', 'dnsx', 'httpx'], ports: ['nmap'], vuln_nuclei: ['nuclei'], vuln_openvas: ['openvas'] };
    return [...new Set(w.kinds.flatMap((k) => need[k] ?? []))].filter((t) => w.tools[t] === false);
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

export function VmsOverview() {
    const [data, setData] = useState<Overview | null>(null);
    const [events, setEvents] = useState<VmsEvent[]>([]);
    const [findings, setFindings] = useState<FindingSummary | null>(null);
    const [ops, setOps] = useState<VmsOperations | null>(null);
    const [coverage, setCoverage] = useState<VmsEndpointsResponse['coverage'] | null>(null);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        let active = true;
        void Promise.all([loadJson<Overview>('/api/vms/overview'), loadJson<{ events: VmsEvent[] }>('/api/vms/events?days=7')]).then(([o, e]) => {
            if (!active) return;
            setData(o.ok ? o.data : null);
            setError(o.ok ? null : o.error);
            setEvents(e.ok ? e.data.events.slice(0, 15) : []);
        });
        void Promise.all([loadJson<FindingSummary>('/api/vms/findings/summary'), loadJson<VmsOperations>('/api/vms/operations'), loadJson<VmsEndpointsResponse>('/api/vms/endpoints')]).then(([f, o, en]) => {
            if (!active) return;
            setFindings(f.ok ? f.data : null);
            setOps(o.ok ? o.data : null);
            setCoverage(en.ok ? en.data.coverage : null);
        });
        return () => { active = false; };
    }, []);

    return (
        <div className="space-y-5">
            <div>
                <h1 className="text-lg font-black text-foreground flex items-center gap-2"><Radar className="w-5 h-5" /> Vulnerability Management</h1>
                <p className="text-xs text-foreground-muted">Your attack surface: what is exposed, what changed, and what has been scanned. Only authorised scope is ever scanned.</p>
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {data && (
                <>
                    {!data.worker.seen_recently && (
                        <div className="rounded-xl p-3 border border-amber/30 bg-amber/10 text-xs text-amber font-semibold flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4" />
                            {data.worker.last_heartbeat_at
                                ? `No scanner worker has been heard from for ${Math.round((data.worker.online_window_seconds ?? 900) / 60)} minutes; last seen ${fmtWat(data.worker.last_heartbeat_at)}. Queued scans will wait until one is back.`
                                : 'No scanner worker has connected yet: the backend has not accepted a request from one. A worker process that is running but cannot authenticate does not count. Scans can be queued but will not run until one connects.'}
                        </div>
                    )}
                    {data.worker.source === 'job_heartbeat' && (
                        <p className="text-[11px] text-foreground-muted">Worker status is read from scan-job heartbeats only, so an idle worker cannot be seen. Apply sql/2026-10-18_p10_vms_worker_presence.sql to record worker presence.</p>
                    )}
                    {data.worker.workers && data.worker.workers.length > 0 && (
                        <div className="bg-card border border-border rounded-xl p-4">
                            <h2 className="text-sm font-black text-foreground mb-2">Scanner workers</h2>
                            <div className="overflow-x-auto">
                                <table className="w-full text-xs">
                                    <thead><tr className="text-left text-foreground-muted"><th className="py-1 pr-3">Worker</th><th className="pr-3">Status</th><th className="pr-3">Last seen</th><th className="pr-3">Last poll</th><th className="pr-3">Last job</th><th className="pr-3">Runs</th><th>Missing tools</th></tr></thead>
                                    <tbody>
                                        {data.worker.workers.map((w) => (
                                            <tr key={w.worker_id} className="border-t border-border">
                                                <td className="py-1.5 pr-3 font-mono text-foreground">{w.worker_id}{w.version ? <span className="text-foreground-muted"> v{w.version}</span> : null}</td>
                                                <td className="pr-3"><span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${w.online ? 'bg-green/10 text-green' : 'bg-amber/10 text-amber'}`}>{w.online ? 'connected' : 'not heard from'}</span></td>
                                                <td className="pr-3">{fmtWat(w.last_seen_at)}</td>
                                                <td className="pr-3">{fmtWat(w.last_claim_at)}</td>
                                                <td className="pr-3">{fmtWat(w.last_job_at)}</td>
                                                <td className="pr-3">{w.kinds.join(', ') || '—'}</td>
                                                <td className={missingTools(w).length ? 'text-amber font-semibold' : 'text-foreground-muted'}>{missingTools(w).join(', ') || 'none'}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                    {data.active_scopes === 0 && (
                        <div className="rounded-xl p-3 border border-border bg-card text-xs text-foreground">
                            No authorised scope yet. <Link href="/admin/vms/scope" className="text-purple font-bold underline">Add the domains and IP ranges you are authorised to assess</Link> before scanning.
                        </div>
                    )}
                    {findings && (
                        <section aria-label="Exposure" className="grid grid-cols-2 lg:grid-cols-6 gap-3">
                            {SEVERITIES.map((sev) => (
                                <Link key={sev} href="/admin/vms/findings" className="bg-card border border-border rounded-xl p-4">
                                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">Open {sev}</p>
                                    <p className={`text-2xl font-black mt-1 inline-block px-2 rounded ${(findings.by_severity[sev] ?? 0) ? SEVERITY_STYLE[sev] : 'text-foreground'}`}>{findings.by_severity[sev] ?? 0}</p>
                                </Link>
                            ))}
                            <Tile label="Known exploited (KEV)" value={findings.known_exploited_open} href="/admin/vms/findings" />
                            <Tile label="Overdue" value={findings.overdue} href="/admin/vms/findings?overdue=true" />
                        </section>
                    )}
                    {(coverage || ops) && (
                        <section aria-label="Coverage and scanning" className="grid grid-cols-2 lg:grid-cols-6 gap-3">
                            {coverage && <Tile label="Managed endpoints" value={coverage.active} href="/admin/vms/endpoints" />}
                            {coverage && <Tile label="Eligible for assessment" value={coverage.eligible} href="/admin/vms/endpoints" />}
                            {coverage && <Tile label="Awaiting assessment" value={coverage.awaiting_assessment} href="/admin/vms/endpoints" />}
                            {coverage && <Tile label="Endpoint coverage (30 days)" value={coverage.active ? `${Math.round((coverage.assessed_last_30_days / coverage.active) * 100)}%` : '—'} href="/admin/vms/endpoints" />}
                            {ops && <Tile label="Active scans" value={ops.queue.queued + ops.queue.running} href="/admin/vms/operations" />}
                            {ops && <Tile label="Failed scans (7 days)" value={Object.values(ops.last_7_days).reduce((n, k) => n + k.failed, 0)} href="/admin/vms/operations" />}
                        </section>
                    )}
                    {ops && (
                        <div className="flex flex-wrap gap-2 items-center text-[11px]">
                            <span className="font-bold text-foreground-muted uppercase tracking-wider text-[10px]">Engines</span>
                            {ops.engines.map((e) => (
                                <Link key={e.id} href="/admin/vms/operations" title={e.note} className={`font-bold px-2 py-1 rounded-full ${ENGINE_STATE_STYLE[e.state]}`}>{e.label.split(' (')[0]}: {ENGINE_STATE_LABEL[e.state]}</Link>
                            ))}
                        </div>
                    )}
                    {data.most_vulnerable_assets && data.most_vulnerable_assets.length > 0 && (
                        <section className="bg-card border border-border rounded-xl p-4">
                            <h2 className="text-sm font-black text-foreground mb-2">Most vulnerable assets</h2>
                            <div className="space-y-1.5">
                                {data.most_vulnerable_assets.map((a) => (
                                    <Link key={a.asset_id} href={`/admin/vms/findings?asset_id=${a.asset_id}`} className="flex items-center justify-between gap-2 text-xs border-t border-border pt-1.5 first:border-0 first:pt-0">
                                        <span className="font-mono font-bold text-foreground">{a.value}</span>
                                        <span className="flex flex-wrap gap-1 justify-end">
                                            {SEVERITIES.filter((sev) => a.by_severity[sev]).map((sev) => <span key={sev} className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${SEVERITY_STYLE[sev]}`}>{a.by_severity[sev]} {sev}</span>)}
                                            <span className="text-foreground-muted">{a.open} open</span>
                                        </span>
                                    </Link>
                                ))}
                            </div>
                        </section>
                    )}
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                        <Tile label="Active assets" value={data.assets.active} href="/admin/vms/assets" />
                        <Tile label="Internet-facing" value={data.assets.internet_facing} href="/admin/vms/assets?exposure=internet" />
                        <Tile label="Open services" value={data.assets.open_services} />
                        <Tile label="Authorised scopes" value={data.active_scopes} href="/admin/vms/scope" />
                    </div>
                    {data.coverage && (
                        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
                            <Tile label="Wazuh endpoints" value={data.coverage.wazuh_endpoints} href="/admin/vms/assets?source=wazuh" />
                            <Tile label="External assets" value={data.coverage.external_assets} href="/admin/vms/assets?source=external" />
                            <Tile label="Assessed (30 days)" value={data.coverage.assessed_last_30_days ?? 'unknown'} />
                            <Tile label="Assessments (30 days)" value={data.coverage.assessments_last_30_days ?? 'not set up'} href="/admin/vms/assessments" />
                            <Tile label="Checks not run (30 days)" value={data.coverage.checks_not_run_last_30_days ?? '—'} href="/admin/vms/assessments" />
                        </div>
                    )}
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                        <Tile label="New assets (7 days)" value={data.last_7_days.new_assets} />
                        <Tile label="Changed assets (7 days)" value={data.last_7_days.changed_assets} />
                        <Tile label="New services (7 days)" value={data.last_7_days.new_services} />
                        <Tile label="Gone assets" value={data.assets.gone} />
                    </div>
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                        <div className="bg-card border border-border rounded-xl p-4 space-y-2">
                            <div className="flex items-center justify-between"><h2 className="text-sm font-black text-foreground">Recent scans</h2><Link href="/admin/vms/scans" className="text-[11px] font-bold text-purple">All scans →</Link></div>
                            {data.recent_scans.length === 0 ? <p className="text-xs text-foreground-muted">No data — no scan has been queued yet.</p> : data.recent_scans.map((s) => (
                                <div key={s.id} className="flex items-center justify-between gap-2 text-xs border-t border-border pt-2">
                                    <span className="text-foreground">{SCAN_KIND_LABEL[s.kind]}</span>
                                    <span className="text-foreground-muted">{fmtWat(s.finished_at ?? s.requested_at)}</span>
                                    <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${SCAN_STATUS_STYLE[s.status]}`}>{s.status}</span>
                                </div>
                            ))}
                        </div>
                        <div className="bg-card border border-border rounded-xl p-4 space-y-2">
                            <h2 className="text-sm font-black text-foreground">Changes in the last 7 days</h2>
                            {events.length === 0 ? <p className="text-xs text-foreground-muted">No data — nothing new, changed or gone.</p> : events.map((e) => (
                                <div key={e.id} className="text-xs border-t border-border pt-2">
                                    <span className="font-bold text-foreground">{EVENT_LABEL[e.event] ?? e.event}</span>
                                    <span className="text-foreground"> · {e.vms_assets?.value ?? '—'}</span>
                                    <span className="text-foreground-muted"> · {describeEvent(e)} · {fmtWat(e.at)}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                    <VmsTrends />
                </>
            )}
        </div>
    );
}
