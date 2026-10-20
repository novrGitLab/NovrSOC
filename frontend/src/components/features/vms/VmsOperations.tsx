'use client';

// Scanner Operations (phase P19): engine availability, workers, the queue, job outcomes, failures
// with retry, and the scan profiles. All from /api/vms/operations and /api/vms/profiles.
// An engine is "available" only when a connected worker reports it enabled with its tool installed;
// a scan that ran but could not reach its target is counted as inconclusive, never as a success;
// progress is what the worker reported (a fraction only when it reported done/total).

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { Gauge, RefreshCw, AlertTriangle } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { loadJson } from '@/lib/alerts';
import { getAdminUser } from '@/lib/admin-auth';
import {
    fmtWat, fmtDuration, scanProgress, SCAN_KIND_LABEL, SCAN_STATUS_STYLE, ENGINE_STATE_LABEL, ENGINE_STATE_STYLE, PROFILE_LABEL,
    type VmsOperations as Ops, type VmsProfile, type VmsScan,
} from '@/lib/vms';

const card = 'bg-card border border-border rounded-xl p-4';
const kindLabel = (k: string) => SCAN_KIND_LABEL[k as VmsScan['kind']] ?? k;

export function VmsOperations() {
    const canRun = ['super_admin', 'soc_manager', 'analyst'].includes(getAdminUser().role);
    const [ops, setOps] = useState<Ops | null>(null);
    const [profiles, setProfiles] = useState<VmsProfile[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [msg, setMsg] = useState<string | null>(null);
    const [tick, setTick] = useState(0);
    const reload = useCallback(() => setTick((t) => t + 1), []);

    useEffect(() => {
        let active = true;
        void Promise.all([loadJson<Ops>('/api/vms/operations'), loadJson<{ profiles: VmsProfile[] }>('/api/vms/profiles')]).then(([o, p]) => {
            if (!active) return;
            setOps(o.ok ? o.data : null);
            setError(o.ok ? null : o.error);
            setProfiles(p.ok ? p.data.profiles : null);
        });
        return () => { active = false; };
    }, [tick]);
    useEffect(() => {
        if (!ops || (ops.queue.queued === 0 && ops.queue.running === 0)) return;
        const t = setInterval(reload, 20_000);
        return () => clearInterval(t);
    }, [ops, reload]);

    async function retry(id: string) {
        setMsg(null);
        const r = await apiFetch(apiUrl(`/api/vms/scans/${id}/retry`), { method: 'POST' });
        const d = await r.json().catch(() => null);
        setMsg(r.ok ? (d?.existing ? 'The same scan is already queued.' : 'Queued again.') : d?.error ?? `HTTP ${r.status}`);
        reload();
    }

    const kinds = ops ? Object.entries(ops.last_7_days) : [];
    return (
        <div className="space-y-5">
            <div className="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <h1 className="text-lg font-black text-foreground flex items-center gap-2"><Gauge className="w-5 h-5" /> Scanner Operations</h1>
                    <p className="text-xs text-foreground-muted max-w-3xl">Which scanning engines can run now, what is queued and running, how scans ended over the last 7 days, and what each scan profile covers. Engine state comes from what the connected workers report.</p>
                </div>
                <button onClick={reload} className="flex items-center gap-1 text-[11px] font-bold border border-border rounded-lg px-3 py-1.5"><RefreshCw className="w-3.5 h-3.5" /> Refresh</button>
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {msg && <p role="status" className="text-xs text-foreground font-semibold">{msg}</p>}
            {ops && (
                <>
                    {ops.worker_presence.state !== 'online' && (
                        <div className="rounded-xl p-3 border border-amber/30 bg-amber/10 text-xs text-amber font-semibold flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4" />
                            {ops.worker_presence.state === 'never' ? 'No scanner worker has connected: queued scans will not run.' : `No scanner worker is connected (last seen ${fmtWat(ops.worker_presence.last_seen_at)}): queued scans wait until one is back.`}
                        </div>
                    )}
                    <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3" aria-label="Engines">
                        {ops.engines.map((e) => (
                            <div key={e.id} className={card}>
                                <div className="flex items-center justify-between gap-2">
                                    <p className="text-xs font-black text-foreground">{e.label}</p>
                                    <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full whitespace-nowrap ${ENGINE_STATE_STYLE[e.state]}`}>{ENGINE_STATE_LABEL[e.state]}</span>
                                </div>
                                <p className="text-[11px] text-foreground-muted mt-1">{e.note}</p>
                                {e.versions.length > 0 && <p className="text-[11px] text-foreground mt-1 font-mono break-words">{e.versions.join(' · ')}</p>}
                                {e.id === 'openvas' && e.versions.length === 0 && e.state === 'available' && <p className="text-[11px] text-foreground-muted mt-1">Feed state not reported yet (worker 1.8.0 reports it).</p>}
                            </div>
                        ))}
                    </section>

                    <section className="grid grid-cols-2 lg:grid-cols-4 gap-3" aria-label="Queue">
                        {[['Queued', ops.queue.queued], ['Running', ops.queue.running], ['Oldest queued', ops.queue.oldest_queued_at ? fmtWat(ops.queue.oldest_queued_at) : '—'], ['Failed (7 days)', kinds.reduce((n, [, v]) => n + v.failed, 0)]].map(([k, v]) => (
                            <div key={String(k)} className={card}><p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{k}</p><p className="text-xl font-black text-foreground mt-1">{v}</p></div>
                        ))}
                    </section>

                    <section className={card}>
                        <h2 className="text-sm font-black text-foreground mb-2">Scans in the last 7 days, by kind</h2>
                        {kinds.length === 0 ? <p className="text-xs text-foreground-muted">No scans in the last 7 days.</p> : (
                            <div className="overflow-x-auto">
                                <table className="w-full text-xs">
                                    <thead><tr className="text-left text-foreground-muted"><th className="py-1 pr-3">Kind</th><th className="pr-3">Assessed</th><th className="pr-3" title="Ran, but could not reach or assess the target">Inconclusive</th><th className="pr-3">Failed</th><th className="pr-3">Cancelled</th><th className="pr-3">Queued / running</th><th>Median duration</th></tr></thead>
                                    <tbody>
                                        {kinds.map(([k, v]) => (
                                            <tr key={k} className="border-t border-border">
                                                <td className="py-1.5 pr-3 font-bold text-foreground">{kindLabel(k)}</td>
                                                <td className="pr-3 text-green font-bold">{v.succeeded}</td>
                                                <td className={`pr-3 ${v.inconclusive ? 'text-amber font-bold' : ''}`}>{v.inconclusive}</td>
                                                <td className={`pr-3 ${v.failed ? 'text-red font-bold' : ''}`}>{v.failed}</td>
                                                <td className="pr-3">{v.cancelled}</td>
                                                <td className="pr-3">{v.queued} / {v.running}</td>
                                                <td>{fmtDuration(v.median_duration_s)}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </section>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                        <section className={`${card} space-y-2`}>
                            <div className="flex items-center justify-between"><h2 className="text-sm font-black text-foreground">Active jobs</h2><Link href="/admin/vms/scans" className="text-[11px] font-bold text-purple">All scans →</Link></div>
                            {ops.active.length === 0 ? <p className="text-xs text-foreground-muted">Nothing queued or running.</p> : ops.active.map((j) => (
                                <div key={j.id} className="text-xs border-t border-border pt-2">
                                    <div className="flex items-center justify-between gap-2">
                                        <span className="font-bold text-foreground">{kindLabel(j.kind)} · <span className="font-mono">{j.targets.slice(0, 3).join(', ')}{j.targets.length > 3 ? ` +${j.targets.length - 3}` : ''}</span></span>
                                        <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${SCAN_STATUS_STYLE[j.status]}`}>{j.status}</span>
                                    </div>
                                    <p className="text-foreground-muted">{j.status === 'running' ? `${scanProgress(j.progress) || 'Running'} · worker ${j.worker_id ?? '?'} · last heartbeat ${fmtWat(j.heartbeat_at)}` : `Queued ${fmtWat(j.requested_at)}${j.attention ? ` · ${j.attention}` : ''}`}</p>
                                </div>
                            ))}
                        </section>
                        <section className={`${card} space-y-2`}>
                            <h2 className="text-sm font-black text-foreground">Recent failures</h2>
                            {ops.recent_failures.length === 0 ? <p className="text-xs text-foreground-muted">No failed scans in the last 7 days.</p> : ops.recent_failures.map((j) => (
                                <div key={j.id} className="text-xs border-t border-border pt-2">
                                    <div className="flex items-center justify-between gap-2">
                                        <span className="font-bold text-foreground">{kindLabel(j.kind)} · <span className="font-mono">{j.targets.slice(0, 2).join(', ')}</span></span>
                                        {canRun && !j.assessment_id && j.purpose !== 'verification' && <button onClick={() => void retry(j.id)} className="text-[10px] font-bold text-white bg-purple rounded px-2 py-0.5">Retry</button>}
                                        {j.assessment_id && <Link href={`/admin/vms/assessments?id=${j.assessment_id}`} className="text-[10px] font-bold text-purple">Assessment →</Link>}
                                    </div>
                                    <p className="text-red break-words">{j.error ?? 'No reason given'}</p>
                                    <p className="text-foreground-muted">{fmtWat(j.finished_at)}</p>
                                </div>
                            ))}
                        </section>
                    </div>

                    {ops.workers && ops.workers.length > 0 && (
                        <section className={card}>
                            <h2 className="text-sm font-black text-foreground mb-2">Workers</h2>
                            <div className="overflow-x-auto">
                                <table className="w-full text-xs">
                                    <thead><tr className="text-left text-foreground-muted"><th className="py-1 pr-3">Worker</th><th className="pr-3">Status</th><th className="pr-3">Runs</th><th className="pr-3">Tool versions</th><th className="pr-3">Private networks</th><th>Last seen</th></tr></thead>
                                    <tbody>
                                        {ops.workers.map((w) => (
                                            <tr key={w.worker_id} className="border-t border-border align-top">
                                                <td className="py-1.5 pr-3 font-mono text-foreground">{w.worker_id}{w.version ? <span className="text-foreground-muted"> v{w.version}</span> : null}</td>
                                                <td className="pr-3"><span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${w.online ? 'bg-green/10 text-green' : 'bg-amber/10 text-amber'}`}>{w.online ? 'connected' : 'not heard from'}</span></td>
                                                <td className="pr-3">{w.kinds.map(kindLabel).join(', ') || '—'}</td>
                                                <td className="pr-3 font-mono text-[11px]">{Object.entries(w.tool_versions).map(([k, v]) => `${k} ${v}`).join(' · ') || '—'}</td>
                                                <td className="pr-3 font-mono">{w.networks.join(', ') || 'none'}</td>
                                                <td>{fmtWat(w.last_seen_at)}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </section>
                    )}

                    <section className={card}>
                        <h2 className="text-sm font-black text-foreground">Wazuh agent data</h2>
                        <p className="text-xs text-foreground mt-1">
                            {ops.wazuh_sync.last_complete_at ? `Last complete sync ${fmtWat(ops.wazuh_sync.last_complete_at)}` : 'No complete Wazuh sync yet'}
                            {ops.wazuh_sync.complete === false && ops.wazuh_sync.problem ? <span className="text-amber"> · latest attempt incomplete: {ops.wazuh_sync.problem}</span> : null}
                        </p>
                    </section>
                </>
            )}

            {profiles && (
                <section aria-label="Scan profiles" className="space-y-2">
                    <h2 className="text-sm font-black text-foreground">Scan profiles</h2>
                    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                        {profiles.map((p) => (
                            <div key={p.id} className={`${card} text-xs space-y-1.5`}>
                                <div className="flex items-center justify-between gap-2">
                                    <p className="font-black text-foreground">{PROFILE_LABEL[p.id] ?? p.label}</p>
                                    {p.runnable ? <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded-full bg-blue/10 text-blue">Assessment</span>
                                        : <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${p.available ? 'bg-green/10 text-green' : 'bg-amber/10 text-amber'}`}>{p.available ? 'Available' : 'Not available'}</span>}
                                </div>
                                <p className="text-foreground">{p.description}</p>
                                <p className="text-foreground-muted"><span className="font-bold">Engines:</span> {p.engines.join(', ')}{p.ports ? ` · ports ${p.ports}` : ''}</p>
                                <p className="text-foreground-muted"><span className="font-bold">Does not cover:</span> {p.not_covered.join('; ')}</p>
                                {p.availability_note && <p className="text-foreground-muted italic">{p.availability_note}</p>}
                            </div>
                        ))}
                    </div>
                    <p className="text-[11px] text-foreground-muted">A profile runs only the checks the authorised scope allows and a connected worker supports; anything else is listed in the assessment as not attempted or unsupported.</p>
                </section>
            )}
        </div>
    );
}
