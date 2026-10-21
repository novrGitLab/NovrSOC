'use client';

// Managed Endpoints (phase P19): the organisation's Wazuh-enrolled endpoints, whether each may be
// assessed automatically and at which address, and when it was and will next be assessed. From
// /api/vms/endpoints, which evaluates eligibility on every read: an address Wazuh reports is
// assessed only when it is inside the organisation's agreed coverage (authorised scope) and a
// scanner worker can reach it — offline agents and shared (DHCP/NAT) addresses are not.

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { MonitorSmartphone, RefreshCw } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { loadJson } from '@/lib/alerts';
import { getAdminUser } from '@/lib/admin-auth';
import {
    fmtWat, CRIT_STYLE, ELIGIBILITY_LABEL, ELIGIBILITY_STYLE, PROFILE_LABEL, SEVERITIES, SEVERITY_STYLE,
    type VmsEndpointsResponse, type EligibilityStatus,
} from '@/lib/vms';

const card = 'bg-card border border-border rounded-xl p-4';
const input = 'bg-card border border-border rounded-lg px-2.5 py-1.5 text-xs text-foreground';

export function VmsEndpoints() {
    const canRun = ['super_admin', 'soc_manager', 'analyst'].includes(getAdminUser().role);
    const [data, setData] = useState<VmsEndpointsResponse | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [msg, setMsg] = useState<string | null>(null);
    const [q, setQ] = useState('');
    const [elig, setElig] = useState<'all' | EligibilityStatus>('all');
    const [profile, setProfile] = useState<'discovery' | 'standard' | 'full'>('standard');
    const [tick, setTick] = useState(0);
    const reload = useCallback(() => setTick((t) => t + 1), []);

    useEffect(() => {
        let active = true;
        void loadJson<VmsEndpointsResponse>('/api/vms/endpoints').then((r) => {
            if (!active) return;
            setData(r.ok ? r.data : null);
            setError(r.ok ? null : r.error);
        });
        return () => { active = false; };
    }, [tick]);

    const rows = useMemo(() => {
        const t = q.trim().toLowerCase();
        return (data?.endpoints ?? []).filter((e) => e.status === 'active')
            .filter((e) => elig === 'all' || e.eligibility?.status === elig)
            .filter((e) => !t || [e.name, e.os ?? '', e.wazuh_agent_id ?? '', ...e.ips].some((x) => x.toLowerCase().includes(t)));
    }, [data, q, elig]);

    async function post(path: string, body?: unknown) {
        setMsg(null);
        const r = await apiFetch(apiUrl(path), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
        const d = await r.json().catch(() => null);
        return { ok: r.ok, data: d, error: d?.error ?? `HTTP ${r.status}` };
    }
    async function assess(id: string, name: string) {
        const r = await post('/api/vms/assessments', { asset_id: id, profile });
        setMsg(r.ok ? `${name}: ${r.data.existing ? 'an assessment is already in progress' : `${PROFILE_LABEL[profile]} assessment planned`}.` : `${name}: ${r.error}`);
        reload();
    }
    async function reevaluate() {
        const r = await post('/api/vms/eligibility/refresh');
        setMsg(r.ok ? 'Eligibility re-evaluated.' : r.error);
        reload();
    }

    const c = data?.coverage;
    const pct = c && c.active ? Math.round((c.assessed_last_30_days / c.active) * 100) : null;
    return (
        <div className="space-y-5">
            <div className="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <h2 className="text-sm font-bold text-foreground flex items-center gap-2"><MonitorSmartphone className="w-4 h-4" /> Managed Endpoints</h2>
                    <p className="text-xs text-foreground-muted max-w-3xl">Endpoints enrolled in Wazuh. Each is assessed automatically by an enabled assessment policy when its address is inside the organisation&apos;s agreed coverage (<Link href="/admin/vms/discovery" className="text-purple font-bold">Authorised Scope</Link>) and a scanner can reach it. An address seen in telemetry alone never authorises a scan.</p>
                </div>
                {canRun && <button onClick={() => void reevaluate()} className="flex items-center gap-1 text-[11px] font-bold border border-border rounded-lg px-3 py-1.5"><RefreshCw className="w-3.5 h-3.5" /> Re-evaluate</button>}
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {msg && <p role="status" className="text-xs text-foreground font-semibold">{msg}</p>}
            {data && !data.eligibility_stored && <p className="text-[11px] text-amber">Eligibility is evaluated on each view but not stored yet: apply sql/2026-10-25_p19_vms_automation.sql.</p>}
            {c && (
                <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
                    {[['Managed endpoints', c.active], ['Eligible for assessment', c.eligible], ['Assessed (30 days)', c.assessed_last_30_days], ['Awaiting assessment', c.awaiting_assessment], ['Coverage (30 days)', pct === null ? '—' : `${pct}%`]].map(([k, v]) => (
                        <div key={String(k)} className={card}><p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{k}</p><p className="text-2xl font-black text-foreground mt-1">{v}</p></div>
                    ))}
                </div>
            )}
            {c && Object.values(c.not_eligible).some(Boolean) && (
                <div className="flex flex-wrap gap-2 text-[11px]">
                    {Object.entries(c.not_eligible).filter(([, n]) => n).map(([k, n]) => (
                        <button key={k} onClick={() => setElig(k as EligibilityStatus)} className={`font-bold px-2 py-1 rounded-full ${ELIGIBILITY_STYLE[k as EligibilityStatus]}`}>{ELIGIBILITY_LABEL[k as EligibilityStatus]}: {n}</button>
                    ))}
                </div>
            )}
            <div className="flex flex-wrap gap-2 items-center">
                <input className={input} placeholder="Name, IP, OS or agent id" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search endpoints" />
                <select className={input} value={elig} onChange={(e) => setElig(e.target.value as typeof elig)} aria-label="Eligibility">
                    <option value="all">All eligibility states</option>
                    {(Object.keys(ELIGIBILITY_LABEL) as EligibilityStatus[]).map((k) => <option key={k} value={k}>{ELIGIBILITY_LABEL[k]}</option>)}
                </select>
                {canRun && (
                    <label className="text-[11px] text-foreground-muted flex items-center gap-1">Assess with
                        <select className={input} value={profile} onChange={(e) => setProfile(e.target.value as typeof profile)} aria-label="Profile for Assess now">
                            {(['discovery', 'standard', 'full'] as const).map((p) => <option key={p} value={p}>{PROFILE_LABEL[p]}</option>)}
                        </select>
                    </label>
                )}
            </div>
            <div className={`${card} p-0 overflow-x-auto`}>
                {data && rows.length === 0 ? (
                    <p className="text-xs text-foreground-muted p-6 text-center">{data.endpoints.length === 0 ? 'No Wazuh endpoints yet: they appear after the hourly Wazuh sync for an organisation whose Wazuh group is mapped.' : 'No endpoint matches the filters.'}</p>
                ) : (
                    <table className="w-full text-xs">
                        <thead><tr className="text-left text-foreground-muted border-b border-border">
                            <th className="p-2">Endpoint</th><th className="p-2">Agent</th><th className="p-2">Addresses</th><th className="p-2">Scan eligibility</th><th className="p-2">Last assessed</th><th className="p-2">Next scan</th><th className="p-2">Open findings</th><th className="p-2" />
                        </tr></thead>
                        <tbody>
                            {rows.map((e) => (
                                <tr key={e.id} className="border-t border-border align-top">
                                    <td className="p-2">
                                        <Link href={`/admin/vms/assets?id=${e.id}`} className="font-bold text-foreground hover:underline">{e.name}</Link>
                                        <p className="text-foreground-muted">{e.os ?? 'OS not reported'}</p>
                                        <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${CRIT_STYLE[e.criticality]}`}>{e.criticality}</span>
                                    </td>
                                    <td className="p-2">
                                        <p className="font-mono">{e.wazuh_agent_id ?? '—'}</p>
                                        <p className={e.agent_status === 'active' ? 'text-green font-bold' : 'text-foreground-muted'}>{e.agent_status ?? 'status not recorded'}</p>
                                        <p className="text-foreground-muted">{e.agent_last_keepalive ? `keep-alive ${fmtWat(e.agent_last_keepalive)}` : 'keep-alive not reported'}</p>
                                    </td>
                                    <td className="p-2 font-mono">{e.ips.join(', ') || '—'}</td>
                                    <td className="p-2 max-w-xs">
                                        {e.eligibility ? (
                                            <>
                                                <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${ELIGIBILITY_STYLE[e.eligibility.status]}`}>{ELIGIBILITY_LABEL[e.eligibility.status]}</span>
                                                <p className="text-foreground-muted mt-1">{e.eligibility.reason}</p>
                                            </>
                                        ) : <span className="text-foreground-muted">Not evaluated</span>}
                                    </td>
                                    <td className="p-2">
                                        {e.last_assessment ? <Link href={`/admin/vms/scans?id=${e.last_assessment.id}`} className="text-purple font-bold">{fmtWat(e.last_assessment.requested_at)}</Link> : <span className="text-foreground-muted">Never</span>}
                                        {e.last_assessment && <p className="text-foreground-muted">{PROFILE_LABEL[e.last_assessment.profile] ?? e.last_assessment.profile} at {e.last_assessment.target}</p>}
                                        {e.last_assessed_at && !e.assessed_recently && <p className="text-amber">No scan reached it in 30 days</p>}
                                    </td>
                                    <td className="p-2">{e.next_scan_at ? fmtWat(e.next_scan_at) : <span className="text-foreground-muted">{e.eligibility?.status === 'eligible' ? 'No enabled policy has planned it' : '—'}</span>}</td>
                                    <td className="p-2">
                                        <div className="flex flex-wrap gap-1">
                                            {SEVERITIES.filter((s) => e.open_findings[s]).map((s) => <span key={s} className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${SEVERITY_STYLE[s]}`}>{e.open_findings[s]} {s}</span>)}
                                            {!SEVERITIES.some((s) => e.open_findings[s]) && <span className="text-foreground-muted">none open</span>}
                                        </div>
                                    </td>
                                    <td className="p-2">
                                        {canRun && e.eligibility?.status === 'eligible' && <button onClick={() => void assess(e.id, e.name)} className="text-[10px] font-bold text-white bg-purple rounded px-2 py-1 whitespace-nowrap">Assess now</button>}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
            <p className="text-[11px] text-foreground-muted">Automatic assessments are run by assessment policies (VMS Admin) on Wazuh endpoints; each run respects the cooldown, re-assesses an endpoint early when its address changes, and records the next due time here.</p>
        </div>
    );
}
