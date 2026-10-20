'use client';

// VMS administration (phase P14) — for managers; the backend refuses everyone else (vms:scope).
// Workers and their capabilities, assessment policies (created disabled), integration freshness,
// evidence retention and recent VMS audit entries. Integrations show configured / not configured
// and timestamps only; no secret value is ever sent to the browser.

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { Settings2, Play } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { loadJson } from '@/lib/alerts';
import { fmtWat, PROFILE_LABEL, ELIGIBILITY_LABEL, type EligibilityStatus } from '@/lib/vms';

interface Policy {
    id: string; name: string; enabled: boolean; asset_source: 'wazuh' | 'external' | 'any'; profile?: string; cooldown_hours: number; max_per_run: number; last_run_at: string | null;
    last_result: { queued?: number; existing?: number; skipped_cooldown?: number; blocked?: { asset: string; reason: string }[]; blocked_total?: number; not_evaluated?: number; event_triggered?: number; ineligible?: Record<string, number> } | null;
}
interface Status {
    deployed_version: string | null;
    workers: { source: string; online: number; window_seconds: number; list: { worker_id: string; online: boolean; version: string | null; kinds: string[]; tools: Record<string, boolean>; tool_versions: Record<string, string>; networks: string[]; features: string[]; last_seen_at: string; last_job_at: string | null }[] };
    scheduler: { last_run_at: string | null; policies: { at?: string } | null };
    wazuh: { available: boolean; sync?: { last_synced_at?: string; last_result?: unknown } | null; freshness?: { last_attempt_at: string | null; last_complete_at: string | null; complete: boolean | null; problem: string | null }; note?: string | null };
    cve_intel: { tracked: number; kev_checked_at: string | null; epss_fetched_at: string | null; nvd_fetched_at: string | null; osv?: { available: boolean; fetched_at?: string | null; note?: string } };
    ai: { configured: boolean; model: string };
    evidence: { available: boolean; retention_days?: number; items?: number; next_expiry?: string | null };
    scopes: { active: number; expired_or_revoked: number; with_exclusions: number; passive_only: number; vuln_allowed: number };
    policies: { available: boolean; note?: string; list?: Policy[] };
    audit: { source: string; entries: { id: string; timestamp: string; user: string; action: string; details?: string }[] };
}
type Part = { ok: boolean; error?: string } & Record<string, unknown>;
interface WazuhCheck { checked_at: string; verdict: 'working' | 'reachable_not_synced' | 'not_working' | 'not_configured'; configured: { manager_api: boolean; indexer: boolean }; manager: Part & { api_version?: string | null }; agents: Part & { count?: number; active?: number; groups?: string[] }; vulnerabilities: Part & { records_for_org?: number; by_severity?: Record<string, number> } }
const VERDICT: Record<WazuhCheck['verdict'], string> = { working: 'Working', reachable_not_synced: 'Reachable, not yet synced completely', not_working: 'Not working', not_configured: 'Not configured' };
const SOURCE_LABEL = { wazuh: 'Wazuh endpoints', external: 'External hosts and IPs', any: 'All assets' } as const;

export function VmsAdmin() {
    const [s, setS] = useState<Status | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [msg, setMsg] = useState<string | null>(null);
    const [form, setForm] = useState({ name: '', asset_source: 'external' as Policy['asset_source'], profile: 'full' as 'discovery' | 'standard' | 'full', cooldown_hours: 168, max_per_run: 5 });
    const [tick, setTick] = useState(0);
    const [check, setCheck] = useState<WazuhCheck | null>(null);
    const [checking, setChecking] = useState(false);
    const reload = useCallback(() => setTick((t) => t + 1), []);

    useEffect(() => {
        let active = true;
        void loadJson<Status>('/api/vms/admin/status').then((r) => { if (active) { setS(r.ok ? r.data : null); setError(r.ok ? null : r.status === 403 ? 'VMS administration is for SOC managers and super admins.' : r.error); } });
        return () => { active = false; };
    }, [tick]);

    async function send(method: 'POST' | 'PATCH', path: string, body?: unknown) {
        const r = await apiFetch(apiUrl(path), { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
        const d = await r.json().catch(() => null);
        return r.ok ? { ok: true as const, data: d } : { ok: false as const, error: d?.error ?? `HTTP ${r.status}` };
    }
    async function createPolicy() {
        const r = await send('POST', '/api/vms/admin/policies', form);
        setMsg(r.ok ? 'Policy created — disabled until you turn it on.' : r.error);
        if (r.ok) { setForm({ ...form, name: '' }); reload(); }
    }
    async function toggle(p: Policy) {
        if (!p.enabled && !window.confirm(`Turn on "${p.name}"? Every hour, up to ${p.max_per_run} ${SOURCE_LABEL[p.asset_source].toLowerCase()} will get a ${PROFILE_LABEL[p.profile ?? 'full'] ?? 'Full Assessment'} assessment (only the checks their authorised scope and the workers allow).`)) return;
        const r = await send('PATCH', `/api/vms/admin/policies/${p.id}`, { enabled: !p.enabled });
        setMsg(r.ok ? `Policy ${!p.enabled ? 'enabled' : 'disabled'}` : r.error);
        reload();
    }
    async function checkWazuh() {
        setChecking(true);
        const r = await send('POST', '/api/vms/admin/wazuh/check');
        setChecking(false);
        if (r.ok) setCheck(r.data as WazuhCheck); else setMsg(r.error);
    }
    async function runNow(p: Policy) {
        const r = await send('POST', `/api/vms/admin/policies/${p.id}/run`);
        setMsg(r.ok ? `Run: ${r.data.run.queued} queued, ${r.data.run.existing} already in progress, ${r.data.run.skipped_cooldown} in cooldown, ${r.data.run.blocked_total ?? r.data.run.blocked.length} blocked${r.data.run.not_evaluated ? `, ${r.data.run.not_evaluated} left for the next run` : ''}` : r.error);
        reload();
    }

    const input = 'bg-card-muted border border-border rounded-lg px-2 py-1 text-xs text-foreground';
    const card = 'bg-card border border-border rounded-xl p-4 text-xs space-y-2';
    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground flex items-center gap-2"><Settings2 className="w-5 h-5" /> VMS Admin</h1>
                <p className="text-xs text-foreground-muted">Scanner workers, automatic assessment policies and integration health. Policies never authorise anything a manual assessment could not: scope, exclusions, worker capabilities and routes are checked for every asset.</p>
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {msg && <p role="status" className="text-xs text-foreground font-semibold">{msg}</p>}
            {s && (
                <>
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                        <div className={card}>
                            <h2 className="text-sm font-black text-foreground">Integrations</h2>
                            <p>Backend version: {s.deployed_version ?? 'not reported'}</p>
                            <p>Wazuh sync: {!s.wazuh.available ? 'not set up' : !s.wazuh.freshness?.last_attempt_at ? s.wazuh.note
                                : `last complete ${s.wazuh.freshness.last_complete_at ? fmtWat(s.wazuh.freshness.last_complete_at) : 'never'}${s.wazuh.freshness.complete === false ? ` · last run ${fmtWat(s.wazuh.freshness.last_attempt_at)} incomplete: ${s.wazuh.freshness.problem}` : ''}`}</p>
                            <div>
                                <button onClick={() => void checkWazuh()} disabled={checking} className="text-[11px] font-bold text-purple disabled:opacity-50">{checking ? 'Checking Wazuh…' : 'Check Wazuh integration'}</button>
                                {check && (
                                    <div className="mt-1 border border-border rounded-lg p-2 space-y-0.5">
                                        <p className="font-bold">{VERDICT[check.verdict]} <span className="font-normal text-foreground-muted">· checked {fmtWat(check.checked_at)}</span></p>
                                        <p>Manager API: {check.manager.ok ? `Wazuh ${check.manager.api_version ?? 'version not reported'}` : check.manager.error}</p>
                                        <p>Agents: {check.agents.ok ? `${check.agents.count} in ${(check.agents.groups ?? []).join(', ')} (${check.agents.active} active)` : check.agents.error}</p>
                                        <p>Vulnerability index: {check.vulnerabilities.ok ? `${check.vulnerabilities.records_for_org} record(s) for this organisation${Object.keys(check.vulnerabilities.by_severity ?? {}).length ? ` — ${Object.entries(check.vulnerabilities.by_severity ?? {}).map(([k, v]) => `${v} ${k}`).join(', ')}` : ''}` : check.vulnerabilities.error}</p>
                                    </div>
                                )}
                            </div>
                            <p>CVE intelligence: {s.cve_intel.tracked} CVEs · KEV {fmtWat(s.cve_intel.kev_checked_at)} · EPSS {fmtWat(s.cve_intel.epss_fetched_at)} · NVD {fmtWat(s.cve_intel.nvd_fetched_at)} · OSV {!s.cve_intel.osv ? 'unknown' : s.cve_intel.osv.available ? fmtWat(s.cve_intel.osv.fetched_at ?? null) : 'not set up'}</p>
                            <p>AI (NVIDIA): {s.ai.configured ? `configured (${s.ai.model})` : 'not configured — deterministic rules and templates only'}</p>
                            <p>Raw evidence: {s.evidence.available ? `${s.evidence.items} item(s), kept ${s.evidence.retention_days} days; next expiry ${fmtWat(s.evidence.next_expiry ?? null)}` : 'not set up'}</p>
                            <p>Scheduler: last scan-schedule run {fmtWat(s.scheduler.last_run_at)}; last policy run {fmtWat(s.scheduler.policies?.at ?? null)}</p>
                        </div>
                        <div className={card}>
                            <h2 className="text-sm font-black text-foreground">Authorised scope</h2>
                            <p>{s.scopes.active} active entries ({s.scopes.passive_only} passive only, {s.scopes.vuln_allowed} allowing vulnerability scans, {s.scopes.with_exclusions} with exclusions); {s.scopes.expired_or_revoked} expired or revoked.</p>
                            <Link href="/admin/vms/scope" className="text-purple font-bold">Manage scope and exclusions</Link>
                        </div>
                    </div>

                    <div className={card}>
                        <h2 className="text-sm font-black text-foreground">Scanner workers ({s.workers.online} online{s.workers.source !== 'presence' ? '; presence not recorded' : ''})</h2>
                        <div className="overflow-x-auto">
                            <table className="w-full">
                                <thead><tr className="text-left text-foreground-muted"><th className="py-1 pr-2">Worker</th><th className="pr-2">Status</th><th className="pr-2">Runs</th><th className="pr-2">Tools</th><th className="pr-2">Networks</th><th>Enforces</th></tr></thead>
                                <tbody>
                                    {s.workers.list.map((w) => (
                                        <tr key={w.worker_id} className="border-t border-border align-top">
                                            <td className="py-1 pr-2 font-mono">{w.worker_id}<p className="text-foreground-muted font-sans">v{w.version ?? '?'}</p></td>
                                            <td className="pr-2">{w.online ? <span className="text-green font-bold">connected</span> : <span className="text-amber font-bold">not heard from</span>}<p className="text-foreground-muted">{fmtWat(w.last_seen_at)}</p></td>
                                            <td className="pr-2">{w.kinds.join(', ') || '—'}</td>
                                            <td className="pr-2">{Object.entries(w.tools).map(([t, ok]) => <span key={t} className={`block ${ok ? '' : 'text-foreground-muted line-through'}`}>{t}{ok && w.tool_versions[t] ? ` ${w.tool_versions[t]}` : ''}</span>)}</td>
                                            <td className="pr-2">{w.networks.join(', ') || 'public internet only'}</td>
                                            <td>{w.features.join(', ') || '—'}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div className={card}>
                        <h2 className="text-sm font-black text-foreground">Automatic assessment policies</h2>
                        {!s.policies.available ? <p className="text-amber">{s.policies.note}</p> : (
                            <>
                                <form onSubmit={(e) => { e.preventDefault(); void createPolicy(); }} className="flex flex-wrap gap-2 items-end">
                                    <label>Name<br /><input className={input} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="External hosts weekly" /></label>
                                    <label>Assets<br /><select className={input} value={form.asset_source} onChange={(e) => setForm({ ...form, asset_source: e.target.value as Policy['asset_source'] })}><option value="external">External hosts and IPs</option><option value="wazuh">Wazuh endpoints</option><option value="any">All assets</option></select></label>
                                    <label>Profile<br /><select className={input} value={form.profile} onChange={(e) => setForm({ ...form, profile: e.target.value as typeof form.profile })}>{(['discovery', 'standard', 'full'] as const).map((x) => <option key={x} value={x}>{PROFILE_LABEL[x]}</option>)}</select></label>
                                    <label>Not more often than (hours)<br /><input type="number" min={24} max={2160} className={input} value={form.cooldown_hours} onChange={(e) => setForm({ ...form, cooldown_hours: Number(e.target.value) })} /></label>
                                    <label>At most per run<br /><input type="number" min={1} max={50} className={input} value={form.max_per_run} onChange={(e) => setForm({ ...form, max_per_run: Number(e.target.value) })} /></label>
                                    <button className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5" disabled={form.name.trim().length < 3}>Create (disabled)</button>
                                </form>
                                {(s.policies.list ?? []).length === 0 && <p className="text-foreground-muted">No policies. Assessments run only when someone starts them.</p>}
                                {(s.policies.list ?? []).map((p) => (
                                    <div key={p.id} className="border-t border-border pt-2">
                                        <div className="flex items-center justify-between gap-2 flex-wrap">
                                            <span className="font-bold text-foreground">{p.name} <span className="font-normal text-foreground-muted">· {SOURCE_LABEL[p.asset_source]} · {PROFILE_LABEL[p.profile ?? 'full'] ?? p.profile} · every {p.cooldown_hours} h at most · up to {p.max_per_run} per run</span></span>
                                            <div className="flex gap-2">
                                                <button onClick={() => void toggle(p)} className={`text-[11px] font-bold rounded-lg px-3 py-1 ${p.enabled ? 'bg-green/10 text-green' : 'border border-border'}`}>{p.enabled ? 'Enabled' : 'Disabled'}</button>
                                                <button onClick={() => void runNow(p)} className="flex items-center gap-1 text-[11px] font-bold border border-border rounded-lg px-3 py-1"><Play className="w-3 h-3" /> Run now</button>
                                            </div>
                                        </div>
                                        <p className="text-foreground-muted">Last run {fmtWat(p.last_run_at)}{p.last_result ? `: ${p.last_result.queued ?? 0} queued, ${p.last_result.skipped_cooldown ?? 0} in cooldown, ${p.last_result.blocked_total ?? (p.last_result.blocked ?? []).length} blocked${p.last_result.not_evaluated ? `, ${p.last_result.not_evaluated} left for the next run` : ''}${p.last_result.event_triggered ? `, ${p.last_result.event_triggered} early because the address changed` : ''}` : ''}</p>
                                        {p.last_result?.ineligible && Object.keys(p.last_result.ineligible).length > 0 && <p className="text-foreground-muted">Not eligible: {Object.entries(p.last_result.ineligible).map(([k, n]) => `${n} ${ELIGIBILITY_LABEL[k as EligibilityStatus] ?? k}`).join(', ')} (<Link href="/admin/vms/endpoints" className="text-purple font-bold">Managed Endpoints</Link>)</p>}
                                        {(p.last_result?.blocked ?? []).slice(0, 5).map((b, i) => <p key={i} className="text-amber">{b.asset}: {b.reason}</p>)}
                                    </div>
                                ))}
                            </>
                        )}
                    </div>

                    <div className={card}>
                        <h2 className="text-sm font-black text-foreground">Recent VMS audit entries</h2>
                        {s.audit.entries.length === 0 ? <p className="text-foreground-muted">None.</p> : (
                            <ul className="space-y-0.5">{s.audit.entries.slice(0, 25).map((e) => <li key={e.id}>{fmtWat(e.timestamp)} · {e.user} · <span className="font-mono">{e.action}</span>{e.details ? ` · ${e.details}` : ''}</li>)}</ul>
                        )}
                        <Link href="/admin/settings/audit" className="text-purple font-bold">Full audit log</Link>
                    </div>
                </>
            )}
        </div>
    );
}
