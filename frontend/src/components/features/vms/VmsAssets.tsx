'use client';

// Attack surface inventory (phase P4) — every hostname and IP the scanners found inside authorised
// scope, with services, technologies and change history. Owner and criticality are set by people
// (they drive risk prioritisation in Release 2); everything else is what the tools observed.

import { useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { Search, Globe } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { loadJson } from '@/lib/alerts';
import { OUTCOME_LABEL, OUTCOME_STYLE, portStates, ASSESSMENT_STATUS_LABEL, ASSESSMENT_STATUS_STYLE, type VmsAssessment } from '@/lib/vms';
import Link from 'next/link';
import { apiUrl as assessUrl, apiFetch as assessFetch } from '@/lib/api';
import { getAdminUser } from '@/lib/admin-auth';
import { AiPanel } from '@/components/shared/AiPanel';
import { AttackSurfaceMap } from './AttackSurfaceMap';
import { fmtWat, CRIT_STYLE, EVENT_LABEL, describeEvent, type VmsAsset, type VmsService, type VmsTech, type VmsEvent } from '@/lib/vms';

interface Linked { id: string; asset_type: string; value: string; exposure: string; last_seen: string; relation: string; services: VmsService[] }
interface Detail { asset: VmsAsset; services: VmsService[]; technologies: VmsTech[]; events: VmsEvent[]; linked?: Linked[] }

export function VmsAssets() {
    const params = useSearchParams();
    const [exposure, setExposure] = useState(params.get('exposure') ?? 'all');
    // Wazuh-managed endpoints vs assets VMS found or registered (P14); filtered here, same records.
    const [source, setSource] = useState<'all' | 'wazuh' | 'external'>((params.get('source') as 'wazuh' | 'external' | null) ?? 'all');
    const [status, setStatus] = useState('active');
    const [search, setSearch] = useState('');
    const [text, setText] = useState('');
    const [assets, setAssets] = useState<VmsAsset[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [detail, setDetail] = useState<Detail | null>(null);
    const [msg, setMsg] = useState<string | null>(null);

    useEffect(() => {
        let active = true;
        const p = new URLSearchParams();
        if (exposure !== 'all') p.set('exposure', exposure);
        if (status !== 'all') p.set('status', status);
        if (text) p.set('q', text);
        void loadJson<{ assets: VmsAsset[] }>(`/api/vms/assets?${p.toString()}`).then((r) => {
            if (!active) return;
            setAssets(r.ok ? r.data.assets : null);
            setError(r.ok ? null : r.error);
        });
        return () => { active = false; };
    }, [exposure, status, text]);

    async function open(a: { id: string }) {
        setMsg(null);
        const r = await loadJson<Detail>(`/api/vms/assets/${a.id}`);
        setDetail(r.ok ? r.data : null);
    }
    const shown = assets?.filter((a) => source === 'all' || (source === 'wazuh' ? a.asset_type === 'endpoint' : a.asset_type !== 'endpoint')) ?? null;
    async function patch(body: Record<string, unknown>) {
        if (!detail) return;
        const r = await apiFetch(apiUrl(`/api/vms/assets/${detail.asset.id}`), { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        const d = await r.json().catch(() => null);
        if (!r.ok) { setMsg(d?.error ?? `HTTP ${r.status}`); return; }
        setDetail({ ...detail, asset: d.asset });
        setAssets((prev) => prev?.map((x) => (x.id === d.asset.id ? d.asset : x)) ?? prev);
        setMsg('Saved');
    }

    const chip = (on: boolean) => `text-[11px] font-bold px-2.5 py-1 rounded-md ${on ? 'bg-blue text-white' : 'text-foreground-muted hover:text-foreground'}`;
    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground flex items-center gap-2"><Globe className="w-5 h-5" /> Attack Surface</h1>
                <p className="text-xs text-foreground-muted">Hostnames and IP addresses found inside authorised scope, with what they expose.</p>
            </div>
            <div className="flex flex-wrap gap-2 items-center">
                <div className="flex gap-1 bg-card border border-border rounded-lg p-1">{['all', 'internet', 'internal', 'unknown'].map((x) => <button key={x} onClick={() => setExposure(x)} className={chip(exposure === x)}>{x === 'all' ? 'Any exposure' : x}</button>)}</div>
                <div className="flex gap-1 bg-card border border-border rounded-lg p-1">{['active', 'gone', 'all'].map((x) => <button key={x} onClick={() => setStatus(x)} className={chip(status === x)}>{x}</button>)}</div>
                <div className="flex gap-1 bg-card border border-border rounded-lg p-1">{(['all', 'wazuh', 'external'] as const).map((x) => <button key={x} onClick={() => setSource(x)} className={chip(source === x)}>{x === 'all' ? 'Any source' : x === 'wazuh' ? 'Wazuh-managed' : 'External'}</button>)}</div>
                <form onSubmit={(e) => { e.preventDefault(); setText(search.trim()); }} className="flex items-center gap-1 bg-card border border-border rounded-lg px-2 py-1">
                    <Search className="w-3.5 h-3.5 text-foreground-muted" />
                    <input aria-label="Search assets" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="hostname or IP" className="bg-transparent text-[11px] outline-none w-40" />
                </form>
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
                <div className="lg:col-span-2 bg-card border border-border rounded-xl overflow-hidden">
                    {assets === null && !error && <div className="h-24 bg-card-muted animate-pulse" />}
                    {assets && assets.length === 0 && <p className="text-sm text-foreground-muted text-center py-10">No data — no assets{text || exposure !== 'all' ? ' for these filters' : ' found yet; run a discovery scan'}.</p>}
                    <div className="max-h-[640px] overflow-y-auto divide-y divide-border">
                        {shown?.map((a) => (
                            <button key={a.id} onClick={() => void open(a)} className={`w-full text-left p-3 hover:bg-card-muted ${detail?.asset.id === a.id ? 'bg-card-muted' : ''}`}>
                                <div className="flex items-center justify-between gap-2">
                                    <span className="text-xs font-bold font-mono text-foreground break-all">{a.value}</span>
                                    <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${CRIT_STYLE[a.criticality]}`}>{a.criticality}</span>
                                </div>
                                <p className="text-[10px] text-foreground-muted mt-1">{a.exposure} · {a.ips.join(', ') || 'no IP'} · {a.http?.status ? `HTTP ${a.http.status}` : 'no HTTP'} · seen {fmtWat(a.last_seen)}{a.status === 'gone' ? ' · gone' : ''}{a.asset_type === 'endpoint' ? ' · Wazuh' : ''}{!a.last_assessed_at ? ' · not assessed' : /^reachable/.test(a.last_assessment?.outcome ?? '') ? ` · assessed ${fmtWat(a.last_assessed_at)}` : ` · last check ${fmtWat(a.last_assessed_at)}: ${OUTCOME_LABEL[a.last_assessment?.outcome ?? ''] ?? a.last_assessment?.outcome ?? 'no result'}`}</p>
                            </button>
                        ))}
                    </div>
                </div>
                <div className="lg:col-span-3 bg-card border border-border rounded-xl p-4">
                    {!detail ? <p className="text-xs text-foreground-muted text-center py-10">Select an asset.</p> : (
                        <div className="space-y-4 text-xs">
                            <div>
                                <h2 className="text-sm font-black font-mono text-foreground break-all">{detail.asset.value}</h2>
                                <p className="text-foreground-muted">{detail.asset.asset_type} · {detail.asset.exposure} · first seen {fmtWat(detail.asset.first_seen)} · last seen {fmtWat(detail.asset.last_seen)} · found by {detail.asset.discovery_sources.join(', ')}</p>
                            </div>
                            {detail.asset.last_assessment && (
                                <div className="border border-border rounded-lg p-2 space-y-1">
                                    <p className="text-[10px] font-bold text-foreground-muted uppercase">Last assessment · {detail.asset.last_assessment.method} · {fmtWat(detail.asset.last_assessed_at ?? null)}</p>
                                    <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${OUTCOME_STYLE[detail.asset.last_assessment.outcome] ?? ''}`}>{OUTCOME_LABEL[detail.asset.last_assessment.outcome] ?? detail.asset.last_assessment.outcome}</span>
                                    <p className="text-foreground">{detail.asset.last_assessment.reason}</p>
                                    {detail.asset.last_assessment.ports_scanned ? <p className="text-foreground-muted">{detail.asset.last_assessment.ports_scanned} port(s) scanned: {portStates(detail.asset.last_assessment.port_states)}{detail.asset.last_assessment.host_status ? ` · nmap host status ${detail.asset.last_assessment.host_status}${detail.asset.last_assessment.host_status_reason ? ` (${detail.asset.last_assessment.host_status_reason})` : ''}` : ''}</p> : null}
                                </div>
                            )}
                            <div className="flex flex-wrap gap-3 items-end">
                                <label className="text-[11px] font-bold text-foreground-muted">Owner
                                    <input key={detail.asset.id} defaultValue={detail.asset.owner ?? ''} onBlur={(e) => { if (e.target.value !== (detail.asset.owner ?? '')) void patch({ owner: e.target.value.trim() || null }); }} className="block bg-card-muted border border-border rounded px-2 py-1 text-xs" placeholder="team or person" />
                                </label>
                                <label className="text-[11px] font-bold text-foreground-muted">Business criticality
                                    <select value={detail.asset.criticality} onChange={(e) => void patch({ criticality: e.target.value })} className="block bg-card-muted border border-border rounded px-2 py-1 text-xs">
                                        {['low', 'medium', 'high', 'critical'].map((c) => <option key={c} value={c}>{c}</option>)}
                                    </select>
                                </label>
                                {msg && <span className="text-[11px] text-foreground-muted">{msg}</span>}
                            </div>
                            <div className="grid grid-cols-2 gap-3">
                                <div><p className="text-[10px] font-bold text-foreground-muted uppercase">IP addresses</p><p className="font-mono">{detail.asset.ips.join(', ') || '—'}</p></div>
                                <div><p className="text-[10px] font-bold text-foreground-muted uppercase">CNAME</p><p className="font-mono">{detail.asset.dns?.cname?.join(', ') || '—'}</p></div>
                                <div className="col-span-2"><p className="text-[10px] font-bold text-foreground-muted uppercase">HTTP</p><p>{detail.asset.http ? `${detail.asset.http.url} · ${detail.asset.http.status ?? '—'} · ${detail.asset.http.title ?? 'no title'} · ${detail.asset.http.webserver ?? 'server unknown'}${detail.asset.http.cdn ? ` · CDN ${detail.asset.http.cdn}` : ''}` : 'No web service seen'}</p></div>
                            </div>
                            <div>
                                <p className="text-[10px] font-bold text-foreground-muted uppercase mb-1">Services</p>
                                {detail.services.length === 0 ? <p className="text-foreground-muted">None recorded (port scans need port-scan authorisation).</p> : (
                                    <table className="w-full"><tbody>
                                        {detail.services.map((s) => <tr key={s.id} className="border-t border-border"><td className="py-1 font-mono">{s.port}/{s.protocol}</td><td>{s.service ?? '—'}</td><td>{[s.product, s.version].filter(Boolean).join(' ') || '—'}</td><td className={s.status === 'gone' ? 'text-foreground-muted' : 'text-green'}>{s.status}</td></tr>)}
                                    </tbody></table>
                                )}
                            </div>
                            <div>
                                <p className="text-[10px] font-bold text-foreground-muted uppercase mb-1">Technologies</p>
                                <p>{detail.technologies.length ? detail.technologies.map((t) => `${t.name}${t.version ? ` ${t.version}` : ''}`).join(', ') : '—'}</p>
                            </div>
                            {(detail.linked ?? []).length > 0 && (
                                <div>
                                    <p className="text-[10px] font-bold text-foreground-muted uppercase mb-1">Linked records</p>
                                    {detail.linked!.map((l) => (
                                        <div key={l.id} className="border-t border-border py-1">
                                            <button onClick={() => void open(l)} className="font-mono font-semibold text-purple">{l.value}</button> <span className="text-foreground-muted">({l.asset_type === 'endpoint' ? 'Wazuh endpoint' : 'scanned address'} · {l.relation})</span>
                                            {l.services.length > 0 && <p className="text-foreground-muted">Services seen there: {l.services.map((s) => `${s.port}/${s.protocol}${s.service ? ` ${s.service}` : ''}`).join(', ')}</p>}
                                        </div>
                                    ))}
                                </div>
                            )}
                            <div>
                                <p className="text-[10px] font-bold text-foreground-muted uppercase mb-1">Attack-surface map</p>
                                <AttackSurfaceMap key={`map-${detail.asset.id}`} assetId={detail.asset.id} onOpenAsset={(id) => void open({ id })} />
                            </div>
                            <AssetAssessments key={`as-${detail.asset.id}`} assetId={detail.asset.id} />
                            <AiPanel key={detail.asset.id} purpose="asset_assessment" subjectId={detail.asset.id} title="AI exposure assessment" />
                            <div>
                                <p className="text-[10px] font-bold text-foreground-muted uppercase mb-1">History</p>
                                {detail.events.length === 0 ? <p className="text-foreground-muted">—</p> : detail.events.slice(0, 30).map((e) => <p key={e.id} className="text-foreground-muted">{fmtWat(e.at)} · {EVENT_LABEL[e.event] ?? e.event} · {describeEvent(e)}</p>)}
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

/** Full assessments of one asset, and a button to start one (P13). */
function AssetAssessments({ assetId }: { assetId: string }) {
    const canRun = ['super_admin', 'soc_manager', 'analyst'].includes(getAdminUser().role);
    const [items, setItems] = useState<VmsAssessment[] | null>(null);
    const [msg, setMsg] = useState<string | null>(null);
    const [tick, setTick] = useState(0);
    useEffect(() => {
        let active = true;
        void loadJson<{ assessments: VmsAssessment[] }>(`/api/vms/assessments?asset_id=${assetId}`).then((r) => { if (active) { setItems(r.ok ? r.data.assessments : []); if (!r.ok) setMsg(r.error); } });
        return () => { active = false; };
    }, [assetId, tick]);
    async function start() {
        setMsg(null);
        const r = await assessFetch(assessUrl('/api/vms/assessments'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ asset_id: assetId }) });
        const d = await r.json().catch(() => null);
        setMsg(r.ok ? (d.existing ? 'An assessment of this asset is already in progress.' : 'Full assessment planned.') : d?.error ?? `HTTP ${r.status}`);
        setTick((t) => t + 1);
    }
    return (
        <div>
            <div className="flex items-center justify-between mb-1">
                <p className="text-[10px] font-bold text-foreground-muted uppercase">Assessments</p>
                {canRun && <button onClick={() => void start()} className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1">Run full assessment</button>}
            </div>
            {msg && <p className="text-foreground mb-1">{msg}</p>}
            {items && items.length === 0 && <p className="text-foreground-muted">None yet.</p>}
            {(items ?? []).slice(0, 5).map((a) => (
                <Link key={a.id} href={`/admin/vms/assessments?id=${a.id}`} className="flex items-center justify-between gap-2 border-t border-border py-1">
                    <span className="text-foreground">{fmtWat(a.requested_at)} · {a.progress.finished}/{a.progress.total} checks</span>
                    <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${ASSESSMENT_STATUS_STYLE[a.status]}`}>{ASSESSMENT_STATUS_LABEL[a.status]}</span>
                </Link>
            ))}
        </div>
    );
}
