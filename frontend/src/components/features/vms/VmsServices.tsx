'use client';

// Services & Technology (phase P19): every open service and detected technology across the
// organisation's assets, with the exposure of the asset and the open findings on each asset/port.
// From /api/vms/services — what the scans observed; a service not scanned is simply absent.

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { Server } from 'lucide-react';
import { loadJson } from '@/lib/alerts';
import { fmtWat, SEVERITIES, SEVERITY_STYLE, CRIT_STYLE, type VmsAsset } from '@/lib/vms';

interface AssetRef { id: string; value: string; asset_type: string; exposure: VmsAsset['exposure']; criticality: VmsAsset['criticality'] }
interface Svc { id: string; asset_id: string; port: number; protocol: string; service: string | null; product: string | null; version: string | null; source: string; first_seen: string; last_seen: string; cpe?: string[] | null; asset: AssetRef | null; open_findings: { count: number; severities: Record<string, number> } }
interface Tech { id: string; asset_id: string; name: string; version: string; source: string; first_seen: string; last_seen: string; asset: AssetRef | null; asset_open_findings: number }

const card = 'bg-card border border-border rounded-xl';
const input = 'bg-card border border-border rounded-lg px-2.5 py-1.5 text-xs text-foreground';
const EXPOSURE_STYLE: Record<string, string> = { internet: 'bg-red/10 text-red', internal: 'bg-blue/10 text-blue', unknown: 'bg-card-muted text-foreground-muted' };
type SortKey = 'port' | 'findings' | 'asset' | 'last_seen';

export function VmsServices() {
    const [data, setData] = useState<{ services: Svc[]; technologies: Tech[] } | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [view, setView] = useState<'services' | 'tech'>('services');
    const [q, setQ] = useState('');
    const [exposure, setExposure] = useState<'all' | 'internet' | 'internal'>('all');
    const [sort, setSort] = useState<SortKey>('findings');

    useEffect(() => {
        let active = true;
        void loadJson<{ services: Svc[]; technologies: Tech[] }>('/api/vms/services').then((r) => {
            if (!active) return;
            setData(r.ok ? r.data : null);
            setError(r.ok ? null : r.error);
        });
        return () => { active = false; };
    }, []);

    const t = q.trim().toLowerCase();
    const services = useMemo(() => {
        const list = (data?.services ?? [])
            .filter((s) => exposure === 'all' || s.asset?.exposure === exposure)
            .filter((s) => !t || [String(s.port), s.service ?? '', s.product ?? '', s.version ?? '', s.asset?.value ?? ''].some((x) => x.toLowerCase().includes(t)));
        const by: Record<SortKey, (a: Svc, b: Svc) => number> = {
            port: (a, b) => a.port - b.port,
            findings: (a, b) => b.open_findings.count - a.open_findings.count || a.port - b.port,
            asset: (a, b) => (a.asset?.value ?? '').localeCompare(b.asset?.value ?? '') || a.port - b.port,
            last_seen: (a, b) => Date.parse(b.last_seen) - Date.parse(a.last_seen),
        };
        return [...list].sort(by[sort]);
    }, [data, exposure, t, sort]);
    const techs = useMemo(() => (data?.technologies ?? [])
        .filter((x) => exposure === 'all' || x.asset?.exposure === exposure)
        .filter((x) => !t || [x.name, x.version, x.asset?.value ?? ''].some((v) => v.toLowerCase().includes(t))), [data, exposure, t]);
    const internetFacing = (data?.services ?? []).filter((s) => s.asset?.exposure === 'internet').length;
    const withFindings = (data?.services ?? []).filter((s) => s.open_findings.count > 0).length;

    return (
        <div className="space-y-5">
            <div>
                <h1 className="text-lg font-black text-foreground flex items-center gap-2"><Server className="w-5 h-5" /> Services &amp; Technology</h1>
                <p className="text-xs text-foreground-muted max-w-3xl">Open services and detected technologies across your assets, as the scans observed them, with the exposure of each asset and the open findings on it. A port or technology no scan has covered does not appear here.</p>
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {data && (
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                    {[['Open services', data.services.length], ['On internet-facing assets', internetFacing], ['With open findings', withFindings], ['Technologies', data.technologies.length]].map(([k, v]) => (
                        <div key={String(k)} className={`${card} p-4`}><p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{k}</p><p className="text-2xl font-black text-foreground mt-1">{v}</p></div>
                    ))}
                </div>
            )}
            <div className="flex flex-wrap gap-2 items-center">
                <div className="flex gap-1 bg-card border border-border rounded-lg p-1" role="tablist">
                    {([['services', 'Services'], ['tech', 'Technologies']] as const).map(([k, label]) => (
                        <button key={k} role="tab" aria-selected={view === k} onClick={() => setView(k)} className={`text-[11px] font-bold px-3 py-1 rounded-md ${view === k ? 'bg-blue text-white' : 'text-foreground-muted'}`}>{label}</button>
                    ))}
                </div>
                <input className={input} placeholder={view === 'services' ? 'Port, service, product or asset' : 'Technology or asset'} value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search" />
                <select className={input} value={exposure} onChange={(e) => setExposure(e.target.value as typeof exposure)} aria-label="Exposure">
                    <option value="all">All exposure</option><option value="internet">Internet-facing</option><option value="internal">Internal</option>
                </select>
                {view === 'services' && (
                    <select className={input} value={sort} onChange={(e) => setSort(e.target.value as SortKey)} aria-label="Sort">
                        <option value="findings">Most open findings</option><option value="port">Port</option><option value="asset">Asset</option><option value="last_seen">Last seen</option>
                    </select>
                )}
            </div>
            <div className={`${card} overflow-x-auto`}>
                {view === 'services' ? (
                    services.length === 0 ? <p className="text-xs text-foreground-muted p-6 text-center">{data?.services.length ? 'No service matches the filters.' : 'No open services recorded yet: they come from port scans (Ports & services, or an assessment).'}</p> : (
                        <table className="w-full text-xs">
                            <thead><tr className="text-left text-foreground-muted border-b border-border"><th className="p-2">Asset</th><th className="p-2">Port</th><th className="p-2">Service</th><th className="p-2">Product / version</th><th className="p-2">Exposure</th><th className="p-2">Open findings</th><th className="p-2">Last seen</th></tr></thead>
                            <tbody>
                                {services.map((s) => (
                                    <tr key={s.id} className="border-t border-border align-top">
                                        <td className="p-2">{s.asset ? <Link href={`/admin/vms/assets?id=${s.asset.id}`} className="font-mono font-bold text-foreground hover:underline">{s.asset.value}</Link> : '—'}{s.asset && <span className={`ml-1 text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${CRIT_STYLE[s.asset.criticality]}`}>{s.asset.criticality}</span>}</td>
                                        <td className="p-2 font-mono">{s.port}/{s.protocol}</td>
                                        <td className="p-2">{s.service ?? '—'}</td>
                                        <td className="p-2">{[s.product, s.version].filter(Boolean).join(' ') || <span className="text-foreground-muted">not identified</span>}{s.cpe?.length ? <p className="font-mono text-[10px] text-foreground-muted break-all">{s.cpe[0]}</p> : null}</td>
                                        <td className="p-2">{s.asset && <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${EXPOSURE_STYLE[s.asset.exposure]}`}>{s.asset.exposure}</span>}</td>
                                        <td className="p-2">
                                            {s.open_findings.count === 0 ? <span className="text-foreground-muted">none</span> : (
                                                <Link href={`/admin/vms/findings?asset_id=${s.asset_id}`} className="flex flex-wrap gap-1">
                                                    {SEVERITIES.filter((v) => s.open_findings.severities[v]).map((v) => <span key={v} className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${SEVERITY_STYLE[v]}`}>{s.open_findings.severities[v]} {v}</span>)}
                                                </Link>
                                            )}
                                        </td>
                                        <td className="p-2 text-foreground-muted">{fmtWat(s.last_seen)}<p className="text-[10px]">via {s.source}</p></td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )
                ) : (
                    techs.length === 0 ? <p className="text-xs text-foreground-muted p-6 text-center">{data?.technologies.length ? 'No technology matches the filters.' : 'No technologies recorded yet: they come from discovery (httpx fingerprinting).'}</p> : (
                        <table className="w-full text-xs">
                            <thead><tr className="text-left text-foreground-muted border-b border-border"><th className="p-2">Technology</th><th className="p-2">Version</th><th className="p-2">Asset</th><th className="p-2">Exposure</th><th className="p-2">Open findings on asset</th><th className="p-2">Last seen</th></tr></thead>
                            <tbody>
                                {techs.map((x) => (
                                    <tr key={x.id} className="border-t border-border">
                                        <td className="p-2 font-bold text-foreground">{x.name}</td>
                                        <td className="p-2 font-mono">{x.version || <span className="text-foreground-muted">unknown</span>}</td>
                                        <td className="p-2">{x.asset ? <Link href={`/admin/vms/assets?id=${x.asset.id}`} className="font-mono hover:underline">{x.asset.value}</Link> : '—'}</td>
                                        <td className="p-2">{x.asset && <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${EXPOSURE_STYLE[x.asset.exposure]}`}>{x.asset.exposure}</span>}</td>
                                        <td className="p-2">{x.asset_open_findings ? <Link href={`/admin/vms/findings?asset_id=${x.asset_id}`} className="text-purple font-bold">{x.asset_open_findings}</Link> : <span className="text-foreground-muted">none</span>}</td>
                                        <td className="p-2 text-foreground-muted">{fmtWat(x.last_seen)}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )
                )}
            </div>
        </div>
    );
}
