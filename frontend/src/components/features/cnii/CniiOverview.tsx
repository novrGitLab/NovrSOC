'use client';

// CNII Watch overview (phase P9): the 13 sectors with figures measured from VMS and the Threat
// Information System, the organisations to classify, a passive IP lookup, and the pre-P9 rows
// still waiting to be imported into an organisation. Confirmed and unconfirmed findings are
// always shown apart. Sector-wide figures are for SOC staff; the backend refuses client roles.

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Shield, Search, AlertTriangle, Upload } from 'lucide-react';
import { getAdminUser } from '@/lib/admin-auth';
import { CNII_SECTORS, SECTOR_BY_ID } from '@/lib/cnii-sectors';
import { cniiGet, apiSend, timeAgo, type SectorSummary, type CniiProfile } from '@/lib/cnii-types';
import { CniiIntake } from './CniiIntake';
import { DashboardNigeriaMap } from '@/components/dashboards/DashboardNigeriaMap';

interface OrgRow { slug: string; name: string; industry: string | null; profile: CniiProfile | null }
interface LegacyRow { id: string; ip: string; hostname: string | null; org: string | null; asn: string | null; sector_id: string; open_ports: number[] | null; vuln_count: number | null; last_seen: string; imported_org_id: string | null; imported_at: string | null }

export function CniiOverview() {
    const router = useRouter();
    const role = getAdminUser().role;
    const isManager = role === 'super_admin' || role === 'soc_manager';
    const [sectors, setSectors] = useState<SectorSummary[] | null>(null);
    const [orgs, setOrgs] = useState<OrgRow[]>([]);
    const [legacy, setLegacy] = useState<{ available: boolean; rows: LegacyRow[] } | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [ip, setIp] = useState('');
    const [importTo, setImportTo] = useState<Record<string, string>>({});
    const [msg, setMsg] = useState<string | null>(null);
    const [reloadKey, setReloadKey] = useState(0);
    const reload = useCallback(() => setReloadKey((k) => k + 1), []);

    useEffect(() => {
        let active = true;
        void Promise.all([
            cniiGet<{ sectors: SectorSummary[] }>('/sectors'),
            cniiGet<{ organisations: OrgRow[] }>('/organisations'),
            cniiGet<{ available: boolean; rows: LegacyRow[] }>('/legacy'),
        ]).then(([s, o, l]) => {
            if (!active) return;
            setSectors(s.ok ? s.data.sectors : null);
            setError(s.ok ? null : s.status === 403 ? 'The sector view is for SOC staff. Your organisation\'s CNII page is under Organisations.' : s.error);
            setOrgs(o.ok ? o.data.organisations : []);
            setLegacy(l.ok ? l.data : null);
        });
        return () => { active = false; };
    }, [reloadKey]);

    async function doImport(row: LegacyRow) {
        const org = importTo[row.id];
        if (!org) return;
        const r = await apiSend<{ asset_id: string; findings_new: number; sector_mismatch: { legacy: string; organisation: string } | null }>(`/api/cnii/legacy/${row.id}/import`, 'POST', {}, org);
        setMsg(r.ok ? `Imported ${row.ip} into ${org}${r.data.sector_mismatch ? ` (note: the old row said ${r.data.sector_mismatch.legacy}, the organisation is ${r.data.sector_mismatch.organisation})` : ''}` : r.error);
        reload();
    }

    const totals = (sectors ?? []).reduce((t, s) => ({ orgs: t.orgs + s.organisations, unmonitored: t.unmonitored + s.unmonitored, confirmed: t.confirmed + s.confirmed_p1_p2, unconfirmed: t.unconfirmed + s.unconfirmed_open }), { orgs: 0, unmonitored: 0, confirmed: 0, unconfirmed: 0 });
    const pendingLegacy = (legacy?.rows ?? []).filter((r) => !r.imported_at);
    const input = 'bg-card-muted border border-border rounded-lg px-3 py-2 text-xs text-foreground';

    return (
        <div className="space-y-5">
            <div className="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <h1 className="text-lg font-black text-foreground flex items-center gap-2"><Shield className="w-5 h-5" /> CNII Watch</h1>
                    <p className="text-xs text-foreground-muted max-w-3xl">Critical national infrastructure by sector. Assets, findings and indicator matches come from each organisation&apos;s authorised VMS scope and the Threat Information System. Passive monitoring asks third parties about registered assets; nothing touches a target without an approved scope that allows it.</p>
                </div>
                <form onSubmit={(e) => { e.preventDefault(); if (ip.trim()) router.push(`/admin/cnii/ip/${encodeURIComponent(ip.trim())}`); }} className="flex gap-2">
                    <input className={input} placeholder="Look up an IP address" value={ip} onChange={(e) => setIp(e.target.value)} aria-label="IP address to look up" />
                    <button className="flex items-center gap-1.5 text-[11px] font-bold text-white bg-purple rounded-lg px-3"><Search className="w-3.5 h-3.5" /> Look up</button>
                </form>
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {msg && <p role="status" className="text-xs text-foreground font-semibold">{msg}</p>}

            <DashboardNigeriaMap context="cnii" title="Nigeria Threat Heatmap" description="State-level critical-infrastructure threat activity" />

            {sectors && <CniiIntake orgs={orgs} isManager={isManager} canScan={isManager || role === 'analyst'} />}

            {sectors && (
                <>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        {[['Organisations classified', totals.orgs], ['Without active scope', totals.unmonitored], ['Confirmed P1/P2 open', totals.confirmed], ['Unconfirmed claims open', totals.unconfirmed]].map(([l, v]) => (
                            <div key={String(l)} className="bg-card border border-border rounded-xl p-4">
                                <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{l}</p>
                                <p className="text-2xl font-black text-foreground mt-1">{v}</p>
                            </div>
                        ))}
                    </div>
                    {totals.unmonitored > 0 && (
                        <p className="rounded-xl p-3 border border-amber/30 bg-amber/10 text-xs text-amber font-semibold flex items-center gap-2"><AlertTriangle className="w-4 h-4" /> {totals.unmonitored} classified organisation(s) have no active authorised scope, so nothing about them is monitored and their figures are zero for that reason.</p>
                    )}
                    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                        {sectors.map((s) => {
                            const meta = SECTOR_BY_ID[s.id];
                            const Icon = meta?.icon ?? Shield;
                            return (
                                <Link key={s.id} href={`/admin/cnii/${s.id}`} className="bg-card border border-border rounded-xl p-4 hover:border-purple/40 transition-colors">
                                    <div className="flex items-center gap-2">
                                        <Icon className="w-4 h-4" style={{ color: meta?.color }} />
                                        <p className="text-sm font-bold text-foreground">{meta?.label ?? s.id}</p>
                                    </div>
                                    <p className="text-[11px] text-foreground-muted mt-1">{s.organisations} organisation(s){s.designated ? `, ${s.designated} designated` : ''}{s.unmonitored ? ` · ${s.unmonitored} without scope` : ''}</p>
                                    <div className="grid grid-cols-4 gap-2 mt-3 text-center">
                                        <div><p className="text-base font-black text-foreground">{s.assets}</p><p className="text-[9px] text-foreground-muted uppercase">assets</p></div>
                                        <div><p className="text-base font-black text-red">{s.confirmed_p1_p2}</p><p className="text-[9px] text-foreground-muted uppercase">confirmed P1/P2</p></div>
                                        <div><p className="text-base font-black text-amber">{s.unconfirmed_open}</p><p className="text-[9px] text-foreground-muted uppercase">unconfirmed</p></div>
                                        <div><p className="text-base font-black text-foreground">{s.kev_open}</p><p className="text-[9px] text-foreground-muted uppercase">KEV</p></div>
                                    </div>
                                </Link>
                            );
                        })}
                    </div>
                </>
            )}

            {orgs.length > 0 && (
                <div className="bg-card border border-border rounded-xl p-4">
                    <h2 className="text-sm font-bold text-foreground mb-2">Organisations</h2>
                    <p className="text-[11px] text-foreground-muted mb-3">Classify an organisation into a sector on its page. Being classified does not authorise monitoring: that needs an approved scope with its authorisation reference.</p>
                    <div className="overflow-x-auto">
                        <table className="w-full text-xs">
                            <thead><tr className="text-left text-foreground-muted"><th className="py-1 pr-3">Organisation</th><th className="pr-3">Sector</th><th className="pr-3">Designation</th><th /></tr></thead>
                            <tbody>
                                {orgs.map((o) => (
                                    <tr key={o.slug} className="border-t border-border">
                                        <td className="py-1.5 pr-3 font-semibold text-foreground">{o.name} <span className="text-foreground-muted font-normal">({o.slug})</span></td>
                                        <td className="pr-3">{o.profile ? SECTOR_BY_ID[o.profile.sector_id]?.label ?? o.profile.sector_id : <span className="text-foreground-muted">not classified</span>}</td>
                                        <td className="pr-3">{o.profile?.designation ?? '—'}</td>
                                        <td className="text-right"><Link className="text-purple font-bold" href={`/admin/cnii/org/${encodeURIComponent(o.slug)}`}>Open</Link></td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {legacy?.available && pendingLegacy.length > 0 && (
                <div className="bg-card border border-border rounded-xl p-4">
                    <h2 className="text-sm font-bold text-foreground mb-1 flex items-center gap-2"><Upload className="w-4 h-4" /> Earlier CNII Watch records ({pendingLegacy.length} not yet imported)</h2>
                    <p className="text-[11px] text-foreground-muted mb-3">These rows came from the old IP scanner, which also ran an active port scan without a recorded authorisation. Import one into an organisation only once that organisation has a profile and an approved scope covering the address. Its data comes in as low-confidence observations and unconfirmed findings.</p>
                    <div className="overflow-x-auto">
                        <table className="w-full text-xs">
                            <thead><tr className="text-left text-foreground-muted"><th className="py-1 pr-3">IP</th><th className="pr-3">Recorded owner</th><th className="pr-3">Old sector</th><th className="pr-3">Last scan</th>{isManager && <th>Import into</th>}</tr></thead>
                            <tbody>
                                {pendingLegacy.map((r) => (
                                    <tr key={r.id} className="border-t border-border">
                                        <td className="py-1.5 pr-3 font-mono text-foreground">{r.ip}{r.hostname ? <span className="text-foreground-muted"> {r.hostname}</span> : null}</td>
                                        <td className="pr-3">{r.org ?? '—'} {r.asn ?? ''}</td>
                                        <td className="pr-3">{SECTOR_BY_ID[r.sector_id]?.label ?? r.sector_id}</td>
                                        <td className="pr-3">{timeAgo(r.last_seen)}</td>
                                        {isManager && (
                                            <td className="flex gap-2 py-1">
                                                <select className={input} value={importTo[r.id] ?? ''} onChange={(e) => setImportTo({ ...importTo, [r.id]: e.target.value })} aria-label={`Organisation for ${r.ip}`}>
                                                    <option value="">Choose…</option>
                                                    {orgs.filter((o) => o.profile).map((o) => <option key={o.slug} value={o.slug}>{o.name}</option>)}
                                                </select>
                                                <button disabled={!importTo[r.id]} onClick={() => void doImport(r)} className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 disabled:opacity-40">Import</button>
                                            </td>
                                        )}
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
            {!sectors && !error && <p className="text-xs text-foreground-muted">Loading…</p>}
            {sectors && sectors.every((s) => s.organisations === 0) && (
                <p className="text-xs text-foreground-muted">No organisation is classified yet. Open an organisation below and set its sector. Available sectors: {CNII_SECTORS.map((s) => s.label).join(', ')}.</p>
            )}
        </div>
    );
}
