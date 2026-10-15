'use client';

// Passive lookup of one IP address (phase P9): who the registry says holds it, a suggested CNII
// sector, whether it is a known threat indicator, and which organisation (if any) has it in an
// authorised scope. Nothing is stored and nothing touches the address. A suggestion is not
// ownership and authorises nothing.

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { ArrowLeft, Search } from 'lucide-react';
import { SECTOR_BY_ID } from '@/lib/cnii-sectors';
import { apiSend, timeAgo } from '@/lib/cnii-types';

interface Lookup {
    ip: string; network: { asns: string[]; prefix: string | null } | null; holder: string | null;
    sector_suggestion: { sectorId: string; subfield: string; confidence: number } | null;
    indicator: { id: string; status: string; max_confidence: number | null; malware_families: string[]; threat_types: string[]; source_count: number; last_seen: string } | null;
    in_inventory_of: { org_id: string; asset_id: string; authorised: boolean }[];
    opencti: { source: string; description: string; severity: string }[] | null;
    sources: Record<string, string>; note: string;
}

export function CniiLookup({ ip }: { ip: string }) {
    const [r, setR] = useState<Lookup | null>(null);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        let active = true;
        void apiSend<Lookup>('/api/cnii/lookup', 'POST', { ip }).then((x) => { if (active) { setR(x.ok ? x.data : null); setError(x.ok ? null : x.error); } });
        return () => { active = false; };
    }, [ip]);

    return (
        <div className="space-y-4 text-xs">
            <Link href="/admin/cnii" className="text-[11px] text-foreground-muted flex items-center gap-1"><ArrowLeft className="w-3 h-3" /> CNII Watch</Link>
            <h1 className="text-lg font-black text-foreground flex items-center gap-2"><Search className="w-5 h-5" /> <span className="font-mono">{ip}</span></h1>
            {error && <p role="alert" className="text-red font-semibold">{error}</p>}
            {!r && !error && <p className="text-foreground-muted">Looking up…</p>}
            {r && (
                <>
                    <p className="text-foreground-muted">{r.note}</p>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div className="bg-card border border-border rounded-xl p-4 space-y-1">
                            <h2 className="text-sm font-bold text-foreground">Registry (RIPE Stat)</h2>
                            <p>Holder: <span className="font-semibold">{r.holder ?? 'unknown'}</span></p>
                            <p>Announced by: {r.network?.asns.join(', ') || 'unknown'} · prefix {r.network?.prefix ?? 'unknown'}</p>
                            <p>Suggested sector: {r.sector_suggestion ? `${SECTOR_BY_ID[r.sector_suggestion.sectorId]?.label ?? r.sector_suggestion.sectorId}${r.sector_suggestion.subfield ? ` · ${r.sector_suggestion.subfield}` : ''} (keyword match, ${r.sector_suggestion.confidence}%)` : 'none matched'}</p>
                        </div>
                        <div className="bg-card border border-border rounded-xl p-4 space-y-1">
                            <h2 className="text-sm font-bold text-foreground">In NovrSOC</h2>
                            {r.in_inventory_of.length === 0 ? <p>Not in any organisation&apos;s inventory.</p> : r.in_inventory_of.map((h) => (
                                <p key={h.asset_id}><Link className="text-purple font-bold" href={`/admin/cnii/org/${encodeURIComponent(h.org_id)}/asset/${h.asset_id}`}>{h.org_id}</Link> · {h.authorised ? 'inside an authorised scope' : 'no longer inside an authorised scope'}</p>
                            ))}
                            <p className="pt-1">Threat indicator: {r.indicator ? `${r.indicator.status}, ${r.indicator.source_count} source(s)${r.indicator.malware_families.length ? `, ${r.indicator.malware_families.join(', ')}` : ''}, last listed ${timeAgo(r.indicator.last_seen)}` : 'not listed by any feed'}</p>
                        </div>
                    </div>
                    <div className="bg-card border border-border rounded-xl p-4">
                        <h2 className="text-sm font-bold text-foreground mb-1">OpenCTI</h2>
                        {r.opencti === null ? <p className="text-foreground-muted">{r.sources.opencti}</p> : r.opencti.length === 0 ? <p>OpenCTI has nothing on this address.</p> : <ul className="list-disc ml-5">{r.opencti.map((o, i) => <li key={i}>{o.description} <span className="text-foreground-muted">({o.severity}, as OpenCTI states)</span></li>)}</ul>}
                    </div>
                    <p className="text-foreground-muted">Sources: {Object.entries(r.sources).map(([k, v]) => `${k}: ${v}`).join(' · ')}</p>
                </>
            )}
        </div>
    );
}
