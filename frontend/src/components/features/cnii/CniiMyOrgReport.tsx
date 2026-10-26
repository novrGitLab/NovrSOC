'use client';

// CNII Watch report for an executive's own organisation (R3.3B correction). Reads only
// GET /api/cnii/profile (cnii:read — never cnii:sector, so this never reaches national or
// cross-organisation data) for the CNII-specific framing (sector, designation, monitoring
// coverage state, threat intelligence summary), then reuses the existing VmsReport component
// verbatim for the detailed Executive/Technical vulnerability report — executives already hold
// vms:read (lib/permissions.ts), confined to their own organisation by lib/resolveOrg.ts exactly
// the same way cnii:read is, so this introduces no new privilege.

import { useEffect, useState } from 'react';
import { Building2 } from 'lucide-react';
import { SECTOR_BY_ID } from '@/lib/cnii-sectors';
import { cniiGet, type OrgStats } from '@/lib/cnii-types';
import { Card, StatusPill, type Tone } from '../vms/ui';
import { ErrorState, KpiCard } from '../vms/kit';
import { VmsReport } from '../vms/VmsReport';

type CoverageState = 'connected_fresh' | 'connected_stale' | 'configured_not_receiving' | 'not_connected' | 'unknown';
interface ProfileResp {
    organisation: { slug: string; name?: string };
    profile: { sector_id: string; subfield: string | null; designation: 'designated' | 'candidate' } | null;
    stats: OrgStats;
    gaps: string[];
    coverage_state: CoverageState;
    threat_intelligence: { total: number; verified: number; contextual: number };
}

// CNII Watch has no continuous endpoint agent of its own: "connected" means a recent authorised
// passive collection run (a point-in-time external scan), never continuous Wazuh/EDR telemetry.
const COVERAGE_TONE: Record<CoverageState, Tone> = { connected_fresh: 'good', connected_stale: 'warning', configured_not_receiving: 'warning', not_connected: 'critical', unknown: 'neutral' };
const COVERAGE_LABEL: Record<CoverageState, string> = { connected_fresh: 'Recent authorised passive collection', connected_stale: 'Passive collection has run, but not recently', configured_not_receiving: 'Authorised, but no passive collection has run yet', not_connected: 'No active authorised scope — not connected', unknown: 'Monitoring status unknown' };

export function CniiMyOrgReport() {
    const [data, setData] = useState<ProfileResp | null>(null);
    const [error, setError] = useState<{ message: string; status?: number } | null>(null);

    useEffect(() => {
        let active = true;
        void cniiGet<ProfileResp>('/profile').then((r) => {
            if (!active) return;
            if (r.ok) { setData(r.data); setError(null); } else { setData(null); setError({ message: r.error, status: r.status }); }
        });
        return () => { active = false; };
    }, []);

    if (error) return <ErrorState error={error.message} status={error.status} />;
    const meta = data?.profile ? SECTOR_BY_ID[data.profile.sector_id] : undefined;

    return (
        <div className="space-y-4">
            {!data ? <div className="h-24 rounded-2xl bg-card-muted motion-safe:animate-pulse" /> : (
                <Card>
                    <div className="p-1 flex flex-wrap items-start gap-4">
                        <span className="w-10 h-10 rounded-xl flex items-center justify-center bg-purple/10 text-purple dark:text-[var(--vz-prog-4)] shrink-0"><Building2 className="w-5 h-5" aria-hidden /></span>
                        <div className="flex-1 min-w-[220px] space-y-2">
                            <div>
                                <h1 className="text-lg font-black text-foreground">{data.organisation.name ?? data.organisation.slug}</h1>
                                <p className="text-xs text-foreground-muted">{meta?.label ?? data.profile?.sector_id ?? 'No sector classified'}{data.profile?.subfield ? ` · ${data.profile.subfield}` : ''}</p>
                            </div>
                            <div className="flex flex-wrap items-center gap-2">
                                {data.profile && <StatusPill tone={data.profile.designation === 'designated' ? 'good' : 'warning'} label={data.profile.designation === 'designated' ? 'Designated CNII' : 'Candidate — not yet designated'} />}
                                <StatusPill tone={COVERAGE_TONE[data.coverage_state]} label={COVERAGE_LABEL[data.coverage_state]} />
                            </div>
                            {data.gaps.length > 0 && <ul className="text-[11px] text-foreground-muted space-y-0.5">{data.gaps.map((g) => <li key={g}>• {g}</li>)}</ul>}
                        </div>
                        <KpiCard label="Threat intelligence matches" value={data.threat_intelligence.total} tone={data.threat_intelligence.verified > 0 ? 'critical' : 'good'}
                            sub={data.threat_intelligence.total ? `${data.threat_intelligence.verified} verified association(s) · ${data.threat_intelligence.contextual} contextual only — not a confirmed attack or compromise` : 'No indicator matches'} />
                    </div>
                </Card>
            )}
            {/* The detailed vulnerability report below is the same Executive/Technical VmsReport
             * every VMS page uses — vms:read already confines it to this organisation. */}
            <VmsReport />
        </div>
    );
}
