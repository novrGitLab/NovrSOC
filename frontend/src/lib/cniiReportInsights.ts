// Pure, data-driven "key recommendations" for the CNII Watch Executive report (R3.3B Stage 6).
// Same discipline as lib/vmsReportInsights.ts: every line cites a specific real figure already
// returned by GET /api/cnii/national/orgs/:org — nothing here invents a score or a trend, and a
// monitoring gap is always named for what it actually is, never smoothed into "everything's fine".

export type CoverageState = 'connected_fresh' | 'connected_stale' | 'configured_not_receiving' | 'not_connected' | 'unknown';

const COVERAGE_RECOMMENDATION: Record<CoverageState, string | null> = {
    connected_fresh: null,
    connected_stale: 'Monitoring telemetry for this organisation is stale — collection has not run recently enough to trust the figures below as current.',
    configured_not_receiving: 'An authorised scope exists, but no passive collection has ever run for this organisation — the figures below reflect only what was known before, or nothing at all.',
    not_connected: 'This organisation has no active authorised scope — nothing is actively monitored. The figures below are historical, not current.',
    unknown: 'This organisation\'s monitoring status could not be determined — treat the figures below as unverified.',
};

export interface CniiReportInput {
    coverage_state: CoverageState;
    critical_high: number;
    kev_open: number;
    assets_requiring_attention: number;
    threat_intelligence: { total: number; verified: number; contextual: number };
    remediation_open: number;
    remediation_closed: number;
}

/** Ordered by urgency: the monitoring state itself (it changes how much to trust everything
 * else), then verified threat intelligence, then KEV, then open critical/high exposure, then
 * remediation progress. Returns one honest line when there is nothing to flag. */
export function keyRecommendations(r: CniiReportInput): string[] {
    const out: string[] = [];

    const coverageLine = COVERAGE_RECOMMENDATION[r.coverage_state];
    if (coverageLine) out.push(coverageLine);

    if (r.threat_intelligence.verified > 0) {
        out.push(`${r.threat_intelligence.verified} verified threat intelligence association${r.threat_intelligence.verified === 1 ? '' : 's'} on this organisation's assets — review immediately. A verified association is a confirmed analyst finding, not an inference from a shared indicator alone.`);
    }
    if (r.kev_open > 0) {
        out.push(`${r.kev_open} open finding${r.kev_open === 1 ? '' : 's'} on CISA's Known Exploited Vulnerabilities list.`);
    }
    if (r.critical_high > 0) {
        out.push(`${r.critical_high} open critical or high severity finding${r.critical_high === 1 ? '' : 's'} across ${r.assets_requiring_attention} asset${r.assets_requiring_attention === 1 ? '' : 's'} requiring attention.`);
    }
    if (r.threat_intelligence.contextual > 0 && r.threat_intelligence.verified === 0) {
        out.push(`${r.threat_intelligence.contextual} contextual-only threat intelligence match${r.threat_intelligence.contextual === 1 ? '' : 'es'} — not yet confirmed as relevant to this organisation specifically.`);
    }
    const totalRem = r.remediation_open + r.remediation_closed;
    if (totalRem > 0) {
        const pct = Math.round((r.remediation_closed / totalRem) * 100);
        if (pct < 50) out.push(`Remediation progress is ${pct}% (${r.remediation_closed} of ${totalRem} findings closed) — below half.`);
    }

    if (out.length === 0) out.push('No critical/high exposure, known-exploited vulnerabilities or verified threat intelligence associations are currently open, and monitoring is receiving telemetry.');
    return out;
}
