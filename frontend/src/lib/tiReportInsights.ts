// Pure, data-driven "key recommendations" for the Threat Intelligence Executive report (R3.3D).
// Every line is derived directly from a specific, named figure already in the report payload
// (backend GET /api/ti/report) — nothing here invents a score, a trend or an attribution that
// isn't already a real count the backend returned.

export interface TiReportForRecommendations {
    relevant: { by_tier: { critical: number; high: number; medium: number; low: number } };
    kev: { new_in_period: number; your_open_findings: number };
    matches: { verified: number; total: number };
    engine: { correlation_last_run_at: string | null };
}

/** Ordered by urgency: critical-tier relevance first, then KEV affecting open findings, then
 * verified associations, then engine health. Returns one honest line when there is nothing to
 * flag, never an empty list that could read as "nothing was checked". */
export function keyRecommendations(r: TiReportForRecommendations): string[] {
    const out: string[] = [];

    if (r.relevant.by_tier.critical > 0) {
        out.push(`${r.relevant.by_tier.critical} indicator match${r.relevant.by_tier.critical === 1 ? '' : 'es'} rate${r.relevant.by_tier.critical === 1 ? 's' : ''} as critical relevance — verified, and matched to a known-exploited vulnerability or a critical-criticality asset.`);
    }
    if (r.relevant.by_tier.high > 0) {
        out.push(`${r.relevant.by_tier.high} further match${r.relevant.by_tier.high === 1 ? '' : 'es'} rate${r.relevant.by_tier.high === 1 ? 's' : ''} as high relevance and ${r.relevant.by_tier.high === 1 ? 'has' : 'have'} not yet been reviewed.`);
    }
    if (r.kev.your_open_findings > 0) {
        out.push(`${r.kev.your_open_findings} open finding${r.kev.your_open_findings === 1 ? '' : 's'} ${r.kev.your_open_findings === 1 ? 'is' : 'are'} affected by a CVE newly added to CISA's Known Exploited Vulnerabilities list in this period.`);
    }
    if (r.matches.verified > 0) {
        out.push(`${r.matches.verified} of ${r.matches.total} current match${r.matches.total === 1 ? '' : 'es'} ${r.matches.verified === 1 ? 'is' : 'are'} a verified association — promoted by an analyst or linked to a case.`);
    }
    if (!r.engine.correlation_last_run_at) {
        out.push('The correlation engine that turns new records into matches has not reported a completed run in the process serving this report — figures above may not reflect the latest alerts, assets or findings. This resets on every restart or deploy, so on its own it is not evidence the engine is broken.');
    }

    if (out.length === 0) out.push('No critical- or high-relevance intelligence currently applies to this organisation\'s records.');
    return out;
}
