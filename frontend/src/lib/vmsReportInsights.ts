// Pure, data-driven "key recommendations" for the VMS Executive report (2026 redesign, R3.3A).
// Every line is derived directly from a specific, named figure already in the period report
// (services/vmsContinuous.ts periodReport) — nothing here invents a score, a trend or a
// compliance determination that isn't already a real count the backend returned.

export interface VmsReportOpenNow {
    total: number;
    by_severity: Record<string, number>;
    overdue: number;
    known_exploited: number;
    affected_assets: number;
}

export interface VmsReportClosure {
    available: boolean;
    awaiting_verification_now?: number | null;
}

export interface VmsReportCompliance {
    overall_impact: 'No impact' | 'Low impact' | 'Medium impact' | 'High impact';
    frameworks: Record<string, { failing: number; at_risk: number }>;
}

export interface VmsReportForRecommendations {
    open_now: VmsReportOpenNow;
    closure?: VmsReportClosure | { available: false; note: string };
    compliance: VmsReportCompliance;
}

/** Ordered by urgency: known-exploited first, then overdue, then open critical exposure, then
 * unverified claims, then the compliance-impact summary. Returns one honest line when there is
 * nothing to flag, never an empty list that could read as "nothing was checked". */
export function keyRecommendations(r: VmsReportForRecommendations): string[] {
    const out: string[] = [];

    if (r.open_now.known_exploited > 0) {
        out.push(`${r.open_now.known_exploited} open finding${r.open_now.known_exploited === 1 ? '' : 's'} ${r.open_now.known_exploited === 1 ? 'is' : 'are'} on CISA's Known Exploited Vulnerabilities list — prioritise ${r.open_now.known_exploited === 1 ? 'it' : 'these'} first.`);
    }
    if (r.open_now.overdue > 0) {
        out.push(`${r.open_now.overdue} open finding${r.open_now.overdue === 1 ? '' : 's'} ${r.open_now.overdue === 1 ? 'is' : 'are'} past its remediation deadline.`);
    }
    const critical = r.open_now.by_severity.critical ?? 0;
    if (critical > 0) {
        out.push(`${critical} open critical-severity finding${critical === 1 ? '' : 's'} across ${r.open_now.affected_assets} affected asset${r.open_now.affected_assets === 1 ? '' : 's'}.`);
    }
    if (r.closure && r.closure.available && typeof r.closure.awaiting_verification_now === 'number' && r.closure.awaiting_verification_now > 0) {
        out.push(`${r.closure.awaiting_verification_now} finding${r.closure.awaiting_verification_now === 1 ? '' : 's'} ${r.closure.awaiting_verification_now === 1 ? 'is' : 'are'} marked fixed and awaiting verification — not yet confirmed closed.`);
    }
    if (r.compliance.overall_impact !== 'No impact') {
        const frameworkCount = Object.keys(r.compliance.frameworks).length;
        out.push(`Current exposure maps to a "${r.compliance.overall_impact}" compliance impact across ${frameworkCount} framework${frameworkCount === 1 ? '' : 's'} — see Compliance Context below. This is a technical mapping, not a compliance determination.`);
    }

    if (out.length === 0) out.push('No critical findings, overdue items or known-exploited vulnerabilities are currently open.');
    return out;
}
