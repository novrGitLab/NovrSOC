// The one mapping from a Wazuh rule level to a severity label.
//
//   level >= 13  critical
//   level >= 10  high
//   level >= 7   medium
//   otherwise    low
//
// Matches the SOAR engine's get_severity() (infra/soar/soar.py), which is Python and keeps its own
// copy of these thresholds. The frontend mirrors this file in frontend/src/lib/severity.ts; a test
// there (frontend/scripts/severity.test.mjs) fails if the two ever disagree.
//
// Indexer queries that bucket alerts by severity should use SEVERITY_MIN_LEVEL rather than
// literal numbers, so a count of "critical" alerts means the same thing everywhere.
//
// Scores (phase R2). Every 0-100 risk or confidence score (IOC risk, AbuseIPDB confidence, URL
// scan risk, OpenCTI/feed confidence, phishing risk points) maps through the same bands:
//
//   score >= 90  critical            score >= 70  malicious
//   score >= 70  high                score >= 30  suspicious
//   score >= 30  medium              otherwise    clean
//   otherwise    low
//
// so "malicious" is exactly high-or-critical and "suspicious" exactly medium. These replace the
// earlier per-file bands (70/30, 75/25, 80/50, 90/70/40, 80/60/40, 75/50/30). CVSS base scores
// (0-10) use the CVSS v3 qualitative bands via severityFromCvss.
//
// Not severities, so not routed here: health/grade scores where higher is better (DNS/email auth
// records, posture), SLA percentages, and counts.

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low'];

/** Lowest Wazuh rule level that falls into each severity. */
export const SEVERITY_MIN_LEVEL = { critical: 13, high: 10, medium: 7, low: 0 } as const;

export function severityFromLevel(level: number): Severity {
    if (level >= SEVERITY_MIN_LEVEL.critical) return 'critical';
    if (level >= SEVERITY_MIN_LEVEL.high) return 'high';
    if (level >= SEVERITY_MIN_LEVEL.medium) return 'medium';
    return 'low';
}

export type Verdict = 'malicious' | 'suspicious' | 'clean';

/** Lowest 0-100 score that falls into each severity. */
export const SCORE_MIN = { critical: 90, high: 70, medium: 30, low: 0 } as const;

export function severityFromScore(score: number): Severity {
    if (score >= SCORE_MIN.critical) return 'critical';
    if (score >= SCORE_MIN.high) return 'high';
    if (score >= SCORE_MIN.medium) return 'medium';
    return 'low';
}

/** malicious = high or critical, suspicious = medium, clean = low. */
export function verdictFromScore(score: number): Verdict {
    const s = severityFromScore(score);
    return s === 'critical' || s === 'high' ? 'malicious' : s === 'medium' ? 'suspicious' : 'clean';
}

/** CVSS v3 qualitative rating: 9.0+ critical, 7.0+ high, 4.0+ medium, otherwise low. */
export function severityFromCvss(score: number): Severity {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    return 'low';
}
