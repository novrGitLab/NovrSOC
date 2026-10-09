// Mirror of backend/src/lib/severity.ts — the one mapping from a Wazuh rule level to a severity.
//
//   level >= 13  critical
//   level >= 10  high
//   level >= 7   medium
//   otherwise    low
//
// 0-100 risk / confidence scores (higher = worse) use one set of bands, also mirrored:
//
//   score >= 90 critical · >= 70 high · >= 30 medium · otherwise low
//   verdict: >= 70 malicious · >= 30 suspicious · otherwise clean
//
// CVSS base scores (0-10) use the CVSS v3 bands. Components map severity/verdict to their own
// colours, but never re-derive the thresholds.
//
// scripts/severity.test.mjs fails if these thresholds ever differ from the backend's.

export type Severity = 'critical' | 'high' | 'medium' | 'low';

/** Lowest Wazuh rule level that falls into each severity. */
export const SEVERITY_MIN_LEVEL = { critical: 13, high: 10, medium: 7, low: 0 } as const;

export function severityFromLevel(level: number): Severity {
    if (level >= SEVERITY_MIN_LEVEL.critical) return 'critical';
    if (level >= SEVERITY_MIN_LEVEL.high) return 'high';
    if (level >= SEVERITY_MIN_LEVEL.medium) return 'medium';
    return 'low';
}

/** Text colour for a Wazuh rule level, by severity. */
export function levelTextClass(level: number): string {
    const s = severityFromLevel(level);
    return s === 'critical' ? 'text-red' : s === 'low' ? 'text-blue' : 'text-amber';
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
