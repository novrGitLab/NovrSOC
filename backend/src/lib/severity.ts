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
