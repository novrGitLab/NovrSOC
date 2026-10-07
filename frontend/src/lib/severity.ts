// Mirror of backend/src/lib/severity.ts — the one mapping from a Wazuh rule level to a severity.
//
//   level >= 13  critical
//   level >= 10  high
//   level >= 7   medium
//   otherwise    low
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
