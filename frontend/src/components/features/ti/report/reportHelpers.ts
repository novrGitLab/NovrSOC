// Pure helpers for the Threat Intelligence report (/admin/ti/report). Side-effect-free and
// framework-free so they're directly unit-testable — no DOM, no fetch, no React.

/** A deterministic, human-meaningful report identifier for this view — not a stored artifact id
 * (this page has none of its own; the scheduled Reporting Center is a separate system). Stable
 * for the same org+period within a minute, distinguishable a minute apart. */
export function tiReportId(orgSlug: string, days: number, generatedAt: Date = new Date()): string {
    const stamp = generatedAt.toISOString().slice(0, 16).replace(/[-:T]/g, '');
    const org = (orgSlug || 'org').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12) || 'ORG';
    return `TIR-${org}-${stamp}-${days}D`;
}

export interface DaySeries { day: string; count: number }
/** Merges two independently-keyed daily series (new indicators, new matches) into one row set
 * TimeChart can plot — a day present in only one series gets 0 for the other, not a missing row. */
export function mergeTrend(indicators: DaySeries[], matches: DaySeries[]): { day: string; indicators: number; matches: number }[] {
    const days = [...new Set([...indicators.map((d) => d.day), ...matches.map((d) => d.day)])].sort();
    const iByDay = new Map(indicators.map((d) => [d.day, d.count]));
    const mByDay = new Map(matches.map((d) => [d.day, d.count]));
    return days.map((day) => ({ day, indicators: iByDay.get(day) ?? 0, matches: mByDay.get(day) ?? 0 }));
}
