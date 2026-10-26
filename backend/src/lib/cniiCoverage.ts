// CNII Watch monitoring-coverage state (R3.3B, Stage 2). A pure function over the same figures
// routes/cnii.ts's orgStats() already computes (active_scopes, last_collection) — no new query,
// no new table. Replaces a binary "Monitored"/"No scope" read with the five states the release
// asks for, so "we have never heard from this organisation" is never shown the same as "healthy".
//
// What this measures: CNII Watch has no continuous endpoint agent of its own (it deliberately
// never reads Wazuh — routes/cnii.ts's own header comment). "Connected" here means the
// organisation has an active authorised scope AND a recent periodic passive OSINT collection run
// (services/cniiPassive.ts, queued on demand or on a schedule) — a point-in-time external scan,
// not continuous telemetry the way a Wazuh agent or an EDR sensor reports. The label and every
// definition string below say "passive collection" explicitly so this is never mistaken for
// continuous endpoint monitoring.
//
// The critical rule this exists to enforce: unknown monitoring is not healthy monitoring. A
// missing or unparseable timestamp is 'unknown', never 'connected_fresh'.

export type CoverageState = 'connected_fresh' | 'connected_stale' | 'configured_not_receiving' | 'not_connected' | 'unknown';

export const COVERAGE_LABEL: Record<CoverageState, string> = {
    connected_fresh: 'Recent authorised passive collection',
    connected_stale: 'Passive collection has run, but not recently',
    configured_not_receiving: 'Authorised, but no passive collection has run yet',
    not_connected: 'No active authorised scope — not connected',
    unknown: 'Monitoring status unknown',
};

export interface CoverageInput {
    active_scopes: number;
    last_collection: { at: string; status: string } | null;
}

/** Threshold matches routes/cnii.ts's existing gaps() check ("passive collection older than 8
 * days") — the same documented threshold, not a new one invented for this function. */
export const STALE_AFTER_DAYS = 8;

export function coverageState(s: CoverageInput, now = Date.now(), staleAfterDays = STALE_AFTER_DAYS): CoverageState {
    if (!Number.isFinite(s.active_scopes) || s.active_scopes < 0) return 'unknown';
    if (s.active_scopes === 0) return 'not_connected';
    if (!s.last_collection) return 'configured_not_receiving';
    if (s.last_collection.status === 'failed') return 'configured_not_receiving';
    const age = now - Date.parse(s.last_collection.at);
    if (!Number.isFinite(age)) return 'unknown';
    return age > staleAfterDays * 86_400_000 ? 'connected_stale' : 'connected_fresh';
}

export interface CoverageTally { connected_fresh: number; connected_stale: number; configured_not_receiving: number; not_connected: number; unknown: number }
export const emptyCoverageTally = (): CoverageTally => ({ connected_fresh: 0, connected_stale: 0, configured_not_receiving: 0, not_connected: 0, unknown: 0 });

/** Aggregates coverage state counts for a sector/national summary, with a plain percentage and
 * its denominator stated explicitly alongside it (never a bare, ambiguous percentage). */
export function tallyCoverage(states: CoverageState[]): { by_state: CoverageTally; total: number; connected_pct: number | null } {
    const by_state = emptyCoverageTally();
    for (const s of states) by_state[s]++;
    const total = states.length;
    const connected = by_state.connected_fresh + by_state.connected_stale;
    return { by_state, total, connected_pct: total ? Math.round((connected / total) * 100) : null };
}
