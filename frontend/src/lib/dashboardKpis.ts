// Honest-failure-state display logic for the main dashboard's KPI row (2026 redesign, Stage 4).
// Pulled out of GeneralDashboard.tsx so the "unknown vs. zero vs. not-for-your-role" rules are
// pure functions a test can exercise directly, instead of only reachable by rendering the page.
// The rule throughout: a count that could not be read is "—" with a reason, never a false 0.

export type KpiType = 'green' | 'orange' | 'red' | 'purple' | 'blue';

export interface PlatformHealthData {
    overall: string;
    services: Array<{ status: string }>;
    error?: string;
}

export interface PlatformHealthDisplay {
    pct: string;
    type: KpiType;
    sub: string;
}

/** Platform Health is super_admin-only on the backend (requireRole('super_admin')) — every
 * other role always got a 403 here, which used to render as a red "0%" rather than
 * "unavailable for your role". */
export function platformHealthDisplay(isSuperAdmin: boolean, health: PlatformHealthData | null): PlatformHealthDisplay {
    if (!isSuperAdmin) return { pct: '—', type: 'purple', sub: 'not available for your role' };
    if (!health) return { pct: '—', type: 'purple', sub: 'checking…' };
    if (health.error) return { pct: '—', type: 'purple', sub: health.error };
    const servicesUp = health.services.filter((s) => s.status === 'up').length;
    const servicesTotal = health.services.length;
    const sub = `${servicesUp}/${servicesTotal} services up`;
    if (health.overall === 'operational') return { pct: '100%', type: 'green', sub };
    if (health.overall === 'degraded') return { pct: `${Math.round((servicesUp / Math.max(servicesTotal, 1)) * 100)}%`, type: 'orange', sub };
    return { pct: '0%', type: 'red', sub };
}

export interface CountDisplay { value: string; sub: string }

/** A null count means the load failed or hasn't finished — not that the count is zero. */
export function honestCountDisplay(count: number | null, failed: boolean, okSub: string): CountDisplay {
    if (count !== null) return { value: String(count), sub: okSub };
    return { value: '—', sub: failed ? 'unavailable' : 'checking…' };
}

/** Open Cases also carries a secondary "N critical" figure once the load succeeds. */
export function openCasesDisplay(kpis: { total: number; critical: number } | null, failed: boolean): CountDisplay {
    if (kpis) return { value: String(kpis.total), sub: `${kpis.critical} critical` };
    return { value: '—', sub: failed ? 'unavailable' : 'checking…' };
}
