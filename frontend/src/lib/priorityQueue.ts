// Pure composition logic for the dashboard's Priority Action Queue (2026 redesign, R3.2).
// Pulled out of GeneralDashboard.tsx, same reasoning as lib/dashboardKpis.ts: these rules —
// which records qualify, how they're labelled, and how the "My Cases" filter matches — are a
// test's business, not only reachable by rendering the page.

export type PriorityKind = 'case' | 'approval' | 'remediation';
export type PrioritySeverity = 'critical' | 'high' | 'medium' | 'low' | null;

export interface PriorityItem {
    id: string;
    kind: PriorityKind;
    title: string;
    severity: PrioritySeverity;
    href: string;
    meta: string;
}

export interface QueueCase {
    id: string;
    name: string;
    asset: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    status: string;
    assignedTo: string | null;
}

export interface QueueApproval {
    id: string;
    action: string;
    target: string;
    target_label: string | null;
    requested_at: string;
}

export interface QueueOverdueFinding {
    id: string;
    title: string;
    asset_value: string | null;
    scanner_severity: PrioritySeverity;
    priority: string | null;
}

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

/**
 * "My Cases" — matches against cases.assigned_to, which the backend resolves and stores as the
 * analyst's platform_users.name at assignment time (routes/cases.ts POST /:id/assign), the same
 * name claim carried in this session's own token (routes/auth.ts, both read from
 * platform_users.name). There is no assigned_to filter on GET /api/cases, so this filters data
 * the dashboard already fetched for the case queue — never a separate download.
 */
export function filterMyCases<T extends { assignedTo: string | null }>(
    cases: T[] | null,
    myCasesOnly: boolean,
    currentUserName: string,
): T[] | null {
    if (!myCasesOnly || !cases) return cases;
    return cases.filter((c) => c.assignedTo === currentUserName);
}

/**
 * Critical/high cases + pending response approvals + overdue remediation, each kept as a
 * distinct, labelled row (never merged into one fabricated count), sorted by severity with
 * un-severitised rows (approvals) placed after every severitised one.
 */
export function buildPriorityItems(
    cases: QueueCase[] | null,
    approvals: QueueApproval[] | null,
    overdueFindings: QueueOverdueFinding[] | null,
    formatRequestedAt: (iso: string) => string,
): PriorityItem[] {
    return [
        ...(cases ?? []).filter((c) => c.severity === 'critical' || c.severity === 'high').map((c): PriorityItem => ({
            id: c.id, kind: 'case', title: c.name, severity: c.severity, href: '/admin/secops/cases',
            meta: `${c.status} · ${c.asset}`,
        })),
        ...(approvals ?? []).map((a): PriorityItem => ({
            id: a.id, kind: 'approval', title: a.target_label || a.target, severity: null, href: '/admin/secops/approvals',
            meta: `${a.action.replace(/_/g, ' ')} · requested ${formatRequestedAt(a.requested_at)}`,
        })),
        ...(overdueFindings ?? []).map((f): PriorityItem => ({
            id: f.id, kind: 'remediation', title: f.title, severity: f.scanner_severity, href: '/admin/vms/findings',
            meta: [f.asset_value ?? 'Unknown asset', f.priority].filter(Boolean).join(' · '),
        })),
    ].sort((a, b) => (SEV_RANK[a.severity ?? ''] ?? 4) - (SEV_RANK[b.severity ?? ''] ?? 4));
}

/** Names which of the three sources could not be read, so the queue above can say so instead of
 * silently looking empty or complete. */
export function priorityFailedSources(casesFailed: boolean, approvalsFailed: boolean, overdueFindingsFailed: boolean): string[] {
    return [
        ...(casesFailed ? ['cases'] : []),
        ...(approvalsFailed ? ['approvals'] : []),
        ...(overdueFindingsFailed ? ['VMS findings'] : []),
    ];
}
