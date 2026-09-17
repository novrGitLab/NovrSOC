// In-memory audit log — same "module-level mutable store, live until process restart" pattern
// as lib/orgCtiStore.ts and every other mock-data route in this codebase. Swap for a real
// Supabase audit_log table when one exists; until then this is a real trail of real actions
// (unlike the Audit Log page's other rows, which stay clearly-labeled mock/historical data).

export interface AuditEntry {
    id: string;
    timestamp: string;
    user: string;
    action: string;
    resource: string;
    ip: string;
    result: 'success' | 'failed';
    details?: string;
    // Operational weight of the event, for filtering and colour-coding in the Audit Log page.
    // Distinct from `result`: a successful DELETE_ORG is still critical, and a failed read is
    // only informational. Defaults to 'info' when a call site doesn't classify itself.
    severity?: 'info' | 'warning' | 'critical';
    /** The id of the thing acted on (incident id, org id, user id), when there is one. */
    resource_id?: string;
}

const auditLog: AuditEntry[] = [];
const MAX_ENTRIES = 1000;

export function logAudit(entry: Omit<AuditEntry, 'id' | 'timestamp'>): void {
    auditLog.push({
        id: `audit-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        timestamp: new Date().toISOString(),
        severity: 'info',
        ...entry,
    });
    if (auditLog.length > MAX_ENTRIES) auditLog.splice(0, auditLog.length - MAX_ENTRIES);
}

export function getAuditLog(limit = 100): AuditEntry[] {
    return auditLog.slice(-limit).reverse();
}
