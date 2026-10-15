// Audit log. logAudit() is synchronous for its callers: the entry goes into a small in-memory
// buffer at once and is written to the Supabase `audit_log` table in the background
// (sql/2026-10-14_p2_identity_audit.sql). Entries survive restarts once the table exists; until
// then (or while the database is unreachable) the buffer is the only copy, as before, and a
// failed write is retried a few times before it is reported once in the log.
//
// readAuditLog() reads the table when it can and falls back to the buffer, saying which.

import { getSupabase } from '../services/geoEnrichment';

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
    /** The organisation the action concerned, when there is one. */
    org_id?: string;
}

const auditLog: AuditEntry[] = [];
const MAX_ENTRIES = 1000;
const pending: { entry: AuditEntry; tries: number }[] = [];
const MAX_PENDING = 5000;
let flushing = false;
let warnedNoTable = false;

const toRow = (e: AuditEntry) => ({
    at: e.timestamp, actor: e.user.slice(0, 320), action: e.action.slice(0, 120), resource: e.resource.slice(0, 200),
    resource_id: e.resource_id?.slice(0, 200) ?? null, org_id: e.org_id ?? null, ip: e.ip?.slice(0, 64) ?? null,
    result: e.result, severity: e.severity ?? 'info', details: e.details?.slice(0, 2000) ?? null,
});

async function flush(): Promise<void> {
    if (flushing) return;
    const supabase = getSupabase();
    if (!supabase || pending.length === 0) return;
    flushing = true;
    try {
        while (pending.length) {
            const batch = pending.slice(0, 200);
            const { error } = await supabase.from('audit_log').insert(batch.map((p) => toRow(p.entry)));
            if (!error) { pending.splice(0, batch.length); continue; }
            if (/audit_log/.test(error.message) && /does not exist|Could not find/i.test(error.message)) {
                if (!warnedNoTable) console.warn('[audit] audit_log table missing — entries kept in memory only (run sql/2026-10-14_p2_identity_audit.sql)');
                warnedNoTable = true;
                pending.length = 0;
                return;
            }
            for (const p of batch) p.tries++;
            const dropped = pending.filter((p) => p.tries >= 5);
            if (dropped.length) {
                console.error(`[audit] could not persist ${dropped.length} audit entr${dropped.length === 1 ? 'y' : 'ies'}: ${error.message.slice(0, 160)}`);
                for (const d of dropped) pending.splice(pending.indexOf(d), 1);
            }
            setTimeout(() => { void flush(); }, 5_000).unref?.();
            return;
        }
    } finally {
        flushing = false;
    }
}

export function logAudit(entry: Omit<AuditEntry, 'id' | 'timestamp'>): void {
    const full: AuditEntry = {
        id: `audit-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        timestamp: new Date().toISOString(),
        severity: 'info',
        ...entry,
    };
    auditLog.push(full);
    if (auditLog.length > MAX_ENTRIES) auditLog.splice(0, auditLog.length - MAX_ENTRIES);
    if (pending.length < MAX_PENDING) pending.push({ entry: full, tries: 0 });
    void flush().catch((err) => console.error('[audit] flush failed:', err instanceof Error ? err.message : err));
}

/** Newest first, from this process's memory only. */
export function getAuditLog(limit = 100): AuditEntry[] {
    return auditLog.slice(-limit).reverse();
}

/** Newest first: the durable table when available, else this process's memory. */
export async function readAuditLog(limit = 100): Promise<{ entries: AuditEntry[]; source: 'database' | 'memory' }> {
    const supabase = getSupabase();
    if (supabase && !warnedNoTable) {
        const { data, error } = await supabase.from('audit_log').select('id, at, actor, action, resource, resource_id, org_id, ip, result, severity, details')
            .order('at', { ascending: false }).limit(limit);
        if (!error) {
            return {
                source: 'database',
                entries: (data ?? []).map((r) => ({
                    id: r.id, timestamp: r.at, user: r.actor, action: r.action, resource: r.resource, ip: r.ip ?? 'unknown',
                    result: r.result, severity: r.severity, details: r.details ?? undefined, resource_id: r.resource_id ?? undefined, org_id: r.org_id ?? undefined,
                })),
            };
        }
    }
    return { entries: getAuditLog(limit), source: 'memory' };
}

/** Test hook: wait until queued entries have been written (or given up on). */
export async function flushAuditForTests(): Promise<void> {
    for (let i = 0; i < 50 && (pending.length || flushing); i++) { await flush(); await new Promise((r) => setTimeout(r, 10)); }
}
