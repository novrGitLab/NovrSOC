// Alert store retention (R3.3C), once a day. sql/2026-10-09_alert_retention.sql's
// purge_old_alerts() existed with its pg_cron line commented out and nothing in Node ever called
// it — the exact same defect jobs/vmsContinuousJob.ts's purgeVmsHistory() fixed for VMS in R3.3A,
// fixed here the same way. The function's own header says "not callable through the API" because
// EXECUTE is revoked from PUBLIC/anon/authenticated — but not from service_role, which is what
// this backend's Supabase client authenticates as (confirmed working for purge_vms_history,
// whose SQL revokes the identical three roles).
//
// Deletes only alerts with case_id IS NULL older than retain_days (default 90) and ingest-reject
// rows older than reject_days (default 14); an alert ever linked to a case is never touched.

import { getSupabase } from '../services/geoEnrichment';

export const lastAlertRetentionRun: { at: string | null; result: unknown } = { at: null, result: null };

export async function purgeOldAlerts(): Promise<{ alerts_deleted: number; rejects_deleted: number } | { error: string }> {
    const supabase = getSupabase();
    if (!supabase) return { error: 'Database not configured' };
    const { data, error } = await supabase.rpc('purge_old_alerts');
    if (error) return { error: error.message };
    const row = Array.isArray(data) ? data[0] : data;
    return { alerts_deleted: row?.alerts_deleted ?? 0, rejects_deleted: row?.rejects_deleted ?? 0 };
}

export function startAlertRetentionJob(): void {
    let running = false;
    const tick = async () => {
        if (running) return;
        running = true;
        try {
            const r = await purgeOldAlerts();
            lastAlertRetentionRun.at = new Date().toISOString();
            lastAlertRetentionRun.result = r;
            if ('error' in r) console.error(`[alerts] retention purge failed: ${r.error}`);
            else if (r.alerts_deleted || r.rejects_deleted) console.log(`[alerts] purged ${r.alerts_deleted} alert(s), ${r.rejects_deleted} ingest reject(s) past retention`);
        } catch (err) {
            console.error('[alerts] retention purge failed:', err instanceof Error ? err.message : err);
        } finally {
            running = false;
        }
    };
    setTimeout(() => { void tick(); }, 20 * 60_000).unref();
    setInterval(() => { void tick(); }, 24 * 60 * 60_000).unref();
}
