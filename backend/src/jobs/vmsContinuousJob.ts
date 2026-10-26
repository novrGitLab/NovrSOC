// VMS Release 3 background work (phase P7), where mutating jobs run (lib/runtimeEnv.ts):
//   • every 5 minutes: due scan schedules are queued (services/vmsContinuous.ts runDueSchedules)
//   • every hour: today's risk snapshot per organisation (re-measured; one row per day)
//   • every 30 minutes, only with VMS_NOTIFY_ENABLED=true: change digest per organisation
//   • every hour: enabled assessment policies (services/vmsPolicies.ts) — created disabled; each
//     run is capped and respects the cooldown, and planning applies every scope and worker check
//   • once a day (R3.3A): sql/2026-10-16_p7_vms_continuous.sql's purge_vms_history() — asset
//     change events and finished scan jobs after 365 days, risk snapshots after 730 days.
//     Findings, their evidence and history are never purged by this (they are the remediation
//     record). The SQL file's own pg_cron line is commented out, same as every other scheduled
//     SQL function in this codebase; this backend calls it directly instead, as jobs/vmsMaintenance.ts
//     already does for raw scan evidence (purge_vms_job_evidence) — this was the one retention
//     function nothing had ever actually been calling.
// Each run's outcome is logged; failures are reported and retried on the next run.

import { getSupabase } from '../services/geoEnrichment';
import { runDueSchedules, snapshotOrg, notifyChanges, notifyEnabled } from '../services/vmsContinuous';
import { correlationOrgs } from './threatInfoJob';
import { runEnabledPolicies } from '../services/vmsPolicies';

export const lastVmsContinuousRun: { schedules: unknown; snapshots: unknown; notify: unknown; policies: unknown; purge: unknown; at: string | null } = { schedules: null, snapshots: null, notify: null, policies: null, purge: null, at: null };

/** sql/2026-10-16_p7_vms_continuous.sql's purge_vms_history(). Exported for a direct test. */
export async function purgeVmsHistory(): Promise<{ events_deleted: number; jobs_deleted: number; snapshots_deleted: number } | { error: string }> {
    const supabase = getSupabase();
    if (!supabase) return { error: 'Database not configured' };
    const { data, error } = await supabase.rpc('purge_vms_history');
    if (error) return { error: error.message };
    const row = Array.isArray(data) ? data[0] : data;
    return { events_deleted: row?.events_deleted ?? 0, jobs_deleted: row?.jobs_deleted ?? 0, snapshots_deleted: row?.snapshots_deleted ?? 0 };
}

export function startVmsContinuousJob(): void {
    const busy = new Set<string>();
    const once = (name: string, fn: () => Promise<void>) => async () => {
        if (busy.has(name)) return;
        busy.add(name);
        try { await fn(); } catch (err) { console.error(`[vms-continuous] ${name} failed:`, err instanceof Error ? err.message : err); } finally { busy.delete(name); }
    };
    const schedules = once('schedules', async () => {
        const r = await runDueSchedules();
        lastVmsContinuousRun.schedules = r;
        lastVmsContinuousRun.at = new Date().toISOString();
        for (const x of r) console.log(`[vms-continuous] schedule ${x.id} (${x.org}): ${x.outcome} — ${x.detail}`);
    });
    const snapshots = once('snapshots', async () => {
        const out: Record<string, unknown> = {};
        for (const org of await correlationOrgs()) {
            try { out[org] = await snapshotOrg(org); } catch (err) { out[org] = { error: err instanceof Error ? err.message : String(err) }; }
        }
        lastVmsContinuousRun.snapshots = out;
    });
    const notify = once('notify', async () => {
        const out: Record<string, unknown> = {};
        for (const org of await correlationOrgs()) {
            try { const r = await notifyChanges(org); out[org] = { changes: r.lines.length, sent: r.sent, detail: r.detail }; } catch (err) { out[org] = { error: err instanceof Error ? err.message : String(err) }; }
        }
        lastVmsContinuousRun.notify = out;
    });
    const policies = once('policies', async () => {
        const r = await runEnabledPolicies();
        lastVmsContinuousRun.policies = { at: new Date().toISOString(), result: r };
        if (Array.isArray(r)) for (const x of r) if (x.queued || x.blocked.length) console.log(`[vms-continuous] policy ${x.policy} (${x.org}): ${x.queued} queued, ${x.blocked.length} blocked`);
    });
    const purge = once('purge', async () => {
        const r = await purgeVmsHistory();
        lastVmsContinuousRun.purge = { at: new Date().toISOString(), result: r };
        if ('error' in r) console.error(`[vms-continuous] history purge failed: ${r.error}`);
        else if (r.events_deleted || r.jobs_deleted || r.snapshots_deleted) console.log(`[vms-continuous] purged ${r.events_deleted} asset event(s), ${r.jobs_deleted} finished job(s), ${r.snapshots_deleted} snapshot(s) past retention`);
    });
    setTimeout(() => { void schedules(); void snapshots(); }, 120_000).unref();
    setTimeout(() => { void policies(); }, 10 * 60_000).unref();
    setTimeout(() => { void purge(); }, 15 * 60_000).unref();
    setInterval(() => { void policies(); }, 60 * 60_000).unref();
    setInterval(() => { void schedules(); }, 5 * 60_000).unref();
    setInterval(() => { void snapshots(); }, 60 * 60_000).unref();
    setInterval(() => { void purge(); }, 24 * 60 * 60_000).unref();
    if (notifyEnabled()) setInterval(() => { void notify(); }, 30 * 60_000).unref();
    else console.log('[vms-continuous] change digests off (set VMS_NOTIFY_ENABLED=true to send them)');
}
