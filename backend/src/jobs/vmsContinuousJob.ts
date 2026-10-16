// VMS Release 3 background work (phase P7), where mutating jobs run (lib/runtimeEnv.ts):
//   • every 5 minutes: due scan schedules are queued (services/vmsContinuous.ts runDueSchedules)
//   • every hour: today's risk snapshot per organisation (re-measured; one row per day)
//   • every 30 minutes, only with VMS_NOTIFY_ENABLED=true: change digest per organisation
//   • every hour: enabled assessment policies (services/vmsPolicies.ts) — created disabled; each
//     run is capped and respects the cooldown, and planning applies every scope and worker check
// Each run's outcome is logged; failures are reported and retried on the next run.

import { runDueSchedules, snapshotOrg, notifyChanges, notifyEnabled } from '../services/vmsContinuous';
import { correlationOrgs } from './threatInfoJob';
import { runEnabledPolicies } from '../services/vmsPolicies';

export const lastVmsContinuousRun: { schedules: unknown; snapshots: unknown; notify: unknown; policies: unknown; at: string | null } = { schedules: null, snapshots: null, notify: null, policies: null, at: null };

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
    setTimeout(() => { void schedules(); void snapshots(); }, 120_000).unref();
    setTimeout(() => { void policies(); }, 10 * 60_000).unref();
    setInterval(() => { void policies(); }, 60 * 60_000).unref();
    setInterval(() => { void schedules(); }, 5 * 60_000).unref();
    setInterval(() => { void snapshots(); }, 60 * 60_000).unref();
    if (notifyEnabled()) setInterval(() => { void notify(); }, 30 * 60_000).unref();
    else console.log('[vms-continuous] change digests off (set VMS_NOTIFY_ENABLED=true to send them)');
}
