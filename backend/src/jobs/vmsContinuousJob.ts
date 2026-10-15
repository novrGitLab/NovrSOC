// VMS Release 3 background work (phase P7), where mutating jobs run (lib/runtimeEnv.ts):
//   • every 5 minutes: due scan schedules are queued (services/vmsContinuous.ts runDueSchedules)
//   • every hour: today's risk snapshot per organisation (re-measured; one row per day)
//   • every 30 minutes, only with VMS_NOTIFY_ENABLED=true: change digest per organisation
// Each run's outcome is logged; failures are reported and retried on the next run.

import { runDueSchedules, snapshotOrg, notifyChanges, notifyEnabled } from '../services/vmsContinuous';
import { correlationOrgs } from './threatInfoJob';

export const lastVmsContinuousRun: { schedules: unknown; snapshots: unknown; notify: unknown; at: string | null } = { schedules: null, snapshots: null, notify: null, at: null };

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
    setTimeout(() => { void schedules(); void snapshots(); }, 120_000).unref();
    setInterval(() => { void schedules(); }, 5 * 60_000).unref();
    setInterval(() => { void snapshots(); }, 60 * 60_000).unref();
    if (notifyEnabled()) setInterval(() => { void notify(); }, 30 * 60_000).unref();
    else console.log('[vms-continuous] change digests off (set VMS_NOTIFY_ENABLED=true to send them)');
}
