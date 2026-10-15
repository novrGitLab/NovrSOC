// CNII passive collection runner (phase P9), where mutating jobs run (lib/runtimeEnv.ts).
// Every minute it claims one queued passive_osint job from the VMS queue (the scanner worker never
// takes these), runs it with services/cniiPassive.ts, and reports the outcome on the job:
//   • a heartbeat every 30 s while it runs, so queue upkeep (jobs/vmsMaintenance.ts) can requeue a
//     job whose runner died;
//   • it stops between targets when the job is cancelled or its scope is revoked or expires;
//   • the summary says which sources answered, which failed and why, and which are not configured.
// One job at a time per backend instance. Off with CNII_PASSIVE_ENABLED=false.

import { getSupabase } from '../services/geoEnrichment';
import { activeScopes } from '../routes/vms';
import { PASSIVE_RUNNER_ID } from '../lib/vmsScope';
import { defaultDeps, passiveOutcome, runPassiveJob, type PassiveDeps } from '../services/cniiPassive';
import { logAudit } from '../lib/audit';

const TICK_MS = 60_000;
const HEARTBEAT_MS = 30_000;

/** Claims and runs one passive job if one is waiting. Returns the job id it ran, or null. */
export async function runOnePassiveJob(deps: PassiveDeps = defaultDeps()): Promise<string | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data, error } = await supabase.rpc('vms_claim_job', { p_worker: PASSIVE_RUNNER_ID, p_kinds: ['passive_osint'] });
    if (error) throw new Error(`queue unavailable: ${error.message}`);
    const job = (Array.isArray(data) ? data[0] : data) as { id: string; org_id: string; scope_id: string; targets: unknown } | undefined;
    if (!job) return null;

    let progress = { phase: 'passive', done: 0, total: Array.isArray(job.targets) ? job.targets.length : 0 };
    const beat = setInterval(() => { void supabase.from('vms_scan_jobs').update({ heartbeat_at: new Date().toISOString(), progress }).eq('id', job.id); }, HEARTBEAT_MS);
    beat.unref();
    const shouldStop = async () => {
        const [{ data: j }, { data: s }] = await Promise.all([
            supabase.from('vms_scan_jobs').select('cancel_requested').eq('id', job.id).maybeSingle(),
            supabase.from('vms_scopes').select('status, expires_at').eq('id', job.scope_id).maybeSingle(),
        ]);
        return !!j?.cancel_requested || !s || s.status !== 'active' || Date.parse(s.expires_at) <= Date.now();
    };
    try {
        const scopes = await activeScopes(job.org_id);
        const summary = await runPassiveJob(job, scopes, deps, shouldStop, async (done, total) => {
            progress = { phase: 'passive', done, total };
            await supabase.from('vms_scan_jobs').update({ heartbeat_at: new Date().toISOString(), progress }).eq('id', job.id);
        });
        const stopped = await shouldStop();
        const outcome = stopped ? { status: 'cancelled' as const, error: 'Cancelled, or its scope was revoked or expired' } : passiveOutcome(summary);
        await supabase.from('vms_scan_jobs').update({ status: outcome.status, finished_at: new Date().toISOString(), error: outcome.error, summary, progress: { phase: 'done', done: summary.targets, total: summary.targets } }).eq('id', job.id);
        logAudit({ user: PASSIVE_RUNNER_ID, action: 'CNII_PASSIVE_RUN', resource: 'vms_scan_job', resource_id: job.id, org_id: job.org_id, ip: 'n/a', result: outcome.status === 'failed' ? 'failed' : 'success',
            details: `${summary.targets} target(s), ${summary.assets_new} new asset(s), ${summary.observations_new} new observation(s), ${summary.findings_new} new unconfirmed finding(s)${outcome.error ? `; ${outcome.error}` : ''}`.slice(0, 500) });
    } catch (err) {
        await supabase.from('vms_scan_jobs').update({ status: 'failed', finished_at: new Date().toISOString(), error: `Passive collection failed: ${err instanceof Error ? err.message : String(err)}`.slice(0, 1000) }).eq('id', job.id);
        throw err;
    } finally {
        clearInterval(beat);
    }
    return job.id;
}

export function startCniiPassiveJob(): void {
    if (process.env.CNII_PASSIVE_ENABLED === 'false') { console.log('[cnii] passive collection disabled by CNII_PASSIVE_ENABLED=false'); return; }
    let running = false;
    const tick = async () => {
        if (running) return;
        running = true;
        try {
            const id = await runOnePassiveJob();
            if (id) console.log(`[cnii] passive job ${id} finished`);
        } catch (err) {
            console.error('[cnii] passive collection failed:', err instanceof Error ? err.message : err);
        } finally {
            running = false;
        }
    };
    setTimeout(() => { void tick(); }, 30_000).unref();
    setInterval(() => { void tick(); }, TICK_MS).unref();
}
