// VMS queue upkeep (phase P4), every 2 minutes where mutating jobs run (lib/runtimeEnv.ts):
//   • a running job whose worker has not sent a heartbeat for WORKER_STALE_MINUTES is put back
//     in the queue once; after that it is failed with the reason. Scan status therefore always
//     reflects a worker that is actually alive.
//   • queued jobs whose scope has expired or been revoked are cancelled, never run.

import { getSupabase } from '../services/geoEnrichment';
import { WORKER_STALE_MINUTES } from '../routes/vms';

const TICK_MS = 2 * 60_000;
export const MAX_ATTEMPTS = 2;

export async function runVmsMaintenance(now = Date.now()): Promise<{ requeued: number; failed: number; cancelled: number }> {
    const supabase = getSupabase();
    if (!supabase) return { requeued: 0, failed: 0, cancelled: 0 };
    const out = { requeued: 0, failed: 0, cancelled: 0 };
    const staleBefore = new Date(now - WORKER_STALE_MINUTES * 60_000).toISOString();
    const { data: stale, error } = await supabase.from('vms_scan_jobs').select('id, attempts, worker_id').eq('status', 'running').lt('heartbeat_at', staleBefore);
    if (error) { if (!/vms_/.test(error.message)) console.error('[vms] maintenance read failed:', error.message.slice(0, 160)); return out; }
    for (const j of stale ?? []) {
        if ((j.attempts ?? 0) < MAX_ATTEMPTS) {
            const r = await supabase.from('vms_scan_jobs').update({ status: 'queued', worker_id: null, claimed_at: null, heartbeat_at: null, progress: { message: `Requeued: worker ${j.worker_id ?? '?'} stopped responding` } }).eq('id', j.id).eq('status', 'running').select('id');
            out.requeued += (r.data ?? []).length;
        } else {
            const r = await supabase.from('vms_scan_jobs').update({ status: 'failed', finished_at: new Date(now).toISOString(), error: `The scanner worker stopped responding (${j.attempts} attempts)` }).eq('id', j.id).eq('status', 'running').select('id');
            out.failed += (r.data ?? []).length;
        }
    }
    const { data: queued } = await supabase.from('vms_scan_jobs').select('id, vms_scopes(status, expires_at)').eq('status', 'queued');
    for (const j of queued ?? []) {
        const s = j.vms_scopes as unknown as { status?: string; expires_at?: string } | null;
        if (!s || s.status !== 'active' || !s.expires_at || Date.parse(s.expires_at) <= now) {
            const r = await supabase.from('vms_scan_jobs').update({ status: 'cancelled', finished_at: new Date(now).toISOString(), error: 'Scope expired or revoked before the scan ran' }).eq('id', j.id).eq('status', 'queued').select('id');
            out.cancelled += (r.data ?? []).length;
        }
    }
    return out;
}

export function startVmsMaintenanceJob(): void {
    let running = false;
    const tick = async () => {
        if (running) return;
        running = true;
        try {
            const r = await runVmsMaintenance();
            if (r.requeued || r.failed || r.cancelled) console.log(`[vms] requeued ${r.requeued}, failed ${r.failed}, cancelled ${r.cancelled}`);
        } catch (err) {
            console.error('[vms] maintenance failed:', err instanceof Error ? err.message : err);
        } finally {
            running = false;
        }
    };
    void tick();
    setInterval(() => { void tick(); }, TICK_MS).unref();
}
