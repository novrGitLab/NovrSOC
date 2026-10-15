// Scanner worker presence (phase P10). What "a scanner worker is connected" means, in one place:
//
//   online   the backend accepted a request carrying the worker token (claim or heartbeat) from that
//            worker within WORKER_ONLINE_SECONDS, or a job it runs sent a heartbeat in that window
//   offline  it was seen before, but not within the window
//   never    no worker has ever made an authenticated request
//
// Only requests that passed the token check are recorded (routes/vmsWorker.ts), so a process that
// runs but cannot reach or authenticate to the backend is never shown as connected. Before
// sql/2026-10-18_p10_vms_worker_presence.sql is applied, the status falls back to job heartbeats
// (the earlier behaviour), and says so in `source`.

import { getSupabase } from './geoEnrichment';
import { PASSIVE_RUNNER_ID } from '../lib/vmsScope';

/** A worker polls every 20 s and heartbeats every 60 s; three minutes of silence means it is gone. */
export const WORKER_ONLINE_SECONDS = 180;
/** Fallback window when only job heartbeats exist (they come every 30 s while a job runs). */
const JOB_BEAT_ONLINE_SECONDS = 15 * 60;
const P10_MISSING = 'Worker presence is not set up yet (run sql/2026-10-18_p10_vms_worker_presence.sql)';

export interface WorkerRow {
    worker_id: string; kinds: string[] | null; version: string | null; tools: Record<string, boolean> | null;
    first_seen_at: string; last_seen_at: string; last_heartbeat_at: string | null; last_claim_at: string | null;
    last_job_id: string | null; last_job_at: string | null;
}
export interface WorkerView extends WorkerRow { online: boolean }
export interface ScannerStatus {
    state: 'online' | 'offline' | 'never';
    /** presence = vms_workers; job_heartbeat = fallback before the P10 SQL; none = nothing recorded. */
    source: 'presence' | 'job_heartbeat' | 'none';
    last_seen_at: string | null;
    online_workers: number;
    online_window_seconds: number;
    workers: WorkerView[];
}

const isMissingTable = (e: { message?: string; code?: string } | null) => !!e && (e.code === '42P01' || e.code === 'PGRST205' || /vms_workers/.test(e.message ?? '') && /does not exist|Could not find|schema cache/i.test(e.message ?? ''));
const later = (a: string | null, b: string | null) => (!a ? b : !b ? a : Date.parse(a) >= Date.parse(b) ? a : b);

/**
 * Pure: the scanner status from presence rows (null = presence table not available) and the most
 * recent job heartbeat from a scanner worker (never the backend's passive runner).
 */
export function deriveScannerStatus(rows: WorkerRow[] | null, lastJobBeat: string | null, now = Date.now()): ScannerStatus {
    const recent = (iso: string | null, seconds: number) => !!iso && now - Date.parse(iso) < seconds * 1000;
    if (rows === null) {
        return {
            state: !lastJobBeat ? 'never' : recent(lastJobBeat, JOB_BEAT_ONLINE_SECONDS) ? 'online' : 'offline',
            source: lastJobBeat ? 'job_heartbeat' : 'none', last_seen_at: lastJobBeat,
            online_workers: recent(lastJobBeat, JOB_BEAT_ONLINE_SECONDS) ? 1 : 0, online_window_seconds: JOB_BEAT_ONLINE_SECONDS, workers: [],
        };
    }
    const workers = rows.map((w) => ({ ...w, online: recent(w.last_seen_at, WORKER_ONLINE_SECONDS) }));
    const online = workers.filter((w) => w.online).length + (workers.length === 0 && recent(lastJobBeat, WORKER_ONLINE_SECONDS) ? 1 : 0);
    const last = workers.reduce<string | null>((m, w) => later(m, w.last_seen_at), lastJobBeat);
    return {
        state: online > 0 ? 'online' : last ? 'offline' : 'never',
        source: workers.length ? 'presence' : lastJobBeat ? 'job_heartbeat' : 'none',
        last_seen_at: last, online_workers: online, online_window_seconds: WORKER_ONLINE_SECONDS,
        workers: workers.sort((a, b) => Date.parse(b.last_seen_at) - Date.parse(a.last_seen_at)),
    };
}

/** Reads presence and the latest scanner job heartbeat, and derives the status. */
export async function loadScannerStatus(now = Date.now()): Promise<ScannerStatus> {
    const supabase = getSupabase();
    if (!supabase) return deriveScannerStatus(null, null, now);
    const [w, beat] = await Promise.all([
        supabase.from('vms_workers').select('*').order('last_seen_at', { ascending: false }).limit(50),
        supabase.from('vms_scan_jobs').select('heartbeat_at').not('heartbeat_at', 'is', null).neq('worker_id', PASSIVE_RUNNER_ID).order('heartbeat_at', { ascending: false }).limit(1).maybeSingle(),
    ]);
    const lastBeat = (beat.data?.heartbeat_at as string | undefined) ?? null;
    return deriveScannerStatus(w.error ? null : (w.data ?? []) as WorkerRow[], lastBeat, now);
}

let warnedMissing = false;
/**
 * Records an authenticated worker request. Never throws: presence must not break job claiming.
 * Returns 'missing' when the presence table does not exist yet.
 */
export async function recordWorkerSeen(workerId: string, fields: Partial<Pick<WorkerRow, 'kinds' | 'version' | 'tools' | 'last_heartbeat_at' | 'last_claim_at' | 'last_job_id' | 'last_job_at'>>): Promise<'ok' | 'missing' | 'failed'> {
    const supabase = getSupabase();
    if (!supabase) return 'failed';
    const now = new Date().toISOString();
    const { error } = await supabase.from('vms_workers').upsert({ worker_id: workerId, last_seen_at: now, ...fields }, { onConflict: 'worker_id' });
    if (!error) return 'ok';
    if (isMissingTable(error)) {
        if (!warnedMissing) console.warn(`[vms] ${P10_MISSING}; the dashboard falls back to job heartbeats`);
        warnedMissing = true;
        return 'missing';
    }
    console.error('[vms] could not record worker presence:', error.message);
    return 'failed';
}
export const PRESENCE_MISSING_MESSAGE = P10_MISSING;
