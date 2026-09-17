import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';

// Data Loss Recovery — backup job monitoring, hash-integrity verification, restore-point
// tracking. Demo data for now (real Backup Probe Daemon on EC2-5 doesn't exist yet — same
// "structured mock data now, real crawlers later" pattern used elsewhere in this backend).

const router = Router();

type BackupStatus = 'success' | 'failed' | 'running' | 'missed';

interface BackupJob {
    id: string;
    name: string;
    target: string;
    backup_type: string;
    status: BackupStatus;
    size_bytes: number;
    hash_sha256: string | null;
    hash_verified: boolean;
    started_at: string;
    completed_at: string | null;
    duration_mins: number | null;
    restore_point: string | null;
    retention_days: number;
    next_scheduled: string;
    storage_path: string;
    snapshots_count: number;
    failure_reason?: string;
}

const MOCK_BACKUP_JOBS: BackupJob[] = [
    {
        id: 'bj_001',
        name: 'EC2-1 App Server — Daily Snapshot',
        target: 'ec2-app-server (10.0.1.10)',
        backup_type: 's3',
        status: 'success',
        size_bytes: 8_540_000_000,
        hash_sha256: 'a3f5c2d8e9b1047f6c4a2e8d3f1b5c9e7a2d4f8b1c5e3a7d9f2b4e6c8a1d3f5',
        hash_verified: true,
        started_at: '2026-08-12 02:00:11',
        completed_at: '2026-08-12 02:14:38',
        duration_mins: 14,
        restore_point: '2026-08-12 02:14:38',
        retention_days: 30,
        next_scheduled: '2026-08-13 02:00:00',
        storage_path: 's3://novrsoc-backups/ec2-app/2026-08-12/',
        snapshots_count: 30,
    },
    {
        id: 'bj_002',
        name: 'EC2-2 Wazuh Server — Daily Snapshot',
        target: 'ec2-wazuh-server (10.0.1.20)',
        backup_type: 's3',
        status: 'success',
        size_bytes: 42_300_000_000,
        hash_sha256: 'b7e2d4f6a8c1e3b5d7f9a2c4e6b8d1f3a5c7e9b2d4f6a8c1e3b5d7f9a2c4e6b8',
        hash_verified: true,
        started_at: '2026-08-12 01:00:00',
        completed_at: '2026-08-12 02:47:22',
        duration_mins: 107,
        restore_point: '2026-08-12 02:47:22',
        retention_days: 30,
        next_scheduled: '2026-08-13 01:00:00',
        storage_path: 's3://novrsoc-backups/wazuh/2026-08-12/',
        snapshots_count: 30,
    },
    {
        id: 'bj_003',
        name: 'RDS PostgreSQL — Automated Snapshot',
        target: 'novrsoc-postgres.rds.amazonaws.com',
        backup_type: 's3',
        status: 'success',
        size_bytes: 2_100_000_000,
        hash_sha256: 'c9f3e5a7b2d4f6c8e1a3b5d7f9c2e4a6b8d1f3c5e7a9b2d4f6c8e1a3b5d7f9c2',
        hash_verified: true,
        started_at: '2026-08-12 03:00:00',
        completed_at: '2026-08-12 03:08:14',
        duration_mins: 8,
        restore_point: '2026-08-12 03:08:14',
        retention_days: 7,
        next_scheduled: '2026-08-13 03:00:00',
        storage_path: 's3://novrsoc-backups/rds/2026-08-12/',
        snapshots_count: 7,
    },
    {
        id: 'bj_004',
        name: 'EC2-3 Sensor Instance — Daily Snapshot',
        target: 'ec2-sensor (10.0.1.30)',
        backup_type: 's3',
        status: 'failed', // ← the story: last night's alert
        size_bytes: 0,
        hash_sha256: null,
        hash_verified: false,
        started_at: '2026-08-12 04:00:00',
        completed_at: null,
        duration_mins: null,
        restore_point: '2026-08-11 04:09:32', // last successful restore point
        retention_days: 30,
        next_scheduled: '2026-08-13 04:00:00',
        storage_path: 's3://novrsoc-backups/sensor/2026-08-12/',
        snapshots_count: 29,
        failure_reason: 'S3 upload timeout — EC2 to S3 transfer exceeded 2 hour limit. Disk I/O spike from Zeek log rotation.',
    },
    {
        id: 'bj_005',
        name: 'EC2-5 Auxiliary — Daily Snapshot',
        target: 'ec2-auxiliary (10.0.1.50)',
        backup_type: 's3',
        status: 'success',
        size_bytes: 890_000_000,
        hash_sha256: 'd2e4f6a8c1b3d5f7e9a2c4b6d8f1a3c5e7b9d2f4a6c8e1b3d5f7e9a2c4b6d8f1',
        hash_verified: true,
        started_at: '2026-08-12 04:30:00',
        completed_at: '2026-08-12 04:33:47',
        duration_mins: 3,
        restore_point: '2026-08-12 04:33:47',
        retention_days: 30,
        next_scheduled: '2026-08-13 04:30:00',
        storage_path: 's3://novrsoc-backups/auxiliary/2026-08-12/',
        snapshots_count: 30,
    },
];

interface RetentionEntry {
    date: string;
    status: string;
    size_gb: number;
}

// Retention calendar — last 7 days of snapshots per job. Only the two jobs with a "story"
// (bj_001 healthy, bj_004 today's failure) have demo history; others fall back to [] below.
const MOCK_RETENTION: Record<string, RetentionEntry[]> = {
    bj_001: [
        { date: '2026-08-12', status: 'success', size_gb: 8.54 },
        { date: '2026-08-11', status: 'success', size_gb: 8.51 },
        { date: '2026-08-10', status: 'success', size_gb: 8.49 },
        { date: '2026-08-09', status: 'success', size_gb: 8.47 },
        { date: '2026-08-08', status: 'success', size_gb: 8.45 },
        { date: '2026-08-07', status: 'success', size_gb: 8.43 },
        { date: '2026-08-06', status: 'success', size_gb: 8.40 },
    ],
    bj_004: [
        { date: '2026-08-12', status: 'failed', size_gb: 0 }, // today's failure
        { date: '2026-08-11', status: 'success', size_gb: 15.2 },
        { date: '2026-08-10', status: 'success', size_gb: 15.1 },
        { date: '2026-08-09', status: 'success', size_gb: 14.9 },
        { date: '2026-08-08', status: 'success', size_gb: 14.8 },
        { date: '2026-08-07', status: 'success', size_gb: 14.7 },
        { date: '2026-08-06', status: 'success', size_gb: 14.5 },
    ],
};

// GET /api/recovery/jobs/demo — the original demo dataset, kept reachable so the rest of the
// Data Continuity page (retention, restore points) still has something to render while real
// backup reporting is being rolled out. The REAL GET /jobs is defined below and reads Supabase.
router.get('/jobs/demo', (_req, res) => {
    const stats = {
        total: MOCK_BACKUP_JOBS.length,
        success: MOCK_BACKUP_JOBS.filter((j) => j.status === 'success').length,
        failed: MOCK_BACKUP_JOBS.filter((j) => j.status === 'failed').length,
        total_size_tb: (MOCK_BACKUP_JOBS.reduce((s, j) => s + j.size_bytes, 0) / 1e12).toFixed(2),
        hash_verified: MOCK_BACKUP_JOBS.filter((j) => j.hash_verified).length,
    };
    res.json({ jobs: MOCK_BACKUP_JOBS, stats });
});

// GET /api/recovery/jobs/:id
router.get('/jobs/:id', (req, res) => {
    const job = MOCK_BACKUP_JOBS.find((j) => j.id === req.params.id);
    if (!job) {
        res.status(404).json({ error: 'Job not found' });
        return;
    }
    const retention = MOCK_RETENTION[req.params.id] ?? [];
    res.json({ ...job, retention });
});

// POST /api/recovery/jobs/:id/retry
router.post('/jobs/:id/retry', (req, res) => {
    const job = MOCK_BACKUP_JOBS.find((j) => j.id === req.params.id);
    if (!job) {
        res.status(404).json({ error: 'Job not found' });
        return;
    }
    res.json({
        success: true,
        message: `Backup job "${job.name}" queued for immediate execution.`,
        estimated_start: new Date(Date.now() + 60000).toISOString(),
    });
});

// GET /api/recovery/health
router.get('/health', (_req, res) => {
    const failed = MOCK_BACKUP_JOBS.filter((j) => j.status === 'failed');
    const oldestRestore = MOCK_BACKUP_JOBS
        .filter((j) => j.restore_point)
        .sort((a, b) => new Date(a.restore_point as string).getTime() - new Date(b.restore_point as string).getTime())[0];

    res.json({
        overall_status: failed.length > 0 ? 'degraded' : 'healthy',
        failed_jobs: failed.length,
        success_rate_pct: Math.round((MOCK_BACKUP_JOBS.filter((j) => j.status === 'success').length / MOCK_BACKUP_JOBS.length) * 100),
        oldest_restore_point: oldestRestore?.restore_point ?? null,
        hash_integrity: 'verified',
        aws_s3_status: 'operational',
        object_lock_enabled: true,
    });
});

// ── Real backup job reporting ───────────────────────────────────────────────────────
//
// Backup agents on the protected hosts POST their result here after each run; the dashboard
// reads them back from Supabase. This replaces the demo dataset above as the primary source —
// that one is still served at GET /jobs/demo for the panels that have no real equivalent yet.
//
// Requires a `backup_jobs` table. It is NOT created automatically (this backend has no
// migration runner and the service key deliberately isn't used for DDL) — the Data Continuity
// page shows the exact SQL to run. Until the table exists these routes report that plainly
// rather than failing in a way that looks like "no backups have ever run".

interface BackupJobRow {
    job_name: string;
    org_id: string;
    status: string;
    size_bytes: number;
    duration_seconds: number;
    files_transferred: number;
    error_message: string | null;
    last_run: string;
}

// POST /api/recovery/jobs/report
//
// Intentionally unauthenticated: this is called by a cron script on a backup host, which has no
// interactive session and no way to mint a user JWT. It is a low-risk write — it can only upsert
// a row keyed by (job_name, org_id) in a reporting table, and holds no read access to anything.
// Before exposing it beyond a trusted network, give the agents a shared secret and check it here;
// a note to that effect ships with the script on the Data Continuity page.
router.post('/jobs/report', async (req, res) => {
    const {
        job_name, status, size_bytes, duration_seconds,
        files_transferred, error_message, org_id,
    } = req.body ?? {};

    if (!job_name || typeof job_name !== 'string') {
        res.status(400).json({ error: 'job_name required' });
        return;
    }

    const supabase = getSupabase();
    if (!supabase) {
        res.status(503).json({ error: 'Database not configured — cannot record backup result' });
        return;
    }

    try {
        const { error } = await supabase.from('backup_jobs').upsert({
            job_name,
            org_id: typeof org_id === 'string' && org_id ? org_id : 'cybernovr',
            status: typeof status === 'string' ? status : 'unknown',
            size_bytes: Number(size_bytes) || 0,
            duration_seconds: Number(duration_seconds) || 0,
            files_transferred: Number(files_transferred) || 0,
            error_message: typeof error_message === 'string' && error_message ? error_message : null,
            last_run: new Date().toISOString(),
        }, { onConflict: 'job_name,org_id' });

        if (error) throw error;
        res.json({ success: true });
    } catch (err) {
        // Supabase rejects with a PostgrestError, which is a plain object, not an Error — so
        // `String(err)` yields "[object Object]" and tells the operator nothing. The most useful
        // case here is "relation public.backup_jobs does not exist", which IS the setup step.
        const message = err instanceof Error
            ? err.message
            : (typeof err === 'object' && err !== null && 'message' in err)
                ? String((err as { message: unknown }).message)
                : String(err);
        console.error('[recovery/jobs/report] failed:', message);
        // Surfaces a missing table explicitly — an agent silently "succeeding" against a table
        // that does not exist is the failure mode worth avoiding here.
        res.status(500).json({ error: 'Could not record backup result', detail: message });
    }
});

// GET /api/recovery/jobs — real reported jobs for the caller's org.
router.get('/jobs', async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) {
        res.json({ jobs: [], source: 'unconfigured', message: 'Supabase is not configured, so no backup results can be stored or read.' });
        return;
    }

    const orgId = req.user?.org_id ?? 'cybernovr';

    try {
        const { data, error } = await supabase
            .from('backup_jobs')
            .select('*')
            .eq('org_id', orgId)
            .order('last_run', { ascending: false });

        if (error) throw error;

        const jobs = (data ?? []) as BackupJobRow[];
        res.json({
            jobs,
            source: 'supabase',
            stats: {
                total: jobs.length,
                success: jobs.filter((j) => j.status === 'success').length,
                failed: jobs.filter((j) => j.status === 'failed').length,
                total_bytes: jobs.reduce((sum, j) => sum + (Number(j.size_bytes) || 0), 0),
            },
        });
    } catch (err) {
        // Supabase rejects with a PostgrestError, which is a plain object, not an Error — so
        // `String(err)` yields "[object Object]" and tells the operator nothing. The most useful
        // case here is "relation public.backup_jobs does not exist", which IS the setup step.
        const message = err instanceof Error
            ? err.message
            : (typeof err === 'object' && err !== null && 'message' in err)
                ? String((err as { message: unknown }).message)
                : String(err);
        console.error('[recovery/jobs] failed:', message);
        // 200 with an explicit reason, not 500: "the backup_jobs table does not exist yet" is a
        // setup state the page must be able to explain, not a crash.
        res.json({ jobs: [], source: 'error', message, stats: { total: 0, success: 0, failed: 0, total_bytes: 0 } });
    }
});

export default router;
