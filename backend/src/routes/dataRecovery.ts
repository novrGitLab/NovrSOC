import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';

// Data Loss Recovery — backup job reporting.
//
// Serves only what a real backup agent has reported (see frontend/public/novrsoc-backup-agent.sh).
// There is no demo dataset here any more: hash-integrity verification, retention chains and
// restore points were previously simulated, which on a continuity page reads as an assurance
// that backups are restorable. They return when an agent actually reports them.

const router = Router();


// Demo backup data removed.
//
// This file previously shipped MOCK_BACKUP_JOBS and MOCK_RETENTION: invented nightly jobs with
// invented sizes, invented hash-verification ticks and invented restore points, plus a
// GET /health that computed a success rate and "hash_integrity: verified" from them. On a data
// continuity page that is the worst possible thing to fabricate — it tells an operator their
// backups are healthy and restorable when nothing has been backed up or verified at all.
//
// The only backup data this service now returns is what a real agent reported (see the
// backup_jobs routes below). Retention chains, restore points and hash verification are not
// served at all rather than being simulated: they need the agent to report them first.

// Turns a raw Postgres error into something an operator can act on. The two that actually occur
// here are a missing table (the setup step) and an org_id type mismatch: NovrSOC's JWT carries
// the org SLUG ('cybernovr'), so backup_jobs.org_id must be TEXT. A table created with
// `org_id UUID` rejects every query with "invalid input syntax for type uuid", which on its own
// reads like a NovrSOC bug rather than a schema that needs recreating.
function explainDbError(err: unknown): string {
    const raw = err instanceof Error
        ? err.message
        : (typeof err === 'object' && err !== null && 'message' in err)
            ? String((err as { message: unknown }).message)
            : String(err);

    if (raw.includes('invalid input syntax for type uuid')) {
        return `${raw} — backup_jobs.org_id is typed UUID but NovrSOC sends the org slug. Recreate the table with org_id TEXT, using the SQL on this page.`;
    }
    if (raw.includes('does not exist')) {
        return `${raw} — create the backup_jobs table using the SQL shown on this page.`;
    }
    return raw;
}

// GET /api/recovery/health — derived from real reported jobs only.
router.get('/health', async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) {
        res.json({ configured: false, reason: 'Supabase is not configured, so no backup results can be stored or read.' });
        return;
    }

    const orgId = req.user?.org_id ?? 'cybernovr';
    try {
        const { data, error } = await supabase.from('backup_jobs').select('*').eq('org_id', orgId);
        if (error) throw error;

        const jobs = (data ?? []) as Array<{ status: string; last_run: string }>;
        if (jobs.length === 0) {
            // Explicitly NOT 'healthy'. No reported jobs means unknown, and reporting unknown as
            // healthy is exactly the failure this block replaced.
            res.json({ configured: true, reporting: false, overall_status: 'unknown', failed_jobs: 0, reason: 'No backup agent has reported yet.' });
            return;
        }

        const failed = jobs.filter((j) => j.status === 'failed');
        const newest = jobs.reduce<string | null>((max, j) => (j.last_run && (!max || j.last_run > max) ? j.last_run : max), null);

        res.json({
            configured: true,
            reporting: true,
            overall_status: failed.length > 0 ? 'degraded' : 'healthy',
            failed_jobs: failed.length,
            success_rate_pct: Math.round((jobs.filter((j) => j.status === 'success').length / jobs.length) * 100),
            last_report: newest,
            // Deliberately absent: hash_integrity, oldest_restore_point, object_lock_enabled.
            // The agent does not report them, so there is nothing truthful to put here.
        });
    } catch (err) {
        const message = explainDbError(err);
        res.json({ configured: true, reporting: false, overall_status: 'unknown', failed_jobs: 0, reason: message });
    }
});

// ── Real backup job reporting ───────────────────────────────────────────────────────
//
// Backup agents on the protected hosts POST their result here after each run; the dashboard
// reads them back from Supabase. This is the only source of backup data this service serves.
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
        const message = explainDbError(err);
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
        const message = explainDbError(err);
        console.error('[recovery/jobs] failed:', message);
        // 200 with an explicit reason, not 500: "the backup_jobs table does not exist yet" is a
        // setup state the page must be able to explain, not a crash.
        res.json({ jobs: [], source: 'error', message, stats: { total: 0, success: 0, failed: 0, total_bytes: 0 } });
    }
});

export default router;
