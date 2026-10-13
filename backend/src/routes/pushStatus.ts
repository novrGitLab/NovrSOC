// Delivery status of the Stellar Cyber push (jobs/stellarPush.ts) — phase X3.
// Mounted at /api/admin/push-status behind requireAuth + requireRole('super_admin').
//
//   GET  /                     configuration summary (host only, never the key or full URL),
//                              persisted counters, backlog, open dead letters, this process's job state
//   POST /dead-letters/retry   ask the job to re-send every open dead letter (audited)

import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';
import { dbErrorMessage } from '../services/cases';
import { logAudit } from '../lib/audit';
import { pushConfig, pushRuntime, DESTINATION } from '../jobs/stellarPush';

const router = Router();

function hostOf(u: string | undefined): string | null {
    try { return u ? new URL(u).host : null; } catch { return null; }
}

router.get('/', async (_req, res) => {
    const cfg = pushConfig();
    const config = {
        enabled: process.env.STELLAR_PUSH_ENABLED === 'true',
        valid: !('error' in cfg),
        error: 'error' in cfg ? cfg.error : null,
        host: hostOf(process.env.STELLAR_PUSH_URL),
        orgs: 'error' in cfg ? [] : cfg.orgs,
        profile: 'error' in cfg ? null : cfg.profile,
        max_per_min: 'error' in cfg ? null : cfg.maxPerMin,
        timeout_ms: 'error' in cfg ? null : cfg.timeoutMs,
        auth_header: 'error' in cfg ? null : Object.keys(cfg.headers).find((h) => h !== 'Content-Type') ?? null,
    };
    const supabase = getSupabase();
    if (!supabase) { res.json({ config, runtime: pushRuntime, state: null, backlog: null, dead_letters: null, store_error: 'store not configured' }); return; }

    const st = await supabase.from('push_state').select('last_seq, sent_count, skipped_count, retry_count, last_success_at, last_error, last_error_at, updated_at').eq('destination', DESTINATION).maybeSingle();
    if (st.error) { res.status(502).json({ config, runtime: pushRuntime, error: dbErrorMessage(st.error) }); return; }

    let backlog: number | null = null;
    if (st.data && config.orgs.length) {
        const b = await supabase.from('alerts').select('id', { count: 'exact', head: true }).in('org_id', config.orgs).gt('ingest_seq', st.data.last_seq);
        backlog = b.error ? null : b.count ?? 0;
    }
    const open = await supabase.from('push_dead_letters').select('alert_id, ingest_seq, status_code, attempts, retry_requested, created_at, last_attempt_at', { count: 'exact' })
        .eq('destination', DESTINATION).is('resolved_at', null).order('ingest_seq', { ascending: false }).limit(20);
    res.json({
        config,
        runtime: pushRuntime,
        state: st.data ?? null,
        backlog,
        dead_letters: open.error ? null : { open: open.count ?? (open.data ?? []).length, recent: open.data ?? [] },
    });
});

router.post('/dead-letters/retry', async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'store not configured' }); return; }
    const { data, error } = await supabase.from('push_dead_letters').update({ retry_requested: true })
        .eq('destination', DESTINATION).is('resolved_at', null).select('id');
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    const n = (data ?? []).length;
    logAudit({
        user: req.user?.email ?? 'unknown', action: 'PUSH_DEAD_LETTERS_RETRY', resource: 'push_destination', resource_id: DESTINATION,
        ip: req.ip ?? 'unknown', result: 'success', severity: 'warning', details: `${n} dead letter(s) queued for retry`,
    });
    res.json({ queued: n });
});

export default router;
