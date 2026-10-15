// /api/vms/worker — the scanner worker's API (phase P4). The worker (infra/vms-worker) runs on a
// separate host with the scanning tools; it authenticates with VMS_WORKER_TOKEN (Bearer) and is
// never a user. Fails closed: with the variable unset every call is 503.
//
//   POST /heartbeat            { worker_id, kinds[], version?, tools? } -> { ok, server_time, queued } (phase P10)
//   POST /claim                { worker_id, kinds[] }          -> { job, scopes } | { job: null }
//   POST /jobs/:id/heartbeat   { progress }                    -> { cancel }   (cancel = stop now)
//   POST /jobs/:id/results     { observations: [...] }         -> accepted / rejected counts
//   POST /jobs/:id/complete    { status: succeeded|failed|cancelled, error?, summary? }
//
// The worker receives the job's scope entries so it can re-check targets before running a tool,
// but the backend re-checks every result it accepts (services/vmsIngest.ts).
//
// Presence (phase P10, services/vmsWorkers.ts): every request that passes the token check —
// heartbeat, claim (including an empty queue) and job heartbeats — records the worker in
// vms_workers. That record, not a running process, is what the dashboard calls "connected".

import { Router, type Request, type Response, type NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { createHash, timingSafeEqual } from 'crypto';
import { z } from 'zod';
import { getSupabase } from '../services/geoEnrichment';
import { isUuid } from '../services/cases';
import { ingestObservations, markGoneServices } from '../services/vmsIngest';
import { ingestFindings, concludeVerification } from '../services/vmsFindings';
import { activeScopes } from './vms';
import { logAudit } from '../lib/audit';
import { recordWorkerSeen, WORKER_ONLINE_SECONDS, PRESENCE_MISSING_MESSAGE } from '../services/vmsWorkers';

const router = Router();
const digest = (s: string) => createHash('sha256').update(s).digest();
export const MAX_OBSERVATIONS_PER_BATCH = 500;
// The worker's job kinds. passive_osint is not among them: the backend runs it (jobs/cniiPassiveJob.ts).
export const VMS_KINDS = ['discovery', 'ports', 'vuln_nuclei', 'vuln_openvas'] as const;

router.use(rateLimit({ windowMs: 60_000, max: 600, standardHeaders: true, legacyHeaders: false }));
function requireWorkerToken(req: Request, res: Response, next: NextFunction) {
    const expected = process.env.VMS_WORKER_TOKEN ?? '';
    if (expected.length < 32) { res.status(503).json({ error: 'Scanner worker access is not configured' }); return; }
    const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? '');
    if (!m || !timingSafeEqual(digest(m[1]), digest(expected))) { res.status(401).json({ error: 'Invalid or missing worker token' }); return; }
    next();
}
router.use(requireWorkerToken);

const WORKER_ID = /^[\w.-]{1,64}$/;
type Job = { id: string; org_id: string; kind: string; status: string; started_at: string | null; targets: unknown; options: unknown; worker_id: string | null; cancel_requested: boolean; purpose?: string };

async function ownJob(req: Request, res: Response): Promise<Job | null> {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Job not found' }); return null; }
    const workerId = String(req.body?.worker_id ?? '');
    const { data } = await getSupabase()!.from('vms_scan_jobs').select('id, org_id, kind, status, started_at, targets, options, worker_id, cancel_requested, purpose').eq('id', req.params.id).maybeSingle();
    if (!data) { res.status(404).json({ error: 'Job not found' }); return null; }
    if (data.worker_id !== workerId) { res.status(409).json({ error: 'This job belongs to another worker' }); return null; }
    if (data.status !== 'running') { res.status(409).json({ error: `Job is ${data.status}` }); return null; }
    return data as Job;
}

// The worker's own heartbeat, independent of jobs: says it is alive, what it runs and which tools
// it has. Validated strictly; tool names are limited to the ones the worker knows.
const TOOL_NAMES = ['subfinder', 'dnsx', 'httpx', 'nmap', 'nuclei', 'openvas'] as const;
const WorkerHeartbeat = z.object({
    worker_id: z.string().regex(WORKER_ID),
    kinds: z.array(z.enum(VMS_KINDS)).min(1).max(VMS_KINDS.length),
    version: z.string().trim().max(40).regex(/^[\w.+-]*$/).optional(),
    tools: z.record(z.enum(TOOL_NAMES), z.boolean()).optional(),
}).strict();
const heartbeatLimiter = rateLimit({ windowMs: 60_000, max: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many worker heartbeats: at most 30 a minute' } });

router.post('/heartbeat', heartbeatLimiter, async (req, res) => {
    const p = WorkerHeartbeat.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: `Body must be { worker_id: [A-Za-z0-9_.-]{1,64}, kinds: [${VMS_KINDS.join(' | ')}], version?, tools?: { ${TOOL_NAMES.join(', ')}: boolean } }` }); return; }
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const now = new Date().toISOString();
    const r = await recordWorkerSeen(p.data.worker_id, { kinds: [...new Set(p.data.kinds)], version: p.data.version ?? null, tools: p.data.tools ?? {}, last_heartbeat_at: now });
    if (r === 'missing') { res.status(503).json({ error: PRESENCE_MISSING_MESSAGE }); return; }
    if (r === 'failed') { res.status(503).json({ error: 'Could not record the heartbeat' }); return; }
    // How many jobs are waiting for this worker's kinds: lets the worker say "idle" vs "work waiting".
    const { count } = await supabase.from('vms_scan_jobs').select('id', { count: 'exact', head: true }).eq('status', 'queued').in('kind', p.data.kinds);
    res.json({ ok: true, worker_id: p.data.worker_id, server_time: now, online_window_seconds: WORKER_ONLINE_SECONDS, queued: count ?? 0 });
});

router.post('/claim', async (req, res) => {
    const workerId = String(req.body?.worker_id ?? '');
    const kinds = Array.isArray(req.body?.kinds) ? req.body.kinds.filter((k: unknown) => (VMS_KINDS as readonly unknown[]).includes(k)) : [];
    if (!WORKER_ID.test(workerId) || !kinds.length) { res.status(400).json({ error: `Body must be { worker_id, kinds: [${VMS_KINDS.join(' | ')}] }` }); return; }
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const { data, error } = await supabase.rpc('vms_claim_job', { p_worker: workerId, p_kinds: kinds });
    if (error) { res.status(503).json({ error: 'Queue unavailable' }); return; }
    const job = (Array.isArray(data) ? data[0] : data) as Job | undefined;
    const now = new Date().toISOString();
    // An authenticated poll is presence, even when the queue is empty.
    await recordWorkerSeen(workerId, { kinds, last_claim_at: now, ...(job ? { last_job_id: job.id, last_job_at: now } : {}) });
    if (!job) { res.json({ job: null }); return; }
    const scopes = await activeScopes(job.org_id);
    res.json({ job, scopes: scopes.map((s) => ({ kind: s.kind, value: s.value, include_subdomains: s.include_subdomains, allow_discovery: s.allow_discovery !== false, allow_port_scan: s.allow_port_scan, allow_vuln_scan: s.allow_vuln_scan, expires_at: s.expires_at, status: s.status })) });
});

const Progress = z.object({ phase: z.string().max(60).optional(), done: z.number().int().min(0).optional(), total: z.number().int().min(0).optional(), message: z.string().max(300).optional() }).strict();
router.post('/jobs/:id/heartbeat', async (req, res) => {
    const job = await ownJob(req, res);
    if (!job) return;
    const p = Progress.safeParse(req.body?.progress ?? {});
    await getSupabase()!.from('vms_scan_jobs').update({ heartbeat_at: new Date().toISOString(), ...(p.success ? { progress: p.data } : {}) }).eq('id', job.id);
    if (job.worker_id) await recordWorkerSeen(job.worker_id, {});
    res.json({ cancel: job.cancel_requested });
});

router.post('/jobs/:id/results', async (req, res) => {
    const job = await ownJob(req, res);
    if (!job) return;
    const obs = req.body?.observations;
    if (!Array.isArray(obs) || obs.length > MAX_OBSERVATIONS_PER_BATCH) { res.status(400).json({ error: `observations must be an array of at most ${MAX_OBSERVATIONS_PER_BATCH}` }); return; }
    try {
        // Vulnerability jobs send findings; discovery and port jobs send inventory observations.
        const scopes = await activeScopes(job.org_id);
        const r = job.kind.startsWith('vuln_') ? await ingestFindings(job, obs, scopes) : await ingestObservations(job, obs, scopes);
        await getSupabase()!.from('vms_scan_jobs').update({ heartbeat_at: new Date().toISOString() }).eq('id', job.id);
        if (r.rejected_out_of_scope) logAudit({ user: `worker:${job.worker_id}`, action: 'VMS_RESULT_OUT_OF_SCOPE', resource: 'vms_scan_job', resource_id: job.id, org_id: job.org_id, ip: req.ip ?? 'unknown', result: 'failed', severity: 'warning', details: `${r.rejected_out_of_scope} observation(s) outside authorised scope dropped` });
        res.json(r);
    } catch (err) {
        res.status(502).json({ error: err instanceof Error ? err.message : 'ingest failed' });
    }
});

const Complete = z.object({ worker_id: z.string(), status: z.enum(['succeeded', 'failed', 'cancelled']), error: z.string().max(1000).optional(), summary: z.record(z.string(), z.unknown()).optional() });
router.post('/jobs/:id/complete', async (req, res) => {
    const job = await ownJob(req, res);
    if (!job) return;
    const p = Complete.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: 'Body must be { worker_id, status: succeeded|failed|cancelled, error?, summary? }' }); return; }
    let gone = 0;
    if (p.data.status === 'succeeded' && job.kind === 'ports') gone = await markGoneServices(job);
    // A verification scan concludes its findings: verified only when it succeeded without detecting them.
    const verification = job.purpose === 'verification' ? await concludeVerification(job, p.data.status) : null;
    const summary = { ...(p.data.summary ?? {}), ...(gone ? { services_gone: gone } : {}), ...(verification ? { verification } : {}) };
    await getSupabase()!.from('vms_scan_jobs').update({ status: p.data.status, finished_at: new Date().toISOString(), error: p.data.error ?? null, summary }).eq('id', job.id);
    res.json({ ok: true, services_gone: gone });
});

export default router;
