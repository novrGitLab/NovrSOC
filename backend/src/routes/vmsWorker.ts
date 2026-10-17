// /api/vms/worker — the scanner worker's API (phase P4). The worker (infra/vms-worker) runs on a
// separate host with the scanning tools; it authenticates with VMS_WORKER_TOKEN (Bearer) and is
// never a user. Fails closed: with the variable unset every call is 503.
//
//   POST /heartbeat            { worker_id, kinds[], version?, tools? } -> { ok, server_time, queued } (phase P10)
//   POST /claim                { worker_id, kinds[] }          -> { job, scopes } | { job: null }
//   POST /jobs/:id/heartbeat   { progress }                    -> { cancel }   (cancel = stop now)
//   POST /jobs/:id/results     { observations: [...] }         -> accepted / rejected counts
//   POST /jobs/:id/complete    { status: succeeded|failed|cancelled, error?, summary? }  (error/summary may be null)
//   POST /jobs/:id/evidence    { target, tool, content, truncated }   raw tool output, redacted, kept 30 days (P12)
//   POST /jobs/:id/release     { reason }   the worker is stopping: back to the queue (P12)
//
// The worker receives the job's scope entries so it can re-check targets before running a tool,
// but the backend re-checks every result it accepts (services/vmsIngest.ts).
//
// Presence (phase P10, services/vmsWorkers.ts): every request that passes the token check —
// heartbeat, claim (including an empty queue) and job heartbeats — records the worker in
// vms_workers. That record, not a running process, is what the dashboard calls "connected".
//
// Job lifecycle (P11 repair): queued -> running (claim) -> succeeded | failed | cancelled (complete).
//   • /complete is idempotent: the same worker completing a job it already finished gets 200, so a
//     retry after a lost response is safe. It only moves a job that is still running and still this
//     worker's; anything else (requeued, failed by upkeep, another worker) is 409.
//   • A worker that asks for work while the backend still has a running job assigned to it lost
//     that job (restart, or the claim response never arrived). The job is re-sent to it instead of
//     waiting for queue upkeep to requeue it, so a lost response never loses or duplicates a job.
//   • A failed claim says why in the log (database code and message) and, sanitised, in the reply.

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
import { parseCidr } from '../lib/cidr';
import { parseTarget } from '../lib/vmsScope';
import { redactString } from '../lib/redact';

const router = Router();
const digest = (s: string) => createHash('sha256').update(s).digest();
export const MAX_OBSERVATIONS_PER_BATCH = 500;
// The worker's job kinds. passive_osint is not among them: the backend runs it (jobs/cniiPassiveJob.ts).
export const VMS_KINDS = ['discovery', 'ports', 'vuln_nuclei', 'vuln_openvas'] as const;
/** Features a worker must announce to be given a job (P13): exclusions need a worker that enforces them. */
export const WORKER_FEATURES = ['exclusions', 'pinned_addresses'] as const;

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
    // partialRecord: an enum-keyed z.record requires every key (zod 4); a worker may report a subset.
    tools: z.partialRecord(z.enum(TOOL_NAMES), z.boolean()).optional(),
    // Private networks this worker can reach (VMS_WORKER_NETWORKS). Each must be a valid CIDR.
    networks: z.array(z.string().max(50).refine((n) => !!parseCidr(n), 'not a CIDR')).max(32).optional(),
    // What it enforces itself (P13), e.g. 'exclusions'.
    features: z.array(z.enum(WORKER_FEATURES)).max(WORKER_FEATURES.length).optional(),
    // Versions as each tool reports them (P14), e.g. { nmap: "7.94SVN" }.
    tool_versions: z.partialRecord(z.enum(TOOL_NAMES), z.string().max(80)).optional(),
}).strict();
const heartbeatLimiter = rateLimit({ windowMs: 60_000, max: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many worker heartbeats: at most 30 a minute' } });

router.post('/heartbeat', heartbeatLimiter, async (req, res) => {
    const p = WorkerHeartbeat.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: `Body must be { worker_id: [A-Za-z0-9_.-]{1,64}, kinds: [${VMS_KINDS.join(' | ')}], version?, tools?: { ${TOOL_NAMES.join(', ')}: boolean } }` }); return; }
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const now = new Date().toISOString();
    // A heartbeat states the worker's whole capability: what it does not announce, it does not have.
    // (Absent fields used to keep their old values, so after a rollback from 1.5.0 to an older
    // worker — whose --self-test had announced 'exclusions' — the old worker kept that feature and
    // could be given jobs whose exclusions it does not enforce.)
    const r = await recordWorkerSeen(p.data.worker_id, { kinds: [...new Set(p.data.kinds)], version: p.data.version ?? null, tools: p.data.tools ?? {}, networks: p.data.networks ?? [], features: p.data.features ?? [], tool_versions: p.data.tool_versions ?? {}, last_heartbeat_at: now });
    if (r === 'missing') { res.status(503).json({ error: PRESENCE_MISSING_MESSAGE }); return; }
    if (r === 'failed') { res.status(503).json({ error: 'Could not record the heartbeat' }); return; }
    // How many jobs are waiting for this worker's kinds: lets the worker say "idle" vs "work waiting".
    const { count } = await supabase.from('vms_scan_jobs').select('id', { count: 'exact', head: true }).eq('status', 'queued').in('kind', p.data.kinds);
    res.json({ ok: true, worker_id: p.data.worker_id, server_time: now, online_window_seconds: WORKER_ONLINE_SECONDS, queued: count ?? 0 });
});

/** Why a queue call failed, for the worker's log: a category, never a credential or a query. */
export function queueFailure(e: { message?: string; code?: string; details?: string; hint?: string }): { reason: string; detail: string } {
    const msg = `${e.message ?? ''} ${e.details ?? ''}`;
    if (e.code === 'PGRST202' || /Could not find the function/i.test(msg)) return { reason: 'claim_function_missing', detail: 'vms_claim_job is not available to the API (run sql/2026-10-14_p4_vms_asm.sql, then reload the API schema)' };
    if (e.code === '42501' || /permission denied/i.test(msg)) return { reason: 'permission_denied', detail: 'the backend database role may not execute vms_claim_job' };
    if (e.code === '57014' || /statement timeout|canceling statement/i.test(msg)) return { reason: 'database_timeout', detail: 'the claim query timed out' };
    if (/fetch failed|ECONNRESET|ETIMEDOUT|ENOTFOUND|ECONNREFUSED|socket|network|Connect Timeout/i.test(msg)) return { reason: 'database_unreachable', detail: 'the backend could not reach the database' };
    return { reason: 'database_error', detail: `database error${e.code ? ` ${e.code}` : ''}` };
}

const scopesFor = async (orgId: string) => (await activeScopes(orgId)).map((s) => ({ kind: s.kind, value: s.value, include_subdomains: s.include_subdomains, allow_discovery: s.allow_discovery !== false, allow_port_scan: s.allow_port_scan, allow_vuln_scan: s.allow_vuln_scan, exclusions: s.exclusions ?? [], pinned_addresses: s.pinned_addresses ?? [], expires_at: s.expires_at, status: s.status }));

async function workerFeatures(workerId: string): Promise<string[]> {
    const { data, error } = await getSupabase()!.from('vms_workers').select('features').eq('worker_id', workerId).maybeSingle();
    return error ? [] : ((data?.features as string[] | undefined) ?? []);
}

router.post('/claim', async (req, res) => {
    const workerId = String(req.body?.worker_id ?? '');
    const kinds = Array.isArray(req.body?.kinds) ? req.body.kinds.filter((k: unknown) => (VMS_KINDS as readonly unknown[]).includes(k)) : [];
    if (!WORKER_ID.test(workerId) || !kinds.length) { res.status(400).json({ error: `Body must be { worker_id, kinds: [${VMS_KINDS.join(' | ')}] }` }); return; }
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }

    // A job still running under this worker id was lost by the worker: send it again.
    const { data: orphan, error: orphanErr } = await supabase.from('vms_scan_jobs').select('id, org_id, kind, status, started_at, targets, options, worker_id, cancel_requested, purpose, attempts')
        .eq('status', 'running').eq('worker_id', workerId).in('kind', kinds).order('claimed_at', { ascending: true }).limit(1).maybeSingle();
    if (orphanErr) {
        const f = queueFailure(orphanErr);
        console.error(`[vms] claim by ${workerId}: reading its running jobs failed (${f.reason}): ${orphanErr.code ?? ''} ${orphanErr.message}`);
        res.status(503).json({ error: 'Queue unavailable', reason: f.reason, detail: f.detail }); return;
    }
    if (orphan) {
        const now = new Date().toISOString();
        if (orphan.cancel_requested) {
            await supabase.from('vms_scan_jobs').update({ status: 'cancelled', finished_at: now, error: 'Cancelled while the worker was away' }).eq('id', orphan.id).eq('status', 'running');
        } else {
            await supabase.from('vms_scan_jobs').update({ heartbeat_at: now, progress: { message: 'Re-sent to the worker: it asked for work while this job was still assigned to it' } }).eq('id', orphan.id).eq('status', 'running');
            await recordWorkerSeen(workerId, { kinds, last_claim_at: now, last_job_id: orphan.id, last_job_at: now });
            console.warn(`[vms] job ${orphan.id} re-sent to ${workerId} (it was still assigned to it)`);
            res.json({ job: orphan, scopes: await scopesFor(orphan.org_id), redelivered: true });
            return;
        }
    }

    const { data, error } = await supabase.rpc('vms_claim_job', { p_worker: workerId, p_kinds: kinds });
    if (error) {
        const f = queueFailure(error);
        console.error(`[vms] claim by ${workerId} failed (${f.reason}): ${error.code ?? ''} ${error.message}${error.hint ? ` — ${error.hint}` : ''}`);
        res.status(503).json({ error: 'Queue unavailable', reason: f.reason, detail: f.detail });
        return;
    }
    const job = (Array.isArray(data) ? data[0] : data) as Job | undefined;
    const now = new Date().toISOString();
    // A job whose scope carves out exclusions goes only to a worker that enforces them: an older
    // worker would probe excluded names it discovers. Put it straight back, as it was.
    if (job) {
        const { data: sc } = await supabase.from('vms_scopes').select('*').eq('id', (job as Job & { scope_id?: string }).scope_id ?? '').maybeSingle();
        // The same for a CNII authorisation pinned to approved addresses (P18): worker 1.7.0 or later.
        const needs = [...(((sc?.exclusions as string[] | undefined) ?? []).length ? ['exclusions'] : []), ...(((sc?.pinned_addresses as string[] | undefined) ?? []).length ? ['pinned_addresses'] : [])];
        const has = needs.length ? await workerFeatures(workerId) : [];
        const lacking = needs.filter((f) => !has.includes(f));
        if (lacking.length) {
            const which = lacking.includes('pinned_addresses') ? 'enforces CNII pinned addresses (worker 1.7.0 or later)' : 'enforces scope exclusions (worker 1.4.0 or later)';
            await supabase.from('vms_scan_jobs').update({ status: 'queued', worker_id: null, claimed_at: null, heartbeat_at: null, started_at: null, attempts: Math.max(0, Number((job as Job & { attempts?: number }).attempts ?? 1) - 1), progress: { message: `Waiting for a worker that ${which}` } }).eq('id', job.id).eq('status', 'running');
            await recordWorkerSeen(workerId, { kinds, last_claim_at: now });
            res.json({ job: null, notice: `A queued job needs a worker that ${which}; upgrade this worker` });
            return;
        }
    }
    // An authenticated poll is presence, even when the queue is empty.
    await recordWorkerSeen(workerId, { kinds, last_claim_at: now, ...(job ? { last_job_id: job.id, last_job_at: now } : {}) });
    if (!job) { res.json({ job: null }); return; }
    res.json({ job, scopes: await scopesFor(job.org_id) });
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
        // The worker gets a category, not the database's own words; the log keeps those.
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`[vms] storing results for job ${job.id} failed: ${msg.slice(0, 500)}`);
        res.status(502).json({ error: 'Could not store results; retry or check the backend log', reason: queueFailure({ message: msg }).reason });
    }
});

// Raw tool output for one target (or a tool run over several), redacted again here and capped.
// Evidence only: it never creates assets or findings. Kept 30 days (vms_job_evidence.expires_at).
export const EVIDENCE_MAX_CHARS = 70_000;
export const EVIDENCE_PER_JOB = 50;
const Evidence = z.object({
    worker_id: z.string().regex(WORKER_ID),
    target: z.string().trim().min(1).max(253).refine((t) => t.split(',').every((x) => !!parseTarget(x) || !!parseCidr(x)), 'not a host, IP or CIDR'),
    tool: z.enum(['nmap', 'httpx', 'dnsx', 'subfinder', 'nuclei', 'openvas']),
    content: z.string().min(1).max(EVIDENCE_MAX_CHARS),
    truncated: z.boolean().default(false),
}).strict();
router.post('/jobs/:id/evidence', async (req, res) => {
    const p = Evidence.safeParse(req.body);
    if (!p.success) { const i = p.error.issues[0]; res.status(400).json({ error: `Invalid evidence: ${i?.path.join('.') || 'body'} ${i?.message ?? ''}`.trim() }); return; }
    const job = await ownJob(req, res);
    if (!job) return;
    const content = redactString(p.data.content);
    if (content === null) { res.status(400).json({ error: 'Evidence could not be redacted, so it is not stored' }); return; }
    const supabase = getSupabase()!;
    // A plain read, not a HEAD count: a HEAD reply has no body, so a missing table could not be told apart.
    const { data: existing, error: cErr } = await supabase.from('vms_job_evidence').select('id').eq('job_id', job.id).limit(EVIDENCE_PER_JOB);
    const count = existing?.length ?? 0;
    if (cErr) {
        const missing = /vms_job_evidence/.test(cErr.message) || cErr.code === 'PGRST205' || cErr.code === '42P01';
        if (!missing) console.error(`[vms] evidence count for job ${job.id} failed: ${cErr.message}`);
        res.status(503).json({ error: missing ? 'Raw evidence is not set up yet (run sql/2026-10-19_p12_vms_outcomes_evidence.sql)' : 'Could not store evidence' });
        return;
    }
    if (count >= EVIDENCE_PER_JOB) { res.status(409).json({ error: `At most ${EVIDENCE_PER_JOB} evidence items per job` }); return; }
    const { error } = await supabase.from('vms_job_evidence').insert({
        org_id: job.org_id, job_id: job.id, target: p.data.target, tool: p.data.tool, content, truncated: p.data.truncated,
        sha256: createHash('sha256').update(content).digest('hex'), bytes: Buffer.byteLength(content),
    });
    if (error) { console.error(`[vms] evidence for job ${job.id} not stored: ${error.message}`); res.status(503).json({ error: 'Could not store evidence' }); return; }
    res.status(201).json({ ok: true });
});

// The worker is stopping (SIGTERM): the job goes back to the queue, or fails after repeated hand-backs.
export const MAX_RELEASES = 3;
const Release = z.object({ worker_id: z.string().regex(WORKER_ID), reason: z.string().trim().min(1).max(300) }).strict();
router.post('/jobs/:id/release', async (req, res) => {
    const p = Release.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: 'Body must be { worker_id, reason }' }); return; }
    const job = await ownJob(req, res);
    if (!job) return;
    const supabase = getSupabase()!;
    const { data: cur } = await supabase.from('vms_scan_jobs').select('attempts').eq('id', job.id).maybeSingle();
    const attempts = Number(cur?.attempts ?? 0);
    const now = new Date().toISOString();
    const update = attempts >= MAX_RELEASES
        ? { status: 'failed', finished_at: now, error: `The worker stopped ${attempts} times before finishing (${p.data.reason}); queue it again when the worker is stable` }
        : { status: 'queued', worker_id: null, claimed_at: null, heartbeat_at: null, started_at: null, progress: { message: `Handed back by ${p.data.worker_id}: ${p.data.reason}` } };
    const { data: moved, error } = await supabase.from('vms_scan_jobs').update(update).eq('id', job.id).eq('status', 'running').eq('worker_id', p.data.worker_id).select('id');
    if (error) { console.error(`[vms] releasing job ${job.id} failed: ${error.message}`); res.status(503).json({ error: 'Could not release the job; retry' }); return; }
    if (!moved?.length) { res.status(409).json({ error: 'The job is no longer running under this worker' }); return; }
    logAudit({ user: `worker:${p.data.worker_id}`, action: 'VMS_JOB_RELEASED', resource: 'vms_scan_job', resource_id: job.id, org_id: job.org_id, ip: req.ip ?? 'unknown', result: 'success', details: `${update.status}: ${p.data.reason}`.slice(0, 200) });
    res.json({ ok: true, status: update.status });
});

// error and summary may be null: the Python worker sends None for "no error" (it always did; the
// earlier schema rejected null, so every successful job's completion was refused with 400).
export const Complete = z.object({
    worker_id: z.string().regex(WORKER_ID),
    status: z.enum(['succeeded', 'failed', 'cancelled']),
    error: z.string().max(1000).nullish(),
    summary: z.record(z.string(), z.unknown()).nullish(),
}).strict();
router.post('/jobs/:id/complete', async (req, res) => {
    const p = Complete.safeParse(req.body);
    if (!p.success) {
        const issue = p.error.issues[0];
        res.status(400).json({ error: `Invalid completion: ${issue?.path.join('.') || 'body'} ${issue?.message ?? ''}`.trim(), expected: '{ worker_id, status: succeeded|failed|cancelled, error?: string|null, summary?: object|null }' });
        return;
    }
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Job not found' }); return; }
    const { data: current } = await getSupabase()!.from('vms_scan_jobs').select('id, status, worker_id, finished_at').eq('id', req.params.id).maybeSingle();
    if (!current) { res.status(404).json({ error: 'Job not found' }); return; }
    if (current.worker_id !== p.data.worker_id) { res.status(409).json({ error: 'This job belongs to another worker' }); return; }
    // A retry of a completion that already landed: same answer, nothing changes.
    if (current.status !== 'running' && current.finished_at) { res.json({ ok: true, already_completed: true, status: current.status }); return; }
    const job = await ownJob(req, res);
    if (!job) return;
    let gone = 0;
    if (p.data.status === 'succeeded' && job.kind === 'ports') gone = await markGoneServices(job);
    // A verification scan concludes its findings: verified only when it succeeded without detecting them.
    const verification = job.purpose === 'verification' ? await concludeVerification(job, p.data.status, p.data.summary ?? null) : null;
    const summary = { ...(p.data.summary ?? {}), ...(gone ? { services_gone: gone } : {}), ...(verification ? { verification } : {}) };
    // Only a job still running under this worker moves: queue upkeep may have requeued or failed it meanwhile.
    const { data: moved, error } = await getSupabase()!.from('vms_scan_jobs')
        .update({ status: p.data.status, finished_at: new Date().toISOString(), error: p.data.error ?? (p.data.status === 'succeeded' ? null : 'No reason given by the worker'), summary })
        .eq('id', job.id).eq('status', 'running').eq('worker_id', p.data.worker_id).select('id');
    if (error) { console.error(`[vms] completing job ${job.id} failed: ${error.code ?? ''} ${error.message}`); res.status(503).json({ error: 'Could not record the completion; retry' }); return; }
    if (!moved?.length) { res.status(409).json({ error: 'The job is no longer running under this worker (requeued or failed by queue upkeep)' }); return; }
    res.json({ ok: true, services_gone: gone });
});

export default router;
