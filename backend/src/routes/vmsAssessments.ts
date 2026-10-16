// /api/vms/assessments — asset-centric Full Assessment (phase P13). Behind requireAuth; every route
// resolves the caller's organisation (requirePermission).
//
//   GET  /assessments?asset_id=           vms:read   newest first, with derived status and progress
//   POST /assessments { asset_id | target, scope_id? }  vms:scan  plans and queues the profile;
//                                          returns the one in progress for the same target (200) instead of a duplicate
//   GET  /assessments/:id                 vms:read   steps (status, reason, outcome), findings, evidence list
//   POST /assessments/:id/retry           vms:scan   re-plans steps that did not complete; completed ones stay
//   POST /assessments/:id/cancel          vms:scan   cancels its queued scans, asks running ones to stop
//   GET  /assessments/:id/report          vms:read   management report, Markdown download
//
// Planning and scope live in services/vmsAssessments.ts; jobs go through routes/vms.ts queueScan.

import { Router, type Response } from 'express';
import { z } from 'zod';
import type { AuthRequest } from '../middleware/auth';
import { requirePermission, requestOrg } from '../lib/permissions';
import { getSupabase } from '../services/geoEnrichment';
import { isUuid } from '../services/cases';
import { logAudit } from '../lib/audit';
import { createAssessment, retryAssessment, describe, assessmentFindings, managementReport, isMissingP13, P13_MISSING, type AssessmentRow } from '../services/vmsAssessments';

const router = Router();
const actor = (req: AuthRequest) => req.user?.email ?? 'unknown';
const unavailable = (res: Response, e: { message?: string; code?: string }) => res.status(isMissingP13(e) ? 503 : 502).json({ error: isMissingP13(e) ? P13_MISSING : 'Could not read assessments' });

router.get('/assessments', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    let q = getSupabase()!.from('vms_assessments').select('*').eq('org_id', requestOrg(req)).order('requested_at', { ascending: false }).limit(50);
    if (typeof req.query.asset_id === 'string' && isUuid(req.query.asset_id)) q = q.eq('asset_id', req.query.asset_id);
    const { data, error } = await q;
    if (error) { unavailable(res, error); return; }
    res.json({ assessments: (await describe((data ?? []) as AssessmentRow[])).map(({ all_job_ids: _j, ...a }) => a) });
});

const NewAssessment = z.object({ asset_id: z.string().uuid().optional(), target: z.string().max(253).optional(), scope_id: z.string().uuid().optional() }).strict()
    .refine((b) => !!b.asset_id !== !!b.target, 'give asset_id or target');
router.post('/assessments', requirePermission('vms:scan'), async (req: AuthRequest, res) => {
    const p = NewAssessment.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: 'Body must be { asset_id } or { target }, with an optional scope_id' }); return; }
    const r = await createAssessment(requestOrg(req), actor(req), p.data, req.ip ?? 'unknown');
    if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
    res.status(r.existing ? 200 : 201).json({ assessment: r.assessment, existing: r.existing });
});

async function load(req: AuthRequest, res: Response) {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Assessment not found' }); return null; }
    const { data, error } = await getSupabase()!.from('vms_assessments').select('*').eq('id', req.params.id).eq('org_id', requestOrg(req)).maybeSingle();
    if (error) { unavailable(res, error); return null; }
    if (!data) { res.status(404).json({ error: 'Assessment not found' }); return null; }
    return (await describe([data as AssessmentRow]))[0];
}

async function evidenceFor(org: string, jobIds: string[], withContent = false) {
    if (!jobIds.length) return [];
    const { data, error } = await getSupabase()!.from('vms_job_evidence').select(`id, job_id, target, tool, truncated, bytes, sha256, created_at, expires_at${withContent ? ', content' : ''}`)
        .eq('org_id', org).in('job_id', jobIds).gt('expires_at', new Date().toISOString()).order('created_at').limit(200);
    return error ? [] : ((data ?? []) as unknown as { id: string; job_id: string; tool: string; target: string; sha256: string; created_at: string; truncated: boolean }[]);
}

router.get('/assessments/:id', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const a = await load(req, res);
    if (!a) return;
    const org = requestOrg(req);
    const findings = await assessmentFindings(org, a.steps.flatMap((s) => s.finding_ids));
    const { all_job_ids: jobIds, ...rest } = a;
    res.json({ assessment: rest, findings, evidence: await evidenceFor(org, jobIds) });
});

router.post('/assessments/:id/retry', requirePermission('vms:scan'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Assessment not found' }); return; }
    const r = await retryAssessment(requestOrg(req), req.params.id, actor(req), req.ip ?? 'unknown');
    if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
    res.json({ assessment: r.assessment, nothing_to_retry: r.existing });
});

router.post('/assessments/:id/cancel', requirePermission('vms:scan'), async (req: AuthRequest, res) => {
    const a = await load(req, res);
    if (!a) return;
    const supabase = getSupabase()!;
    const now = new Date().toISOString();
    const ids = a.steps.map((s) => s.job_id).filter((x): x is string => !!x);
    if (ids.length) {
        await supabase.from('vms_scan_jobs').update({ status: 'cancelled', finished_at: now, error: `Assessment cancelled by ${actor(req)}` }).in('id', ids).eq('status', 'queued');
        await supabase.from('vms_scan_jobs').update({ cancel_requested: true }).in('id', ids).eq('status', 'running');
    }
    await supabase.from('vms_assessments').update({ cancelled_at: now }).eq('id', a.id);
    logAudit({ user: actor(req), action: 'VMS_ASSESSMENT_CANCELLED', resource: 'vms_assessment', resource_id: a.id, org_id: requestOrg(req), ip: req.ip ?? 'unknown', result: 'success', details: a.target });
    res.json({ ok: true });
});

router.get('/assessments/:id/report', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const a = await load(req, res);
    if (!a) return;
    const org = requestOrg(req);
    const [{ data: scope }, findings, evidence] = await Promise.all([
        getSupabase()!.from('vms_scopes').select('kind, value, authorization_reference, approved_by, expires_at, exclusions').eq('id', a.scope_id).eq('org_id', org).maybeSingle(),
        assessmentFindings(org, a.steps.flatMap((s) => s.finding_ids)),
        evidenceFor(org, a.all_job_ids),
    ]);
    const md = managementReport(a, scope ?? {}, findings, evidence);
    const name = `assessment-${a.target.replace(/[^\w.-]/g, '_')}-${a.requested_at.slice(0, 10)}.md`;
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${name}"`);
    res.send(md);
});

export default router;
