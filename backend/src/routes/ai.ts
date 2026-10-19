// /api/ai — AI-backed analysis (NVIDIA, services/nvidia.ts) for SecOps, VMS and the Threat Information System (phase P3).
// Mounted behind requireAuth. Each purpose (services/aiPurposes.ts) carries its own permission and
// only ever reads the caller's organisation.
//
//   GET  /health                          soc_manager / super_admin — model lookup, no generation
//   POST /generate { purpose, subject_id }  the purpose's permission — 200 artifact | 503 unavailable
//   GET  /artifacts?subject_type&subject_id  latest AI outputs for one record (same permission)
//   POST /artifacts/:id/feedback { status: accepted|rejected, feedback? }
//
// AI output is advice. These routes never change alerts, cases, findings or access.

import { Router } from 'express';
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import type { AuthRequest } from '../middleware/auth';
import { requireRole } from '../middleware/auth';
import { hasPermission, requireOrg, requestOrg } from '../lib/permissions';
import { getSupabase } from '../services/geoEnrichment';
import { dbErrorMessage, isUuid } from '../services/cases';
import { aiHealth, generate } from '../services/ai';
import { aiPurpose, aiPurposeNames } from '../services/aiPurposes';
import '../services/aiPurposesVms'; // registers the VMS purposes
import '../services/aiPurposesTi'; // registers the Threat Information System purposes
import '../services/aiPurposesCnii'; // registers the CNII sector briefing (phase P9)
import { logAudit } from '../lib/audit';

const router = Router();
// Generation spends money and takes time: per-user limit.
const genLimiter = rateLimit({
    windowMs: 60_000, max: 10, standardHeaders: true, legacyHeaders: false,
    keyGenerator: (req) => (req as AuthRequest).user?.email ?? ipKeyGenerator(req.ip ?? '0.0.0.0'),
    message: { error: 'Too many AI requests — wait a minute' },
});

router.get('/health', requireRole('super_admin', 'soc_manager'), async (_req, res) => {
    res.json(await aiHealth());
});

router.use(requireOrg);

router.post('/generate', genLimiter, async (req: AuthRequest, res) => {
    const purposeName = typeof req.body?.purpose === 'string' ? req.body.purpose : '';
    const subjectId = typeof req.body?.subject_id === 'string' ? req.body.subject_id : '';
    const purpose = aiPurpose(purposeName);
    if (!purpose) { res.status(400).json({ error: `purpose must be one of ${aiPurposeNames().join(', ')}` }); return; }
    if (!hasPermission(req.user?.role, purpose.permission)) { res.status(403).json({ error: 'Forbidden' }); return; }
    if (!/^[\w:.-]{1,200}$/.test(subjectId)) { res.status(400).json({ error: 'subject_id is required' }); return; }
    const org = requestOrg(req);
    const ctx = await purpose.build(org, subjectId);
    if (!ctx) { res.status(404).json({ error: 'Record not found' }); return; }
    const r = await generate({
        purpose: purposeName, orgId: org, actor: req.user?.email ?? 'unknown', subjectType: purpose.subjectType, subjectId,
        sourceRefs: ctx.refs, records: ctx.records, task: purpose.task, schema: purpose.schema, maxTokens: purpose.maxTokens,
    });
    if (!r.ok) { res.status(r.status).json({ error: r.error, unavailable: r.unavailable }); return; }
    logAudit({ user: req.user?.email ?? 'unknown', action: 'AI_GENERATED', resource: purpose.subjectType, resource_id: subjectId, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: purposeName });
    res.json({ artifact: r.artifact });
});

router.get('/artifacts', async (req: AuthRequest, res) => {
    const subjectType = typeof req.query.subject_type === 'string' ? req.query.subject_type : '';
    const subjectId = typeof req.query.subject_id === 'string' ? req.query.subject_id : '';
    const allowed = aiPurposeNames().map(aiPurpose).filter((p) => p && p.subjectType === subjectType && hasPermission(req.user?.role, p.permission));
    if (!allowed.length) { res.status(403).json({ error: 'Forbidden' }); return; }
    if (!/^[\w:.-]{1,200}$/.test(subjectId)) { res.status(400).json({ error: 'subject_id is required' }); return; }
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const { data, error } = await supabase.from('ai_artifacts').select('id, purpose, content, model, created_by, created_at, status, feedback, feedback_by, feedback_at, source_refs')
        .eq('org_id', requestOrg(req)).eq('subject_type', subjectType).eq('subject_id', subjectId).order('created_at', { ascending: false }).limit(20);
    if (error) { res.status(/ai_artifacts/.test(error.message) ? 503 : 502).json({ error: dbErrorMessage(error) }); return; }
    res.json({ artifacts: data ?? [] });
});

router.post('/artifacts/:id/feedback', async (req: AuthRequest, res) => {
    const { id } = req.params;
    if (!isUuid(id)) { res.status(404).json({ error: 'Not found' }); return; }
    const status = req.body?.status;
    if (status !== 'accepted' && status !== 'rejected') { res.status(400).json({ error: "status must be 'accepted' or 'rejected'" }); return; }
    const feedback = typeof req.body?.feedback === 'string' ? req.body.feedback.trim().slice(0, 2000) || null : null;
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const org = requestOrg(req);
    const { data: art } = await supabase.from('ai_artifacts').select('id, purpose').eq('id', id).eq('org_id', org).maybeSingle();
    const purpose = art ? aiPurpose(art.purpose) : undefined;
    if (!art || !purpose || !hasPermission(req.user?.role, purpose.permission)) { res.status(404).json({ error: 'Not found' }); return; }
    const { data, error } = await supabase.from('ai_artifacts').update({ status, feedback, feedback_by: req.user?.email ?? 'unknown', feedback_at: new Date().toISOString() })
        .eq('id', id).eq('org_id', org).select('id, status, feedback, feedback_by, feedback_at').maybeSingle();
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    res.json({ artifact: data });
});

export default router;
