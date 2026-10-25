// /api/admin/onboarding — Release 3.1's client onboarding wizard (phase P29). Mounted behind
// requireAuth + requireRole('super_admin', 'soc_manager') in index.ts.
//
//   GET    /                       every in-progress or completed wizard record (for "resume")
//   POST   /:id/start              create (or return, idempotently) this organisation's draft
//   GET    /:id                    the draft: steps saved so far, current step, status
//   PATCH  /:id/step/:n            save one step's data; n is 1-6
//   GET    /:id/services           this organisation's module grants (phase P29)
//   PUT    /:id/services           set one module's grant status
//   POST   /:id/activate           finish onboarding — organisations.setup_complete = true
//
// :id is the organisation's UUID (organisations.id), matching every other /api/organisations/:id
// sub-resource — org_onboarding and org_service_grants key on the slug internally, like every
// other org-scoped table in this schema, so every handler below resolves id -> slug first.
//
// Nothing here duplicates the organisation, its users, their invitations, or any permission
// model: `steps` is wizard UI draft state only; Step 3's invitation list and Step 6's review are
// always read fresh from platform_users / auth_links / org_service_grants, never copied in.

import { Router } from 'express';
import { z } from 'zod';
import type { AuthRequest } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';
import { dbErrorMessage, isUuid } from '../services/cases';
import { logAudit } from '../lib/audit';
import { SERVICES, SERVICE_LABEL, serviceGrantsFor, type ServiceKey } from '../lib/serviceAccess';

const router = Router();
const actor = (req: AuthRequest) => req.user?.email ?? 'unknown';
const missing = (e: { message?: string } | null) => !!e && /org_onboarding|org_service_grants/.test(e.message ?? '') && /does not exist|Could not find/i.test(e.message ?? '');
const P29_MISSING = 'The onboarding wizard is not set up yet (run sql/2026-11-08_p29_onboarding_wizard.sql)';
const fail = (res: import('express').Response, e: { message?: string } | null) => res.status(missing(e) ? 503 : 502).json({ error: missing(e) ? P29_MISSING : dbErrorMessage(e) });

/** organisations.id (UUID) -> its row, or null. Every handler below needs the slug, not the id,
 * to touch org_onboarding / org_service_grants. */
async function orgById(id: string): Promise<{ id: string; slug: string; name: string } | null> {
    if (!isUuid(id)) return null;
    const supabase = getSupabase()!;
    const { data } = await supabase.from('organisations').select('id, slug, name').eq('id', id).maybeSingle();
    return data ?? null;
}

router.get('/', async (_req, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const { data, error } = await supabase.from('org_onboarding').select('*').order('updated_at', { ascending: false }).limit(200);
    if (error) { fail(res, error); return; }
    res.json({ records: data ?? [] });
});

router.post('/:id/start', async (req: AuthRequest, res) => {
    const org = await orgById(req.params.id);
    if (!org) { res.status(404).json({ error: 'Organisation not found' }); return; }
    const supabase = getSupabase()!;
    const { data: existing, error: selErr } = await supabase.from('org_onboarding').select('*').eq('org_id', org.slug).maybeSingle();
    if (selErr) { fail(res, selErr); return; }
    if (existing) { res.json({ record: existing }); return; }
    const now = new Date().toISOString();
    const { data, error } = await supabase.from('org_onboarding')
        .insert({ org_id: org.slug, status: 'draft', current_step: 1, completed_steps: [], steps: {}, created_by: actor(req), updated_by: actor(req), created_at: now, updated_at: now })
        .select('*').single();
    if (error) { fail(res, error); return; }
    logAudit({ user: actor(req), action: 'ONBOARDING_STARTED', resource: 'org_onboarding', resource_id: org.slug, ip: req.ip ?? 'unknown', result: 'success', details: org.name.slice(0, 200) });
    res.status(201).json({ record: data });
});

router.get('/:id', async (req, res) => {
    const org = await orgById(req.params.id);
    if (!org) { res.status(404).json({ error: 'Organisation not found' }); return; }
    const supabase = getSupabase()!;
    const { data, error } = await supabase.from('org_onboarding').select('*').eq('org_id', org.slug).maybeSingle();
    if (error) { fail(res, error); return; }
    if (!data) { res.status(404).json({ error: 'No onboarding record yet — POST /:id/start first' }); return; }
    res.json({ record: data });
});

const StepBody = z.object({ data: z.record(z.string(), z.unknown()), advance_to: z.number().int().min(1).max(6).optional() }).strict();
router.patch('/:id/step/:n', async (req: AuthRequest, res) => {
    const n = Number(req.params.n);
    if (!Number.isInteger(n) || n < 1 || n > 6) { res.status(400).json({ error: 'Step must be 1-6' }); return; }
    const p = StepBody.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: 'Body must be { data: object, advance_to?: 1-6 }' }); return; }
    const org = await orgById(req.params.id);
    if (!org) { res.status(404).json({ error: 'Organisation not found' }); return; }
    const supabase = getSupabase()!;
    const { data: existing, error: selErr } = await supabase.from('org_onboarding').select('*').eq('org_id', org.slug).maybeSingle();
    if (selErr) { fail(res, selErr); return; }
    if (!existing) { res.status(404).json({ error: 'No onboarding record yet — POST /:id/start first' }); return; }
    if (existing.status === 'active') { res.status(409).json({ error: 'This organisation has already completed onboarding' }); return; }
    const steps = { ...(existing.steps ?? {}), [String(n)]: p.data.data };
    const completed = [...new Set([...(existing.completed_steps ?? []), n])].sort((a, b) => a - b);
    const { data, error } = await supabase.from('org_onboarding')
        .update({ steps, completed_steps: completed, current_step: p.data.advance_to ?? n, updated_by: actor(req), updated_at: new Date().toISOString() })
        .eq('org_id', org.slug).select('*').single();
    if (error) { fail(res, error); return; }
    res.json({ record: data });
});

router.get('/:id/services', async (req, res) => {
    const org = await orgById(req.params.id);
    if (!org) { res.status(404).json({ error: 'Organisation not found' }); return; }
    const grants = await serviceGrantsFor(org.slug);
    const byService = new Map(grants.map((g) => [g.service, g]));
    res.json({
        services: SERVICES.map((s) => ({
            service: s, label: SERVICE_LABEL[s],
            status: byService.get(s)?.status ?? 'pending',
            notes: byService.get(s)?.notes ?? null,
            granted_by: byService.get(s)?.granted_by ?? null,
            updated_at: byService.get(s)?.updated_at ?? null,
        })),
    });
});

const ServiceBody = z.object({ service: z.enum(SERVICES), status: z.enum(['enabled', 'configured', 'pending', 'disabled']), notes: z.string().trim().max(500).optional() }).strict();
router.put('/:id/services', async (req: AuthRequest, res) => {
    const p = ServiceBody.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: `Body must be { service: ${SERVICES.join('|')}, status: enabled|configured|pending|disabled, notes? }` }); return; }
    const org = await orgById(req.params.id);
    if (!org) { res.status(404).json({ error: 'Organisation not found' }); return; }
    const supabase = getSupabase()!;
    const now = new Date().toISOString();
    const { data, error } = await supabase.from('org_service_grants')
        .upsert({ org_id: org.slug, service: p.data.service, status: p.data.status, notes: p.data.notes ?? null, granted_by: actor(req), granted_at: now, updated_at: now }, { onConflict: 'org_id,service' })
        .select('*').single();
    if (error) { fail(res, error); return; }
    logAudit({ user: actor(req), action: 'ORG_SERVICE_GRANT_CHANGED', resource: 'org_service_grants', resource_id: org.slug, ip: req.ip ?? 'unknown', result: 'success', severity: 'warning', details: `${p.data.service} -> ${p.data.status}`.slice(0, 200) });
    res.json({ grant: data });
});

router.post('/:id/activate', async (req: AuthRequest, res) => {
    const org = await orgById(req.params.id);
    if (!org) { res.status(404).json({ error: 'Organisation not found' }); return; }
    const supabase = getSupabase()!;
    const { data: record, error: selErr } = await supabase.from('org_onboarding').select('*').eq('org_id', org.slug).maybeSingle();
    if (selErr) { fail(res, selErr); return; }
    if (!record) { res.status(404).json({ error: 'No onboarding record yet — POST /:id/start first' }); return; }
    if (record.status === 'active') { res.status(409).json({ error: 'Already activated' }); return; }

    // Mandatory gate: the organisation profile step is saved, and at least one client-facing
    // account (its first executive, or a portal_user) exists to actually use the portal —
    // "invited" is enough; completing their own setup is their own next step, not this one's.
    const problems: string[] = [];
    if (!record.completed_steps?.includes(1)) problems.push('Step 1 (organisation profile) is not saved yet');
    const { data: people, error: peopleErr } = await supabase.from('platform_users').select('id, role, status').eq('org_id', org.id).in('role', ['executive', 'portal_user']);
    if (peopleErr) { fail(res, peopleErr); return; }
    if (!people || people.length === 0) problems.push('No executive or client user has been invited yet (Step 3)');
    if (problems.length) { res.status(409).json({ error: 'Cannot activate yet', problems }); return; }

    const now = new Date().toISOString();
    const { data, error } = await supabase.from('org_onboarding')
        .update({ status: 'active', activated_by: actor(req), activated_at: now, updated_by: actor(req), updated_at: now })
        .eq('org_id', org.slug).select('*').single();
    if (error) { fail(res, error); return; }
    await supabase.from('organisations').update({ setup_complete: true, status: 'active' }).eq('id', org.id);
    logAudit({ user: actor(req), action: 'ONBOARDING_ACTIVATED', resource: 'org_onboarding', resource_id: org.slug, ip: req.ip ?? 'unknown', result: 'success', severity: 'warning', details: org.name.slice(0, 200) });
    res.json({ record: data });
});

export default router;
