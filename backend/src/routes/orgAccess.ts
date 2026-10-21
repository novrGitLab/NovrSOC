// Organisation access for staff (phase P21).
//
//   /api/admin/org-assignments   (super_admin only, index.ts) — which analysts may act on which
//                                 organisations. Every change is audited.
//     GET    /?org=&user_id=      assignments
//     GET    /analysts            analyst accounts that can be assigned
//     POST   /  { user_id, org_slug, note? }
//     DELETE /:id
//   /api/org-access/mine          (any signed-in user) — the organisations the caller may view,
//                                 so the UI offers only those. The backend still decides on every
//                                 request (lib/resolveOrg.ts); this list grants nothing.

import { Router } from 'express';
import { z } from 'zod';
import type { AuthRequest } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';
import { logAudit } from '../lib/audit';
import { isUuid } from '../services/cases';

export const adminRouter = Router();
export const mineRouter = Router();

const missing = (msg: string) => /staff_org_assignments/.test(msg);
const NOT_SET_UP = 'Analyst assignments are not set up yet (sql/2026-10-27_p21_staff_org_assignments.sql); analysts can act on their own organisation only.';

adminRouter.get('/', async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    let q = supabase.from('staff_org_assignments').select('*').order('assigned_at', { ascending: false }).limit(2000);
    if (typeof req.query.org === 'string' && req.query.org) q = q.eq('org_slug', req.query.org);
    if (typeof req.query.user_id === 'string' && req.query.user_id) q = q.eq('user_id', req.query.user_id);
    const { data, error } = await q;
    if (error) { res.status(missing(error.message) ? 503 : 502).json({ error: missing(error.message) ? NOT_SET_UP : 'Could not read assignments' }); return; }
    res.json({ assignments: data ?? [] });
});

adminRouter.get('/analysts', async (_req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const { data, error } = await supabase.from('platform_users').select('id, email, name, status, organisations(slug, name)').eq('role', 'analyst').neq('status', 'disabled').order('email').limit(1000);
    if (error) { res.status(502).json({ error: 'Could not read analyst accounts' }); return; }
    res.json({ analysts: (data ?? []).map((u) => ({ id: u.id, email: u.email, name: u.name, status: u.status, home_org: (u.organisations as { slug?: string } | null)?.slug ?? null })) });
});

const NewAssignment = z.object({ user_id: z.string().uuid(), org_slug: z.string().trim().min(1).max(100), note: z.string().trim().max(500).optional() }).strict();
adminRouter.post('/', async (req: AuthRequest, res) => {
    const p = NewAssignment.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: 'Body must be { user_id: uuid, org_slug, note? }' }); return; }
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const [{ data: user }, { data: org }] = await Promise.all([
        supabase.from('platform_users').select('id, email, role, status').eq('id', p.data.user_id).maybeSingle(),
        supabase.from('organisations').select('slug, name').eq('slug', p.data.org_slug).maybeSingle(),
    ]);
    if (!user) { res.status(404).json({ error: 'User not found' }); return; }
    if (user.role !== 'analyst') { res.status(400).json({ error: 'Only analyst accounts are assigned; super_admin already has every organisation' }); return; }
    if (user.status === 'disabled') { res.status(409).json({ error: 'The account is disabled' }); return; }
    if (!org) { res.status(404).json({ error: 'Organisation not found' }); return; }
    // The table's UNIQUE (user_id, org_slug) is the guarantee; this gives a clear answer first.
    const existing = await supabase.from('staff_org_assignments').select('id').eq('user_id', user.id).eq('org_slug', org.slug).limit(1);
    if (!existing.error && (existing.data ?? []).length) { res.status(409).json({ error: 'Already assigned' }); return; }
    const { data, error } = await supabase.from('staff_org_assignments').insert({ user_id: user.id, user_email: user.email, org_slug: org.slug, assigned_by: req.user?.email ?? 'unknown', note: p.data.note ?? null }).select('*').single();
    if (error) {
        if (/duplicate|unique/i.test(error.message)) { res.status(409).json({ error: 'Already assigned' }); return; }
        res.status(missing(error.message) ? 503 : 502).json({ error: missing(error.message) ? NOT_SET_UP : 'Could not save the assignment' });
        return;
    }
    logAudit({ user: req.user?.email ?? 'unknown', action: 'ORG_ASSIGNMENT_ADDED', resource: 'staff_org_assignment', resource_id: data.id, org_id: org.slug, ip: req.ip ?? 'unknown', result: 'success', severity: 'warning', details: `${user.email} may act on ${org.slug}` });
    res.status(201).json({ assignment: data });
});

adminRouter.delete('/:id', async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Assignment not found' }); return; }
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const { data, error } = await supabase.from('staff_org_assignments').delete().eq('id', req.params.id).select('*').maybeSingle();
    if (error) { res.status(missing(error.message) ? 503 : 502).json({ error: missing(error.message) ? NOT_SET_UP : 'Could not remove the assignment' }); return; }
    if (!data) { res.status(404).json({ error: 'Assignment not found' }); return; }
    logAudit({ user: req.user?.email ?? 'unknown', action: 'ORG_ASSIGNMENT_REMOVED', resource: 'staff_org_assignment', resource_id: data.id, org_id: data.org_slug, ip: req.ip ?? 'unknown', result: 'success', severity: 'warning', details: `${data.user_email} may no longer act on ${data.org_slug}` });
    res.json({ removed: true });
});

mineRouter.get('/mine', async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    const own = req.user?.org_id ?? null;
    if (!supabase || !own) { res.json({ own, mode: 'own', organisations: [] }); return; }
    const role = req.user?.role;
    if (role === 'super_admin' || role === 'soc_manager') {
        const { data } = await supabase.from('organisations').select('slug, name').order('name').limit(2000);
        res.json({ own, mode: 'all', organisations: (data ?? []).filter((o) => o.slug) });
        return;
    }
    if (role === 'analyst') {
        const { data, error } = await supabase.from('staff_org_assignments').select('org_slug').eq('user_id', req.user?.sub ?? '').limit(2000);
        const slugs = [...new Set([own, ...(error ? [] : (data ?? []).map((r) => r.org_slug))])];
        const { data: orgs } = await supabase.from('organisations').select('slug, name').in('slug', slugs);
        res.json({ own, mode: 'assigned', organisations: orgs ?? [], ...(error ? { note: NOT_SET_UP } : {}) });
        return;
    }
    res.json({ own, mode: 'own', organisations: [] });
});
