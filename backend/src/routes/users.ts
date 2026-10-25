// /api/admin/users — staff account credentials (phase P2). super_admin only (index.ts).
// A client organisation's own users (including its first executive and additional portal_user
// accounts) are created where they always were (POST /api/organisations/:id/users). This router
// is for staff accounts — soc_manager, analyst, executive-on-the-admin-side and super_admin
// itself — which belong to the home organisation, not a client tenant.
//
//   POST  /                   { email, name?, role } -> the new account, status 'invited'
//   POST  /:id/password-link  { purpose?: 'invite' | 'reset' }  -> { url, expires_at } (shown once)
//   PATCH /:id                { status: 'active' | 'disabled' }
//
// A link's token is 32 random bytes; only its SHA-256 is stored (auth_links). The URL carries the
// token in the fragment (#token=…), so it never reaches a server log or a Referer header.
// The account sets its own password at /set-password (POST /api/auth/set-password).

import { Router } from 'express';
import { randomBytes, createHash } from 'crypto';
import { z } from 'zod';
import type { AuthRequest } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';
import { dbErrorMessage, isUuid, DEFAULT_ORG_ID } from '../services/cases';
import { logAudit } from '../lib/audit';
import { sendAccountLinkEmail, sendAccountStatusEmail, isEmailEnabled } from '../services/email';

const router = Router();

// POST /api/admin/users — provision a staff account, including another super_admin. Gated by
// this whole router's super_admin-only mount (index.ts) — provisioning a peer super_admin
// therefore already requires an existing super_admin to do it ("explicit authorisation"), with
// no separate escalation path. Always created under the home organisation: staff accounts are
// not tenant-scoped the way a client's portal_user is, so the caller never names an org here.
const STAFF_ROLES = ['super_admin', 'soc_manager', 'analyst', 'executive'] as const;
const NewStaff = z.object({
    email: z.string().trim().toLowerCase().email().max(320),
    name: z.string().trim().max(200).optional(),
    role: z.enum(STAFF_ROLES),
}).strict();
router.post('/', async (req: AuthRequest, res) => {
    const p = NewStaff.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: `Body must be { email, name?, role } with role one of: ${STAFF_ROLES.join(', ')}` }); return; }
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const { data: home, error: homeErr } = await supabase.from('organisations').select('id').eq('slug', DEFAULT_ORG_ID).maybeSingle();
    if (homeErr) { res.status(502).json({ error: dbErrorMessage(homeErr) }); return; }
    if (!home) { res.status(503).json({ error: 'The home organisation is not set up' }); return; }
    const { data: clash, error: clashErr } = await supabase.from('platform_users').select('id').ilike('email', p.data.email).maybeSingle();
    if (clashErr) { res.status(502).json({ error: dbErrorMessage(clashErr) }); return; }
    if (clash) { res.status(409).json({ error: 'An account with this email already exists' }); return; }
    const { data, error } = await supabase.from('platform_users')
        .insert({ org_id: home.id, email: p.data.email, name: p.data.name || null, role: p.data.role, status: 'invited' })
        .select('id, org_id, email, name, role, status, created_at').single();
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    logAudit({
        user: req.user?.email ?? 'unknown', action: 'STAFF_ACCOUNT_CREATED', resource: 'platform_user', resource_id: data.id,
        ip: req.ip ?? 'unknown', result: 'success', severity: p.data.role === 'super_admin' ? 'warning' : 'info', details: `${p.data.role} ${data.email}`,
    });
    res.status(201).json({ user: data });
});
export const LINK_TTL_HOURS = 72;
export const hashLinkToken = (t: string) => createHash('sha256').update(t).digest('hex');

function frontendBase(req: AuthRequest): string | null {
    const configured = process.env.FRONTEND_URL?.replace(/\/$/, '');
    if (configured) return configured;
    const origin = req.headers.origin;
    return typeof origin === 'string' && /^https:\/\/[a-z0-9.-]+$/i.test(origin) ? origin : null;
}

router.post('/:id/password-link', async (req: AuthRequest, res) => {
    const { id } = req.params;
    if (!isUuid(id)) { res.status(404).json({ error: 'User not found' }); return; }
    const purpose = req.body?.purpose === 'reset' ? 'reset' : 'invite';
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const { data: user, error } = await supabase.from('platform_users').select('id, email, name, status').eq('id', id).maybeSingle();
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    if (!user) { res.status(404).json({ error: 'User not found' }); return; }
    if (user.status === 'disabled') { res.status(409).json({ error: 'Enable the account before issuing a link' }); return; }
    const base = frontendBase(req);
    if (!base) { res.status(503).json({ error: 'FRONTEND_URL is not set, so no link can be built' }); return; }

    const token = randomBytes(32).toString('base64url');
    const expires = new Date(Date.now() + LINK_TTL_HOURS * 3_600_000).toISOString();
    // Older unused links for this user stop working: only the newest one is valid.
    await supabase.from('auth_links').update({ used_at: new Date().toISOString() }).eq('user_id', id).is('used_at', null);
    const ins = await supabase.from('auth_links').insert({ user_id: id, token_hash: hashLinkToken(token), purpose, created_by: req.user?.email ?? 'unknown', expires_at: expires });
    if (ins.error) { res.status(502).json({ error: dbErrorMessage(ins.error) }); return; }
    logAudit({ user: req.user?.email ?? 'unknown', action: purpose === 'reset' ? 'PASSWORD_RESET_LINK' : 'INVITE_USER', resource: 'platform_user', resource_id: id, ip: req.ip ?? 'unknown', result: 'success', severity: 'warning', details: `link for ${user.email}, expires ${expires}` });
    const url = `${base}/set-password#token=${token}`;
    // Best-effort: the link above is valid and already in the response either way — an admin
    // can always copy it manually (the pre-existing behaviour). A send failure (or email not
    // being configured at all, isEmailEnabled()'s own check inside sendAccountLinkEmail) never
    // blocks or fails this request; it's reported back so the UI knows whether to tell the
    // admin to deliver it themselves.
    let email_sent = false;
    let email_error: string | undefined;
    try {
        await sendAccountLinkEmail({ to: user.email, name: user.name || user.email, url, expires_at: expires, purpose });
        email_sent = isEmailEnabled();
    } catch (err) {
        email_error = err instanceof Error ? err.message : 'Could not send the email';
        console.error('[users] account link email failed:', email_error);
        logAudit({ user: req.user?.email ?? 'unknown', action: 'ACCOUNT_LINK_EMAIL_FAILED', resource: 'platform_user', resource_id: id, ip: req.ip ?? 'unknown', result: 'failed', severity: 'warning', details: email_error.slice(0, 200) });
    }
    res.status(201).json({ url, expires_at: expires, purpose, email_sent, ...(email_error ? { email_error } : {}) });
});

const Patch = z.object({ status: z.enum(['active', 'disabled']) }).strict();

router.patch('/:id', async (req: AuthRequest, res) => {
    const { id } = req.params;
    if (!isUuid(id)) { res.status(404).json({ error: 'User not found' }); return; }
    const parsed = Patch.safeParse(req.body);
    if (!parsed.success) { res.status(400).json({ error: "Body must be { status: 'active' | 'disabled' }" }); return; }
    if (req.user?.sub === id && parsed.data.status === 'disabled') { res.status(409).json({ error: 'You cannot disable your own account' }); return; }
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const { data, error } = await supabase.from('platform_users').update({ status: parsed.data.status, ...(parsed.data.status === 'active' ? { failed_logins: 0, locked_until: null } : {}) })
        .eq('id', id).select('id, email, name, status').maybeSingle();
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    if (!data) { res.status(404).json({ error: 'User not found' }); return; }
    if (parsed.data.status === 'disabled') await supabase.from('auth_links').update({ used_at: new Date().toISOString() }).eq('user_id', id).is('used_at', null);
    logAudit({ user: req.user?.email ?? 'unknown', action: parsed.data.status === 'disabled' ? 'USER_DISABLED' : 'USER_ENABLED', resource: 'platform_user', resource_id: id, ip: req.ip ?? 'unknown', result: 'success', severity: 'warning', details: data.email });
    // Security notification, best-effort — told to the account holder, never blocks the response.
    sendAccountStatusEmail({ to: data.email, name: data.name || data.email, status: parsed.data.status }).catch((err: unknown) => console.error('[users] account status email failed:', err instanceof Error ? err.message : err));
    res.json({ user: data });
});

export default router;
