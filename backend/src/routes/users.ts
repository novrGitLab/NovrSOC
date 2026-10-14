// /api/admin/users — staff account credentials (phase P2). super_admin only (index.ts).
// Accounts themselves are created where they always were (POST /api/organisations/:id/users);
// this router only issues one-time password links and enables/disables accounts.
//
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
import { dbErrorMessage, isUuid } from '../services/cases';
import { logAudit } from '../lib/audit';

const router = Router();
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
    const { data: user, error } = await supabase.from('platform_users').select('id, email, status').eq('id', id).maybeSingle();
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
    res.status(201).json({ url: `${base}/set-password#token=${token}`, expires_at: expires, purpose });
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
        .eq('id', id).select('id, email, status').maybeSingle();
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    if (!data) { res.status(404).json({ error: 'User not found' }); return; }
    if (parsed.data.status === 'disabled') await supabase.from('auth_links').update({ used_at: new Date().toISOString() }).eq('user_id', id).is('used_at', null);
    logAudit({ user: req.user?.email ?? 'unknown', action: parsed.data.status === 'disabled' ? 'USER_DISABLED' : 'USER_ENABLED', resource: 'platform_user', resource_id: id, ip: req.ip ?? 'unknown', result: 'success', severity: 'warning', details: data.email });
    res.json({ user: data });
});

export default router;
