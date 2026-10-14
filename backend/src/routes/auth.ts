import { Router } from 'express';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { logAudit } from '../lib/audit';
import { getSupabase } from '../services/geoEnrichment';

const router = Router();
import { APP_BACKEND_URL as BACKEND_URL, isAppBackendConfigured, warnUnconfiguredOnce } from '../lib/legacyBackend';
import { requireAuth, type AuthRequest } from '../middleware/auth';
import { recordPresence } from '../services/presence';

// Staff sign-in (phase P2).
//
//   1. Account sign-in: a platform_users row with a password (bcrypt, set through a one-time link
//      a super_admin issues — routes/users.ts). The token carries that user's own id, role and
//      organisation. 5 wrong passwords lock the account for 15 minutes. A disabled account or one
//      without a password cannot sign in.
//   2. Break-glass: the DEV_ADMIN_EMAIL / DEV_ADMIN_PASSWORD pair from the environment, for when
//      no account works. Fails closed when either is blank; switched off entirely with
//      DEV_ADMIN_LOGIN_ENABLED=false. Every use is audited at warning level.
// Tokens are HS256, signed with JWT_SECRET (or DEV_TOKEN_SECRET) — the same order requireAuth
// verifies with. With neither set, sign-in is refused; there is no built-in fallback secret.
// The old proxy to APP_API_BASE_URL is gone from sign-in: that service no longer exists.

export const TOKEN_TTL_SECONDS = 12 * 60 * 60;
export const MAX_FAILED_LOGINS = 5;
export const LOCK_MINUTES = 15;
const ACTIVE_STATUSES = new Set(['active', 'invited']);
// Compared against when the email is unknown, so a miss costs about the same as a wrong password.
const DUMMY_HASH = bcrypt.hashSync('novrsoc-timing-equaliser', 12);

function signingSecret(): string | null {
    return process.env.JWT_SECRET || process.env.DEV_TOKEN_SECRET || null;
}

export function issueToken(payload: Record<string, unknown>): string {
    const secret = signingSecret();
    if (!secret) throw new Error('No signing secret (JWT_SECRET / DEV_TOKEN_SECRET)');
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
    return `${header}.${body}.${signature}`;
}

const clientIp = (req: { ip?: string }) => req.ip || 'unknown';

interface AccountRow {
    id: string; email: string; name: string | null; role: string; status: string | null;
    password_hash: string | null; failed_logins: number | null; locked_until: string | null;
    organisations: { slug?: string; name?: string } | null;
}

// POST /api/auth/signin { email, password }
router.post('/signin', async (req, res) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const fail = (status: number, error: string, reason: string) => {
        logAudit({ user: email || 'unknown', action: 'LOGIN', resource: 'Admin Portal', ip: clientIp(req), result: 'failed', severity: 'warning', details: reason });
        res.status(status).json({ error });
    };
    if (!email || !password || email.length > 320 || password.length > 1024) { fail(401, 'Invalid email or password', 'missing or oversized credentials'); return; }
    if (!signingSecret()) { console.error('[auth] JWT_SECRET / DEV_TOKEN_SECRET not set — sign-in disabled'); fail(503, 'Sign-in is not configured', 'no signing secret'); return; }

    // 1. Account sign-in.
    const supabase = getSupabase();
    let account: AccountRow | null = null;
    if (supabase) {
        const { data, error } = await supabase.from('platform_users')
            .select('id, email, name, role, status, password_hash, failed_logins, locked_until, organisations(slug, name)')
            .ilike('email', email).maybeSingle();
        // Before the P2 SQL runs the credential columns don't exist; only break-glass works then.
        if (!error) account = data as unknown as AccountRow | null;
        else if (!/password_hash|failed_logins|locked_until/.test(error.message)) console.error('[auth] account lookup failed:', error.message.slice(0, 160));
    }

    if (account?.password_hash) {
        if (account.locked_until && Date.parse(account.locked_until) > Date.now()) { fail(429, 'Account temporarily locked after repeated failed sign-ins. Try again later.', 'account locked'); return; }
        const ok = await bcrypt.compare(password, account.password_hash);
        if (!ok) {
            const failures = (account.failed_logins ?? 0) + 1;
            const lock = failures >= MAX_FAILED_LOGINS;
            await supabase!.from('platform_users').update({
                failed_logins: lock ? 0 : failures,
                locked_until: lock ? new Date(Date.now() + LOCK_MINUTES * 60_000).toISOString() : account.locked_until,
            }).eq('id', account.id);
            fail(401, 'Invalid email or password', lock ? `wrong password; account locked for ${LOCK_MINUTES} min` : 'wrong password');
            return;
        }
        if (!ACTIVE_STATUSES.has(account.status ?? '')) { fail(403, 'This account is disabled', `account status ${account.status}`); return; }
        const org = account.organisations;
        if (!org?.slug) { fail(403, 'This account has no organisation', 'no organisation'); return; }
        await supabase!.from('platform_users').update({ failed_logins: 0, locked_until: null }).eq('id', account.id);
        const now = Math.floor(Date.now() / 1000);
        const user = { email: account.email, name: account.name || account.email, company: org.name || org.slug, role: account.role };
        const token = issueToken({ sub: account.id, ...user, org_id: org.slug, iat: now, exp: now + TOKEN_TTL_SECONDS });
        logAudit({ user: account.email, action: 'LOGIN', resource: 'Admin Portal', ip: clientIp(req), result: 'success', org_id: org.slug, resource_id: account.id });
        void recordPresence(account.email, 'login').catch(() => {});
        res.json({ token, user });
        return;
    }

    // 2. Break-glass environment account.
    const devEmail = (process.env.DEV_ADMIN_EMAIL ?? '').trim().toLowerCase();
    const devPassword = process.env.DEV_ADMIN_PASSWORD ?? '';
    const breakGlass = process.env.DEV_ADMIN_LOGIN_ENABLED !== 'false' && devEmail.length > 0 && devPassword.length > 0;
    const sha = (v: string) => crypto.createHash('sha256').update(v).digest();
    const devMatch = breakGlass && email === devEmail && crypto.timingSafeEqual(sha(password), sha(devPassword));
    if (!devMatch) {
        if (!account) await bcrypt.compare(password, DUMMY_HASH);
        fail(401, 'Invalid email or password', account ? 'account has no password set' : 'unknown account');
        return;
    }
    const org = account?.organisations ?? null;
    const role = account?.role || process.env.DEV_ADMIN_ROLE || 'super_admin';
    const orgId = org?.slug || 'cybernovr';
    const now = Math.floor(Date.now() / 1000);
    const user = { email: devEmail, name: account?.name || process.env.DEV_ADMIN_NAME || 'Dev Admin', company: org?.name || process.env.DEV_ADMIN_COMPANY || 'Cybernovr', role };
    const token = issueToken({ sub: account?.id ?? 'dev-admin', ...user, org_id: orgId, dev: true, iat: now, exp: now + TOKEN_TTL_SECONDS });
    logAudit({ user: devEmail, action: 'LOGIN', resource: 'Admin Portal', ip: clientIp(req), result: 'success', severity: 'warning', org_id: orgId, details: 'break-glass environment account' });
    void recordPresence(devEmail, 'login').catch(() => {});
    res.json({ token, user });
});


// POST /api/auth/set-password { token, password } — completes a one-time link from
// POST /api/admin/users/:id/password-link. Public (the link is the credential), rate limited with
// the rest of /api/auth. The link is consumed atomically, so it works exactly once.
export const MIN_PASSWORD_LENGTH = 12;
router.post('/set-password', async (req, res) => {
    const token = typeof req.body?.token === 'string' ? req.body.token : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) { res.status(400).json({ error: 'This link is not valid' }); return; }
    if (password.length < MIN_PASSWORD_LENGTH || password.length > 128) { res.status(400).json({ error: `Password must be ${MIN_PASSWORD_LENGTH}-128 characters` }); return; }
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Not configured' }); return; }
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    const now = new Date().toISOString();
    const invalid = () => res.status(400).json({ error: 'This link is not valid, has expired or was already used' });
    // Look the link up first and validate the password against its account; consume the link
    // only once the password is acceptable, so a rejected password doesn't burn the link.
    const { data: link, error } = await supabase.from('auth_links').select('id, user_id, purpose')
        .eq('token_hash', hash).is('used_at', null).gt('expires_at', now).maybeSingle();
    if (error || !link) { invalid(); return; }
    const { data: user } = await supabase.from('platform_users').select('id, email, status').eq('id', link.user_id).maybeSingle();
    if (!user || user.status === 'disabled') { invalid(); return; }
    if (password.toLowerCase().includes(String(user.email).split('@')[0].toLowerCase())) { res.status(400).json({ error: 'Password must not contain your email name' }); return; }
    const consumed = await supabase.from('auth_links').update({ used_at: now }).eq('id', link.id).is('used_at', null).select('id').maybeSingle();
    if (consumed.error || !consumed.data) { invalid(); return; } // used concurrently
    const upd = await supabase.from('platform_users').update({ password_hash: await bcrypt.hash(password, 12), password_set_at: now, status: 'active', failed_logins: 0, locked_until: null }).eq('id', user.id);
    if (upd.error) { res.status(502).json({ error: 'Could not save the password' }); return; }
    logAudit({ user: user.email, action: link.purpose === 'reset' ? 'PASSWORD_RESET' : 'PASSWORD_SET', resource: 'platform_user', resource_id: user.id, ip: req.ip || 'unknown', result: 'success', severity: 'warning' });
    res.json({ success: true, email: user.email });
});

// POST /api/auth/google — Google OAuth sign-in proxy. Stubbed ahead of the downstream
// API implementing this: frontend and backend are both wired, but this will 502 until
// APP_API_BASE_URL exposes a matching POST /api/auth/google endpoint of its own.
router.post('/google', async (req, res) => {
    try {
        const response = await fetch(`${BACKEND_URL}/api/auth/google`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req.body),
            signal: AbortSignal.timeout(5000),
        });
        const data = await response.json();
        res.status(response.status).json(data);
    } catch {
        res.status(502).json({ error: 'Google sign-in is not available yet' });
    }
});

// POST /api/auth/signup — self-serve sign-up proxy. Same stub situation as /google:
// no downstream registration endpoint exists yet, so this 502s until one does.
router.post('/signup', async (req, res) => {
    try {
        const response = await fetch(`${BACKEND_URL}/api/auth/signup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req.body),
            signal: AbortSignal.timeout(5000),
        });
        const data = await response.json();
        res.status(response.status).json(data);
    } catch {
        res.status(502).json({ error: 'Sign-up is not available yet. Please contact sales.' });
    }
});

// POST /api/auth/heartbeat { visible?, state? } — presence ping from the admin app every 2
// minutes (services/presence.ts). state: 'offline' is sent on sign-out. Exempt from the login
// rate limit (index.ts) so heartbeats can never lock a team out of signing in.
router.post('/heartbeat', requireAuth, async (req: AuthRequest, res) => {
    const email = req.user?.email;
    if (!email) { res.status(400).json({ ok: false, error: 'No user on token' }); return; }
    await recordPresence(email, req.body?.state === 'offline' ? 'logout' : 'heartbeat', req.body?.visible !== false).catch(() => {});
    res.json({ ok: true });
});

export default router;
