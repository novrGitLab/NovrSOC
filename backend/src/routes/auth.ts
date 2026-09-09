import { Router } from 'express';
import crypto from 'crypto';
import { logAudit } from '../lib/audit';
import { getSupabase } from '../services/geoEnrichment';

const router = Router();
import { APP_BACKEND_URL as BACKEND_URL, isAppBackendConfigured, warnUnconfiguredOnce } from '../lib/legacyBackend';

// Hand-rolled JWT-shaped token (header.payload.signature, HMAC-SHA256) — dev-only convenience,
// avoids pulling in a jsonwebtoken dependency just to sign these. IS verified now: requireAuth
// (middleware/auth.ts) checks this signature on every request to a protected route — see the
// secret-selection note below for why that verification used to always fail.
function issueDevToken(payload: Record<string, unknown>): string {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    // Must match requireAuth's exact secret-selection order (middleware/auth.ts) — a hotfix
    // for a live production bug found during the requireAuth rollout: this used to sign with
    // DEV_TOKEN_SECRET alone, but requireAuth verifies with JWT_SECRET first, falling back to
    // DEV_TOKEN_SECRET. When both are set (as they are here) to different values — the normal
    // case, they're separate secrets on purpose — every dev-issued token was signed with one
    // secret and verified against the other, so it always failed verification. Confirmed live:
    // a freshly-issued dev-admin token 401'd as "invalid or expired" against every route this
    // rollout just protected. Signing with the same priority order requireAuth verifies with
    // fixes it regardless of which of the two vars is actually set.
    const signature = crypto
        .createHmac('sha256', process.env.JWT_SECRET || process.env.DEV_TOKEN_SECRET || 'novrsoc-dev-secret')
        .update(`${header}.${body}`)
        .digest('base64url');
    return `${header}.${body}.${signature}`;
}

// POST /api/auth/signin (admin/staff login proxy)
router.post('/signin', async (req, res) => {
    // Admin bypass — always reachable now, not gated on the env vars being set. It's how this
    // platform logs in at all right now, since no downstream account-backed auth exists yet at
    // APP_API_BASE_URL, and a Railway deploy with DEV_ADMIN_EMAIL/DEV_ADMIN_PASSWORD unset or
    // wrong (whitespace, a stale value, never redeployed after being changed) used to lock
    // everyone out with no way to tell why — this hardcoded fallback is the actual login for
    // rayne@cybernovr.com whether or not Railway's env vars agree with it.
    //
    // Security note: because of that fallback, unsetting DEV_ADMIN_EMAIL/DEV_ADMIN_PASSWORD on
    // Railway no longer disables this bypass — the values below are permanently valid
    // credentials for a super_admin token as long as this code ships. Treat them, and
    // DEV_TOKEN_SECRET below, as real production secrets. If this bypass should ever need to
    // be fully disabled, that requires removing this fallback (and rotating the password), not
    // just unsetting the env var.
    const devEmail = process.env.DEV_ADMIN_EMAIL || 'rayne@cybernovr.com';
    const devPassword = process.env.DEV_ADMIN_PASSWORD || 'N0vrS0C.2026';

    const { email, password } = req.body ?? {};
    if (email === devEmail && password === devPassword) {
        let name = process.env.DEV_ADMIN_NAME || 'Dev Admin';
        let company = process.env.DEV_ADMIN_COMPANY || 'Cybernovr';
        let role = process.env.DEV_ADMIN_ROLE || 'super_admin';
        // Single-tenant placeholder unless overridden below — see routes/orgCTI.ts's header
        // comment for the client-portal-token caveat this still doesn't solve.
        let orgId = 'cybernovr';

        // Look up this email's real role/org in platform_users when it's configured — lets the
        // seeded super_admin (and, once other platform_users rows exist, any future non-bypass
        // login built on top of this) carry its actual role and org instead of the hardcoded
        // defaults above. org_id is deliberately the org's SLUG (organisations.slug), not its
        // UUID primary key — every org-scoped table already live in this codebase (playbooks,
        // org-cti's fallback) keys on the string 'cybernovr', not a UUID, so resolving to the
        // slug here is what keeps this login compatible with that existing data instead of
        // silently orphaning it. Falls back to the hardcoded defaults on any miss or error —
        // this must never be the reason login itself fails.
        try {
            const supabase = getSupabase();
            if (supabase) {
                const { data: platformUser } = await supabase
                    .from('platform_users')
                    .select('name, role, organisations(slug, name)')
                    .eq('email', email)
                    .maybeSingle();
                const org = platformUser?.organisations as unknown as { slug?: string; name?: string } | null;
                if (platformUser) {
                    name = platformUser.name || name;
                    role = platformUser.role || role;
                }
                if (org?.slug) orgId = org.slug;
                if (org?.name) company = org.name;
            }
        } catch (err) {
            console.warn('[auth] platform_users lookup failed, using default dev-admin claims:', err);
        }

        const nowSeconds = Math.floor(Date.now() / 1000);
        const token = issueDevToken({
            sub: 'dev-admin',
            email: devEmail,
            name,
            company,
            role,
            org_id: orgId,
            dev: true,
            iat: nowSeconds,
            exp: nowSeconds + 60 * 60 * 24, // 24h
        });
        logAudit({
            user: devEmail,
            action: 'LOGIN',
            resource: 'Admin Portal',
            ip: req.ip || (req.headers['x-forwarded-for'] as string) || 'unknown',
            result: 'success',
        });
        res.json({ token, user: { email: devEmail, name, company, role } });
        return;
    }
    // Wrong credentials against the dev bypass — worth a failed-login audit entry too, same as
    // a genuinely wrong password would be once real account auth exists.
    logAudit({
        user: (req.body?.email as string) || 'unknown',
        action: 'LOGIN',
        resource: 'Admin Portal',
        ip: req.ip || (req.headers['x-forwarded-for'] as string) || 'unknown',
        result: 'failed',
    });

    try {
        const response = await fetch(`${BACKEND_URL}/api/auth/signin`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req.body),
            signal: AbortSignal.timeout(5000),
        });
        const data = await response.json();
        res.status(response.status).json(data);
    } catch {
        res.status(502).json({ error: 'Failed to reach backend' });
    }
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

export default router;
