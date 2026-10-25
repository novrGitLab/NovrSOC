import { Router } from 'express';
import { logAudit } from '../lib/audit';
import { getSupabase } from '../services/geoEnrichment';
import { checkAccountPassword, equaliseTiming, issueToken, TOKEN_TTL_SECONDS } from './auth';

const router = Router();

// F-03 (2026 redesign): removed six routes that proxied to a legacy external backend
// (APP_API_BASE_URL) which this architecture no longer has and which no frontend page has
// called since the client portal's real backend moved onto this server (phase P21):
//   GET  /dashboard, /incidents, /assets, /advisories — forwarded to `${BACKEND_URL}/api/portal/...`
//     with the caller's Authorization header passed through untouched and never verified here;
//     with APP_API_BASE_URL unset (as on Render today) every call 502'd anyway.
//   POST /scan, GET /scan/history — /scan ran a real local IOC scan (lib/scan.ts) with NO
//     authentication and no scan-specific rate limit (unlike the equivalent anonymous endpoint,
//     /api/public/scan, which both requires none and is capped); /scan/history read
//     `${BACKEND_URL}/api/scan-history` filtered by an organisation id decoded from the request's
//     JWT payload WITHOUT verifying its signature. Confirmed unused by any current page before
//     removal (see NOVRSOC_REDESIGN_TECHNICAL_AUDIT_V2.md, F-03). The real, authenticated
//     equivalents are /api/client/vms/*, /api/cti/lookup and /api/org-cti/iocs.

// GET /api/portal/status — lets the client login page tell "portal isn't set up yet" apart from
// "your password was wrong" before anyone types anything. Sign-in runs on this backend since P21,
// so it works whenever tokens can be signed.
router.get('/status', (_req, res) => {
    const configured = !!(process.env.JWT_SECRET || process.env.DEV_TOKEN_SECRET);
    res.json({ configured, detail: configured ? 'Client portal sign-in is available' : 'No signing secret is configured — client portal sign-in is unavailable.' });
});

// POST /api/portal/auth/signin { email, password } — client portal sign-in (phase P21).
// Client accounts are platform_users with role portal_user, invited like staff (an account in the
// organisation plus a one-time set-password link from a super_admin). Credentials are checked by
// the same code as staff sign-in (routes/auth.ts checkAccountPassword: bcrypt, lockout, disabled
// accounts). Only portal_user accounts get a portal session; any other account gets the same
// answer as a wrong password. The token is this backend's own, carrying the account's
// organisation; requireAuth confines it to /api/client/ (middleware/auth.ts).
router.post('/auth/signin', async (req, res) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const ip = req.ip || 'unknown';
    const fail = (status: number, error: string, reason: string) => {
        logAudit({ user: email || 'unknown', action: 'LOGIN', resource: 'Client Portal', ip, result: 'failed', severity: 'warning', details: reason });
        res.status(status).json({ error });
    };
    if (!email || !password || email.length > 320 || password.length > 1024) { fail(401, 'Invalid email or password', 'missing or oversized credentials'); return; }
    if (!process.env.JWT_SECRET && !process.env.DEV_TOKEN_SECRET) { fail(503, 'Client portal sign-in is not configured', 'no signing secret'); return; }
    const check = await checkAccountPassword(email, password);
    if (check.kind === 'no_password') { if (!check.account) await equaliseTiming(password); fail(401, 'Invalid email or password', check.account ? 'account has no password set' : 'unknown account'); return; }
    if (check.kind === 'fail') { fail(check.status, check.error, check.reason); return; }
    const { account, org } = check;
    if (account.role !== 'portal_user') { fail(401, 'Invalid email or password', `${account.role} account at client portal sign-in`); return; }
    const supabase = getSupabase();
    const { data: orgRow } = supabase ? await supabase.from('organisations').select('*').eq('slug', org.slug).maybeSingle() : { data: null };
    const now = Math.floor(Date.now() / 1000);
    const token = issueToken({ sub: account.id, email: account.email, name: account.name || account.email, company: org.name || org.slug, role: 'portal_user', org_id: org.slug, iat: now, exp: now + TOKEN_TTL_SECONDS });
    logAudit({ user: account.email, action: 'LOGIN', resource: 'Client Portal', ip, result: 'success', org_id: org.slug, resource_id: account.id });
    res.json({
        token,
        user: {
            userId: account.id, name: account.name || account.email, email: account.email, orgId: org.slug, orgName: org.name || org.slug,
            orgIndustry: (orgRow?.industry as string | undefined) ?? null, orgPlan: (orgRow?.plan as string | undefined) ?? null, portalRole: 'Client', wazuhGroup: null,
        },
    });
});

export default router;
