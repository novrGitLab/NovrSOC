import { Router } from 'express';
import { runScan } from '../lib/scan';
import { logAudit } from '../lib/audit';
import { getSupabase } from '../services/geoEnrichment';
import { checkAccountPassword, equaliseTiming, issueToken, TOKEN_TTL_SECONDS } from './auth';

const router = Router();
import { APP_BACKEND_URL as BACKEND_URL } from '../lib/legacyBackend';

// Reads the orgId claim from the portal JWT without verifying the signature — this route
// only uses it to tag which org a scan belongs to; the backend independently verifies the
// token on every portal route that actually returns org-scoped data.
function unverifiedOrgId(authHeader: string | undefined): number | null {
    if (!authHeader?.startsWith('Bearer ')) return null;
    try {
        const payload = JSON.parse(Buffer.from(authHeader.slice(7).split('.')[1], 'base64').toString('utf8'));
        return typeof payload.orgId === 'number' ? payload.orgId : null;
    } catch {
        return null;
    }
}

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

// GET /api/portal/dashboard
router.get('/dashboard', async (req, res) => {
    try {
        const auth = req.headers.authorization ?? '';
        const response = await fetch(`${BACKEND_URL}/api/portal/dashboard`, { headers: { Authorization: auth }, cache: 'no-store', signal: AbortSignal.timeout(5000) });
        const data = await response.json();
        res.status(response.status).json(data);
    } catch {
        res.status(502).json({ error: 'Failed to reach backend' });
    }
});

// GET /api/portal/incidents
router.get('/incidents', async (req, res) => {
    try {
        const auth = req.headers.authorization ?? '';
        const search = req.originalUrl.includes('?') ? `?${req.originalUrl.split('?')[1]}` : '';
        const response = await fetch(`${BACKEND_URL}/api/portal/incidents${search}`, { headers: { Authorization: auth }, cache: 'no-store', signal: AbortSignal.timeout(5000) });
        const data = await response.json();
        res.status(response.status).json(data);
    } catch {
        res.status(502).json({ error: 'Failed to reach backend' });
    }
});

// GET /api/portal/assets
router.get('/assets', async (req, res) => {
    try {
        const auth = req.headers.authorization ?? '';
        const response = await fetch(`${BACKEND_URL}/api/portal/assets`, { headers: { Authorization: auth }, cache: 'no-store', signal: AbortSignal.timeout(5000) });
        const data = await response.json();
        res.status(response.status).json(data);
    } catch {
        res.status(502).json({ error: 'Failed to reach backend' });
    }
});

// GET /api/portal/advisories
router.get('/advisories', async (req, res) => {
    try {
        const auth = req.headers.authorization ?? '';
        const response = await fetch(`${BACKEND_URL}/api/portal/advisories`, { headers: { Authorization: auth }, cache: 'no-store', signal: AbortSignal.timeout(5000) });
        const data = await response.json();
        res.status(response.status).json(data);
    } catch {
        res.status(502).json({ error: 'Failed to reach backend' });
    }
});

// POST /api/portal/scan
router.post('/scan', async (req, res) => {
    try {
        const value: string = req.body?.value ?? '';
        if (!value.trim()) {
            res.status(400).json({ error: 'Value is required' });
            return;
        }

        const orgId = unverifiedOrgId(req.headers.authorization);
        const result = await runScan(value, req.body?.type ?? 'auto');

        fetch(`${BACKEND_URL}/api/scan-history`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                value: result.value, type: result.type, verdict: result.verdict, confidence: result.confidence,
                scanned_by: 'Portal User', result_json: result, org_id: orgId,
            }),
            signal: AbortSignal.timeout(5000),
        }).catch(() => {});

        res.json(result);
    } catch {
        res.status(500).json({ error: 'Scan failed' });
    }
});

// GET /api/portal/scan/history
router.get('/scan/history', async (req, res) => {
    try {
        const orgId = unverifiedOrgId(req.headers.authorization);
        const qs = orgId ? `?org_id=${orgId}` : '';
        const response = await fetch(`${BACKEND_URL}/api/scan-history${qs}`, { cache: 'no-store', signal: AbortSignal.timeout(5000) });
        const data = await response.json();
        res.status(response.status).json(data);
    } catch {
        res.status(502).json({ scans: [] });
    }
});

export default router;
