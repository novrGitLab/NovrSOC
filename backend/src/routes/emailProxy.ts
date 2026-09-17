import { Router } from 'express';
import { timingSafeEqual } from 'crypto';
import type { AuthRequest } from '../middleware/auth';
import {
    storeEmailVerdict, getEmailLogs, getEmailStats, getProxyDomains, addProxyDomain,
} from '../services/emailProxy';

// Email MX proxy API.
//
// POST /verdict is called by the mail host (Postfix + Amavis); the GET routes are called by the
// Email Monitoring page.

const router = Router();

// ── Authentication for the mail host ────────────────────────────────────────────────
//
// This is a SHARED SECRET, not an IP allowlist, and that is a deliberate departure from the
// original design. An IP allowlist does not work here:
//
//   1. index.ts sets `app.set('trust proxy', 1)` (needed for per-IP rate limiting behind
//      Railway's edge). req.ip is therefore derived from the X-Forwarded-For header. A caller
//      who sends their own X-Forwarded-For controls what Express reports as req.ip, so
//      "only accept from 169.58.242.x" is satisfied by anyone willing to set a header.
//   2. A substring test like clientIP.includes('169.58.242') is looser still — it matches any
//      address merely containing those characters.
//
// That matters more than usual for this endpoint: it is an unauthenticated write into a table
// holding sender, recipient and subject for real mail. A spoofable check would let anyone inject
// fabricated email records into a customer's security log, or bury real detections under noise.
//
// So: EMAIL_PROXY_TOKEN must be set, and the caller must present it. If it is not set the route
// refuses every request rather than falling open — an unconfigured secret must not mean "accept
// everything".
function isAuthorisedMailHost(req: AuthRequest): { ok: boolean; reason?: string } {
    const expected = (process.env.EMAIL_PROXY_TOKEN ?? '').trim();
    if (!expected) {
        return { ok: false, reason: 'EMAIL_PROXY_TOKEN is not configured on the server, so verdict reporting is disabled.' };
    }

    const header = req.get('x-novrsoc-proxy-token') ?? '';
    const a = Buffer.from(header);
    const b = Buffer.from(expected);
    // Length check first: timingSafeEqual throws on a length mismatch.
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
        return { ok: false, reason: 'Invalid or missing proxy token.' };
    }
    return { ok: true };
}

// POST /api/email-proxy/verdict — one scanned message, reported by the mail host.
router.post('/verdict', async (req: AuthRequest, res) => {
    const auth = isAuthorisedMailHost(req);
    if (!auth.ok) {
        // 401, not 403: the caller can fix this by presenting a credential.
        res.status(401).json({ error: 'Unauthorised', detail: auth.reason });
        return;
    }

    const result = await storeEmailVerdict(req.body ?? {});
    if (!result.ok) {
        // 400 for a malformed payload, 500 for a database problem — the mail host should retry
        // the latter and not the former.
        const isValidation = /required|verdict must be/.test(result.error ?? '');
        res.status(isValidation ? 400 : 500).json({ error: result.error });
        return;
    }
    res.json({ success: true });
});

// GET /api/email-proxy/logs
router.get('/logs', async (req: AuthRequest, res) => {
    const orgId = req.user?.org_id ?? 'cybernovr';
    const limit = Number(req.query.limit) || 50;
    const { logs, error } = await getEmailLogs(orgId, limit);
    // 200 with an explicit error: "the table does not exist yet" is a setup state the page has
    // to be able to explain, not a crash.
    res.json({ logs, total: logs.length, ...(error && { error }) });
});

// GET /api/email-proxy/stats
router.get('/stats', async (req: AuthRequest, res) => {
    const orgId = req.user?.org_id ?? 'cybernovr';
    res.json(await getEmailStats(orgId));
});

// GET /api/email-proxy/domains
router.get('/domains', async (req: AuthRequest, res) => {
    const orgId = req.user?.org_id ?? 'cybernovr';
    const { domains, error } = await getProxyDomains(orgId);
    res.json({ domains, total: domains.length, ...(error && { error }) });
});

// POST /api/email-proxy/domains
router.post('/domains', async (req: AuthRequest, res) => {
    const orgId = req.user?.org_id ?? 'cybernovr';
    const { domain, real_mx, forward_to } = req.body ?? {};

    const result = await addProxyDomain({ domain, real_mx, forward_to, org_id: orgId });
    if (!result.ok) {
        res.status(400).json({ error: result.error });
        return;
    }
    res.json({ success: true, domain: result.domain });
});

export default router;
