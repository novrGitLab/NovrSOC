import { Router } from 'express';
import { runScan } from '../lib/scan';

const router = Router();
import { APP_BACKEND_URL as BACKEND_URL, isAppBackendConfigured, warnUnconfiguredOnce } from '../lib/legacyBackend';

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
// "your password was wrong" before anyone types anything. Every route below proxies to
// APP_API_BASE_URL, so with that unset the portal cannot work at all, and saying so up front
// beats a login form that always rejects.
router.get('/status', (_req, res) => {
    res.json({
        configured: isAppBackendConfigured(),
        detail: isAppBackendConfigured()
            ? 'Portal backend configured'
            : 'APP_API_BASE_URL is not set — client portal accounts cannot be authenticated yet.',
    });
});

// POST /api/portal/auth/signin
router.post('/auth/signin', async (req, res) => {
    // Short-circuit when there's no portal backend at all: 503 immediately with an honest
    // reason, rather than burning the 5s timeout below and reporting it as bad credentials.
    if (!isAppBackendConfigured()) {
        warnUnconfiguredOnce('APP_API_BASE_URL', 'client portal sign-in');
        res.status(503).json({
            error: 'Client portal access is still being configured. Contact your NovrSOC administrator.',
            code: 'PORTAL_NOT_CONFIGURED',
        });
        return;
    }

    try {
        const response = await fetch(`${BACKEND_URL}/api/portal/auth/signin`, {
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
