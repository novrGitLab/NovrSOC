import { Router } from 'express';
import { runScan } from '../lib/scan';

const router = Router();
import { APP_BACKEND_URL as BACKEND_URL, isAppBackendConfigured, warnUnconfiguredOnce } from '../lib/legacyBackend';

// POST /api/scan (admin-side — org id trusted directly from body, not JWT)
router.post('/', async (req, res) => {
    try {
        const value: string = req.body?.value ?? '';
        if (!value.trim()) {
            res.status(400).json({ error: 'Value is required' });
            return;
        }

        const result = await runScan(value, req.body?.type ?? 'auto');
        const orgId: number | null = typeof req.body?.orgId === 'number' ? req.body.orgId : null;

        // Best-effort persistence — never block the scan result on this.
        fetch(`${BACKEND_URL}/api/scan-history`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                value: result.value, type: result.type, verdict: result.verdict, confidence: result.confidence,
                scanned_by: orgId ? 'Portal User' : 'Admin User', result_json: result, org_id: orgId,
            }),
            signal: AbortSignal.timeout(5000),
        }).catch(() => {});

        res.json(result);
    } catch {
        res.status(500).json({ error: 'Scan failed' });
    }
});

// GET /api/scan/history (admin-side, query string passthrough, no org filter)
router.get('/history', async (req, res) => {
    try {
        const search = req.originalUrl.includes('?') ? `?${req.originalUrl.split('?')[1]}` : '';
        const response = await fetch(`${BACKEND_URL}/api/scan-history${search}`, { cache: 'no-store', signal: AbortSignal.timeout(5000) });
        const data = await response.json();
        res.status(response.status).json(data);
    } catch {
        res.status(502).json({ scans: [] });
    }
});

export default router;
