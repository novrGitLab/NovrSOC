import { Router } from 'express';

const router = Router();
import { CTIP_URL, isCTIPConfigured, warnUnconfiguredOnce } from '../lib/legacyBackend';

// Generic catch-all reverse proxy to the CTIP backend, forwarding method/body/query.
// Mounted at /api/threat-intel — req.params[0] carries everything after that prefix.
router.all('/*', async (req, res) => {
    try {
        const path = (req.params as Record<string, string>)['0'] ?? '';
        const search = req.originalUrl.includes('?') ? `?${req.originalUrl.split('?')[1]}` : '';
        const target = `${CTIP_URL}/api/ctip/${path}${search}`;

        const response = await fetch(target, {
            method: req.method,
            headers: { 'Content-Type': 'application/json' },
            body: req.method === 'GET' || req.method === 'HEAD' ? undefined : JSON.stringify(req.body),
        });

        const data = await response.json().catch(() => null);
        res.status(response.status).json(data);
    } catch {
        res.status(502).json(null);
    }
});

export default router;
