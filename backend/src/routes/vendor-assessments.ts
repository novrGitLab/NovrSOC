import { Router } from 'express';

const router = Router();
import { APP_BACKEND_URL as BACKEND_URL, isAppBackendConfigured, warnUnconfiguredOnce } from '../lib/legacyBackend';

// GET /api/vendor-assessments
router.get('/', async (req, res) => {
    try {
        const search = req.originalUrl.includes('?') ? `?${req.originalUrl.split('?')[1]}` : '';
        const response = await fetch(`${BACKEND_URL}/api/vendor-assessments${search}`, { cache: 'no-store', signal: AbortSignal.timeout(5000) });
        const data = await response.json();
        res.status(response.status).json(data);
    } catch {
        res.status(502).json({ assessments: [] });
    }
});

// POST /api/vendor-assessments
router.post('/', async (req, res) => {
    try {
        const response = await fetch(`${BACKEND_URL}/api/vendor-assessments`, {
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

// GET /api/vendor-assessments/:id
router.get('/:id', async (req, res) => {
    try {
        const response = await fetch(`${BACKEND_URL}/api/vendor-assessments/${req.params.id}`, { cache: 'no-store', signal: AbortSignal.timeout(5000) });
        const data = await response.json();
        res.status(response.status).json(data);
    } catch {
        res.status(502).json({ error: 'Failed to reach backend' });
    }
});

// PUT /api/vendor-assessments/:id
router.put('/:id', async (req, res) => {
    try {
        const response = await fetch(`${BACKEND_URL}/api/vendor-assessments/${req.params.id}`, {
            method: 'PUT',
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

// DELETE /api/vendor-assessments/:id
router.delete('/:id', async (req, res) => {
    try {
        const response = await fetch(`${BACKEND_URL}/api/vendor-assessments/${req.params.id}`, { method: 'DELETE', signal: AbortSignal.timeout(5000) });
        const data = await response.json();
        res.status(response.status).json(data);
    } catch {
        res.status(502).json({ error: 'Failed to reach backend' });
    }
});

export default router;
