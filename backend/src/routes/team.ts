import { Router } from 'express';
import { requireRole } from '../middleware/auth';
import { teamPresence } from '../services/presence';

// GET /api/admin/team/presence — every platform user with live status, last active, 7-day
// activity, open cases assigned and response time this week. Mounted behind requireAuth.
const router = Router();

router.get('/presence', requireRole('super_admin', 'soc_manager', 'executive'), async (_req, res) => {
    try {
        res.json({ ...(await teamPresence()), generated_at: new Date().toISOString() });
    } catch (err) {
        res.status(502).json({ error: err instanceof Error ? err.message : 'Could not load team presence' });
    }
});

export default router;
