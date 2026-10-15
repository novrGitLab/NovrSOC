// /api/insights — weekly security-operations insights (phase P8). Behind requireAuth.
//   GET /weekly?days=7|30   alerts:read   the counted facts for the period and the one before,
//                                          with platform health and stated limitations. The AI
//                                          write-up (purpose weekly_insights) uses exactly these.

import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { requirePermission, requestOrg } from '../lib/permissions';
import { weeklyFacts } from '../services/weeklyInsights';

const router = Router();

router.get('/weekly', requirePermission('alerts:read'), async (req: AuthRequest, res) => {
    const days = req.query.days === '30' ? 30 : 7;
    try {
        res.json(await weeklyFacts(requestOrg(req), days));
    } catch (err) {
        res.status(502).json({ error: `Could not compute insights: ${err instanceof Error ? err.message : String(err)}`.slice(0, 300) });
    }
});

export default router;
