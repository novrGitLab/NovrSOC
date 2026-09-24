import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { requireAuth, requireRole } from '../middleware/auth';
import { testResendDelivery } from '../services/email';

// Operator diagnostics. Manager-only: these send real messages.
const router = Router();

// POST /api/test/email — one real email to CISO_EMAIL through Resend, with Resend's own verdict.
router.post('/email', requireAuth, requireRole('super_admin', 'soc_manager'), async (_req: AuthRequest, res) => {
    const to = process.env.CISO_EMAIL || 'soc@cybernovr.com';
    try {
        const { id, from } = await testResendDelivery(to);
        res.json({ success: true, id, to, from, provider: 'resend' });
    } catch (err) {
        res.status(502).json({ success: false, to, error: err instanceof Error ? err.message : 'Email test failed' });
    }
});

export default router;
