import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { requireAuth, requireRole } from '../middleware/auth';
import { testResendDelivery, resendDomainStatus, senderAddress } from '../services/email';

// Operator diagnostics. Manager-only: these send real messages.
const router = Router();

// POST /api/test/email — one real email to CISO_EMAIL through Resend alone, reporting the sender
// domain, Resend's verification status for it, and Resend's exact error on rejection.
router.post('/email', requireAuth, requireRole('super_admin', 'soc_manager'), async (_req: AuthRequest, res) => {
    const to = process.env.CISO_EMAIL || 'soc@cybernovr.com';
    const sender = senderAddress();
    const domain = await resendDomainStatus(sender.domain);
    const base = { to, from: `${sender.name} <${sender.email}>`, domain: sender.domain, domain_status: domain.status, domain_detail: domain.detail };
    try {
        const { id } = await testResendDelivery(to);
        res.json({ success: true, id, provider: 'resend', ...base });
    } catch (err) {
        res.status(502).json({ success: false, error: err instanceof Error ? err.message : 'Email test failed', ...base });
    }
});

export default router;
