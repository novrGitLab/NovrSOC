import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { requireAuth, requireRole } from '../middleware/auth';
import { testBrevoDelivery, testResendDelivery, resendDomainStatus, senderAddress, isBrevoConfigured, cisoEmail, warnNoRecipient } from '../services/email';

// Operator diagnostics. Manager-only: these send real messages.
const router = Router();

// POST /api/test/email — one real email to CISO_EMAIL through the primary provider alone (Brevo
// when BREVO_API_KEY is set, otherwise Resend), with no fallback, reporting that provider's exact
// error on rejection. For Resend it also reports the sender domain's verification status.
router.post('/email', requireAuth, requireRole('super_admin', 'soc_manager'), async (_req: AuthRequest, res) => {
    const to = cisoEmail();
    if (!to) {
        warnNoRecipient('Test email');
        res.json({ success: false, outcome: 'skipped', error: 'Not sent — CISO_EMAIL is not set' });
        return;
    }
    if (isBrevoConfigured()) {
        try {
            const { id, from } = await testBrevoDelivery(to);
            res.json({ success: true, id, provider: 'brevo', to, from });
        } catch (err) {
            res.status(502).json({ success: false, provider: 'brevo', to, error: err instanceof Error ? err.message : 'Email test failed' });
        }
        return;
    }
    const sender = senderAddress();
    const domain = await resendDomainStatus(sender.domain);
    const base = { to, from: `${sender.name} <${sender.email}>`, domain: sender.domain, domain_status: domain.status, domain_detail: domain.detail };
    try {
        const { id } = await testResendDelivery(to);
        res.json({ success: true, id, provider: 'resend', ...base });
    } catch (err) {
        res.status(502).json({ success: false, provider: 'resend', error: err instanceof Error ? err.message : 'Email test failed', ...base });
    }
});

export default router;
