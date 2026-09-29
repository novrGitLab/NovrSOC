import { Router } from 'express';
import multer from 'multer';
import { createHmac, timingSafeEqual } from 'crypto';
import { getDb } from '../services/emailsec/db';
import { ingestReport } from '../services/emailsec/dmarcService';
import {
    sendTestEmail,
    sendCriticalAlertEmail,
    sendWeeklyReportEmail,
    isEmailEnabled,
} from '../services/email';

const router = Router();

// Mailgun's inbound route POSTs multipart/form-data (fields + the DMARC XML/zip as a file
// attachment). express.json() (mounted globally in index.ts) can't parse that, so this route
// needs its own multipart parser. memoryStorage + a modest size cap — DMARC aggregate reports
// are small XML/gzip files, not the multi-MB uploads other routes (e.g. brand.ts) handle.
const dmarcUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024, files: 5 } });

// GET /api/email/status
router.get('/status', (req, res) => {
    const hasResend = !!(process.env.RESEND_API_KEY && process.env.RESEND_API_KEY !== 'REPLACE_WHEN_OBTAINED');
    const hasSmtp = !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
    const hasSendGrid = !!(process.env.SENDGRID_API_KEY && process.env.SENDGRID_API_KEY !== 'REPLACE_WHEN_OBTAINED');
    res.json({
        enabled: isEmailEnabled(),
        // Resend first — see services/email.ts's sendEmail() for why it's tried before SMTP
        // (Railway blocks outbound SMTP port 587, Resend is a plain HTTPS API call).
        provider: hasResend ? 'Resend' : hasSmtp ? 'Zoho SMTP' : hasSendGrid ? 'SendGrid' : 'none',
        from: process.env.SMTP_FROM_EMAIL || process.env.SENDGRID_FROM_EMAIL || 'not configured',
        resend_configured: hasResend,
        smtp_configured: hasSmtp,
        sendgrid_configured: hasSendGrid,
    });
});

// POST /api/email/test
router.post('/test', async (req, res) => {
    const { to } = req.body ?? {};
    if (!to) {
        res.status(400).json({ error: 'to email required' });
        return;
    }
    try {
        await sendTestEmail(to);
        res.json({ success: true, message: `Test email sent to ${to}` });
    } catch (err: any) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/email/alert
router.post('/alert', async (req, res) => {
    try {
        await sendCriticalAlertEmail(req.body ?? {});
        res.json({ success: true });
    } catch (err: any) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/email/weekly-report
router.post('/weekly-report', async (req, res) => {
    try {
        await sendWeeklyReportEmail(req.body ?? {});
        res.json({ success: true });
    } catch (err: any) {
        res.status(500).json({ error: err.message });
    }
});

// Mailgun signs every webhook: HMAC-SHA256(signing key, timestamp + token) = signature.
// Without the key configured the inbox refuses everything — an unauthenticated endpoint that
// writes into DMARC data would let anyone forge "authorised" sending sources.
function mailgunSignatureValid(body: Record<string, unknown>): boolean {
    const key = process.env.MAILGUN_WEBHOOK_SIGNING_KEY;
    const { timestamp, token, signature } = body as { timestamp?: string; token?: string; signature?: string };
    if (!key || !timestamp || !token || !signature) return false;
    if (Math.abs(Date.now() / 1000 - Number(timestamp)) > 15 * 60) return false; // replay window
    const expected = createHmac('sha256', key).update(`${timestamp}${token}`).digest('hex');
    return expected.length === signature.length && timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}

// POST /api/email/dmarc-inbound — Mailgun inbound route for the DMARC report mailbox (rua=).
router.post('/dmarc-inbound', dmarcUpload.any(), async (req, res) => {
    if (!process.env.MAILGUN_WEBHOOK_SIGNING_KEY) {
        res.status(503).json({ error: 'DMARC report inbox is not configured (MAILGUN_WEBHOOK_SIGNING_KEY).' });
        return;
    }
    if (!mailgunSignatureValid(req.body ?? {})) {
        res.status(401).json({ error: 'Invalid Mailgun signature.' });
        return;
    }
    const files = (req.files as Express.Multer.File[] | undefined) ?? [];
    const attachment = files.find((f) => /\.(xml|gz|zip)$/i.test(f.originalname)) ?? files[0];
    const db = getDb();
    // From here on the answer is always 200: a report that can't be parsed or belongs to no
    // monitored domain will never succeed, so a retry would only repeat the failure.
    if (!attachment || !db) {
        console.warn(`[dmarc-inbound] ${attachment ? 'database not configured' : 'message had no attachment'} (from ${req.body?.sender ?? 'unknown'})`);
        res.status(200).json({ accepted: false, reason: attachment ? 'database not configured' : 'no attachment' });
        return;
    }
    try {
        const r = await ingestReport(db, attachment.buffer, 'mailgun', null);
        if (!r.ok) console.warn(`[dmarc-inbound] rejected ${attachment.originalname}: ${r.error}`);
        res.status(200).json(r.ok ? { accepted: true, duplicate: r.duplicate, domain: r.domain, records: r.records } : { accepted: false, reason: r.error });
    } catch (err) {
        console.error('[dmarc-inbound] failed:', err instanceof Error ? err.message : err);
        // A missing schema or database outage is worth a Mailgun retry.
        res.status(503).json({ accepted: false, reason: err instanceof Error ? err.message : 'ingest failed' });
    }
});

export default router;
