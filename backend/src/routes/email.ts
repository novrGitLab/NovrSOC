import { Router } from 'express';
import multer from 'multer';
import { createHmac, timingSafeEqual } from 'crypto';
import { getDb } from '../services/emailsec/db';
import { ingestReport } from '../services/emailsec/dmarcService';
import rateLimit from 'express-rate-limit';
import { isEmailEnabled } from '../services/email';
import { requireAuth, requireRole, type AuthRequest } from '../middleware/auth';
import { logAudit } from '../lib/audit';

// Platform notification email + the Mailgun DMARC report inbox.
//
// Every route that sends mail requires a staff token (2026-09-29 hardening). Two routes were
// removed rather than protected, because nothing in the application called them and each let
// an anonymous caller send mail:
//   POST /test  — sent a test email to any address. Test sends live at POST /api/test/email
//                 (managers, CISO address only) and POST /api/alerts/test (managers).
//   POST /alert — sent a formatted "critical alert" email to any list of addresses. Critical
//                 alert email is sent by the backend itself (routes/threatManagement.ts calls
//                 sendCriticalAlertEmail directly), never over HTTP.

const router = Router();

// Bounded per user, not per IP — the caller is always an authenticated staff member.
export const sendLimiter = rateLimit({
    windowMs: 10 * 60_000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false,
    keyGenerator: (req) => (req as AuthRequest).user?.email ?? 'anonymous',
    message: { error: 'Too many emails sent — try again in a few minutes.' },
});

// Mailgun's inbound route POSTs multipart/form-data (fields + the DMARC XML/zip as a file
// attachment). express.json() (mounted globally in index.ts) can't parse that, so this route
// needs its own multipart parser. memoryStorage + a modest size cap — DMARC aggregate reports
// are small XML/gzip files, not the multi-MB uploads other routes (e.g. brand.ts) handle.
const dmarcUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024, files: 5 } });

// GET /api/email/status — which provider is configured. Staff only: it discloses sender setup.
router.get('/status', requireAuth, requireRole('super_admin', 'soc_manager', 'analyst', 'executive'), (_req, res) => {
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

// Mailgun signs every webhook: HMAC-SHA256(signing key, timestamp + token) = signature.
// Without the key configured the inbox refuses everything — an unauthenticated endpoint that
// writes into DMARC data would let anyone forge "authorised" sending sources.
// Replay protection: a signed request is only valid inside a 15-minute window, and each Mailgun
// token is accepted once within it (Mailgun's own guidance is to cache used tokens).
const REPLAY_WINDOW_S = 15 * 60;
const usedTokens = new Map<string, number>(); // token -> expiry (ms)
function mailgunSignatureValid(body: Record<string, unknown>): { ok: boolean; reason?: string } {
    const key = process.env.MAILGUN_WEBHOOK_SIGNING_KEY;
    const { timestamp, token, signature } = body as { timestamp?: string; token?: string; signature?: string };
    if (!key || !timestamp || !token || !signature) return { ok: false, reason: 'missing signature fields' };
    if (!Number.isFinite(Number(timestamp)) || Math.abs(Date.now() / 1000 - Number(timestamp)) > REPLAY_WINDOW_S) return { ok: false, reason: 'timestamp outside the 15-minute window' };
    const expected = createHmac('sha256', key).update(`${timestamp}${token}`).digest('hex');
    if (!(expected.length === signature.length && timingSafeEqual(Buffer.from(expected), Buffer.from(signature)))) return { ok: false, reason: 'bad signature' };
    const now = Date.now();
    for (const [t, exp] of usedTokens) if (exp < now) usedTokens.delete(t);
    if (usedTokens.has(token)) return { ok: false, reason: 'token already used (replay)' };
    usedTokens.set(token, now + REPLAY_WINDOW_S * 2 * 1000);
    return { ok: true };
}

// POST /api/email/dmarc-inbound — Mailgun inbound route for the DMARC report mailbox (rua=).
router.post('/dmarc-inbound', dmarcUpload.any(), async (req, res) => {
    if (!process.env.MAILGUN_WEBHOOK_SIGNING_KEY) {
        res.status(503).json({ error: 'DMARC report inbox is not configured (MAILGUN_WEBHOOK_SIGNING_KEY).' });
        return;
    }
    const sig = mailgunSignatureValid(req.body ?? {});
    if (!sig.ok) {
        res.status(401).json({ error: `Invalid Mailgun signature: ${sig.reason}.` });
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
        // Auditable: a report withheld from organisations that registered but have not verified
        // the domain (no report content is logged — only the domain and the organisations).
        const withheld = r.ok ? r.unverified_org_ids : r.code === 'domain_not_verified' ? r.unverified_org_ids ?? [] : [];
        if (withheld.length) {
            logAudit({
                user: 'mailgun-inbound', action: 'EMAILSEC_DMARC_REPORT_WITHHELD', resource: 'email_security', ip: req.ip ?? '', result: 'failed', severity: 'warning',
                details: `DMARC report for ${r.ok ? r.domain : r.domain ?? 'unknown domain'} not delivered to ${withheld.join(', ')}: domain ownership not verified${r.ok ? ` (delivered to verified owner${r.org_ids.length === 1 ? '' : 's'} ${r.org_ids.join(', ')})` : ''}`,
            });
        }
        res.status(200).json(r.ok ? { accepted: true, duplicate: r.duplicate, domain: r.domain, records: r.records } : { accepted: false, reason: r.error });
    } catch (err) {
        console.error('[dmarc-inbound] failed:', err instanceof Error ? err.message : err);
        // A missing schema or database outage is worth a Mailgun retry.
        res.status(503).json({ accepted: false, reason: err instanceof Error ? err.message : 'ingest failed' });
    }
});

export default router;
