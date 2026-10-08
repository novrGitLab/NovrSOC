import { Router } from 'express';
// services/email.ts is the email service (Resend first, then SMTP, then SendGrid) — used here so
// these alerts go through whichever provider is really configured. Email is the only alert
// channel.
import { z } from 'zod';
import { sendTestEmail, isEmailEnabled, sendCaseNotificationEmail, socNotificationRecipients, warnNoRecipient } from '../services/email';
import { requireAuth, requireRole, type AuthRequest } from '../middleware/auth';
import { validate } from '../middleware/validate';
import { logAudit } from '../lib/audit';
import { sendLimiter } from './email';
import { requirePermission } from '../lib/permissions';

// The two sending routes below need a staff token (2026-09-29 hardening): both were callable
// anonymously, and /test sent to any address given in the body.

const router = Router();

function envConfigured(name: string): boolean {
    const val = process.env[name];
    return !!val && val !== 'REPLACE_WHEN_OBTAINED';
}

// GET /api/alerts/status — check which channels are configured
router.get('/status', requirePermission('alerts:read'), (_req, res) => {
    res.json({
        channels: {
            email: { configured: isEmailEnabled(), name: 'Email', description: 'Resend API (Zoho SMTP / SendGrid fallback)' },
            sms: { configured: envConfigured('TWILIO_ACCOUNT_SID'), name: 'SMS', description: 'Twilio SMS to on-call engineers' },
            pagerduty: { configured: envConfigured('PAGERDUTY_API_KEY'), name: 'PagerDuty', description: 'On-call schedule escalation' },
        },
    });
});

// POST /api/alerts/test — send a test alert by email and report the outcome. Kept backward compatible with the existing AlertCommunication.tsx
// caller (which only reads `message`) while also returning `results` — string statuses, not
// booleans, so a caller can distinguish "not configured" from "configured but failed" — for
// PlatformHealth.tsx's dedicated "Test Alert Communications" button.
// Managers only (Platform Health is manager-only). The recipient is always the configured SOC
// address — a caller-chosen `email` is no longer honoured, so this can't be used as a relay.
router.post('/test', requireAuth, requireRole('super_admin', 'soc_manager'), sendLimiter, async (req: AuthRequest, res) => {
    const results: Record<string, string> = {};

    if (isEmailEnabled()) {
        const [to] = socNotificationRecipients();
        if (!to) {
            warnNoRecipient('Test alert', 'ALERT_EMAIL_TO / CISO_EMAIL');
            results.email = 'not configured — set ALERT_EMAIL_TO or CISO_EMAIL';
        } else {
            try {
                await sendTestEmail(to);
                results.email = 'sent';
            } catch (err: any) {
                results.email = `failed: ${err.message}`;
            }
        }
    } else {
        results.email = 'not configured';
    }

    const sentCount = Object.values(results).filter((r) => r === 'sent').length;
    logAudit({ user: req.user?.email ?? 'unknown', action: 'ALERT_TEST_SEND', resource: 'alerts', ip: req.ip ?? '', result: sentCount > 0 ? 'success' : 'failed', details: `email: ${results.email}` });
    res.json({
        success: true,
        results,
        message: sentCount > 0 ? 'Test alerts sent to configured channels' : 'No alert channels configured yet',
    });
});

export const incidentSchema = z.object({
    title: z.string().trim().min(1).max(300),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
    description: z.string().trim().max(4000).optional(),
    affected_host: z.string().trim().max(255).optional(),
    incident_id: z.string().trim().max(64).optional(),
});

// POST /api/alerts/incident — dispatch a real incident alert to the SOC recipients (analysts and above).
router.post('/incident', requireAuth, requireRole('super_admin', 'soc_manager', 'analyst'), sendLimiter, validate(incidentSchema), async (req: AuthRequest, res) => {
    const { title, severity, description, affected_host, incident_id } = req.body as z.infer<typeof incidentSchema>;

    const incident = {
        incident_id: incident_id || `INC-${Date.now()}`,
        title,
        severity,
        description: description || title,
        affected_host: affected_host || 'unknown',
        detected_at: new Date().toLocaleString(),
    };

    const dispatched: string[] = [];
    let emailError: string | null = null;

    const incidentRecipients = socNotificationRecipients();
    if (isEmailEnabled() && incidentRecipients.length === 0) {
        warnNoRecipient('Incident alert email', 'ALERT_EMAIL_TO / CISO_EMAIL');
        emailError = 'No recipient configured — set ALERT_EMAIL_TO or CISO_EMAIL';
    } else if (isEmailEnabled()) {
        try {
            await sendCaseNotificationEmail({
                to: incidentRecipients,
                case_number: incident.incident_id,
                title: incident.title,
                severity: incident.severity,
                headline: 'Incident alert',
                agent: incident.affected_host,
                detail: incident.description,
            });
            dispatched.push('email');
        } catch (err) {
            emailError = err instanceof Error ? err.message : String(err);
        }
    }

    logAudit({ user: req.user?.email ?? 'unknown', action: 'ALERT_INCIDENT_SEND', resource: 'alerts', ip: req.ip ?? '', result: dispatched.length ? 'success' : 'failed', details: `${incident.severity}: ${incident.title}`, resource_id: incident.incident_id, severity: 'warning' });
    res.json({
        dispatched,
        incident_id: incident.incident_id,
        message: dispatched.length > 0
            ? `Alert dispatched via: ${dispatched.join(', ')}`
            : emailError ? `Email failed: ${emailError}` : 'Email is not configured (EMAIL_ENABLED / RESEND_API_KEY) — alert not sent',
    });
});

export default router;
