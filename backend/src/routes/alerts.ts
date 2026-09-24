import { Router } from 'express';
// services/email.ts is the email service (Resend first, then SMTP, then SendGrid) — used here so
// these alerts go through whichever provider is really configured. Email is the only alert
// channel.
import { sendTestEmail, isEmailEnabled, sendCaseNotificationEmail, socNotificationRecipients } from '../services/email';

const router = Router();

function envConfigured(name: string): boolean {
    const val = process.env[name];
    return !!val && val !== 'REPLACE_WHEN_OBTAINED';
}

// GET /api/alerts/status — check which channels are configured
router.get('/status', (_req, res) => {
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
router.post('/test', async (req, res) => {
    const results: Record<string, string> = {};

    if (isEmailEnabled()) {
        const to = req.body?.email || process.env.ALERT_EMAIL_TO || process.env.CISO_EMAIL || 'soc@cybernovr.com';
        try {
            await sendTestEmail(to);
            results.email = 'sent';
        } catch (err: any) {
            results.email = `failed: ${err.message}`;
        }
    } else {
        results.email = 'not configured';
    }

    const sentCount = Object.values(results).filter((r) => r === 'sent').length;
    res.json({
        success: true,
        results,
        message: sentCount > 0 ? 'Test alerts sent to configured channels' : 'No alert channels configured yet',
    });
});

interface IncidentBody {
    title?: string;
    severity?: string;
    description?: string;
    affected_host?: string;
    incident_id?: string;
}

// POST /api/alerts/incident — dispatch a real incident alert
router.post('/incident', async (req, res) => {
    const { title, severity, description, affected_host, incident_id }: IncidentBody = req.body ?? {};
    if (!title || !severity) {
        res.status(400).json({ error: 'title and severity required' });
        return;
    }

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

    if (isEmailEnabled()) {
        try {
            await sendCaseNotificationEmail({
                to: socNotificationRecipients(),
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

    res.json({
        dispatched,
        incident_id: incident.incident_id,
        message: dispatched.length > 0
            ? `Alert dispatched via: ${dispatched.join(', ')}`
            : emailError ? `Email failed: ${emailError}` : 'Email is not configured (EMAIL_ENABLED / RESEND_API_KEY) — alert not sent',
    });
});

export default router;
