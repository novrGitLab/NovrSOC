import { senderAddress } from './email';
// SendGrid — send incident report emails and alerts
// Free: 100 emails/day forever
// Get key: signup.sendgrid.com → Settings → API Keys
// Set: SENDGRID_API_KEY=SG....
//
// Note: the HTML template below uses raw brand hexes deliberately — email clients don't reliably
// support CSS custom properties, so inline hex is the correct choice here (unlike app JSX,
// where this codebase uses token classes throughout).

const SENDGRID_BASE = 'https://api.sendgrid.com/v3';
// Same sender as services/email.ts — cybernovr.com is the verified sending domain.
const FROM_EMAIL = senderAddress().email;
const FROM_NAME = 'NovrSOC Alerts';

function getKey(): string | null {
    const key = process.env.SENDGRID_API_KEY;
    if (!key || key === 'REPLACE_WHEN_OBTAINED') return null;
    return key;
}

export interface EmailPayload {
    to: string;
    subject: string;
    html: string;
    text?: string;
}

export async function sendEmail(payload: EmailPayload): Promise<boolean> {
    const key = getKey();
    if (!key) {
        console.warn('[SendGrid] API key not configured — email not sent');
        return false;
    }

    try {
        const res = await fetch(`${SENDGRID_BASE}/mail/send`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({
                personalizations: [{ to: [{ email: payload.to }] }],
                from: { email: FROM_EMAIL, name: FROM_NAME },
                subject: payload.subject,
                content: [
                    { type: 'text/html', value: payload.html },
                    ...(payload.text ? [{ type: 'text/plain', value: payload.text }] : []),
                ],
            }),
            signal: AbortSignal.timeout(8000),
        });

        return res.status === 202;
    } catch {
        return false;
    }
}

export interface IncidentEmailData {
    id: string;
    title: string;
    severity: string;
    description: string;
    detected_at: string;
    affected_host: string;
}

export async function sendIncidentAlert(incident: IncidentEmailData, recipientEmail: string): Promise<boolean> {
    const severityColor: Record<string, string> = {
        critical: '#CC2B2B',
        high: '#FF6B35',
        medium: '#6B1FA8',
        low: '#7A8099',
    };
    const color = severityColor[incident.severity] ?? '#7A8099';

    const html = `
<!DOCTYPE html>
<html>
<body style="font-family: Inter, sans-serif; background: #F8F9FC; padding: 40px;">
  <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; border: 1px solid #EEF0F6;">
    <div style="background: #1C1F2E; padding: 24px;">
      <img src="https://socnovr.vercel.app/novrsoc.jpg" alt="NovrSOC" width="32" height="32"
           style="width: 32px; height: 32px; border-radius: 8px; vertical-align: middle; margin-right: 10px;" />
      <span style="color: white; font-size: 20px; font-weight: bold; vertical-align: middle;">NovrSOC Alert</span>
      <div style="color: #7A8099; font-size: 13px; margin-top: 4px;">by Cybernovr</div>
    </div>
    <div style="padding: 32px;">
      <div style="display: inline-block; background: ${color}; color: white; font-size: 11px; font-weight: bold; padding: 4px 10px; border-radius: 20px; margin-bottom: 16px;">
        ${incident.severity.toUpperCase()} SEVERITY
      </div>
      <h2 style="font-size: 20px; color: #1C1F2E; margin: 0 0 12px;">${incident.title}</h2>
      <p style="color: #7A8099; font-size: 14px; margin: 0 0 24px;">${incident.description}</p>
      <table style="width: 100%; border-collapse: collapse;">
        <tr><td style="padding: 8px 0; color: #7A8099; font-size: 13px;">Incident ID</td><td style="font-family: monospace; font-size: 13px; color: #1C1F2E;">${incident.id}</td></tr>
        <tr><td style="padding: 8px 0; color: #7A8099; font-size: 13px;">Affected Host</td><td style="font-family: monospace; font-size: 13px; color: #1C1F2E;">${incident.affected_host}</td></tr>
        <tr><td style="padding: 8px 0; color: #7A8099; font-size: 13px;">Detected At</td><td style="font-size: 13px; color: #1C1F2E;">${incident.detected_at}</td></tr>
      </table>
      <div style="margin-top: 32px;">
        <a href="https://app.novrsoc.com/admin/secops/incidents" style="background: #CC2B2B; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: bold; font-size: 14px;">
          View in NovrSOC →
        </a>
      </div>
    </div>
    <div style="background: #F8F9FC; padding: 16px 32px; color: #7A8099; font-size: 12px;">
      NovrSOC by Cybernovr · alerts@novrsoc.com · <a href="#" style="color: #2B3BCC;">Unsubscribe</a>
    </div>
  </div>
</body>
</html>`;

    return sendEmail({ to: recipientEmail, subject: `[${incident.severity.toUpperCase()}] ${incident.title}`, html });
}

export function isConfigured(): boolean {
    return !!getKey();
}
