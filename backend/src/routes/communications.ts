import { Router } from 'express';
import { randomUUID } from 'crypto';
import type { AuthRequest } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';
import { sendAlertCommunicationEmail } from '../services/email';
import { isUuid, dbErrorMessage } from '../services/cases';
import { loadOrgContacts } from '../services/orgContacts';
import { logAudit } from '../lib/audit';
import { requirePermission, requestOrg } from '../lib/permissions';

// Alert Communication — compose and send an alert email, and the log of what was sent.
//
// Sends are real (services/email.ts: Resend, then SMTP, then SendGrid) and every attempt is
// logged with its true status: Sent, or Failed with the provider's error. The log lives in the
// alert_communications table (backend/sql/2026-09-alert-communications.sql). Until that table
// exists, entries are kept in memory and the response says so — they are lost on restart.
//
// Recipients are resolved here, not trusted from the browser, and only from the caller's own
// organisation (services/orgContacts.ts): its active staff from platform_users and its own
// organisations.contact_email / ciso_email. Only "custom" takes a typed address, and only from
// soc_manager / super_admin, to a domain listed in COMMS_ALLOWED_DOMAINS (comma-separated, exact
// domain match; unset = no custom addresses) — anything else is 403. Mounted behind
// requireAuth (index.ts); reads need alerts:read, sending needs handover:write.

const router = Router();

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'] as const;
type RecipientType = 'client' | 'analyst' | 'all_analysts' | 'custom';
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CUSTOM_RECIPIENT_ROLES = ['soc_manager', 'super_admin'];

/** Domains a custom address may use, from COMMS_ALLOWED_DOMAINS. Read per request so a config change needs no code. */
function allowedCustomDomains(): Set<string> {
    return new Set((process.env.COMMS_ALLOWED_DOMAINS ?? '').split(',').map((d) => d.trim().toLowerCase().replace(/^@/, '')).filter(Boolean));
}

interface LogEntry {
    id: string;
    org_id: string;
    recipient_type: RecipientType;
    recipients: string[];
    subject: string;
    body: string;
    severity: string;
    case_id: string | null;
    case_number: string | null;
    sent_by: string;
    status: 'sent' | 'failed';
    error: string | null;
    created_at: string;
}

const memoryLog: LogEntry[] = [];

// GET /api/communications/recipients
router.get('/recipients', requirePermission('alerts:read'), async (req: AuthRequest, res) => {
    res.json(await loadOrgContacts(requestOrg(req)));
});

// GET /api/communications?limit= — newest first. source says where the log is kept.
router.get('/', requirePermission('alerts:read'), async (req: AuthRequest, res) => {
    const orgId = requestOrg(req);
    const limit = Math.min(Math.max(Number(req.query.limit) || 200, 1), 500);
    const supabase = getSupabase();
    if (supabase) {
        const { data, error } = await supabase.from('alert_communications').select('*').eq('org_id', orgId).order('created_at', { ascending: false }).limit(limit);
        if (!error) { res.json({ entries: data ?? [], source: 'supabase' }); return; }
        // 42P01 / PGRST205: the table hasn't been created yet — fall back and say so.
        console.warn('[communications] log table unavailable, serving memory:', dbErrorMessage(error));
    }
    res.json({ entries: memoryLog.filter((e) => e.org_id === orgId).slice(0, limit), source: 'memory' });
});

// POST /api/communications/send
//   { recipient_type, analyst_email?, client_email?, custom_email?, subject, body, severity, case_id? }
router.post('/send', requirePermission('handover:write'), async (req: AuthRequest, res) => {
    const b = req.body ?? {};
    const orgId = requestOrg(req);
    const sentBy = req.user?.email || 'NovrSOC analyst';
    const type = b.recipient_type as RecipientType;
    const subject = typeof b.subject === 'string' ? b.subject.trim() : '';
    const body = typeof b.body === 'string' ? b.body.trim() : '';
    const severity = (SEVERITIES as readonly string[]).includes(b.severity) ? b.severity : null;

    if (!['client', 'analyst', 'all_analysts', 'custom'].includes(type)) { res.status(400).json({ success: false, error: 'recipient_type must be client, analyst, all_analysts or custom' }); return; }
    if (!subject || !body) { res.status(400).json({ success: false, error: 'subject and body are required' }); return; }
    if (!severity) { res.status(400).json({ success: false, error: `severity must be one of ${SEVERITIES.join(', ')}` }); return; }
    if (type === 'custom') {
        if (!CUSTOM_RECIPIENT_ROLES.includes(req.user?.role ?? '')) {
            res.status(403).json({ success: false, error: 'Only a SOC manager can send to a custom address — pick a recipient on file' });
            return;
        }
        const addr = typeof b.custom_email === 'string' ? b.custom_email.trim() : '';
        if (!EMAIL_RE.test(addr)) { res.status(400).json({ success: false, error: 'Enter a valid email address' }); return; }
        if (!allowedCustomDomains().has(addr.split('@').pop()!.toLowerCase())) {
            res.status(403).json({ success: false, error: 'That email domain is not allowed for custom recipients (COMMS_ALLOWED_DOMAINS)' });
            return;
        }
    }

    const { analysts, clients } = await loadOrgContacts(orgId);
    let recipients: string[] = [];
    if (type === 'all_analysts') recipients = analysts.map((a) => a.email);
    if (type === 'analyst') recipients = analysts.filter((a) => a.email === b.analyst_email).map((a) => a.email);
    if (type === 'client') recipients = clients.filter((c) => c.email === b.client_email).map((c) => c.email);
    if (type === 'custom' && typeof b.custom_email === 'string' && EMAIL_RE.test(b.custom_email.trim())) recipients = [b.custom_email.trim()];
    if (recipients.length === 0) {
        res.status(400).json({ success: false, error: type === 'custom' ? 'Enter a valid email address' : 'That recipient is not on file' });
        return;
    }

    // Linked case: verified to exist, and its number recorded with the log entry.
    let caseId: string | null = null;
    let caseNumber: string | null = null;
    if (typeof b.case_id === 'string' && isUuid(b.case_id)) {
        const { data } = await getSupabase()?.from('cases').select('id, case_number').eq('id', b.case_id).eq('org_id', orgId).maybeSingle() ?? { data: null };
        if (data) { caseId = data.id; caseNumber = data.case_number; }
    }

    let status: LogEntry['status'] = 'sent';
    let errorMsg: string | null = null;
    try {
        await sendAlertCommunicationEmail({ to: recipients, subject, body, severity, sentBy, caseNumber });
    } catch (err) {
        status = 'failed';
        errorMsg = err instanceof Error ? err.message : String(err);
    }

    const entry: LogEntry = {
        id: randomUUID(), org_id: orgId, recipient_type: type, recipients, subject, body, severity,
        case_id: caseId, case_number: caseNumber, sent_by: sentBy, status, error: errorMsg, created_at: new Date().toISOString(),
    };

    let logSource: 'supabase' | 'memory' = 'memory';
    const supabase = getSupabase();
    if (supabase) {
        const { error } = await supabase.from('alert_communications').insert(entry);
        if (!error) logSource = 'supabase';
        else console.warn('[communications] log insert failed, keeping in memory:', dbErrorMessage(error));
    }
    if (logSource === 'memory') memoryLog.unshift(entry);

    logAudit({
        user: sentBy, action: 'ALERT_COMMUNICATION_SENT', resource: 'communication', resource_id: entry.id,
        ip: req.ip ?? 'unknown', result: status === 'sent' ? 'success' : 'failed',
        details: `${severity} "${subject.slice(0, 80)}" to ${recipients.join(', ')}${errorMsg ? ` — ${errorMsg}` : ''}`.slice(0, 200),
        severity: severity === 'critical' ? 'critical' : 'info',
    });

    res.status(status === 'sent' ? 200 : 502).json({ success: status === 'sent', entry, log_source: logSource, error: errorMsg });
});

export default router;
