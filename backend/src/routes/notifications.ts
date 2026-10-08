import { Router } from 'express';
import { search } from '../lib/wazuh-indexer';
import { getSupabase } from '../services/geoEnrichment';
import type { AuthRequest } from '../middleware/auth';
import { sendAlertCommunicationEmail, socNotificationRecipients } from '../services/email';
import { SEVERITY_MIN_LEVEL } from '../lib/severity';
import { requirePermission, requestOrg } from '../lib/permissions';
import { loadOrgContacts, contactAddresses } from '../services/orgContacts';

// GET needs a SecOps token with alerts:read and lists only the caller's organisation's cases.
// Header.tsx polls it from both the admin app and the client portal; portal tokens can't be
// verified by this backend, so the portal header gets no notifications until portal auth
// exists (see index.ts).

const router = Router();

interface IndexerAlertHit {
    _id: string;
    _source?: {
        timestamp?: string;
        rule?: { level?: number; description?: string };
        agent?: { name?: string };
        data?: { srcip?: string };
    };
}
interface IndexerSearchResponse { hits?: { hits?: IndexerAlertHit[] } }

interface Notification {
    id: string;
    type: 'alert' | 'case';
    severity: 'medium' | 'high';
    title: string;
    message: string;
    time: string;
    read: boolean;
}

// GET /api/notifications — medium-severity (level 7-9) Wazuh alerts from the last 24h, plus the
// most recent open high/critical cases of the caller's organisation. MEDIUM alerts land here and only here — no email, per
// the Security Operations redesign spec (HIGH/CRITICAL email via routes/threatManagement.ts's
// notifyCriticalAlerts instead).
router.get('/', requirePermission('alerts:read'), async (req: AuthRequest, res) => {
    const notifications: Notification[] = [];

    try {
        const result = await search<IndexerSearchResponse>('wazuh-alerts-4.x-*', {
            size: 20,
            sort: [{ timestamp: { order: 'desc' } }],
            query: { bool: { must: [{ range: { 'rule.level': { gte: SEVERITY_MIN_LEVEL.medium, lt: SEVERITY_MIN_LEVEL.high } } }, { range: { timestamp: { gte: 'now-24h' } } }] } },
        });
        const hits = result?.hits?.hits ?? [];
        for (const h of hits) {
            const src = h._source ?? {};
            notifications.push({
                id: h._id,
                type: 'alert',
                severity: 'medium',
                title: src.rule?.description ?? 'Wazuh alert',
                message: `Agent: ${src.agent?.name ?? 'Unknown'} • ${src.data?.srcip ?? 'No IP'}`,
                time: src.timestamp ?? new Date().toISOString(),
                read: false,
            });
        }
    } catch (err) {
        console.error('[notifications] Wazuh alert fetch failed:', err instanceof Error ? err.message : err);
    }

    const supabase = getSupabase();
    if (supabase) {
        // Open high/critical only: auto-closed tier-1 cases never needed a person, and listing
        // them would bury the ones that do.
        const { data, error } = await supabase
            .from('cases')
            .select('id, case_number, title, severity, status, created_at')
            .eq('org_id', requestOrg(req))
            .in('severity', ['high', 'critical'])
            .neq('status', 'resolved')
            .order('created_at', { ascending: false })
            .limit(5);
        if (error) console.error('[notifications] case fetch failed:', error.message);
        for (const c of data ?? []) {
            notifications.push({
                id: c.id,
                type: 'case',
                severity: 'high',
                title: c.title,
                message: `Case ${c.case_number} — ${c.severity} · ${c.status}`,
                time: c.created_at,
                read: false,
            });
        }
    }

    notifications.sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime());
    res.json({ notifications, unread: notifications.filter((n) => !n.read).length });
});

// POST /api/notifications/send { subject, message, severity?, to?, recipient? } — emails the SOC mailbox
// (or the given addresses). Real send; success is false with the provider's error otherwise.
// Needs handover:write. Explicit `to` addresses must all be contacts of the caller's own
// organisation (services/orgContacts.ts) — anything else is refused, so this is not a relay.
router.post('/send', requirePermission('handover:write'), async (req: AuthRequest, res) => {
    const subject = typeof req.body?.subject === 'string' ? req.body.subject.trim() : '';
    const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
    const severity = typeof req.body?.severity === 'string' && req.body.severity ? req.body.severity : 'informational';
    // recipient: 'ciso' sends to CISO_EMAIL (the address stays server-side); otherwise explicit
    // `to` addresses, else the SOC mailbox.
    const to: string[] = req.body?.recipient === 'ciso'
        ? [process.env.CISO_EMAIL || 'soc@cybernovr.com']
        : Array.isArray(req.body?.to) && req.body.to.length > 0
            ? req.body.to.filter((x: unknown): x is string => typeof x === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x))
            : socNotificationRecipients();
    if (!subject || !message) { res.status(400).json({ success: false, error: 'subject and message are required' }); return; }
    if (to.length === 0) { res.status(400).json({ success: false, error: 'no valid recipient address' }); return; }
    if (req.body?.recipient !== 'ciso' && Array.isArray(req.body?.to) && req.body.to.length > 0) {
        const allowed = contactAddresses(await loadOrgContacts(requestOrg(req)));
        const outside = to.filter((addr) => !allowed.has(addr.toLowerCase()));
        if (outside.length > 0) {
            res.status(400).json({ success: false, error: `Not a contact of your organisation: ${outside.join(', ')}` });
            return;
        }
    }
    try {
        await sendAlertCommunicationEmail({ to, subject, body: message, severity, sentBy: req.user?.email ?? 'NovrSOC analyst' });
        res.json({ success: true, outcome: 'success', message: `Sent to ${to.join(', ')}` });
    } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        const notConnected = /disabled|not configured/i.test(msg);
        res.status(notConnected ? 200 : 502).json({ success: false, outcome: notConnected ? 'skipped' : 'failed', message: msg });
    }
});

export default router;
