import { Router } from 'express';
import { search } from '../lib/wazuh-indexer';
import { getSupabase } from '../services/geoEnrichment';

// Not gated with requireAuth — Header.tsx (which polls this) is shared by both the admin app
// and the client portal, and client-portal users carry a portal_token this backend's
// requireAuth can't verify (see index.ts's block comment on the same constraint for
// /api/incidents, /api/wazuh, etc.). Same open-by-necessity category as those routes.

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
// most recent open high/critical cases. MEDIUM alerts land here and only here — no email, per
// the Security Operations redesign spec (HIGH/CRITICAL email via routes/threatManagement.ts's
// notifyCriticalAlerts instead).
router.get('/', async (_req, res) => {
    const notifications: Notification[] = [];

    try {
        const result = await search<IndexerSearchResponse>('wazuh-alerts-4.x-*', {
            size: 20,
            sort: [{ timestamp: { order: 'desc' } }],
            query: { bool: { must: [{ range: { 'rule.level': { gte: 7, lt: 10 } } }, { range: { timestamp: { gte: 'now-24h' } } }] } },
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

export default router;
