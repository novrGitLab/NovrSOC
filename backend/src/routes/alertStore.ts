// Stored Wazuh alerts (phase R2) — the durable, org-scoped `alerts` table filled by
// POST /api/ingest/alerts. Mounted at /api/alerts beside routes/alerts.ts (whose /status, /test and
// /incident routes don't overlap these).
//
//   GET   /api/alerts              alerts:read    filters + keyset (cursor) pagination
//   GET   /api/alerts/stats        alerts:read    counts by severity and status, newest received_at
//   GET   /api/alerts/:id          alerts:read    404 for another org's alert (never 403)
//   PATCH /api/alerts/:id/status   alerts:triage  audited
//
// The organisation is resolved by requirePermission (lib/resolveOrg.ts): the token's org, or for
// staff another existing org named in X-Org-Id (audited). Every query is scoped to it.

import { Router, type Response } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { requirePermission, requestOrg } from '../lib/permissions';
import { getSupabase } from '../services/geoEnrichment';
import { isUuid, dbErrorMessage } from '../services/cases';
import { SEVERITIES, type Severity } from '../lib/severity';
import { logAudit } from '../lib/audit';

const router = Router();

export const ALERT_STATUSES = ['new', 'triaged', 'escalated', 'closed', 'false_positive'] as const;
export type AlertStatus = (typeof ALERT_STATUSES)[number];

// The list never carries `raw` (up to 32 KB each); the detail route does.
const LIST_COLUMNS = 'id, org_id, wazuh_alert_id, rule_id, rule_level, rule_description, agent_id, agent_name, agent_ip, severity, mitre_ids, wazuh_groups, location, raw_truncated, event_time, received_at, status, case_id';

function noStore(res: Response): boolean {
    if (getSupabase()) return false;
    res.status(503).json({ error: 'Alert store not configured', connected: false });
    return true;
}

/** Comma-separated list restricted to `allowed`; null when absent, false when any value is unknown. */
function listParam<T extends string>(v: unknown, allowed: readonly T[]): T[] | null | false {
    if (typeof v !== 'string' || !v) return null;
    const parts = v.split(',').map((x) => x.trim()).filter(Boolean);
    return parts.every((p) => (allowed as readonly string[]).includes(p)) ? (parts as T[]) : false;
}

function isoParam(v: unknown): string | null | false {
    if (typeof v !== 'string' || !v) return null;
    const t = Date.parse(v);
    return Number.isNaN(t) ? false : new Date(t).toISOString();
}

// Cursor = base64url of {t: event_time ISO, id: uuid} of the last row of the previous page.
const encodeCursor = (t: string, id: string) => Buffer.from(JSON.stringify({ t, id })).toString('base64url');
function decodeCursor(c: string): { t: string; id: string } | null {
    try {
        const v = JSON.parse(Buffer.from(c, 'base64url').toString('utf8')) as { t?: unknown; id?: unknown };
        if (typeof v.t !== 'string' || typeof v.id !== 'string' || !isUuid(v.id) || Number.isNaN(Date.parse(v.t))) return null;
        // The exact string the database returned: re-formatting could drop sub-millisecond precision
        // and skip rows at the page boundary.
        if (!/^[\d\-T:.+Z ]{10,40}$/.test(v.t)) return null;
        return { t: v.t, id: v.id };
    } catch {
        return null;
    }
}

const AGENT_RE = /^[\w.:@-]{1,128}$/;

// GET /api/alerts?severity=critical,high&status=new&agent=web-01&from=ISO&to=ISO&limit=50&cursor=…
// Newest first by (event_time, id).
router.get('/', requirePermission('alerts:read'), async (req: AuthRequest, res) => {
    if (noStore(res)) return;
    const q = req.query;
    const severity = listParam<Severity>(q.severity, SEVERITIES);
    const status = listParam<AlertStatus>(q.status, ALERT_STATUSES);
    const from = isoParam(q.from);
    const to = isoParam(q.to);
    const agent = typeof q.agent === 'string' && q.agent ? q.agent : null;
    const cursor = typeof q.cursor === 'string' && q.cursor ? decodeCursor(q.cursor) : null;
    if (severity === false) { res.status(400).json({ error: `severity must be from ${SEVERITIES.join(', ')}` }); return; }
    if (status === false) { res.status(400).json({ error: `status must be from ${ALERT_STATUSES.join(', ')}` }); return; }
    if (from === false || to === false) { res.status(400).json({ error: 'from / to must be ISO timestamps' }); return; }
    if (agent !== null && !AGENT_RE.test(agent)) { res.status(400).json({ error: 'agent must be an agent name or id' }); return; }
    if (typeof q.cursor === 'string' && q.cursor && !cursor) { res.status(400).json({ error: 'invalid cursor' }); return; }
    const limit = Math.min(Math.max(Number(q.limit) || 50, 1), 200);

    let query = getSupabase()!.from('alerts').select(LIST_COLUMNS).eq('org_id', requestOrg(req));
    if (severity) query = query.in('severity', severity);
    if (status) query = query.in('status', status);
    if (from) query = query.gte('event_time', from);
    if (to) query = query.lte('event_time', to);
    if (agent) query = query.or(`agent_name.eq."${agent}",agent_id.eq."${agent}"`);
    if (cursor) query = query.or(`event_time.lt."${cursor.t}",and(event_time.eq."${cursor.t}",id.lt.${cursor.id})`);
    const { data, error } = await query
        .order('event_time', { ascending: false })
        .order('id', { ascending: false })
        .limit(limit + 1);
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }

    const rows = (data ?? []) as unknown as { id: string; event_time: string }[];
    const page = rows.slice(0, limit);
    const last = page[page.length - 1];
    res.json({ alerts: page, next_cursor: rows.length > limit && last ? encodeCursor(last.event_time, last.id) : null });
});

// GET /api/alerts/stats?range=24h|7d|30d — counts in the window by severity and by status, plus
// the newest received_at/event_time overall (null = nothing ever received), which the frontend
// uses for its stale-data banner.
const RANGE_HOURS: Record<string, number> = { '24h': 24, '7d': 168, '30d': 720 };

router.get('/stats', requirePermission('alerts:read'), async (req: AuthRequest, res) => {
    if (noStore(res)) return;
    const supabase = getSupabase()!;
    const org = requestOrg(req);
    const range = typeof req.query.range === 'string' && RANGE_HOURS[req.query.range] ? req.query.range : '24h';
    const since = new Date(Date.now() - RANGE_HOURS[range] * 3600_000).toISOString();
    const base = () => supabase.from('alerts').select('id', { count: 'exact', head: true }).eq('org_id', org).gte('event_time', since);
    const count = async (q: PromiseLike<{ count: number | null; error: unknown }>) => {
        const { count: c, error } = await q;
        if (error) throw error;
        return c ?? 0;
    };
    try {
        const [total, bySeverity, byStatus, newest] = await Promise.all([
            count(base()),
            Promise.all(SEVERITIES.map((s) => count(base().eq('severity', s)))),
            Promise.all(ALERT_STATUSES.map((s) => count(base().eq('status', s)))),
            supabase.from('alerts').select('received_at, event_time').eq('org_id', org).order('received_at', { ascending: false }).limit(1).maybeSingle(),
        ]);
        if (newest.error) throw newest.error;
        res.json({
            range,
            since,
            total,
            by_severity: Object.fromEntries(SEVERITIES.map((s, i) => [s, bySeverity[i]])),
            by_status: Object.fromEntries(ALERT_STATUSES.map((s, i) => [s, byStatus[i]])),
            last_received_at: newest.data?.received_at ?? null,
            last_event_time: newest.data?.event_time ?? null,
            connected: true,
        });
    } catch (err) {
        res.status(502).json({ error: dbErrorMessage(err), connected: true });
    }
});

// GET /api/alerts/:id — the full alert, raw included. Another org's id looks exactly like a
// missing one.
router.get('/:id', requirePermission('alerts:read'), async (req: AuthRequest, res) => {
    if (noStore(res)) return;
    const { id } = req.params;
    if (!isUuid(id)) { res.status(404).json({ error: 'Alert not found' }); return; }
    const { data, error } = await getSupabase()!.from('alerts').select('*').eq('id', id).eq('org_id', requestOrg(req)).maybeSingle();
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    if (!data) { res.status(404).json({ error: 'Alert not found' }); return; }
    res.json({ alert: data });
});

// PATCH /api/alerts/:id/status { status } — triage.
router.patch('/:id/status', requirePermission('alerts:triage'), async (req: AuthRequest, res) => {
    if (noStore(res)) return;
    const { id } = req.params;
    const status = req.body?.status as unknown;
    if (!isUuid(id)) { res.status(404).json({ error: 'Alert not found' }); return; }
    if (typeof status !== 'string' || !(ALERT_STATUSES as readonly string[]).includes(status)) {
        res.status(400).json({ error: `status must be one of ${ALERT_STATUSES.join(', ')}` });
        return;
    }
    const supabase = getSupabase()!;
    const org = requestOrg(req);
    const { data: before, error: readErr } = await supabase.from('alerts').select('id, status, wazuh_alert_id').eq('id', id).eq('org_id', org).maybeSingle();
    if (readErr) { res.status(502).json({ error: dbErrorMessage(readErr) }); return; }
    if (!before) { res.status(404).json({ error: 'Alert not found' }); return; }

    const { data, error } = await supabase.from('alerts').update({ status }).eq('id', id).eq('org_id', org).select(LIST_COLUMNS).maybeSingle();
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    if (!data) { res.status(404).json({ error: 'Alert not found' }); return; }

    logAudit({
        user: req.user?.email ?? 'unknown', action: 'ALERT_STATUS_CHANGED', resource: 'alert', resource_id: id,
        ip: req.ip ?? 'unknown', result: 'success', severity: 'info',
        details: `${org} alert ${String(before.wazuh_alert_id).slice(0, 60)}: ${before.status} -> ${status}`,
    });
    res.json({ success: true, alert: data });
});

export default router;
