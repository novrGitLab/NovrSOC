// /api/client/secops — the client portal's view of its own organisation's security monitoring
// (phase P24). Read-only.
//
// Every route needs secops:client (portal_user; staff hold it too, to preview the client view).
// The organisation is the token's org_id: for a client role resolveOrg ignores X-Org-Id, so a
// client can only ever read its own records. Data comes from the org-scoped stored alerts
// (routes/alertStore.ts's table) and the organisation's own Wazuh agents (lib/orgScope.ts).
// Responses leave out the SOC's internal working: no raw log content, triage notes, assignees,
// Wazuh group names or quarantine state.
//
//   GET /summary   alert counts (24 h, 7 d) by severity, firewall actions over 7 d, the newest
//                  alert received, and the organisation's agents by state
//   GET /alerts    stored alerts, newest first (?severity=, ?action=, ?firewall=1, ?cursor=)
//   GET /agents    the organisation's enrolled Wazuh agents

import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { requirePermission, requestOrg } from '../lib/permissions';
import { getSupabase } from '../services/geoEnrichment';
import { isUuid } from '../services/cases';
import { SEVERITIES, type Severity } from '../lib/severity';
import { NETWORK_COLUMNS, FIREWALL_ACTIONS, missingNetworkColumns } from '../lib/alertNetwork';
import { orgScope } from '../lib/orgScope';
import { staleAfterMinutes } from './alertStore';

const router = Router();
const can = requirePermission('secops:client');

const BASE = 'id, rule_id, rule_level, rule_description, agent_name, severity, mitre_ids, location, event_time, received_at, status';
const COLUMNS = `${BASE}, ${NETWORK_COLUMNS.join(', ')}`;
const errText = (e: unknown) => (e instanceof Error ? e.message : e && typeof e === 'object' && 'message' in e ? String((e as { message: unknown }).message) : String(e));

router.get('/summary', can, async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Alert store not configured', connected: false }); return; }
    const org = requestOrg(req);
    const since = (h: number) => new Date(Date.now() - h * 3600_000).toISOString();
    const count = async (build: () => PromiseLike<{ count: number | null; error: unknown }>) => {
        const { count: c, error } = await build();
        if (error) throw error;
        return c ?? 0;
    };
    const base = (h: number) => supabase.from('alerts').select('id', { count: 'exact', head: true }).eq('org_id', org).gte('event_time', since(h));

    try {
        const [day, week, newest] = await Promise.all([
            Promise.all(SEVERITIES.map((s) => count(() => base(24).eq('severity', s)))),
            Promise.all(SEVERITIES.map((s) => count(() => base(168).eq('severity', s)))),
            supabase.from('alerts').select('received_at, event_time').eq('org_id', org).order('received_at', { ascending: false }).limit(1).maybeSingle(),
        ]);
        if (newest.error) throw newest.error;

        // Firewall actions (P24 columns). null when the columns aren't there yet — not zero.
        let firewall: Record<string, number> | null = null;
        try {
            // GET with a count (not HEAD): a missing column must come back with its error message.
            const counts = await Promise.all(FIREWALL_ACTIONS.map((a) => count(() =>
                supabase.from('alerts').select('id', { count: 'exact' }).eq('org_id', org).gte('event_time', since(168)).eq('net_action', a).limit(1))));
            firewall = Object.fromEntries(FIREWALL_ACTIONS.map((a, i) => [a, counts[i]]));
        } catch (e) {
            if (!missingNetworkColumns(e as { message?: string })) throw e;
        }

        // The organisation's agents. Unavailable is said, never shown as zero agents.
        let agents: { total: number; active: number; disconnected: number; never_connected: number } | null = null;
        let agentsError: string | null = null;
        try {
            const scope = await orgScope(org);
            const n = (...s: string[]) => scope.agents.filter((a) => s.includes(a.status)).length;
            agents = { total: scope.agents.length, active: n('active'), disconnected: n('disconnected'), never_connected: n('never_connected', 'pending') };
        } catch (e) {
            agentsError = errText(e);
        }

        const bySev = (arr: number[]) => Object.fromEntries(SEVERITIES.map((s, i) => [s, arr[i]])) as Record<Severity, number>;
        res.json({
            alerts_24h: { total: day.reduce((a, b) => a + b, 0), by_severity: bySev(day) },
            alerts_7d: { total: week.reduce((a, b) => a + b, 0), by_severity: bySev(week) },
            firewall_7d: firewall,
            last_received_at: newest.data?.received_at ?? null,
            last_event_time: newest.data?.event_time ?? null,
            stale_after_minutes: staleAfterMinutes(),
            agents,
            agents_error: agentsError,
            connected: true,
        });
    } catch (err) {
        res.status(502).json({ error: errText(err), connected: true });
    }
});

const encodeCursor = (t: string, id: string) => Buffer.from(JSON.stringify({ t, id })).toString('base64url');
function decodeCursor(c: string): { t: string; id: string } | null {
    try {
        const v = JSON.parse(Buffer.from(c, 'base64url').toString('utf8')) as { t?: unknown; id?: unknown };
        if (typeof v.t !== 'string' || typeof v.id !== 'string' || !isUuid(v.id) || !/^[\d\-T:.+Z ]{10,40}$/.test(v.t)) return null;
        return { t: v.t, id: v.id };
    } catch {
        return null;
    }
}

router.get('/alerts', can, async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Alert store not configured', connected: false }); return; }
    const q = req.query;
    const severity = typeof q.severity === 'string' && q.severity ? q.severity.split(',') : null;
    if (severity && severity.some((s) => !(SEVERITIES as readonly string[]).includes(s))) { res.status(400).json({ error: `severity must be from ${SEVERITIES.join(', ')}` }); return; }
    const action = typeof q.action === 'string' && q.action ? q.action.split(',').map((s) => s.trim().toLowerCase()) : null;
    if (action && action.some((a) => !/^[a-z_-]{1,32}$/.test(a))) { res.status(400).json({ error: 'action must be a comma-separated list such as block,reject' }); return; }
    const firewallOnly = q.firewall === '1' || q.firewall === 'true';
    const cursor = typeof q.cursor === 'string' && q.cursor ? decodeCursor(q.cursor) : null;
    if (typeof q.cursor === 'string' && q.cursor && !cursor) { res.status(400).json({ error: 'invalid cursor' }); return; }
    const limit = Math.min(Math.max(Number(q.limit) || 50, 1), 200);

    const build = (columns: string) => {
        let query = supabase.from('alerts').select(columns).eq('org_id', requestOrg(req));
        if (severity) query = query.in('severity', severity);
        if (action) query = query.in('net_action', action);
        if (firewallOnly) query = query.not('net_action', 'is', null);
        if (cursor) query = query.or(`event_time.lt."${cursor.t}",and(event_time.eq."${cursor.t}",id.lt.${cursor.id})`);
        return query.order('event_time', { ascending: false }).order('id', { ascending: false }).limit(limit + 1);
    };
    let { data, error } = await build(COLUMNS);
    if (missingNetworkColumns(error)) {
        if (action || firewallOnly) { res.status(503).json({ error: 'Firewall fields are not available yet' }); return; }
        ({ data, error } = await build(BASE));
    }
    if (error) { res.status(502).json({ error: errText(error) }); return; }
    const rows = (data ?? []) as unknown as { id: string; event_time: string }[];
    const page = rows.slice(0, limit);
    const last = page[page.length - 1];
    res.json({ alerts: page, next_cursor: rows.length > limit && last ? encodeCursor(last.event_time, last.id) : null });
});

router.get('/agents', can, async (req: AuthRequest, res) => {
    try {
        const scope = await orgScope(requestOrg(req));
        res.json({
            agents: scope.agents.map((a) => ({ id: a.id, name: a.name, ip: a.ip, os: a.os, status: a.status, lastSeen: a.lastKeepAlive })),
            total: scope.agents.length,
            active: scope.agents.filter((a) => a.status === 'active').length,
        });
    } catch (err) {
        res.status(503).json({ error: errText(err), agents: [], total: null, active: null });
    }
});

export default router;
