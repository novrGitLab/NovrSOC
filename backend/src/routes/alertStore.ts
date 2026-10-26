// Stored Wazuh alerts (phase R2) — the durable, org-scoped `alerts` table filled by
// POST /api/ingest/alerts. Mounted at /api/alerts beside routes/alerts.ts (whose /status, /test and
// /incident routes don't overlap these).
//
//   GET   /api/alerts              alerts:read    filters + keyset (cursor) pagination; network and
//                                                 firewall filters (P24): action, ip, protocol, port, firewall=1
//   GET   /api/alerts/stats        alerts:read    counts by severity and status, newest received_at
//   GET   /api/alerts/:id          alerts:read    404 for another org's alert (never 403)
//   PATCH /api/alerts/:id/status   alerts:triage  audited, recorded in alert_events
//   PATCH /api/alerts/:id          alerts:triage  { assigned_to?, acknowledged?, triage_note? } (phase P3)
//   GET   /api/alerts/:id/events   alerts:read    the alert's triage history (phase P3)
//   POST  /api/alerts/:id/case     cases:write    promote to a case, or return the case it is in (phase P3)
//
// The organisation is resolved by requirePermission (lib/resolveOrg.ts): the token's org, or for
// staff another existing org named in X-Org-Id (audited). Every query is scoped to it.

import { Router, type Response } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { requirePermission, requestOrg } from '../lib/permissions';
import { isStaffRole } from '../lib/resolveOrg';
import { getSupabase } from '../services/geoEnrichment';
import { isUuid, dbErrorMessage, createCase, addTimeline, isCaseSeverity } from '../services/cases';
import { SEVERITIES, type Severity } from '../lib/severity';
import { logAudit } from '../lib/audit';
import { NETWORK_COLUMNS, missingNetworkColumns } from '../lib/alertNetwork';
import { isIP } from 'net';
import { tiDetailFor } from '../lib/tiCorrelation';

const router = Router();

export const ALERT_STATUSES = ['new', 'triaged', 'escalated', 'closed', 'false_positive'] as const;
export type AlertStatus = (typeof ALERT_STATUSES)[number];

// The list never carries `raw` (up to 32 KB each); the detail route does.
const BASE_COLUMNS = 'id, org_id, wazuh_alert_id, rule_id, rule_level, rule_description, agent_id, agent_name, agent_ip, severity, mitre_ids, wazuh_groups, location, raw_truncated, event_time, received_at, status, case_id';
// Network and firewall columns added by sql/2026-10-29_p24_wazuh_sources.sql. Until that runs,
// reads fall back to the columns above and the network filters answer 503 saying what is missing.
const LIST_COLUMNS = `${BASE_COLUMNS}, ${NETWORK_COLUMNS.join(', ')}`;
const P24_MISSING = 'Network and firewall fields are not available yet (run sql/2026-10-29_p24_wazuh_sources.sql)';
// Triage columns added by sql/2026-10-14_p3_secops_ai.sql. Until that runs, reads fall back to
// LIST_COLUMNS and the triage-only features answer 503 saying what is missing.
const TRIAGE_COLUMNS = `${LIST_COLUMNS}, assigned_to, acknowledged_at, acknowledged_by, triage_note, updated_at`;
const missingTriageColumns = (e: { message?: string } | null) => !!e && /assigned_to|acknowledged_|triage_note|updated_at|alert_events/.test(e.message ?? '');
const P3_MISSING = 'Alert triage fields are not available yet (run sql/2026-10-14_p3_secops_ai.sql)';

/** Records one triage change; a missing table only loses the history line, never the change. */
async function recordEvent(alertId: string, org: string, actor: string, action: string, from: string | null, to: string | null, details?: string) {
    const { error } = await getSupabase()!.from('alert_events').insert({ alert_id: alertId, org_id: org, actor, action, from_value: from, to_value: to, details: details?.slice(0, 1000) ?? null });
    if (error && !missingTriageColumns(error)) console.error('[alerts] event insert failed:', error.message.slice(0, 160));
}

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
    // Free text over rule description, rule id and agent name. Letters, digits, space . : _ - only,
    // so it can't break out of the PostgREST filter.
    const text = typeof q.q === 'string' && q.q.trim() ? q.q.trim() : null;
    if (text !== null && !/^[\w .:-]{1,100}$/.test(text)) { res.status(400).json({ error: 'q may hold letters, digits, spaces and . : _ - (up to 100)' }); return; }
    const assigned = typeof q.assigned === 'string' && q.assigned ? q.assigned : null; // 'me' | 'unassigned' | an email
    if (assigned !== null && assigned !== 'me' && assigned !== 'unassigned' && !/^[^\s,()"]{3,320}$/.test(assigned)) { res.status(400).json({ error: "assigned must be 'me', 'unassigned' or an email" }); return; }
    const inCase = q.case === 'linked' ? true : q.case === 'unlinked' ? false : null;
    // Network / firewall (P24). action: comma-separated pass|block|reject|...; ip: source or
    // destination; firewall=1: only alerts that carry a firewall action.
    const action = typeof q.action === 'string' && q.action ? q.action.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean) : null;
    if (action && (action.length > 10 || action.some((a) => !/^[a-z_-]{1,32}$/.test(a)))) { res.status(400).json({ error: 'action must be a comma-separated list such as block,reject' }); return; }
    const ip = typeof q.ip === 'string' && q.ip.trim() ? q.ip.trim() : null;
    if (ip !== null && isIP(ip) === 0) { res.status(400).json({ error: 'ip must be an IP address' }); return; }
    const protocol = typeof q.protocol === 'string' && q.protocol.trim() ? q.protocol.trim().toLowerCase() : null;
    if (protocol !== null && !/^[a-z0-9._-]{1,32}$/.test(protocol)) { res.status(400).json({ error: 'protocol must be a protocol name such as tcp' }); return; }
    const port = typeof q.port === 'string' && q.port.trim() ? Number(q.port) : null;
    if (port !== null && !(Number.isInteger(port) && port >= 0 && port <= 65535)) { res.status(400).json({ error: 'port must be 0-65535' }); return; }
    const firewallOnly = q.firewall === '1' || q.firewall === 'true';
    const networkFilter = !!(action || ip || protocol || port !== null || firewallOnly);
    const cursor = typeof q.cursor === 'string' && q.cursor ? decodeCursor(q.cursor) : null;
    if (severity === false) { res.status(400).json({ error: `severity must be from ${SEVERITIES.join(', ')}` }); return; }
    if (status === false) { res.status(400).json({ error: `status must be from ${ALERT_STATUSES.join(', ')}` }); return; }
    if (from === false || to === false) { res.status(400).json({ error: 'from / to must be ISO timestamps' }); return; }
    if (agent !== null && !AGENT_RE.test(agent)) { res.status(400).json({ error: 'agent must be an agent name or id' }); return; }
    if (typeof q.cursor === 'string' && q.cursor && !cursor) { res.status(400).json({ error: 'invalid cursor' }); return; }
    const limit = Math.min(Math.max(Number(q.limit) || 50, 1), 200);

    const build = (columns: string) => {
        let query = getSupabase()!.from('alerts').select(columns).eq('org_id', requestOrg(req));
        if (severity) query = query.in('severity', severity);
        if (status) query = query.in('status', status);
        if (from) query = query.gte('event_time', from);
        if (to) query = query.lte('event_time', to);
        if (agent) query = query.or(`agent_name.eq."${agent}",agent_id.eq."${agent}"`);
        if (text) query = query.or(`rule_description.ilike."*${text}*",rule_id.eq."${text}",agent_name.ilike."*${text}*"`);
        if (action) query = query.in('net_action', action);
        if (firewallOnly) query = query.not('net_action', 'is', null);
        if (ip) query = query.or(`src_ip.eq."${ip}",dst_ip.eq."${ip}"`);
        if (protocol) query = query.eq('protocol', protocol);
        if (port !== null) query = query.or(`src_port.eq.${port},dst_port.eq.${port}`);
        if (inCase === true) query = query.not('case_id', 'is', null);
        if (inCase === false) query = query.is('case_id', null);
        if (assigned === 'unassigned') query = query.is('assigned_to', null);
        else if (assigned) query = query.ilike('assigned_to', assigned === 'me' ? (req.user?.email ?? '') : assigned);
        if (cursor) query = query.or(`event_time.lt."${cursor.t}",and(event_time.eq."${cursor.t}",id.lt.${cursor.id})`);
        return query.order('event_time', { ascending: false }).order('id', { ascending: false }).limit(limit + 1);
    };
    let { data, error } = await build(TRIAGE_COLUMNS);
    if (missingNetworkColumns(error)) {
        if (networkFilter) { res.status(503).json({ error: P24_MISSING }); return; }
        ({ data, error } = await build(TRIAGE_COLUMNS.replace(LIST_COLUMNS, BASE_COLUMNS)));
    }
    if (missingTriageColumns(error)) {
        if (assigned) { res.status(503).json({ error: P3_MISSING }); return; }
        ({ data, error } = await build(BASE_COLUMNS));
    }
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
/** Minutes without a newly stored alert before pages warn that data may be stale — the same
 *  setting Platform Health uses (services/pipelineHealth.ts), so the two never disagree. */
export const staleAfterMinutes = () => (Number(process.env.ALERT_STALE_MINUTES) > 0 ? Number(process.env.ALERT_STALE_MINUTES) : 60);

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
            stale_after_minutes: staleAfterMinutes(),
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
    // R3.3C: Threat Intelligence correlation already computed by services/threatInfo.ts and
    // written by jobs/threatInfoJob.ts, just never surfaced here before now.
    const threat_intelligence = await tiDetailFor('alert', id);
    res.json({ alert: data, threat_intelligence });
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

    const { data, error } = await supabase.from('alerts').update({ status }).eq('id', id).eq('org_id', org).select(BASE_COLUMNS).maybeSingle();
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    if (!data) { res.status(404).json({ error: 'Alert not found' }); return; }

    await recordEvent(id, org, req.user?.email ?? 'unknown', 'status', before.status, status);
    logAudit({
        user: req.user?.email ?? 'unknown', action: 'ALERT_STATUS_CHANGED', resource: 'alert', resource_id: id,
        ip: req.ip ?? 'unknown', result: 'success', severity: 'info',
        details: `${org} alert ${String(before.wazuh_alert_id).slice(0, 60)}: ${before.status} -> ${status}`,
    });
    res.json({ success: true, alert: data });
});

// PATCH /api/alerts/:id { assigned_to?: email | null, acknowledged?: true, triage_note?: string | null }
// assigned_to must be an active account in the alert's organisation (or a staff account).
router.patch('/:id', requirePermission('alerts:triage'), async (req: AuthRequest, res) => {
    if (noStore(res)) return;
    const { id } = req.params;
    if (!isUuid(id)) { res.status(404).json({ error: 'Alert not found' }); return; }
    const body = req.body ?? {};
    const keys = Object.keys(body);
    if (!keys.length || keys.some((k) => !['assigned_to', 'acknowledged', 'triage_note'].includes(k))) {
        res.status(400).json({ error: 'Body may hold assigned_to (email or null), acknowledged (true) and triage_note (text or null)' });
        return;
    }
    if ('acknowledged' in body && body.acknowledged !== true) { res.status(400).json({ error: 'acknowledged can only be set to true' }); return; }
    if ('triage_note' in body && body.triage_note !== null && (typeof body.triage_note !== 'string' || body.triage_note.length > 4000)) { res.status(400).json({ error: 'triage_note must be text up to 4000 characters, or null' }); return; }
    if ('assigned_to' in body && body.assigned_to !== null && (typeof body.assigned_to !== 'string' || !/^[^\s,()"]{3,320}$/.test(body.assigned_to))) { res.status(400).json({ error: 'assigned_to must be an email or null' }); return; }

    const supabase = getSupabase()!;
    const org = requestOrg(req);
    const actor = req.user?.email ?? 'unknown';
    const { data: before, error: readErr } = await supabase.from('alerts').select('id, assigned_to, acknowledged_at, triage_note').eq('id', id).eq('org_id', org).maybeSingle();
    if (missingTriageColumns(readErr)) { res.status(503).json({ error: P3_MISSING }); return; }
    if (readErr) { res.status(502).json({ error: dbErrorMessage(readErr) }); return; }
    if (!before) { res.status(404).json({ error: 'Alert not found' }); return; }

    const patch: Record<string, unknown> = { updated_at: new Date().toISOString() };
    if ('assigned_to' in body) {
        let assignee: string | null = null;
        if (body.assigned_to) {
            // A real, enabled account — never a free-text name.
            const { data: member } = await supabase.from('platform_users').select('email, role, status, organisations(slug)').ilike('email', body.assigned_to).maybeSingle();
            const memberOrg = (member?.organisations as unknown as { slug?: string } | null)?.slug;
            if (!member || member.status === 'disabled' || (memberOrg !== org && !isStaffRole(member.role))) { res.status(400).json({ error: 'assigned_to must be an active user who can see this organisation' }); return; }
            assignee = String(member.email).toLowerCase();
        }
        patch.assigned_to = assignee;
    }
    if (body.acknowledged === true && !before.acknowledged_at) { patch.acknowledged_at = patch.updated_at; patch.acknowledged_by = actor; }
    if ('triage_note' in body) patch.triage_note = body.triage_note === null ? null : String(body.triage_note).trim() || null;

    const { data, error } = await supabase.from('alerts').update(patch).eq('id', id).eq('org_id', org).select(`${BASE_COLUMNS}, assigned_to, acknowledged_at, acknowledged_by, triage_note, updated_at`).maybeSingle();
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    if ('assigned_to' in patch && patch.assigned_to !== before.assigned_to) await recordEvent(id, org, actor, 'assign', before.assigned_to, patch.assigned_to as string | null);
    if (patch.acknowledged_at) await recordEvent(id, org, actor, 'acknowledge', null, actor);
    if ('triage_note' in patch && patch.triage_note !== before.triage_note) await recordEvent(id, org, actor, 'note', null, null, (patch.triage_note as string | null) ?? '(cleared)');
    logAudit({ user: actor, action: 'ALERT_TRIAGED', resource: 'alert', resource_id: id, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: keys.join(', ') });
    res.json({ success: true, alert: data });
});

// GET /api/alerts/:id/events — triage history, oldest first.
router.get('/:id/events', requirePermission('alerts:read'), async (req: AuthRequest, res) => {
    if (noStore(res)) return;
    const { id } = req.params;
    if (!isUuid(id)) { res.status(404).json({ error: 'Alert not found' }); return; }
    const org = requestOrg(req);
    const supabase = getSupabase()!;
    const { data: alert } = await supabase.from('alerts').select('id').eq('id', id).eq('org_id', org).maybeSingle();
    if (!alert) { res.status(404).json({ error: 'Alert not found' }); return; }
    const { data, error } = await supabase.from('alert_events').select('at, actor, action, from_value, to_value, details').eq('alert_id', id).eq('org_id', org).order('at', { ascending: true }).limit(500);
    if (missingTriageColumns(error)) { res.status(503).json({ error: P3_MISSING }); return; }
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    res.json({ events: data ?? [] });
});

// POST /api/alerts/:id/case — open a case for this alert, or return the case it already belongs
// to (automatic grouping, the SOAR engine, or an earlier promotion). Never a second case.
router.post('/:id/case', requirePermission('cases:write'), async (req: AuthRequest, res) => {
    if (noStore(res)) return;
    const { id } = req.params;
    if (!isUuid(id)) { res.status(404).json({ error: 'Alert not found' }); return; }
    const org = requestOrg(req);
    const actor = req.user?.email ?? 'unknown';
    const supabase = getSupabase()!;
    const { data: a, error } = await supabase.from('alerts').select('id, wazuh_alert_id, rule_id, rule_level, rule_description, agent_id, agent_name, severity, mitre_ids, case_id, raw, raw_truncated').eq('id', id).eq('org_id', org).maybeSingle();
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    if (!a) { res.status(404).json({ error: 'Alert not found' }); return; }
    if (a.case_id) {
        const { data: c } = await supabase.from('cases').select('id, case_number, title, status').eq('id', a.case_id).eq('org_id', org).maybeSingle();
        if (c) { res.json({ success: true, created: false, case: c, message: `Already in case ${c.case_number}` }); return; }
    }
    const srcip = !a.raw_truncated && a.raw && typeof a.raw === 'object' ? (a.raw as { data?: { srcip?: unknown } }).data?.srcip : null;
    const r = await createCase({
        org_id: org, source: 'alert', source_id: a.id, severity: isCaseSeverity(a.severity) ? a.severity : 'medium',
        title: `${a.rule_description ?? `Wazuh rule ${a.rule_id ?? 'unknown'}`} on ${a.agent_name ?? a.agent_id ?? 'unknown agent'}`,
        description: `Promoted from alert ${a.wazuh_alert_id} by ${actor}.`,
        agent_id: a.agent_id, agent_name: a.agent_name, source_ip: typeof srcip === 'string' ? srcip : null,
        rule_id: a.rule_id, rule_level: a.rule_level, mitre_technique: a.mitre_ids?.[0] ?? null, tags: ['from-alert'],
    }, actor);
    if (!r.ok) { res.status(r.status).json({ success: false, error: r.error }); return; }
    // .select('id') so an unexpected 0-row update (a race: something else already set this
    // alert's case_id between the read above and this write) is visible, not silently assumed
    // to have worked — the case itself was created either way, but the alert this request named
    // may not actually be the one now pointing at it.
    const link = await supabase.from('alerts').update({ case_id: r.case.id }).eq('id', id).eq('org_id', org).is('case_id', null).select('id');
    if (link.error) {
        console.error('[alerts] case link failed:', link.error.message.slice(0, 160));
        logAudit({ user: actor, action: 'ALERT_CASE_LINK_FAILED', resource: 'alert', resource_id: id, org_id: org, ip: req.ip ?? 'unknown', result: 'failed', severity: 'warning', details: `case ${r.case.case_number}: ${link.error.message.slice(0, 160)}` });
    } else if (!link.data || link.data.length === 0) {
        // case_id was no longer null when this write ran. Benign if a concurrent promote of the
        // same alert already linked it to this exact case — createCase()'s own dedup (the
        // cases_org_source_source_id_key unique index) guarantees a concurrent caller gets this
        // same case, never a different one — so only a mismatch is a real, reportable failure.
        const { data: now } = await supabase.from('alerts').select('case_id').eq('id', id).eq('org_id', org).maybeSingle();
        if (now?.case_id !== r.case.id) {
            console.error(`[alerts] case link for alert ${id} affected 0 rows and it is linked to a different case than expected`);
            logAudit({ user: actor, action: 'ALERT_CASE_LINK_FAILED', resource: 'alert', resource_id: id, org_id: org, ip: req.ip ?? 'unknown', result: 'failed', severity: 'warning', details: `case ${r.case.case_number}: alert is linked to ${now?.case_id ?? 'no case'}, not this one` });
        }
    }
    await recordEvent(id, org, actor, 'case_link', null, r.case.id, `Case ${r.case.case_number}`);
    if (r.created) await addTimeline(r.case.id, actor, `Opened from alert ${a.wazuh_alert_id}`);
    logAudit({ user: actor, action: 'ALERT_PROMOTED_TO_CASE', resource: 'alert', resource_id: id, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: `case ${r.case.case_number}` });
    res.status(r.created ? 201 : 200).json({ success: true, created: r.created, case: { id: r.case.id, case_number: r.case.case_number, title: r.case.title, status: r.case.status } });
});

export default router;
