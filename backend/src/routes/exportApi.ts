// Vendor export API (phase X1): GET /api/export/v1/events — a third-party XDR pulls stored alerts
// (the R2 `alerts` table) as JSON or NDJSON. Not behind requireAuth: the caller is a machine with
// its own credential from /api/admin/export-clients.
//
// Order of checks — each failure is final:
//   1. EXPORT_API_ENABLED must be exactly "true", else 503 (global kill switch, default off).
//   2. Per-IP limiter on every request (slows token guessing).
//   3. Bearer token -> SHA-256 -> export_clients row; hashes compared in constant time. Missing,
//      unknown or disabled token: 401 with the same generic body.
//   4. Per-client rate limit.
//   5. Source IP (req.ip, see below) must fall in the client's allowed_cidrs, else 403; an IP that
//      can't be determined is 403 (fail closed).
//   6. Only cursor, limit, format, org are accepted, each once; anything else is 400.
//   7. Org scope comes only from the client record; `org` may narrow it to a subset, anything
//      outside is 403.
//
// Source IP: index.ts sets `trust proxy` to 1, so Express takes req.ip from the right-most
// X-Forwarded-For entry — the one appended by the single proxy in front of the app (Railway's edge)
// — and ignores anything a client put further left. This assumes exactly one proxy hop that
// always appends the real peer address and that the app can't be reached except through it; if a
// CDN/WAF is ever put in front, the hop count changes and this must be revisited
// (docs/audit/PHASE_X1_REPORT.md).
//
// Paging: strict (event_time, id) ascending. The opaque cursor carries both values of the last row
// returned, and the next page starts strictly after that pair, so rows sharing a timestamp are
// never skipped or repeated.
//
// Every call by an identifiable client is written to export_access_log (no payloads). Logs carry
// the client id, row counts and cursors only — never a token or event content.

import { Router, type Request, type Response, type NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { timingSafeEqual } from 'crypto';
import { getSupabase } from '../services/geoEnrichment';
import { isUuid } from '../services/cases';
import { hashToken } from './exportClients';
import { normalizeIp, ipAllowed } from '../lib/cidr';
import { toExportEvent, EXPORT_SCHEMA_VERSION, type AlertRowForExport } from '../lib/exportEvent';

export const EXPORT_DEFAULT_LIMIT = 500;
export const EXPORT_MAX_LIMIT = 1000;
export const EXPORT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
export const EXPORT_CLIENT_RATE_PER_MIN = 60;
const ALLOWED_PARAMS = new Set(['cursor', 'limit', 'format', 'org']);
const COLUMNS = 'id, org_id, event_time, received_at, severity, rule_id, rule_level, rule_description, agent_id, agent_name, agent_ip, mitre_ids, location, raw, raw_truncated';

interface ExportClient {
    id: string;
    token_hash: string;
    org_ids: string[];
    allowed_cidrs: string[];
    enabled: boolean | null;
    redaction_profile: string | null;
}

const router = Router();
const UNAUTHORIZED = { error: 'Unauthorized' };

// 1. Kill switch.
router.use((_req, res, next) => {
    if (process.env.EXPORT_API_ENABLED !== 'true') { res.status(503).json({ error: 'Export API is disabled' }); return; }
    next();
});

// 2. Per source address, before authentication.
router.use(rateLimit({
    windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false,
    message: { error: 'Rate limit exceeded' },
}));

const clientOf = (res: Response) => res.locals.exportClient as ExportClient;

/** Writes one export_access_log row. Never throws; a logging failure is reported without content. */
async function logAccess(client: ExportClient | null, entry: { source_ip: string | null; org_ids: string[] | null; row_count: number; cursor_from: string | null; cursor_to: string | null; status_code: number }) {
    const supabase = getSupabase();
    if (!supabase || !client) return;
    try {
        const { error } = await supabase.from('export_access_log').insert({ client_id: client.id, ...entry });
        if (error) console.error(`[export] access log write failed for client ${client.id}: ${error.code ?? ''}`);
    } catch {
        console.error(`[export] access log write failed for client ${client.id}`);
    }
    console.log(`[export] client ${client.id} status ${entry.status_code} rows ${entry.row_count} cursor ${entry.cursor_from ?? '-'} -> ${entry.cursor_to ?? '-'}`);
}

async function refuse(res: Response, status: number, body: object, client: ExportClient | null, ip: string | null, orgs: string[] | null, cursor: string | null) {
    await logAccess(client, { source_ip: ip, org_ids: orgs, row_count: 0, cursor_from: cursor, cursor_to: null, status_code: status });
    res.status(status).json(body);
}

// 3. Authentication.
async function authenticate(req: Request, res: Response, next: NextFunction) {
    const m = /^Bearer\s+(\S+)$/i.exec(req.get('authorization') ?? '');
    if (!m) { res.status(401).json(UNAUTHORIZED); return; }
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Export store not configured' }); return; }
    const presented = hashToken(m[1]);
    const { data, error } = await supabase.from('export_clients')
        .select('id, token_hash, org_ids, allowed_cidrs, enabled, redaction_profile').eq('token_hash', presented).maybeSingle();
    if (error) { res.status(503).json({ error: 'Export store unavailable' }); return; }
    const client = data as ExportClient | null;
    const match = !!client && client.token_hash.length === presented.length
        && timingSafeEqual(Buffer.from(client.token_hash, 'utf8'), Buffer.from(presented, 'utf8'));
    if (!client || !match) { res.status(401).json(UNAUTHORIZED); return; }
    if (client.enabled === false) {
        await refuse(res, 401, UNAUTHORIZED, client, normalizeIp(req.ip), null, null);
        return;
    }
    res.locals.exportClient = client;
    next();
}

// 4. Per client.
const perClient = rateLimit({
    windowMs: 60_000,
    max: EXPORT_CLIENT_RATE_PER_MIN,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (_req, res) => `export-client:${clientOf(res).id}`,
    handler: (req, res) => { void refuse(res, 429, { error: 'Rate limit exceeded' }, clientOf(res), normalizeIp(req.ip), null, null); },
});

// Cursor: base64url JSON { t: event_time exactly as stored, id: uuid } of the last row returned.
const CURSOR_TIME = /^[\d\-T:.+Z ]{10,40}$/;
export const encodeCursor = (t: string, id: string) => Buffer.from(JSON.stringify({ t, id })).toString('base64url');
export function decodeCursor(c: string): { t: string; id: string } | null {
    if (!/^[A-Za-z0-9_-]{1,512}$/.test(c)) return null;
    try {
        const v = JSON.parse(Buffer.from(c, 'base64url').toString('utf8')) as { t?: unknown; id?: unknown };
        if (typeof v.t !== 'string' || typeof v.id !== 'string' || !CURSOR_TIME.test(v.t) || Number.isNaN(Date.parse(v.t)) || !isUuid(v.id)) return null;
        return { t: v.t, id: v.id };
    } catch {
        return null;
    }
}

router.get('/events', authenticate, perClient, async (req: Request, res: Response) => {
    const client = clientOf(res);
    const ip = normalizeIp(req.ip);
    const rawCursor = typeof req.query.cursor === 'string' ? req.query.cursor : null;

    // 5. Source address.
    if (!ip || !ipAllowed(ip, client.allowed_cidrs)) {
        await refuse(res, 403, { error: 'Forbidden' }, client, ip, null, rawCursor);
        return;
    }

    // 6. Parameters.
    for (const [k, v] of Object.entries(req.query)) {
        if (!ALLOWED_PARAMS.has(k) || typeof v !== 'string') {
            await refuse(res, 400, { error: `Unsupported or repeated parameter: ${ALLOWED_PARAMS.has(k) ? k : 'unknown'}. Allowed: cursor, limit, format, org` }, client, ip, null, rawCursor);
            return;
        }
    }
    const q = req.query as Record<string, string | undefined>;
    let limit = EXPORT_DEFAULT_LIMIT;
    if (q.limit !== undefined) {
        if (!/^\d{1,7}$/.test(q.limit) || Number(q.limit) < 1) { await refuse(res, 400, { error: 'limit must be a positive integer' }, client, ip, null, rawCursor); return; }
        limit = Math.min(Number(q.limit), EXPORT_MAX_LIMIT);
    }
    const format = q.format ?? 'json';
    if (format !== 'json' && format !== 'ndjson') { await refuse(res, 400, { error: 'format must be json or ndjson' }, client, ip, null, rawCursor); return; }
    const cursor = q.cursor !== undefined ? decodeCursor(q.cursor) : null;
    if (q.cursor !== undefined && !cursor) { await refuse(res, 400, { error: 'Malformed cursor' }, client, ip, null, rawCursor); return; }

    // 7. Org scope: the client's orgs, optionally narrowed.
    let orgs = client.org_ids;
    if (q.org !== undefined) {
        const wanted = [...new Set(q.org.split(',').map((o) => o.trim()))];
        if (wanted.some((o) => !o || !client.org_ids.includes(o))) { await refuse(res, 403, { error: 'Forbidden' }, client, ip, null, rawCursor); return; }
        orgs = wanted;
    }

    const supabase = getSupabase()!;
    let query = supabase.from('alerts').select(COLUMNS).in('org_id', orgs);
    if (cursor) query = query.or(`event_time.gt."${cursor.t}",and(event_time.eq."${cursor.t}",id.gt.${cursor.id})`);
    const { data, error } = await query.order('event_time', { ascending: true }).order('id', { ascending: true }).limit(limit + 1);
    if (error) { await refuse(res, 502, { error: 'Export store unavailable' }, client, ip, orgs, rawCursor); return; }

    const rows = (data ?? []) as unknown as AlertRowForExport[];
    const events: Record<string, unknown>[] = [];
    let bytes = 0;
    let cutBySize = false;
    for (const row of rows.slice(0, limit)) {
        const ev = toExportEvent(row, client.redaction_profile);
        const size = Buffer.byteLength(JSON.stringify(ev)) + 1;
        if (events.length > 0 && bytes + size > EXPORT_MAX_RESPONSE_BYTES) { cutBySize = true; break; }
        events.push(ev);
        bytes += size;
    }
    const last = events[events.length - 1] as { event_time: string; id: string } | undefined;
    const nextCursor = last ? encodeCursor(last.event_time, last.id) : (rawCursor ?? null);
    const hasMore = rows.length > limit || cutBySize;

    await logAccess(client, { source_ip: ip, org_ids: orgs, row_count: events.length, cursor_from: rawCursor, cursor_to: nextCursor, status_code: 200 });
    const touched = await supabase.from('export_clients').update({ last_used_at: new Date().toISOString() }).eq('id', client.id);
    if (touched.error) console.error(`[export] last_used_at update failed for client ${client.id}`);

    res.set('Cache-Control', 'no-store');
    if (format === 'ndjson') {
        res.type('application/x-ndjson');
        res.send(events.map((e) => JSON.stringify(e)).concat(JSON.stringify({ schema_version: EXPORT_SCHEMA_VERSION, next_cursor: nextCursor, has_more: hasMore })).join('\n') + '\n');
        return;
    }
    res.json({ schema_version: EXPORT_SCHEMA_VERSION, events, next_cursor: nextCursor, has_more: hasMore });
});

export default router;
