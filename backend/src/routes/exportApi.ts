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
// Paging: strictly by alerts.ingest_seq ascending (sql/2026-10-09_alerts_ingest_seq.sql) — the
// order rows were stored in, not event_time. Alerts are often stored after the fact (forwarder
// backfill, replay, overlap), and paging by event_time skipped any that arrived with an event_time
// behind a client's cursor. The opaque cursor carries the last ingest_seq returned; it is never a
// client-facing filter. event_time stays in each event.
//
// Settle window (EXPORT_SETTLE_SECONDS, default 60): a row is served only once its received_at is
// that old, and a page stops at the first row that isn't. Sequence values are assigned before a
// transaction commits, so two concurrent inserts can become visible out of order (seq 101 visible,
// seq 100 still committing). Without the window, a reader could return 101, move its cursor past
// 100 and never see it. Ingest writes are single short statements, so any row older than the
// window has committed (or never will); the guarantee holds as long as no insert into alerts takes
// longer than EXPORT_SETTLE_SECONDS to commit.
//
// Every call by an identifiable client is written to export_access_log (no payloads). Logs carry
// the client id, row counts and cursors only — never a token or event content.

import { Router, type Request, type Response, type NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { timingSafeEqual } from 'crypto';
import { getSupabase } from '../services/geoEnrichment';
import { hashToken } from './exportClients';
import { normalizeIp, ipAllowed } from '../lib/cidr';
import { toExportEvent, EXPORT_SCHEMA_VERSION, type AlertRowForExport } from '../lib/exportEvent';

export const EXPORT_DEFAULT_LIMIT = 500;
export const EXPORT_MAX_LIMIT = 1000;
export const EXPORT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
export const EXPORT_CLIENT_RATE_PER_MIN = 60;
const ALLOWED_PARAMS = new Set(['cursor', 'limit', 'format', 'org']);
const COLUMNS = 'id, ingest_seq, org_id, event_time, received_at, severity, rule_id, rule_level, rule_description, agent_id, agent_name, agent_ip, mitre_ids, location, raw, raw_truncated';

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

// Cursor: base64url JSON { s: "<ingest_seq>" } of the last row returned — opaque to the client.
// ingest_seq is a bigint, carried as a decimal string so no precision is lost above 2^53.
const INT8_MAX = 9223372036854775807n;
export const encodeCursor = (seq: string | number) => Buffer.from(JSON.stringify({ s: String(seq) })).toString('base64url');
export function decodeCursor(c: string): string | null {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(c)) return null;
    try {
        const v = JSON.parse(Buffer.from(c, 'base64url').toString('utf8')) as { s?: unknown };
        if (!v || typeof v !== 'object' || Object.keys(v).length !== 1 || typeof v.s !== 'string' || !/^\d{1,19}$/.test(v.s)) return null;
        const n = BigInt(v.s);
        return n <= INT8_MAX ? n.toString() : null;
    } catch {
        return null;
    }
}

/** EXPORT_SETTLE_SECONDS (default 60, 0-3600): how old received_at must be before a row is served. */
export function settleSeconds(): number {
    const raw = process.env.EXPORT_SETTLE_SECONDS;
    if (raw === undefined || raw === '') return 60;
    return /^\d{1,4}$/.test(raw) && Number(raw) <= 3600 ? Number(raw) : 60;
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
    if (cursor) query = query.gt('ingest_seq', cursor);
    const { data, error } = await query.order('ingest_seq', { ascending: true }).limit(limit + 1);
    if (error) { await refuse(res, 502, { error: 'Export store unavailable' }, client, ip, orgs, rawCursor); return; }

    const rows = (data ?? []) as unknown as (AlertRowForExport & { ingest_seq: number | string })[];
    // Settle window: serve rows in ingest_seq order only up to the first one received less than
    // settleSeconds() ago. Sequence numbers are taken before commit, so a lower number can become
    // visible after a higher one; stopping at the first unsettled row (instead of skipping it) keeps
    // the cursor from moving past a number that may still be committing.
    const cutoff = Date.now() - settleSeconds() * 1000;
    const settledCount = (() => {
        const i = rows.findIndex((r) => r.received_at !== null && r.received_at !== undefined && Date.parse(r.received_at) > cutoff);
        return i === -1 ? rows.length : i;
    })();
    const events: Record<string, unknown>[] = [];
    let lastSeq: string | null = null;
    let bytes = 0;
    let cutBySize = false;
    for (const row of rows.slice(0, Math.min(limit, settledCount))) {
        const ev = toExportEvent(row, client.redaction_profile);
        const size = Buffer.byteLength(JSON.stringify(ev)) + 1;
        if (events.length > 0 && bytes + size > EXPORT_MAX_RESPONSE_BYTES) { cutBySize = true; break; }
        events.push(ev);
        lastSeq = String(row.ingest_seq);
        bytes += size;
    }
    const nextCursor = lastSeq !== null ? encodeCursor(lastSeq) : (rawCursor ?? null);
    // More is available right now only if settled rows remain beyond this page.
    const hasMore = cutBySize || settledCount > limit;

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
