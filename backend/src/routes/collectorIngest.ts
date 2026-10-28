// Collector V1 ingestion gateway (phase P31). Called by the Vector appliance (infra/novrsoc-
// collector/) running at a client site — never by a user, so it is NOT behind requireAuth, and
// deliberately NOT routes/ingest.ts's single shared ALERT_INGEST_TOKEN: each collector has its
// own revocable identity (lib/collectorAuth.ts), because a fleet of client-site appliances needs
// per-collector revocation, not one secret shared by everything that forwards logs.
//
//   Authorization: Bearer <collectorId>.<secret>
//
// POST /api/collectors/ingest/heartbeat  { vector_version?, events_received, events_forwarded,
//                                           delivery_failures, buffer_pct?, sources: [...] }
// POST /api/collectors/ingest/events     { events: [ { source_key, host?, event_time?, message } ] }
//
// Trust rules — mirrors routes/ingest.ts exactly, for the same reasons:
//   • org_id is NEVER read from the request body. It comes only from the authenticated collector
//     row (authenticateCollector() resolves collectorId -> org_id server-side). A collector that
//     is revoked, or still "enrolling" past its enrollment window, authenticates to nothing.
//   • Each event is validated on its own; one malformed event is rejected without failing the
//     whole batch (events_log's own forwarder cursor would otherwise stall on one bad line).
//   • message is capped at 32 KB (services/collectors.ts's capMessage(), the same cap and
//     reasoning as routes/ingest.ts's capRaw()). NUL bytes are stripped (Postgres refuses them).
//   • Duplicates (same collector + hash of source+message) are ignored and counted — safe to
//     resend after a network outage, the same idempotency guarantee alerts already have.
//   • These are raw, unscored logs, not alerts — nothing here writes to the `alerts` table or
//     calls the Wazuh Manager API. See sql/2026-11-12_p31_collector_v1.sql's header.
//
// Acknowledgement: a 2xx answer means every event in the batch is durably stored or rejected as
// invalid (not merely "received") — a failed write answers 502/503 so the collector's own local
// buffer keeps the batch and retries, exactly like the alert forwarder's contract.
//
// Mounted in index.ts BEFORE the global JSON parser and the /api limiter: its own parser, own
// rate limit (keyed by collector id, not source IP — many collectors may share a NAT gateway).

import express, { Router, type Request, type Response, type NextFunction } from 'express';
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import { z } from 'zod';
import { authenticateCollector, recordHeartbeat, storeLogEvents, type LogEventInput } from '../services/collectors';
import { parseCredential } from '../lib/collectorAuth';

export const INGEST_BODY_LIMIT = '2mb';
export const EVENTS_MAX_BATCH = 500;

const router = Router();

interface AuthedRequest extends Request { collector?: { id: string; org_id: string } }

router.use(rateLimit({
    windowMs: 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Collector ingest rate limit exceeded' },
    // Keyed by collector identity, not source IP: several collectors can sit behind one NAT
    // gateway at a client site, and an IP-keyed limiter would wrongly throttle all of them
    // together. Falls back to the IP for an unauthenticated request (nothing else identifies it).
    keyGenerator: (req) => parseCredential(req.get('authorization'))?.collectorId ?? ipKeyGenerator(req.ip ?? ''),
}));

async function requireCollector(req: AuthedRequest, res: Response, next: NextFunction) {
    const cred = parseCredential(req.get('authorization'));
    if (!cred) { res.status(401).json({ error: 'Missing or malformed collector credential' }); return; }
    const result = await authenticateCollector(cred.collectorId, cred.secret);
    if ('error' in result) {
        const message = {
            not_found: 'Unknown collector',
            revoked: 'This collector has been revoked',
            enrollment_expired: 'Enrollment window expired — re-enroll this collector',
            bad_secret: 'Invalid collector credential',
        }[result.error];
        res.status(401).json({ error: message });
        return;
    }
    req.collector = { id: result.id, org_id: result.org_id };
    next();
}

router.use(requireCollector);

const SourceIn = z.object({ source_key: z.string().min(1).max(128), kind: z.enum(['syslog_tcp', 'syslog_udp', 'syslog_tls', 'wef_bridge', 'file', 'other']), label: z.string().max(256).optional(), events_total: z.number().int().min(0).optional() });
const HeartbeatIn = z.object({
    vector_version: z.string().max(64).optional(),
    events_received: z.number().int().min(0),
    events_forwarded: z.number().int().min(0),
    delivery_failures: z.number().int().min(0),
    buffer_pct: z.number().min(0).max(100).optional(),
    sources: z.array(SourceIn).max(64).default([]),
});

router.post('/heartbeat', express.json({ limit: INGEST_BODY_LIMIT }), async (req: AuthedRequest, res: Response) => {
    const parsed = HeartbeatIn.safeParse(req.body);
    if (!parsed.success) { res.status(400).json({ error: `Invalid heartbeat: ${parsed.error.issues[0]?.path.join('.') ?? 'body'}` }); return; }
    const r = await recordHeartbeat(req.collector!.id, { ...parsed.data, ip: req.ip ?? 'unknown' });
    if (!r.ok) { res.status(502).json({ error: 'Could not record heartbeat — retry later' }); return; }
    res.json({ ok: true, received_at: new Date().toISOString() });
});

const EventIn = z.object({
    source_key: z.string().min(1).max(128),
    host: z.string().max(256).optional(),
    event_time: z.string().datetime({ offset: true }).optional(),
    message: z.string().min(1).max(200_000), // generous pre-cap ceiling; capMessage() caps to 32KB for storage
});

/**
 * Accepts the three batch shapes a real HTTP sink can plausibly produce, rather than assuming
 * one exact wire format: `{ events: [...] }` (what a hand-written or test client sends), a bare
 * JSON array (what Vector's `http` sink sends with `encoding.codec = "json"` framing), or
 * newline-delimited JSON objects (what the same sink produces with
 * `encoding.framing.method = "newline_delimited"`, config/vector.toml's setting). Returns the
 * parsed items plus a count of lines/entries that were not even valid JSON — counted as invalid
 * below, same as an item that parses but fails schema validation.
 */
function parseBatch(raw: string): { items: unknown[]; unparseable: number } | null {
    const trimmed = raw.trim();
    if (!trimmed) return null;
    try {
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed)) return { items: parsed, unparseable: 0 };
        if (parsed && typeof parsed === 'object' && Array.isArray((parsed as { events?: unknown }).events)) return { items: (parsed as { events: unknown[] }).events, unparseable: 0 };
        return null;
    } catch {
        const lines = trimmed.split('\n').map((l) => l.trim()).filter(Boolean);
        const items: unknown[] = [];
        let unparseable = 0;
        for (const line of lines) {
            try { items.push(JSON.parse(line)); } catch { unparseable++; }
        }
        return items.length || unparseable ? { items, unparseable } : null;
    }
}

router.post('/events', express.text({ type: '*/*', limit: INGEST_BODY_LIMIT }), async (req: AuthedRequest, res: Response) => {
    const batch = parseBatch(req.body);
    if (!batch || batch.items.length + batch.unparseable === 0 || batch.items.length + batch.unparseable > EVENTS_MAX_BATCH) {
        res.status(400).json({ error: `Body must be { events: [...] }, a bare array, or newline-delimited JSON objects, with 1-${EVENTS_MAX_BATCH} events` });
        return;
    }

    const valid: LogEventInput[] = [];
    let invalid = batch.unparseable;
    for (const item of batch.items) {
        const parsed = EventIn.safeParse(item);
        if (!parsed.success) { invalid++; continue; }
        valid.push(parsed.data);
    }

    let accepted = 0;
    if (valid.length > 0) {
        const r = await storeLogEvents(req.collector!.id, req.collector!.org_id, valid);
        if ('error' in r) { res.status(502).json({ error: 'Log store write failed — retry later' }); return; }
        accepted = r.accepted;
    }
    const duplicates = valid.length - accepted;
    res.json({ accepted, duplicates, invalid });
});

// Body-parser failures (too large, malformed JSON): a short JSON error, never the body.
router.use((err: { status?: number; type?: string }, _req: Request, res: Response, next: NextFunction) => {
    if (err?.type === 'entity.too.large' || err?.status === 413) { res.status(413).json({ error: `Body larger than ${INGEST_BODY_LIMIT}` }); return; }
    if (err?.type === 'entity.parse.failed') { res.status(400).json({ error: 'Body is not valid JSON' }); return; }
    next(err);
});

export default router;
