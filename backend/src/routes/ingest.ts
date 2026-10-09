// Machine ingest of Wazuh alerts (phase R2). Called by the SOAR forwarder (infra/soar/soar.py
// --forward) on the Wazuh manager — never by a user, so it is NOT behind requireAuth:
//
//   Authorization: Bearer <ALERT_INGEST_TOKEN>   compared in constant time
//   ALERT_INGEST_TOKEN unset                     503 for every request (fail closed)
//
// POST /api/ingest/alerts  { alerts: [ … up to 100 … ] }  ->  { accepted, duplicates, rejected }
// GET  /api/ingest/alerts/watermark                       ->  newest event_time / received_at per org
//
// Trust rules — the payload is untrusted log content:
//   • org, severity and status are never read from the payload. Org comes only from
//     wazuh_group_org_map via the agent's groups (none mapped -> rejected `unmapped_group`; groups
//     mapped to more than one org -> rejected `ambiguous_org`). Severity is computed from
//     rule.level with lib/severity.ts. Status starts at the table default ('new').
//   • Each alert is validated on its own; an invalid one is rejected (`invalid: <field>`) without
//     failing the batch, so one bad alert can't stall the forwarder's cursor.
//   • raw is capped at 32 KB per alert (truncated and flagged with raw_truncated). The body is
//     capped at 1 MB. NUL characters, which Postgres text/jsonb refuse, are stripped.
//   • Content is stored, never executed or interpolated; nothing here logs a token or a payload.
// Duplicates (same org + Wazuh alert id) are ignored and counted, so the forwarder can safely
// resend after an outage.
//
// Mounted in index.ts BEFORE the global express.json() (100 KB limit) and the /api limiter: this
// router has its own 1 MB parser and its own rate limit.

import express, { Router, type Request, type Response, type NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { createHash, timingSafeEqual } from 'crypto';
import { z } from 'zod';
import { getSupabase } from '../services/geoEnrichment';
import { severityFromLevel } from '../lib/severity';

export const INGEST_MAX_BATCH = 100;
export const INGEST_BODY_LIMIT = '1mb';
export const RAW_MAX_BYTES = 32 * 1024;

const router = Router();

router.use(rateLimit({
    windowMs: 60 * 1000,
    max: 120, // 120 batches of up to 100 alerts a minute per source address
    message: { error: 'Ingest rate limit exceeded' },
    standardHeaders: true,
    legacyHeaders: false,
}));

const digest = (s: string) => createHash('sha256').update(s).digest();

/** Bearer ALERT_INGEST_TOKEN, compared in constant time (hashed first, so length doesn't leak). */
function requireIngestToken(req: Request, res: Response, next: NextFunction) {
    const expected = process.env.ALERT_INGEST_TOKEN ?? '';
    if (!expected) {
        res.status(503).json({ error: 'Alert ingest is not configured (ALERT_INGEST_TOKEN is not set)' });
        return;
    }
    const m = /^Bearer\s+(.+)$/i.exec(req.get('authorization') ?? '');
    if (!m || !timingSafeEqual(digest(m[1].trim()), digest(expected))) {
        res.status(401).json({ error: 'Invalid or missing ingest token' });
        return;
    }
    next();
}

router.use(requireIngestToken);
router.use(express.json({ limit: INGEST_BODY_LIMIT }));

// ── Validation ───────────────────────────────────────────────────────────────────────────────
const shortStr = (max: number) => z.string().max(max);
const AlertIn = z.object({
    id: z.string().min(1).max(128),
    timestamp: z.string().min(1).max(64),
    rule: z.object({
        id: z.union([z.string().max(64), z.number()]).optional(),
        level: z.number().int().min(0).max(16),
        description: shortStr(2000).optional(),
        mitre: z.object({ id: z.array(shortStr(32)).max(50).optional() }).optional(),
    }),
    agent: z.object({
        id: shortStr(64).optional(),
        name: shortStr(256).optional(),
        ip: shortStr(64).optional(),
    }).optional(),
    agent_groups: z.array(z.string().min(1).max(128)).max(64),
    location: shortStr(1024).optional(),
    raw: z.unknown().optional(),
});
type AlertIn = z.infer<typeof AlertIn>;

const Batch = z.object({ alerts: z.array(z.unknown()).min(1).max(INGEST_MAX_BATCH) });

const noNul = (s: string) => s.replace(/\u0000/g, '');
const opt = (s: string | undefined | null) => (s ? noNul(s) : null);

/** Wazuh writes "+0000"; ISO-8601 parsers want "+00:00". */
function parseTime(ts: string): string | null {
    const t = Date.parse(ts.replace(/([+-]\d{2})(\d{2})$/, '$1:$2'));
    return Number.isNaN(t) ? null : new Date(t).toISOString();
}

/** raw as stored: NULs stripped, at most RAW_MAX_BYTES of JSON, truncation flagged. */
export function capRaw(raw: unknown): { raw: unknown; truncated: boolean } {
    if (raw === undefined) return { raw: null, truncated: false };
    const json = JSON.stringify(raw, (_k, v) => (typeof v === 'string' ? noNul(v) : v)) ?? 'null';
    const bytes = Buffer.byteLength(json);
    if (bytes <= RAW_MAX_BYTES) return { raw: JSON.parse(json), truncated: false };
    // Too big: keep a prefix as a string (never re-parsed), plus the original size.
    const preview = Buffer.from(json).subarray(0, RAW_MAX_BYTES - 256).toString('utf8').replace(/�+$/, '');
    return { raw: { truncated: true, original_bytes: bytes, preview }, truncated: true };
}

interface Reject { reason: string; wazuh_alert_id: string | null; wazuh_groups: string[] | null }

router.post('/alerts', async (req: Request, res: Response) => {
    const batch = Batch.safeParse(req.body);
    if (!batch.success) {
        res.status(400).json({ error: `Body must be { alerts: [...] } with 1-${INGEST_MAX_BATCH} alerts` });
        return;
    }
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Alert store not configured' }); return; }

    const rejects: Reject[] = [];
    const valid: { a: AlertIn; eventTime: string }[] = [];
    for (const item of batch.data.alerts) {
        const parsed = AlertIn.safeParse(item);
        const idGuess = typeof (item as { id?: unknown })?.id === 'string' ? String((item as { id: string }).id).slice(0, 128) : null;
        if (!parsed.success) {
            const field = parsed.error.issues[0]?.path.join('.') || 'alert';
            rejects.push({ reason: `invalid: ${field}`.slice(0, 120), wazuh_alert_id: idGuess && noNul(idGuess), wazuh_groups: null });
            continue;
        }
        const eventTime = parseTime(parsed.data.timestamp);
        if (!eventTime) {
            rejects.push({ reason: 'invalid: timestamp', wazuh_alert_id: noNul(parsed.data.id), wazuh_groups: parsed.data.agent_groups.map(noNul) });
            continue;
        }
        valid.push({ a: parsed.data, eventTime });
    }

    // Group -> org, for every group named in the batch.
    const groups = [...new Set(valid.flatMap((v) => v.a.agent_groups.map(noNul)))];
    const groupOrg = new Map<string, string>();
    if (groups.length > 0) {
        const { data, error } = await supabase.from('wazuh_group_org_map').select('wazuh_group, org_id').in('wazuh_group', groups);
        if (error) { res.status(503).json({ error: 'Group map unavailable — retry later' }); return; }
        for (const r of data ?? []) groupOrg.set(r.wazuh_group, r.org_id);
    }

    const rows = new Map<string, Record<string, unknown>>();
    let mapped = 0; // alerts that resolved to exactly one org (in-batch repeats included)
    for (const { a, eventTime } of valid) {
        const agentGroups = a.agent_groups.map(noNul);
        const orgs = [...new Set(agentGroups.map((g) => groupOrg.get(g)).filter((o): o is string => !!o))];
        if (orgs.length !== 1) {
            rejects.push({ reason: orgs.length === 0 ? 'unmapped_group' : 'ambiguous_org', wazuh_alert_id: noNul(a.id), wazuh_groups: agentGroups });
            continue;
        }
        mapped++;
        const { raw, truncated } = capRaw(a.raw);
        const key = `${orgs[0]}\n${a.id}`;
        if (rows.has(key)) continue; // same alert twice in one batch: counted as a duplicate below
        rows.set(key, {
            org_id: orgs[0],
            wazuh_alert_id: noNul(a.id),
            rule_id: a.rule.id !== undefined ? noNul(String(a.rule.id)) : null,
            rule_level: a.rule.level,
            rule_description: opt(a.rule.description),
            agent_id: opt(a.agent?.id),
            agent_name: opt(a.agent?.name),
            agent_ip: opt(a.agent?.ip),
            severity: severityFromLevel(a.rule.level),
            mitre_ids: a.rule.mitre?.id?.map(noNul) ?? null,
            wazuh_groups: agentGroups,
            location: opt(a.location),
            raw,
            raw_truncated: truncated,
            event_time: eventTime,
        });
    }

    let accepted = 0;
    if (rows.size > 0) {
        const { data, error } = await supabase
            .from('alerts')
            .upsert([...rows.values()], { onConflict: 'org_id,wazuh_alert_id', ignoreDuplicates: true })
            .select('id');
        if (error) {
            console.error('[ingest] alert insert failed:', error.code ?? '', error.message?.slice(0, 200));
            res.status(502).json({ error: 'Alert store write failed — retry later' });
            return;
        }
        accepted = (data ?? []).length;
    }
    // Already stored (same org + Wazuh alert id), or repeated within this batch.
    const duplicates = mapped - accepted;

    if (rejects.length > 0) {
        const { error } = await supabase.from('alert_ingest_rejects').insert(rejects);
        if (error) console.error(`[ingest] could not record ${rejects.length} rejected alert(s):`, error.message?.slice(0, 200));
    }
    console.log(`[ingest] batch of ${batch.data.alerts.length}: accepted ${accepted}, duplicates ${duplicates}, rejected ${rejects.length}`);
    res.json({ accepted, duplicates, rejected: rejects.length });
});

// GET /api/ingest/alerts/watermark — newest stored event per org (every org in the group map),
// so the forwarder or an operator can spot a gap. null = nothing stored yet for that org.
router.get('/alerts/watermark', async (_req: Request, res: Response) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Alert store not configured' }); return; }
    const { data: map, error } = await supabase.from('wazuh_group_org_map').select('org_id');
    if (error) { res.status(503).json({ error: 'Group map unavailable' }); return; }
    const orgs = [...new Set((map ?? []).map((m) => m.org_id as string))].sort();
    const out = await Promise.all(orgs.map(async (org) => {
        const { data } = await supabase.from('alerts').select('event_time, received_at')
            .eq('org_id', org).order('event_time', { ascending: false }).limit(1).maybeSingle();
        return { org_id: org, latest_event_time: data?.event_time ?? null, latest_received_at: data?.received_at ?? null };
    }));
    res.json({ orgs: out, generated_at: new Date().toISOString() });
});

// Body-parser failures (too large, malformed JSON): a short JSON error, never the body.
router.use((err: { status?: number; type?: string }, _req: Request, res: Response, next: NextFunction) => {
    if (err?.type === 'entity.too.large' || err?.status === 413) { res.status(413).json({ error: `Body larger than ${INGEST_BODY_LIMIT}` }); return; }
    if (err?.type === 'entity.parse.failed') { res.status(400).json({ error: 'Body is not valid JSON' }); return; }
    next(err);
});

export default router;
