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
//   • Syslog the manager receives itself (OPNsense and other agentless senders, phase P24) is
//     agent 000 with no group: its org comes from wazuh_source_org_map by the sender address in
//     `location` (not mapped -> rejected `unmapped_source`). Only agent 000 is ever matched by
//     location — an enrolled agent's location is a log file path that every agent shares.
//   • Network and firewall fields (src/dst IP and port, protocol, action, direction, interface,
//     decoder, syslog host) are extracted from the alert itself (lib/alertNetwork.ts), before raw
//     is capped, so a truncated raw still has them.
//   • Each alert is validated on its own; an invalid one is rejected (`invalid: <field>`) without
//     failing the batch, so one bad alert can't stall the forwarder's cursor.
//   • raw is capped at 32 KB per alert (truncated and flagged with raw_truncated). The body is
//     capped at 1 MB. NUL characters, which Postgres text/jsonb refuse, are stripped.
//   • Content is stored, never executed or interpolated; nothing here logs a token or a payload.
// Duplicates (same org + Wazuh alert id) are ignored and counted, so the forwarder can safely
// resend after an outage.
//
// Acknowledgement: a 2xx answer means every alert in the batch is durably stored, quarantined, or
// refused as invalid. A failed alert or quarantine write answers 502 / 503, so the forwarder keeps
// its checkpoint and resends the batch (it never advances past an unacknowledged batch).
//
// Mounted in index.ts BEFORE the global express.json() (100 KB limit) and the /api limiter: this
// router has its own 1 MB parser and its own rate limit.

import express, { Router, type Request, type Response, type NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { createHash, timingSafeEqual } from 'crypto';
import { z } from 'zod';
import { getSupabase } from '../services/geoEnrichment';
import { severityFromLevel } from '../lib/severity';
import { alertNetwork, missingNetworkColumns, withoutNetworkColumns } from '../lib/alertNetwork';

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

/** The alerts row for a validated alert, minus org_id (resolved separately from its groups). */
function alertRowWithoutOrg(a: AlertIn, eventTime: string): Record<string, unknown> {
    const { raw, truncated } = capRaw(a.raw);
    return {
        wazuh_alert_id: noNul(a.id),
        rule_id: a.rule.id !== undefined ? noNul(String(a.rule.id)) : null,
        rule_level: a.rule.level,
        rule_description: opt(a.rule.description),
        agent_id: opt(a.agent?.id),
        agent_name: opt(a.agent?.name),
        agent_ip: opt(a.agent?.ip),
        severity: severityFromLevel(a.rule.level),
        mitre_ids: a.rule.mitre?.id?.map(noNul) ?? null,
        wazuh_groups: a.agent_groups.map(noNul),
        location: opt(a.location),
        raw,
        raw_truncated: truncated,
        event_time: eventTime,
        ...alertNetwork(a.raw),
    };
}

/** The manager itself: syslog it receives (OPNsense) carries this agent id and no group. */
export const MANAGER_AGENT_ID = '000';

/**
 * location -> org for the given syslog senders. A missing table (P24 SQL not applied yet) is an
 * empty map; any other failure is an error so the batch is retried instead of quarantined.
 */
export async function sourceOrgs(supabase: NonNullable<ReturnType<typeof getSupabase>>, locations: string[]): Promise<Map<string, string> | { error: string }> {
    const out = new Map<string, string>();
    if (locations.length === 0) return out;
    const { data, error } = await supabase.from('wazuh_source_org_map').select('location, org_id').in('location', locations);
    if (error) return /wazuh_source_org_map/.test(error.message ?? '') ? out : { error: error.message ?? 'source map unreadable' };
    for (const r of data ?? []) out.set(String(r.location), String(r.org_id));
    return out;
}

/** Upsert alerts rows; before the P24 columns exist, the same rows without them. */
export async function insertAlerts(supabase: NonNullable<ReturnType<typeof getSupabase>>, rows: Record<string, unknown>[]) {
    const go = (r: Record<string, unknown>[]) => supabase.from('alerts').upsert(r, { onConflict: 'org_id,wazuh_alert_id', ignoreDuplicates: true }).select('id');
    const first = await go(rows);
    if (first.error && missingNetworkColumns(first.error)) return go(rows.map(withoutNetworkColumns));
    return first;
}

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

    // Sender address -> org, for agent-000 alerts that no group could place.
    const senderLocations = [...new Set(valid
        .filter((v) => v.a.agent?.id === MANAGER_AGENT_ID && v.a.location && !v.a.agent_groups.some((g) => groupOrg.has(noNul(g))))
        .map((v) => noNul(v.a.location!)))];
    const senders = await sourceOrgs(supabase, senderLocations);
    if ('error' in senders) { res.status(503).json({ error: 'Source map unavailable — retry later' }); return; }

    const rows = new Map<string, Record<string, unknown>>();
    // Unmapped / ambiguous alerts are kept without an org so they can be replayed once the group
    // is mapped (services/alertQuarantine.ts). Keyed by Wazuh alert id: a retry overwrites.
    const quarantine = new Map<string, Record<string, unknown>>();
    let mapped = 0; // alerts that resolved to exactly one org (in-batch repeats included)
    for (const { a, eventTime } of valid) {
        const agentGroups = a.agent_groups.map(noNul);
        const orgs = [...new Set(agentGroups.map((g) => groupOrg.get(g)).filter((o): o is string => !!o))];
        const isManager = a.agent?.id === MANAGER_AGENT_ID;
        if (orgs.length === 0 && isManager && a.location) {
            const sender = senders.get(noNul(a.location));
            if (sender) orgs.push(sender);
        }
        if (orgs.length !== 1) {
            const reason = orgs.length > 1 ? 'ambiguous_org' : isManager ? 'unmapped_source' : 'unmapped_group';
            rejects.push({ reason, wazuh_alert_id: noNul(a.id), wazuh_groups: agentGroups });
            quarantine.set(noNul(a.id), {
                wazuh_alert_id: noNul(a.id), wazuh_groups: agentGroups, reason,
                alert: alertRowWithoutOrg(a, eventTime), last_seen_at: new Date().toISOString(),
            });
            continue;
        }
        mapped++;
        const key = `${orgs[0]}\n${a.id}`;
        if (rows.has(key)) continue; // same alert twice in one batch: counted as a duplicate below
        rows.set(key, { org_id: orgs[0], ...alertRowWithoutOrg(a, eventTime) });
    }

    let accepted = 0;
    if (rows.size > 0) {
        const { data, error } = await insertAlerts(supabase, [...rows.values()]);
        if (error) {
            console.error('[ingest] alert insert failed:', error.code ?? '', error.message?.slice(0, 200));
            res.status(502).json({ error: 'Alert store write failed — retry later' });
            return;
        }
        accepted = (data ?? []).length;
    }
    // Already stored (same org + Wazuh alert id), or repeated within this batch.
    const duplicates = mapped - accepted;

    // An unmapped or ambiguous alert is recoverable only from the quarantine. Unless every one of
    // them is confirmed stored there, answer 503: the forwarder then keeps its checkpoint and
    // resends the batch. A 200 here would let it move past alerts that then exist nowhere but the
    // indexer. Every write in this handler is idempotent, so the resend is harmless.
    let quarantined = 0;
    if (quarantine.size > 0) {
        const put = (q: Record<string, unknown>[]) => supabase.from('alert_quarantine').upsert(q, { onConflict: 'wazuh_alert_id' }).select('wazuh_alert_id');
        let { data, error } = await put([...quarantine.values()]);
        // Before the P24 SQL the reason check doesn't know unmapped_source: keep them as unmapped_group.
        if (error && /reason|check constraint/i.test(error.message ?? '')) {
            ({ data, error } = await put([...quarantine.values()].map((q) => (q.reason === 'unmapped_source' ? { ...q, reason: 'unmapped_group' } : q))));
        }
        const kept = new Set((data ?? []).map((r) => String(r.wazuh_alert_id)));
        const missing = [...quarantine.keys()].filter((id) => !kept.has(id));
        if (error || missing.length > 0) {
            console.error(`[ingest] could not quarantine ${error ? quarantine.size : missing.length} of ${quarantine.size} alert(s) — batch refused for retry:`, (error?.message ?? 'rows not confirmed').slice(0, 200));
            res.status(503).json({ error: 'Alert quarantine unavailable — retry later' });
            return;
        }
        quarantined = quarantine.size;
    }
    // Reasons only (no payload): failing to record them loses no alert, so it doesn't fail the batch.
    if (rejects.length > 0) {
        const { error } = await supabase.from('alert_ingest_rejects').insert(rejects);
        if (error) console.error(`[ingest] could not record ${rejects.length} rejected alert(s):`, error.message?.slice(0, 200));
    }
    // invalid = refused by validation; no organisation can ever be derived from them, so they are
    // not quarantined (their reasons are in alert_ingest_rejects). The forwarder logs these. The
    // rest of `rejected` is quarantined.
    const invalid = rejects.filter((r) => r.reason.startsWith('invalid')).length;
    console.log(`[ingest] batch of ${batch.data.alerts.length}: accepted ${accepted}, duplicates ${duplicates}, rejected ${rejects.length} (quarantined ${quarantined}, invalid ${invalid})`);
    res.json({ accepted, duplicates, rejected: rejects.length, quarantined, invalid });
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
