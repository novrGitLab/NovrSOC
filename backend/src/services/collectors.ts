// Collector V1 (phase P31) — collector lifecycle: enroll, authenticate, heartbeat, revoke, and
// the honest status a collector that has never reported in actually has.

import { createHash, randomUUID } from 'crypto';
import { getSupabase } from './geoEnrichment';
import { issueCredential, secretMatches, type IssuedCredential } from '../lib/collectorAuth';
import { logAudit } from '../lib/audit';

export type CollectorStatus = 'enrolling' | 'connected' | 'disconnected' | 'revoked';
export interface Collector {
    id: string; org_id: string; name: string; status: CollectorStatus;
    token_prefix: string; enrollment_expires_at: string | null; activated_at: string | null;
    revoked_at: string | null; revoked_by: string | null; config_version: number;
    vector_version: string | null; last_heartbeat_at: string | null; last_ip: string | null;
    last_events_received: number; last_events_forwarded: number; last_delivery_failures: number;
    last_buffer_pct: number | null; created_by: string; created_at: string;
}

const ENROLLMENT_WINDOW_HOURS = 24;
/** A collector that hasn't heartbeated within this window is "disconnected", not "connected". */
export const HEARTBEAT_STALE_MINUTES = 10;

export async function createCollector(org: string, name: string, actor: string): Promise<{ collector: Collector; token: string } | { error: string }> {
    const supabase = getSupabase();
    if (!supabase) return { error: 'Database not configured' };
    const id = randomUUID();
    const cred: IssuedCredential = issueCredential(id);
    const { data, error } = await supabase.from('collectors').insert({
        id, org_id: org, name, status: 'enrolling', token_hash: cred.token_hash, token_prefix: cred.token_prefix,
        enrollment_expires_at: new Date(Date.now() + ENROLLMENT_WINDOW_HOURS * 3_600_000).toISOString(),
        created_by: actor,
    }).select('*').single();
    if (error) return { error: error.code === '23505' ? 'A collector with that name already exists for this organisation' : error.message };
    logAudit({ user: actor, action: 'COLLECTOR_CREATED', resource: 'collector', resource_id: id, org_id: org, ip: 'unknown', result: 'success', details: name });
    return { collector: data as Collector, token: cred.token };
}

export async function listCollectors(org: string): Promise<Collector[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    const { data } = await supabase.from('collectors').select('*').eq('org_id', org).order('created_at', { ascending: false });
    return (data ?? []) as Collector[];
}

export async function getCollector(id: string, org: string): Promise<Collector | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data } = await supabase.from('collectors').select('*').eq('id', id).eq('org_id', org).maybeSingle();
    return (data as Collector | null) ?? null;
}

export async function revokeCollector(id: string, org: string, actor: string): Promise<{ ok: true } | { ok: false; error: string }> {
    const supabase = getSupabase();
    if (!supabase) return { ok: false, error: 'Database not configured' };
    const { data, error } = await supabase.from('collectors').update({ status: 'revoked', revoked_at: new Date().toISOString(), revoked_by: actor })
        .eq('id', id).eq('org_id', org).neq('status', 'revoked').select('id').maybeSingle();
    if (error) return { ok: false, error: error.message };
    if (!data) return { ok: false, error: 'Collector not found, or already revoked' };
    logAudit({ user: actor, action: 'COLLECTOR_REVOKED', resource: 'collector', resource_id: id, org_id: org, ip: 'unknown', result: 'success', severity: 'warning' });
    return { ok: true };
}

/** Issues a fresh credential and invalidates the old one — the only way to recover a lost
 * secret, since (per the brief) an issued secret is never shown again. Bumps config_version so
 * the collector's own log makes the change visible even though no human watched it happen. */
export async function rotateCredential(id: string, org: string, actor: string): Promise<{ token: string } | { error: string }> {
    const supabase = getSupabase();
    if (!supabase) return { error: 'Database not configured' };
    const cred = issueCredential(id);
    const { data, error } = await supabase.from('collectors').update({ token_hash: cred.token_hash, token_prefix: cred.token_prefix })
        .eq('id', id).eq('org_id', org).neq('status', 'revoked').select('config_version').maybeSingle();
    if (error) return { error: error.message };
    if (!data) return { error: 'Collector not found, or revoked' };
    await supabase.from('collectors').update({ config_version: (data.config_version as number) + 1 }).eq('id', id);
    logAudit({ user: actor, action: 'COLLECTOR_CREDENTIAL_ROTATED', resource: 'collector', resource_id: id, org_id: org, ip: 'unknown', result: 'success', severity: 'warning' });
    return { token: cred.token };
}

export interface AuthenticatedCollector { id: string; org_id: string; status: CollectorStatus }

/** Resolves a presented secret to its collector — the ONLY place a request's organisation is
 * decided for the ingestion gateway. Never trusts anything in the request body. Revoked or
 * expired-unactivated collectors authenticate to nothing. */
export async function authenticateCollector(collectorId: string, secret: string): Promise<AuthenticatedCollector | { error: 'not_found' | 'revoked' | 'enrollment_expired' | 'bad_secret' }> {
    const supabase = getSupabase();
    if (!supabase) return { error: 'not_found' };
    const { data } = await supabase.from('collectors').select('id, org_id, status, token_hash, enrollment_expires_at').eq('id', collectorId).maybeSingle();
    if (!data) return { error: 'not_found' };
    if (data.status === 'revoked') return { error: 'revoked' };
    if (data.status === 'enrolling' && data.enrollment_expires_at && Date.parse(data.enrollment_expires_at as string) < Date.now()) return { error: 'enrollment_expired' };
    if (!secretMatches(secret, data.token_hash as string)) return { error: 'bad_secret' };
    return { id: data.id as string, org_id: data.org_id as string, status: data.status as CollectorStatus };
}

export interface HeartbeatInput {
    vector_version?: string; events_received: number; events_forwarded: number; delivery_failures: number;
    buffer_pct?: number; sources: { source_key: string; kind: string; label?: string; events_total?: number }[];
    ip: string;
}

/** Records one heartbeat: updates the collector's current snapshot, appends to the time series
 * for the throughput chart, upserts each reported source, and — the only way a collector leaves
 * "enrolling" — activates it on its first successful heartbeat. */
export async function recordHeartbeat(collectorId: string, h: HeartbeatInput): Promise<{ ok: true } | { ok: false; error: string }> {
    const supabase = getSupabase();
    if (!supabase) return { ok: false, error: 'Database not configured' };
    const now = new Date().toISOString();
    const { data: existing } = await supabase.from('collectors').select('status').eq('id', collectorId).maybeSingle();
    const updates: Record<string, unknown> = {
        last_heartbeat_at: now, last_ip: h.ip, vector_version: h.vector_version ?? null,
        last_events_received: h.events_received, last_events_forwarded: h.events_forwarded,
        last_delivery_failures: h.delivery_failures, last_buffer_pct: h.buffer_pct ?? null,
    };
    if (existing?.status === 'enrolling') { updates.status = 'connected'; updates.activated_at = now; updates.enrollment_expires_at = null; }
    else if (existing?.status === 'disconnected') updates.status = 'connected';
    const { error } = await supabase.from('collectors').update(updates).eq('id', collectorId);
    if (error) return { ok: false, error: error.message };
    await supabase.from('collector_heartbeats').insert({ collector_id: collectorId, at: now, events_received: h.events_received, events_forwarded: h.events_forwarded, delivery_failures: h.delivery_failures, buffer_pct: h.buffer_pct ?? null });
    for (const s of h.sources) {
        await supabase.from('collector_sources').upsert({ collector_id: collectorId, source_key: s.source_key, kind: s.kind, label: s.label ?? null, events_total: s.events_total ?? 0, last_event_at: now }, { onConflict: 'collector_id,source_key' });
    }
    return { ok: true };
}

/** A collector whose heartbeat has gone quiet reads as "disconnected", not frozen at its last
 * reported "connected" status — computed at read time rather than requiring a background sweep. */
export function effectiveStatus(c: Pick<Collector, 'status' | 'last_heartbeat_at'>): CollectorStatus {
    if (c.status !== 'connected') return c.status;
    if (!c.last_heartbeat_at) return 'disconnected';
    return Date.now() - Date.parse(c.last_heartbeat_at) > HEARTBEAT_STALE_MINUTES * 60_000 ? 'disconnected' : 'connected';
}

export interface LogEventInput { source_key: string; host?: string; event_time?: string; message: string }
const RAW_MAX_BYTES = 32 * 1024;
const noNul = (s: string) => s.replace(/\u0000/g, '');

/** Caps a message exactly like routes/ingest.ts's capRaw() — same size, same reasoning: Postgres
 * refuses NUL bytes, and an unbounded message could make one hostile log line exhaust storage. */
export function capMessage(message: string): { message: string; truncated: boolean } {
    const clean = noNul(message);
    const bytes = Buffer.byteLength(clean, 'utf8');
    if (bytes <= RAW_MAX_BYTES) return { message: clean, truncated: false };
    return { message: `${Buffer.from(clean, 'utf8').subarray(0, RAW_MAX_BYTES - 32).toString('utf8').replace(/�+$/, '')}… [truncated, ${bytes} bytes originally]`, truncated: true };
}

export const dedupKey = (collectorId: string, sourceKey: string, message: string): string =>
    createHash('sha256').update(`${collectorId}\n${sourceKey}\n${message}`).digest('hex');

/** Stores a batch of already-authenticated, already-capped log events for one collector/org.
 * Duplicates (same collector + dedup_key) are silently ignored via the unique index — a buffered
 * batch resent after a network outage is always safe to resend. */
export async function storeLogEvents(collectorId: string, org: string, events: LogEventInput[]): Promise<{ accepted: number } | { error: string }> {
    const supabase = getSupabase();
    if (!supabase) return { error: 'Database not configured' };
    const rows = events.map((e) => {
        const { message, truncated } = capMessage(e.message);
        return {
            org_id: org, collector_id: collectorId, source_key: e.source_key, host: e.host ? noNul(e.host).slice(0, 256) : null,
            event_time: e.event_time ?? null, message, truncated, dedup_key: dedupKey(collectorId, e.source_key, message),
        };
    });
    const { data, error } = await supabase.from('collector_log_events').upsert(rows, { onConflict: 'collector_id,dedup_key', ignoreDuplicates: true }).select('id');
    if (error) return { error: error.message };
    return { accepted: (data ?? []).length };
}
