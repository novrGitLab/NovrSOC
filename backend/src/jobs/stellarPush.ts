// Outbound push of stored alerts to Stellar Cyber's webhook ingest (phase X3).
//
// The vendor chose push over the pull export (routes/exportApi.ts). Same source, same order and
// the same settle window as the export: alerts are read from `alerts` in ingest_seq order, only
// once they are older than settleSeconds(), so an alert still committing is never skipped. Each
// alert is one HTTPS POST of lib/stellarEvent.ts's JSON (no batching: the receiver's contract is
// one event per request). Position is kept in `push_state` (sql/2026-10-11_push_state.sql), so a
// restart resumes where it stopped. There is no in-memory queue — `alerts` is the queue.
//
// Delivery: at least once, in order. The position is saved after every batch, so a crash
// mid-batch re-sends at most that batch; the receiver de-duplicates on event_id.
//   2xx                → delivered
//   413                → re-sent once without `raw` (profile no_raw); if still refused, as below
//   400 / 413 / 422    → the receiver refused this event's content. It is written to
//                        push_dead_letters (nothing is dropped silently) and the feed moves on, so
//                        one bad event can't block the rest. A super_admin can request a retry
//                        (POST /api/admin/push-status/dead-letters/retry).
//   anything else      → transient (network error, timeout, 401/403, 404, 408, 429, 5xx): stop,
//                        keep the position, retry the same event later with exponential backoff
//                        and jitter (30 s doubling to 10 min; 429's Retry-After is honoured, capped
//                        at 10 min). Never dropped; failures are counted in push_state.retry_count.
// Ingestion is unaffected either way: this job only reads `alerts`.
//
// Configuration (Railway); while a required one is missing the job logs once and does nothing:
//   STELLAR_PUSH_ENABLED      required, exactly "true" — the kill switch
//   STELLAR_PUSH_URL          required, full https webhook URL (…/webhook/<tenant>/<id>)
//   STELLAR_PUSH_API_KEY      required, the API key Stellar issued; never logged or returned
//   STELLAR_PUSH_ORG_IDS      required, comma-separated org slugs whose alerts are sent — only these
//   STELLAR_PUSH_AUTH_HEADER  default "Authorization"
//   STELLAR_PUSH_AUTH_SCHEME  default "Bearer"; "none" sends the bare key
//   STELLAR_PUSH_PROFILE      'standard' (default: includes the redacted original alert) or 'no_raw'
//   STELLAR_PUSH_START        first run only: 'latest' (default: alerts stored from now on),
//                             'hours:N' (alerts stored in the last N hours, 1-2160) or 'beginning'
//   STELLAR_PUSH_TIMEOUT_MS   per request, default 10000 (1000-60000)
//   STELLAR_PUSH_MAX_PER_MIN  send rate cap, default 600 (1-6000) — bounds a backfill
// It sends production data to a third party, so it starts only where the mutating jobs do
// (lib/runtimeEnv.ts) — never from a local copy of the production .env. TLS is verified by
// Node's fetch; redirects are refused so the key is never sent to another host.

import { getSupabase } from '../services/geoEnrichment';
import { settleSeconds } from '../routes/exportApi';
import { REDACTION_PROFILES } from '../lib/redact';
import { toStellarEvent } from '../lib/stellarEvent';
import type { AlertRowForExport } from '../lib/exportEvent';

export const DESTINATION = 'stellar';
export const BATCH = 200;
export const TICK_MS = 15_000;
const MAX_ROUNDS_PER_TICK = 10;
const DEAD_LETTER_RETRIES_PER_TICK = 50;
export const BACKOFF_MIN_MS = 30_000;
export const BACKOFF_MAX_MS = 10 * 60_000;
const CONTENT_REJECTED = new Set([400, 413, 422]);
// src_ip/src_port/dst_ip/dst_port/protocol are the P24 normalized columns — selected so
// lib/exportEvent.ts's networkForExport() can prefer them over re-deriving from raw (which it
// still does, per field, for any alert stored before P24 or missing a backfill run).
const COLUMNS = 'id, ingest_seq, org_id, event_time, received_at, severity, rule_id, rule_level, rule_description, agent_id, agent_name, agent_ip, mitre_ids, location, raw, raw_truncated, src_ip, src_port, dst_ip, dst_port, protocol';

export type StartPoint = { kind: 'latest' } | { kind: 'beginning' } | { kind: 'hours'; hours: number };
export interface PushConfig {
    url: string;
    headers: Record<string, string>;
    orgs: string[];
    profile: string;
    start: StartPoint;
    timeoutMs: number;
    maxPerMin: number;
}

function intEnv(v: string | undefined, def: number, min: number, max: number): number | null {
    if (v === undefined || v.trim() === '') return def;
    if (!/^\d{1,7}$/.test(v.trim())) return null;
    const n = Number(v.trim());
    return n >= min && n <= max ? n : null;
}

export function parseStart(v: string | undefined): StartPoint | null {
    const s = (v ?? '').trim() || 'latest';
    if (s === 'latest' || s === 'beginning') return { kind: s };
    const m = /^hours:(\d{1,4})$/.exec(s);
    return m && Number(m[1]) >= 1 && Number(m[1]) <= 2160 ? { kind: 'hours', hours: Number(m[1]) } : null;
}

/** The configuration, or the reason the job can't run. Never includes the key in a reason. */
export function pushConfig(env: NodeJS.ProcessEnv = process.env): PushConfig | { error: string } {
    if (env.STELLAR_PUSH_ENABLED !== 'true') return { error: 'STELLAR_PUSH_ENABLED is not "true"' };
    let url: URL;
    try { url = new URL(env.STELLAR_PUSH_URL ?? ''); } catch { return { error: 'STELLAR_PUSH_URL is missing or not a URL' }; }
    if (url.protocol !== 'https:') return { error: 'STELLAR_PUSH_URL must be https' };
    const key = (env.STELLAR_PUSH_API_KEY ?? '').trim();
    if (!key) return { error: 'STELLAR_PUSH_API_KEY is not set' };
    const orgs = [...new Set((env.STELLAR_PUSH_ORG_IDS ?? '').split(',').map((o) => o.trim()).filter(Boolean))];
    if (orgs.length === 0) return { error: 'STELLAR_PUSH_ORG_IDS is not set' };
    const profile = env.STELLAR_PUSH_PROFILE?.trim() || 'standard';
    if (!(REDACTION_PROFILES as readonly string[]).includes(profile)) return { error: `STELLAR_PUSH_PROFILE must be one of ${REDACTION_PROFILES.join(', ')}` };
    const start = parseStart(env.STELLAR_PUSH_START);
    if (!start) return { error: 'STELLAR_PUSH_START must be latest, beginning or hours:N (1-2160)' };
    const timeoutMs = intEnv(env.STELLAR_PUSH_TIMEOUT_MS, 10_000, 1_000, 60_000);
    if (timeoutMs === null) return { error: 'STELLAR_PUSH_TIMEOUT_MS must be 1000-60000' };
    const maxPerMin = intEnv(env.STELLAR_PUSH_MAX_PER_MIN, 600, 1, 6_000);
    if (maxPerMin === null) return { error: 'STELLAR_PUSH_MAX_PER_MIN must be 1-6000' };
    const header = env.STELLAR_PUSH_AUTH_HEADER?.trim() || 'Authorization';
    const scheme = env.STELLAR_PUSH_AUTH_SCHEME?.trim() || 'Bearer';
    return {
        url: url.toString(),
        headers: { 'Content-Type': 'application/json', [header]: scheme.toLowerCase() === 'none' ? key : `${scheme} ${key}` },
        orgs, profile, start, timeoutMs, maxPerMin,
    };
}

/** Events allowed per tick under the rate cap. */
export const perTickBudget = (cfg: PushConfig) => Math.max(1, Math.ceil((cfg.maxPerMin * TICK_MS) / 60_000));

/** Backoff for the nth consecutive failure (n ≥ 1): exponential, capped, with jitter in [½, 1]. */
export function backoffMs(n: number, retryAfterMs: number | null = null, rand: () => number = Math.random): number {
    const base = Math.min(BACKOFF_MIN_MS * 2 ** Math.max(0, n - 1), BACKOFF_MAX_MS);
    const jittered = Math.round(base / 2 + rand() * (base / 2));
    return retryAfterMs === null ? jittered : Math.max(jittered, Math.min(retryAfterMs, BACKOFF_MAX_MS));
}

/** Retry-After as milliseconds (delta-seconds or an HTTP date), or null. */
export function parseRetryAfter(v: string | null, now = Date.now()): number | null {
    if (!v) return null;
    if (/^\d{1,6}$/.test(v.trim())) return Number(v.trim()) * 1000;
    const t = Date.parse(v);
    return Number.isNaN(t) ? null : Math.max(0, t - now);
}

interface PushState { last_seq: number; sent_count: number; skipped_count: number; retry_count: number }
export interface TickResult { sent: number; skipped: number; dead_letters_resent: number; error: string | null; retryAfterMs: number | null }
type Outcome = { kind: 'ok' } | { kind: 'rejected'; status: number } | { kind: 'transient'; reason: string; retryAfterMs: number | null };
type Row = AlertRowForExport & { ingest_seq: number | string };

/** What the status endpoint reports about this process's job. Never holds the key. */
export const pushRuntime = {
    started_at: null as string | null,
    not_started_reason: null as string | null,
    last_tick_at: null as string | null,
    last_result: null as TickResult | null,
    consecutive_failures: 0,
    next_attempt_at: null as string | null,
};

const num = (v: unknown) => Number(v ?? 0) || 0;

async function loadState(cfg: PushConfig): Promise<PushState> {
    const supabase = getSupabase()!;
    const { data, error } = await supabase.from('push_state').select('last_seq, sent_count, skipped_count, retry_count').eq('destination', DESTINATION).maybeSingle();
    if (error) throw new Error(`push_state read failed: ${error.message}`);
    if (data) return { last_seq: num(data.last_seq), sent_count: num(data.sent_count), skipped_count: num(data.skipped_count), retry_count: num(data.retry_count) };

    // First run: where to start. Never a silent full replay — 'beginning' must be asked for.
    let last = 0;
    if (cfg.start.kind !== 'beginning') {
        let q = supabase.from('alerts').select('ingest_seq').in('org_id', cfg.orgs);
        if (cfg.start.kind === 'hours') q = q.lt('received_at', new Date(Date.now() - cfg.start.hours * 3_600_000).toISOString());
        const top = await q.order('ingest_seq', { ascending: false }).limit(1);
        if (top.error) throw new Error(`alerts read failed: ${top.error.message}`);
        last = top.data?.length ? num(top.data[0].ingest_seq) : 0;
    }
    const init = await supabase.from('push_state').insert({ destination: DESTINATION, last_seq: last });
    if (init.error) throw new Error(`push_state init failed: ${init.error.message}`);
    const label = cfg.start.kind === 'hours' ? `last ${cfg.start.hours}h` : cfg.start.kind;
    console.log(`[stellar-push] first run (${label}): starting after ingest_seq ${last}`);
    return { last_seq: last, sent_count: 0, skipped_count: 0, retry_count: 0 };
}

async function saveState(s: PushState, fields: { last_success_at?: string; last_error?: string | null; last_error_at?: string } = {}) {
    const { error } = await getSupabase()!.from('push_state').update({ ...s, ...fields, updated_at: new Date().toISOString() }).eq('destination', DESTINATION);
    if (error) throw new Error(`push_state update failed: ${error.message}`);
}

/** POSTs one event: status 0 for a network error/timeout. Only the status and Retry-After are read. */
async function post(cfg: PushConfig, body: unknown): Promise<{ status: number; retryAfter: string | null }> {
    try {
        const r = await fetch(cfg.url, { method: 'POST', headers: cfg.headers, body: JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(cfg.timeoutMs) });
        await r.arrayBuffer().catch(() => undefined);
        return { status: r.status, retryAfter: r.headers.get('retry-after') };
    } catch {
        return { status: 0, retryAfter: null };
    }
}

async function deliver(cfg: PushConfig, row: Row): Promise<Outcome> {
    let r = await post(cfg, toStellarEvent(row, cfg.profile));
    // Too large: the redacted original is the bulky part; send the event without it.
    if (r.status === 413 && cfg.profile !== 'no_raw') r = await post(cfg, toStellarEvent(row, 'no_raw'));
    if (r.status >= 200 && r.status < 300) return { kind: 'ok' };
    if (CONTENT_REJECTED.has(r.status)) return { kind: 'rejected', status: r.status };
    const reason = r.status === 0 ? 'network error or timeout'
        : r.status === 401 || r.status === 403 ? `${r.status} (check STELLAR_PUSH_API_KEY / auth header)`
        : r.status === 429 ? '429 rate limited'
        : String(r.status);
    return { kind: 'transient', reason, retryAfterMs: r.status === 429 ? parseRetryAfter(r.retryAfter) : null };
}

async function deadLetter(row: Row, status: number) {
    const now = new Date().toISOString();
    const { error } = await getSupabase()!.from('push_dead_letters').upsert(
        { destination: DESTINATION, alert_id: row.id, ingest_seq: num(row.ingest_seq), status_code: status, retry_requested: false, last_attempt_at: now },
        { onConflict: 'destination,alert_id' },
    );
    // Not recorded → don't move past it: losing it silently is worse than waiting.
    if (error) throw new Error(`push_dead_letters write failed: ${error.message}`);
}

/** Re-sends dead letters a super_admin asked to retry. Returns the number delivered, or a transient failure. */
async function retryDeadLetters(cfg: PushConfig): Promise<{ resent: number; failure: Outcome | null }> {
    const supabase = getSupabase()!;
    const { data, error } = await supabase.from('push_dead_letters').select('id, alert_id, attempts')
        .eq('destination', DESTINATION).eq('retry_requested', true).is('resolved_at', null).order('ingest_seq', { ascending: true }).limit(DEAD_LETTER_RETRIES_PER_TICK);
    if (error) throw new Error(`push_dead_letters read failed: ${error.message}`);
    let resent = 0;
    for (const dl of data ?? []) {
        const now = new Date().toISOString();
        const a = await supabase.from('alerts').select(COLUMNS).eq('id', dl.alert_id).in('org_id', cfg.orgs).limit(1);
        if (a.error) throw new Error(`alerts read failed: ${a.error.message}`);
        const row = (a.data ?? [])[0] as unknown as Row | undefined;
        if (!row) { // purged by retention, or its org is no longer in scope: nothing left to send
            await supabase.from('push_dead_letters').update({ retry_requested: false, last_attempt_at: now, status_code: null }).eq('id', dl.id);
            continue;
        }
        const out = await deliver(cfg, row);
        if (out.kind === 'transient') return { resent, failure: out };
        const upd = out.kind === 'ok'
            ? { resolved_at: now, retry_requested: false, last_attempt_at: now, attempts: num(dl.attempts) + 1 }
            : { retry_requested: false, last_attempt_at: now, attempts: num(dl.attempts) + 1, status_code: out.status };
        const u = await supabase.from('push_dead_letters').update(upd).eq('id', dl.id);
        if (u.error) throw new Error(`push_dead_letters update failed: ${u.error.message}`);
        if (out.kind === 'ok') resent++;
    }
    return { resent, failure: null };
}

/** One pass: requested dead-letter retries, then settled alerts after the saved position, up to the per-tick budget. Throws only on store errors. */
export async function runPushOnce(cfg: PushConfig, budget = perTickBudget(cfg)): Promise<TickResult> {
    const supabase = getSupabase();
    if (!supabase) return { sent: 0, skipped: 0, dead_letters_resent: 0, error: 'store not configured', retryAfterMs: null };
    const state = await loadState(cfg);
    let sent = 0;
    let skipped = 0;
    const transientStop = async (out: Extract<Outcome, { kind: 'transient' }>, resent: number): Promise<TickResult> => {
        state.retry_count++;
        await saveState(state, { last_error: out.reason, last_error_at: new Date().toISOString(), ...(sent || resent ? { last_success_at: new Date().toISOString() } : {}) });
        return { sent, skipped, dead_letters_resent: resent, error: out.reason, retryAfterMs: out.retryAfterMs };
    };

    const dl = await retryDeadLetters(cfg);
    if (dl.failure && dl.failure.kind === 'transient') return transientStop(dl.failure, dl.resent);

    for (let round = 0; round < MAX_ROUNDS_PER_TICK && sent + skipped < budget; round++) {
        const { data, error } = await supabase.from('alerts').select(COLUMNS).in('org_id', cfg.orgs)
            .gt('ingest_seq', state.last_seq).order('ingest_seq', { ascending: true }).limit(Math.min(BATCH, budget - sent - skipped));
        if (error) throw new Error(`alerts read failed: ${error.message}`);
        const rows = (data ?? []) as unknown as Row[];
        // Same rule as the export: stop at the first row still inside the settle window.
        const cutoff = Date.now() - settleSeconds() * 1000;
        const firstUnsettled = rows.findIndex((r) => r.received_at != null && Date.parse(r.received_at) > cutoff);
        const ready = firstUnsettled === -1 ? rows : rows.slice(0, firstUnsettled);

        for (const row of ready) {
            const out = await deliver(cfg, row);
            if (out.kind === 'transient') return transientStop(out, dl.resent);
            if (out.kind === 'ok') {
                sent++; state.sent_count++;
            } else {
                await deadLetter(row, out.status);
                skipped++; state.skipped_count++;
                console.error(`[stellar-push] receiver refused alert ${row.id} (${out.status}); kept in push_dead_letters`);
            }
            state.last_seq = num(row.ingest_seq);
        }
        if (ready.length) {
            await saveState(state, {
                ...(sent || dl.resent ? { last_success_at: new Date().toISOString() } : {}),
                ...(skipped ? { last_error: `refused by receiver: ${skipped} alert(s) in push_dead_letters`, last_error_at: new Date().toISOString() } : {}),
            });
        }
        if (ready.length < rows.length || rows.length === 0) break;
    }
    return { sent, skipped, dead_letters_resent: dl.resent, error: null, retryAfterMs: null };
}

export function startStellarPushJob(): void {
    const cfg = pushConfig();
    if ('error' in cfg) {
        pushRuntime.not_started_reason = cfg.error;
        if (process.env.STELLAR_PUSH_ENABLED === 'true') console.error(`[stellar-push] not started: ${cfg.error}`);
        return;
    }
    if (!getSupabase()) { pushRuntime.not_started_reason = 'store not configured'; console.error('[stellar-push] not started: store not configured'); return; }
    pushRuntime.started_at = new Date().toISOString();
    console.log(`[stellar-push] pushing orgs ${cfg.orgs.join(',')} to ${new URL(cfg.url).host} (profile ${cfg.profile}, max ${cfg.maxPerMin}/min)`);

    let running = false;
    let nextAt = 0;
    const fail = (reason: string, retryAfterMs: number | null) => {
        pushRuntime.consecutive_failures++;
        const wait = backoffMs(pushRuntime.consecutive_failures, retryAfterMs);
        nextAt = Date.now() + wait;
        pushRuntime.next_attempt_at = new Date(nextAt).toISOString();
        console.error(`[stellar-push] ${reason}; retrying in ${Math.round(wait / 1000)}s`);
    };
    const tick = async () => {
        if (running || Date.now() < nextAt) return;
        running = true;
        pushRuntime.last_tick_at = new Date().toISOString();
        try {
            const r = await runPushOnce(cfg);
            pushRuntime.last_result = r;
            if (r.sent || r.skipped || r.dead_letters_resent) console.log(`[stellar-push] sent ${r.sent}, refused ${r.skipped}, dead letters re-sent ${r.dead_letters_resent}`);
            if (r.error) fail(`delivery failed (${r.error})`, r.retryAfterMs);
            else { pushRuntime.consecutive_failures = 0; pushRuntime.next_attempt_at = null; }
        } catch (err) {
            fail(err instanceof Error ? err.message : String(err), null);
        } finally {
            running = false;
        }
    };
    void tick();
    setInterval(() => { void tick(); }, TICK_MS).unref();
}
