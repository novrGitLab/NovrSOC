// Outbound push of stored alerts to Stellar Cyber's webhook ingest (phase X3).
//
// The vendor chose push over the pull export (routes/exportApi.ts). Same source, same order and
// the same settle window as the export: alerts are read from `alerts` in ingest_seq order, only
// once they are older than settleSeconds(), so an alert still committing is never skipped. Each
// alert is one HTTPS POST of lib/stellarEvent.ts's JSON. Position is kept in `push_state`
// (sql/2026-10-11_push_state.sql), so a restart resumes where it stopped.
//
// Delivery: at least once, in order. The position is saved after every batch, so a crash
// mid-batch re-sends at most that batch; the receiver de-duplicates on event_id.
//   2xx                → delivered, move on
//   400 / 413 / 422    → the receiver rejected this event's content; it is skipped (counted in
//                        push_state.skipped_count) so one bad event can't block the feed
//   anything else      → stop, keep the position, retry with backoff (30 s doubling to 10 min);
//                        401/403 are logged as credential problems
//
// Configuration (Railway), all required unless noted; while any required one is missing the
// job logs once and does nothing:
//   STELLAR_PUSH_ENABLED      exactly "true" — the kill switch
//   STELLAR_PUSH_URL          full https webhook URL (…/webhook/<tenant>/<id>)
//   STELLAR_PUSH_API_KEY      the API key Stellar issued; never logged
//   STELLAR_PUSH_ORG_IDS      comma-separated org slugs whose alerts are sent — nothing else is
//   STELLAR_PUSH_AUTH_HEADER  optional, default "Authorization"
//   STELLAR_PUSH_AUTH_SCHEME  optional, default "Bearer"; set to "none" to send the bare key
//   STELLAR_PUSH_PROFILE      optional, 'standard' (default, includes redacted raw) or 'no_raw'
//   STELLAR_PUSH_START        optional, 'latest' (default: only alerts stored from now on) or
//                             'beginning' (everything still retained). Read only on first run.
// It sends production data to a third party, so it starts only where the mutating jobs do
// (lib/runtimeEnv.ts) — never from a local copy of the production .env.

import { getSupabase } from '../services/geoEnrichment';
import { settleSeconds } from '../routes/exportApi';
import { REDACTION_PROFILES } from '../lib/redact';
import { toStellarEvent } from '../lib/stellarEvent';
import type { AlertRowForExport } from '../lib/exportEvent';

export const DESTINATION = 'stellar';
export const BATCH = 200;
const TICK_MS = 15_000;
const POST_TIMEOUT_MS = 10_000;
const MAX_ROUNDS_PER_TICK = 10;
const BACKOFF_MIN_MS = 30_000;
const BACKOFF_MAX_MS = 10 * 60_000;
const SKIPPABLE = new Set([400, 413, 422]);
const COLUMNS = 'id, ingest_seq, org_id, event_time, received_at, severity, rule_id, rule_level, rule_description, agent_id, agent_name, agent_ip, mitre_ids, location, raw, raw_truncated';

export interface PushConfig {
    url: string;
    headers: Record<string, string>;
    orgs: string[];
    profile: string;
    start: 'latest' | 'beginning';
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
    const start = env.STELLAR_PUSH_START?.trim() || 'latest';
    if (start !== 'latest' && start !== 'beginning') return { error: 'STELLAR_PUSH_START must be latest or beginning' };
    const header = env.STELLAR_PUSH_AUTH_HEADER?.trim() || 'Authorization';
    const scheme = env.STELLAR_PUSH_AUTH_SCHEME?.trim() || 'Bearer';
    return {
        url: url.toString(),
        headers: { 'Content-Type': 'application/json', [header]: scheme.toLowerCase() === 'none' ? key : `${scheme} ${key}` },
        orgs,
        profile,
        start,
    };
}

interface PushState { last_seq: number; sent_count: number; skipped_count: number }
export interface TickResult { sent: number; skipped: number; error: string | null }

async function loadState(cfg: PushConfig): Promise<PushState> {
    const supabase = getSupabase()!;
    const { data, error } = await supabase.from('push_state').select('last_seq, sent_count, skipped_count').eq('destination', DESTINATION).maybeSingle();
    if (error) throw new Error(`push_state read failed: ${error.message}`);
    if (data) return { last_seq: Number(data.last_seq), sent_count: Number(data.sent_count), skipped_count: Number(data.skipped_count) };

    // First run: start after the newest stored alert, or from the beginning if asked.
    let last = 0;
    if (cfg.start === 'latest') {
        const top = await supabase.from('alerts').select('ingest_seq').in('org_id', cfg.orgs).order('ingest_seq', { ascending: false }).limit(1);
        if (top.error) throw new Error(`alerts read failed: ${top.error.message}`);
        last = top.data?.length ? Number(top.data[0].ingest_seq) : 0;
    }
    const init = await supabase.from('push_state').insert({ destination: DESTINATION, last_seq: last });
    if (init.error) throw new Error(`push_state init failed: ${init.error.message}`);
    console.log(`[stellar-push] first run: starting after ingest_seq ${last} (${cfg.start})`);
    return { last_seq: last, sent_count: 0, skipped_count: 0 };
}

async function saveState(s: PushState, fields: { last_success_at?: string; last_error?: string | null; last_error_at?: string }) {
    const { error } = await getSupabase()!.from('push_state').update({ ...s, ...fields, updated_at: new Date().toISOString() }).eq('destination', DESTINATION);
    if (error) console.error(`[stellar-push] push_state update failed: ${error.message}`);
}

/** POSTs one event. Returns the HTTP status, or 0 for a network error/timeout. */
async function post(cfg: PushConfig, body: unknown): Promise<number> {
    try {
        const r = await fetch(cfg.url, { method: 'POST', headers: cfg.headers, body: JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(POST_TIMEOUT_MS) });
        await r.arrayBuffer().catch(() => undefined);
        return r.status;
    } catch {
        return 0;
    }
}

/** One pass: deliver settled alerts after the saved position. Throws only on store errors. */
export async function runPushOnce(cfg: PushConfig): Promise<TickResult> {
    const supabase = getSupabase();
    if (!supabase) return { sent: 0, skipped: 0, error: 'store not configured' };
    const state = await loadState(cfg);
    let sent = 0;
    let skipped = 0;

    for (let round = 0; round < MAX_ROUNDS_PER_TICK; round++) {
        const { data, error } = await supabase.from('alerts').select(COLUMNS).in('org_id', cfg.orgs)
            .gt('ingest_seq', state.last_seq).order('ingest_seq', { ascending: true }).limit(BATCH);
        if (error) throw new Error(`alerts read failed: ${error.message}`);
        const rows = (data ?? []) as unknown as (AlertRowForExport & { ingest_seq: number | string })[];
        // Same rule as the export: stop at the first row still inside the settle window.
        const cutoff = Date.now() - settleSeconds() * 1000;
        const firstUnsettled = rows.findIndex((r) => r.received_at != null && Date.parse(r.received_at) > cutoff);
        const ready = firstUnsettled === -1 ? rows : rows.slice(0, firstUnsettled);

        for (const row of ready) {
            const status = await post(cfg, toStellarEvent(row, cfg.profile));
            if (status >= 200 && status < 300) {
                sent++; state.sent_count++;
            } else if (SKIPPABLE.has(status)) {
                skipped++; state.skipped_count++;
                console.error(`[stellar-push] receiver rejected alert ${row.id} with ${status}; skipped`);
                await saveState({ ...state, last_seq: Number(row.ingest_seq) }, { last_error: `skipped ${row.id}: ${status}`, last_error_at: new Date().toISOString() });
            } else {
                const reason = status === 0 ? 'network error or timeout' : status === 401 || status === 403 ? `${status} (check STELLAR_PUSH_API_KEY / auth header)` : String(status);
                await saveState(state, { last_error: reason, last_error_at: new Date().toISOString(), ...(sent ? { last_success_at: new Date().toISOString() } : {}) });
                return { sent, skipped, error: reason };
            }
            state.last_seq = Number(row.ingest_seq);
        }
        if (ready.length) await saveState(state, sent ? { last_success_at: new Date().toISOString() } : {});
        if (rows.length < BATCH || ready.length < rows.length) break;
    }
    return { sent, skipped, error: null };
}

export function startStellarPushJob(): void {
    const cfg = pushConfig();
    if ('error' in cfg) {
        if (process.env.STELLAR_PUSH_ENABLED === 'true') console.error(`[stellar-push] not started: ${cfg.error}`);
        return;
    }
    if (!getSupabase()) { console.error('[stellar-push] not started: store not configured'); return; }
    console.log(`[stellar-push] pushing orgs ${cfg.orgs.join(',')} to ${new URL(cfg.url).host} (profile ${cfg.profile})`);

    let running = false;
    let backoff = 0;
    let nextAt = 0;
    const tick = async () => {
        if (running || Date.now() < nextAt) return;
        running = true;
        try {
            const r = await runPushOnce(cfg);
            if (r.sent || r.skipped) console.log(`[stellar-push] sent ${r.sent}, skipped ${r.skipped}`);
            if (r.error) {
                backoff = Math.min(backoff ? backoff * 2 : BACKOFF_MIN_MS, BACKOFF_MAX_MS);
                nextAt = Date.now() + backoff;
                console.error(`[stellar-push] delivery failed (${r.error}); retrying in ${Math.round(backoff / 1000)}s`);
            } else {
                backoff = 0;
            }
        } catch (err) {
            backoff = Math.min(backoff ? backoff * 2 : BACKOFF_MIN_MS, BACKOFF_MAX_MS);
            nextAt = Date.now() + backoff;
            console.error(`[stellar-push] ${err instanceof Error ? err.message : err}; retrying in ${Math.round(backoff / 1000)}s`);
        } finally {
            running = false;
        }
    };
    void tick();
    setInterval(() => { void tick(); }, TICK_MS).unref();
}
