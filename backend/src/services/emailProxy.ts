// Email MX proxy — verdict storage and reporting.
//
// A client repoints their domain's MX at NovrSOC's mail host; Postfix + Amavis on that host
// scan each message and POST the verdict here before the mail is forwarded on. This module owns
// reading and writing those verdicts; routes/emailProxy.ts owns who is allowed to call.
//
// Uses getSupabase() from services/geoEnrichment — there is no services/supabase module in this
// codebase, and every other service reaches the database through that one. Creating a second
// client here with its own createClient() call would mean two clients with two configs and two
// ways to be misconfigured.
//
// PRIVACY NOTE: email_logs holds sender, recipient and subject for every scanned message. That
// is the most sensitive dataset this platform stores. The table is service-role only (RLS), the
// message body is never stored, and attachment names are stored without contents. Keep it that
// way — storing bodies would turn a security log into a mail archive.

import { getSupabase } from './geoEnrichment';

export type EmailVerdict = 'clean' | 'spam' | 'phishing' | 'malware' | 'suspicious';

export interface EmailLogEntry {
    message_id: string;
    org_id: string;
    from_address: string;
    to_address: string;
    subject?: string | null;
    verdict: EmailVerdict;
    score?: number;
    reasons?: string[];
    received_at?: string;
    size_bytes?: number;
    has_attachment?: boolean;
    attachment_names?: string[];
    source_ip?: string | null;
    source_country?: string | null;
    dmarc_result?: string | null;
    spf_result?: string | null;
    dkim_result?: string | null;
}

const VALID_VERDICTS: EmailVerdict[] = ['clean', 'spam', 'phishing', 'malware', 'suspicious'];


// ── Storage seam ─────────────────────────────────────────────────────────────────────────
// The verdict path's database operations, behind one small interface so the whole
// gateway → email_logs → Messaging Suite path can be exercised in tests (setEmailProxyStore).
export interface EmailProxyStore {
    /** org_id of the active gateway domain for this recipient domain, or null if not registered. */
    orgForDomain(domain: string): Promise<{ org_id: string | null; error?: string }>;
    upsertLog(row: Record<string, unknown>): Promise<{ error?: string }>;
    logsSince(orgId: string, since: string, limit: number): Promise<{ rows: Record<string, unknown>[]; error?: string }>;
}

const supabaseStore: EmailProxyStore = {
    async orgForDomain(domain) {
        const supabase = getSupabase();
        if (!supabase) return { org_id: null, error: 'Database not configured' };
        const { data, error } = await supabase.from('email_proxy_domains').select('org_id, active').eq('domain', domain).maybeSingle();
        if (error) return { org_id: null, error: explainDbError(error) };
        const row = data as { org_id: string; active: boolean | null } | null;
        return { org_id: row && row.active !== false ? row.org_id : null };
    },
    async upsertLog(row) {
        const supabase = getSupabase();
        if (!supabase) return { error: 'Database not configured' };
        // Upsert on message_id so a retried report updates rather than duplicating.
        const { error } = await supabase.from('email_logs').upsert(row, { onConflict: 'message_id' });
        return error ? { error: explainDbError(error) } : {};
    },
    async logsSince(orgId, since, limit) {
        const supabase = getSupabase();
        if (!supabase) return { rows: [], error: 'Database not configured' };
        const { data, error } = await supabase.from('email_logs').select('*').eq('org_id', orgId).gt('received_at', since).order('received_at', { ascending: true }).limit(limit);
        return error ? { rows: [], error: explainDbError(error) } : { rows: (data ?? []) as Record<string, unknown>[] };
    },
};
let store: EmailProxyStore = supabaseStore;
/** Tests only. */
export function setEmailProxyStore(s: EmailProxyStore | null): void { store = s ?? supabaseStore; }
export function emailProxyStore(): EmailProxyStore { return store; }

const ADDRESS = /^[^\s@<>]+@([a-z0-9-]+(\.[a-z0-9-]+)+)$/i;
/** "Name <a@b.com>" or "a@b.com" → "a@b.com", lowercased; null when not an address. */
export function normalizeAddress(v: unknown): string | null {
    if (typeof v !== 'string') return null;
    const inner = /<([^>]+)>\s*$/.exec(v)?.[1] ?? v;
    const a = inner.trim().toLowerCase();
    return a.length <= 320 && ADDRESS.test(a) ? a : null;
}
const str = (v: unknown, max: number) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null);
const strList = (v: unknown, max: number, each: number) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string').slice(0, max).map((x) => x.slice(0, each)) : []);
const AUTH_RESULTS = ['pass', 'fail', 'none', 'neutral', 'softfail', 'temperror', 'permerror'];
const authResult = (v: unknown) => { const x = str(v, 20)?.toLowerCase(); return x && AUTH_RESULTS.includes(x) ? x : null; };

export interface StoreResult {
    ok: boolean;
    status?: number;
    error?: string;
    org_id?: string;
}

/**
 * Records one scanned message. The payload comes from a mail server, so it is untrusted:
 * every field is validated and normalised, and the TENANT IS NEVER TAKEN FROM THE PAYLOAD —
 * it is the organisation that registered the recipient's domain with the gateway
 * (email_proxy_domains). A message for an unregistered domain is refused.
 */
export async function storeEmailVerdict(entry: Record<string, unknown>): Promise<StoreResult> {
    const messageId = str(entry?.message_id, 998);
    if (!messageId) return { ok: false, status: 400, error: 'message_id is required' };
    const from = normalizeAddress(entry.from_address);
    const to = normalizeAddress(entry.to_address);
    if (!from || !to) return { ok: false, status: 400, error: 'from_address and to_address are required and must be email addresses' };
    const verdict = typeof entry.verdict === 'string' ? (entry.verdict.trim().toLowerCase() as EmailVerdict) : null;
    if (!verdict || !VALID_VERDICTS.includes(verdict)) {
        return { ok: false, status: 400, error: `verdict must be one of: ${VALID_VERDICTS.join(', ')}` };
    }
    let receivedAt = new Date().toISOString();
    if (entry.received_at !== undefined && entry.received_at !== null) {
        const t = Date.parse(String(entry.received_at));
        if (Number.isNaN(t)) return { ok: false, status: 400, error: 'received_at must be an ISO 8601 timestamp' };
        // Trust the scanner's clock (a retried report lands late), but never a future date.
        receivedAt = new Date(Math.min(t, Date.now())).toISOString();
    }

    const recipientDomain = to.split('@')[1];
    const owner = await store.orgForDomain(recipientDomain);
    if (owner.error) return { ok: false, status: 500, error: owner.error };
    if (!owner.org_id) return { ok: false, status: 422, error: `${recipientDomain} is not an active gateway domain` };

    const row = {
        message_id: messageId,
        org_id: owner.org_id,
        from_address: from,
        to_address: to,
        subject: str(entry.subject, 998),
        verdict,
        score: Number.isFinite(Number(entry.score)) ? Math.round(Number(entry.score)) : 0,
        reasons: strList(entry.reasons, 50, 500),
        received_at: receivedAt,
        size_bytes: Math.max(0, Math.round(Number(entry.size_bytes) || 0)),
        has_attachment: Boolean(entry.has_attachment),
        attachment_names: strList(entry.attachment_names, 50, 255),
        source_ip: str(entry.source_ip, 45),
        source_country: str(entry.source_country, 2),
        dmarc_result: authResult(entry.dmarc_result),
        spf_result: authResult(entry.spf_result),
        dkim_result: authResult(entry.dkim_result),
    };
    const { error } = await store.upsertLog(row);
    if (error) return { ok: false, status: 500, error };
    return { ok: true, org_id: owner.org_id };
}

export interface LogsResult {
    logs: EmailLogEntry[];
    error?: string;
}

export async function getEmailLogs(orgId: string, limit = 50): Promise<LogsResult> {
    const supabase = getSupabase();
    if (!supabase) return { logs: [], error: 'Database not configured' };

    const { data, error } = await supabase
        .from('email_logs')
        .select('*')
        .eq('org_id', orgId)
        .order('received_at', { ascending: false })
        .limit(Math.min(limit, 500));

    if (error) return { logs: [], error: explainDbError(error) };
    return { logs: (data ?? []) as EmailLogEntry[] };
}

export interface EmailStats {
    total: number;
    clean: number;
    spam: number;
    phishing: number;
    malware: number;
    suspicious: number;
    period: string;
    /** Null when the table can't be read — distinguishes "no mail" from "couldn't look". */
    error?: string;
}

export async function getEmailStats(orgId: string): Promise<EmailStats> {
    const empty: EmailStats = { total: 0, clean: 0, spam: 0, phishing: 0, malware: 0, suspicious: 0, period: '7 days' };

    const supabase = getSupabase();
    if (!supabase) return { ...empty, error: 'Database not configured' };

    const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const { data, error } = await supabase
        .from('email_logs')
        .select('verdict')
        .eq('org_id', orgId)
        .gte('received_at', since);

    if (error) return { ...empty, error: explainDbError(error) };

    const logs = (data ?? []) as Array<{ verdict: string }>;
    const count = (v: EmailVerdict) => logs.filter((l) => l.verdict === v).length;

    return {
        total: logs.length,
        clean: count('clean'),
        spam: count('spam'),
        phishing: count('phishing'),
        malware: count('malware'),
        suspicious: count('suspicious'),
        period: '7 days',
    };
}

export interface ProxyDomain {
    domain: string;
    org_id: string;
    real_mx: string;
    forward_to: string;
    active: boolean;
    added_at?: string;
}

export async function getProxyDomains(orgId: string): Promise<{ domains: ProxyDomain[]; error?: string }> {
    const supabase = getSupabase();
    if (!supabase) return { domains: [], error: 'Database not configured' };

    const { data, error } = await supabase
        .from('email_proxy_domains')
        .select('*')
        .eq('org_id', orgId)
        .order('added_at', { ascending: false });

    if (error) return { domains: [], error: explainDbError(error) };
    return { domains: (data ?? []) as ProxyDomain[] };
}

export async function addProxyDomain(params: {
    domain: string; real_mx: string; forward_to: string; org_id: string;
}): Promise<{ ok: boolean; domain?: ProxyDomain; error?: string }> {
    const domain = params.domain?.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!domain || !domain.includes('.')) return { ok: false, error: 'Enter a valid domain, e.g. example.com' };
    if (!params.real_mx?.trim()) return { ok: false, error: 'The current MX host is required' };
    if (!params.forward_to?.trim()) return { ok: false, error: 'A forwarding address is required' };

    const supabase = getSupabase();
    if (!supabase) return { ok: false, error: 'Database not configured' };

    // A domain belongs to one organisation: never re-assign another tenant's registration.
    const { data: existing } = await supabase.from('email_proxy_domains').select('org_id').eq('domain', domain).maybeSingle();
    if (existing && (existing as { org_id: string }).org_id !== params.org_id) {
        return { ok: false, error: `${domain} is already registered to another organisation` };
    }

    const { data, error } = await supabase
        .from('email_proxy_domains')
        .upsert({
            domain,
            real_mx: params.real_mx.trim(),
            forward_to: params.forward_to.trim(),
            org_id: params.org_id,
            active: true,
            added_at: new Date().toISOString(),
        }, { onConflict: 'domain' })
        .select()
        .single();

    if (error) return { ok: false, error: explainDbError(error) };
    return { ok: true, domain: data as ProxyDomain };
}

// Supabase rejects with a PostgrestError — a plain object, not an Error — so String(err) gives
// "[object Object]". The case that actually matters here is a missing table, which is the setup
// step the UI shows SQL for.
function explainDbError(err: unknown): string {
    const raw = err instanceof Error
        ? err.message
        : (typeof err === 'object' && err !== null && 'message' in err)
            ? String((err as { message: unknown }).message)
            : String(err);

    if (raw.includes('does not exist')) {
        return `${raw} — the email_logs / email_proxy_domains tables are missing from the database.`;
    }
    return raw;
}
