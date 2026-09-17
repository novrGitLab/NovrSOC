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

export interface StoreResult {
    ok: boolean;
    error?: string;
}

/**
 * Records one scanned message. Validates before writing — this endpoint is reachable by a mail
 * server rather than the UI, so the payload is treated as untrusted input rather than assumed
 * well-formed.
 */
export async function storeEmailVerdict(entry: EmailLogEntry): Promise<StoreResult> {
    if (!entry?.message_id || typeof entry.message_id !== 'string') {
        return { ok: false, error: 'message_id is required' };
    }
    if (!entry.from_address || !entry.to_address) {
        return { ok: false, error: 'from_address and to_address are required' };
    }
    if (!VALID_VERDICTS.includes(entry.verdict)) {
        return { ok: false, error: `verdict must be one of: ${VALID_VERDICTS.join(', ')}` };
    }

    const supabase = getSupabase();
    if (!supabase) return { ok: false, error: 'Database not configured' };

    const row = {
        message_id: entry.message_id,
        org_id: entry.org_id || 'cybernovr',
        from_address: entry.from_address,
        to_address: entry.to_address,
        subject: entry.subject ?? null,
        verdict: entry.verdict,
        score: Number(entry.score) || 0,
        reasons: Array.isArray(entry.reasons) ? entry.reasons : [],
        // Trusts the scanner's timestamp when present — it knows when the message was received,
        // which can differ from when this call lands if the reporting call was retried.
        received_at: entry.received_at ?? new Date().toISOString(),
        size_bytes: Number(entry.size_bytes) || 0,
        has_attachment: Boolean(entry.has_attachment),
        attachment_names: Array.isArray(entry.attachment_names) ? entry.attachment_names : [],
        source_ip: entry.source_ip ?? null,
        source_country: entry.source_country ?? null,
        dmarc_result: entry.dmarc_result ?? null,
        spf_result: entry.spf_result ?? null,
        dkim_result: entry.dkim_result ?? null,
    };

    // Upsert on message_id so a retried report updates rather than duplicating — a mail server
    // that times out waiting for this response will retry the same message.
    const { error } = await supabase.from('email_logs').upsert(row, { onConflict: 'message_id' });
    if (error) return { ok: false, error: explainDbError(error) };
    return { ok: true };
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
        return `${raw} — create the email_logs and email_proxy_domains tables using the SQL on the Email Monitoring page.`;
    }
    return raw;
}
