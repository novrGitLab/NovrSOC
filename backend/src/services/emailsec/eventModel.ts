// The normalised email-security event. Every provider's telemetry — Microsoft 365, Google
// Workspace, the NovrSOC mail gateway — is mapped to this one shape before it is stored,
// correlated or shown, so detection and correlation never branch on the provider.
//
// `action` is what was actually done to the message and `action_by` is who did it. NovrSOC
// only ever DETECTS on provider telemetry; it records the provider's own action (Microsoft 365
// quarantined it, the gateway rejected it) and never claims to have blocked anything itself.

export type Detection =
    | 'clean' | 'phishing' | 'malware' | 'spam' | 'spoofing' | 'bec' | 'malicious_url'
    | 'suspicious_attachment' | 'impersonation' | 'auth_failure';
export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical';
export type Action = 'allow' | 'flag' | 'quarantine' | 'block';
export type Provider = 'microsoft365' | 'google_workspace' | 'gateway';

export interface EventUrl { url: string; domain: string | null }
export interface EventAttachment { filename: string | null; sha256: string | null; size: number | null; content_type: string | null }

export interface NormalizedEmailEvent {
    provider: Provider;
    provider_event_id: string;
    message_id: string | null;
    sender: string | null;
    sender_domain: string | null;
    recipient: string | null;
    subject: string | null;
    received_at: string;
    source_ip: string | null;
    spf: string | null;
    dkim: string | null;
    dmarc: string | null;
    urls: EventUrl[];
    attachments: EventAttachment[];
    ti_matches: string[];
    categories: Detection[];
    detection: Detection;
    severity: Severity;
    action: Action;
    action_by: string;
    mailbox: string | null;
    tenant: string | null;
}

// Most specific first: the primary detection is the first category in this order.
const PRIORITY: Detection[] = ['malware', 'phishing', 'bec', 'impersonation', 'malicious_url', 'suspicious_attachment', 'spoofing', 'auth_failure', 'spam', 'clean'];
export const primaryDetection = (cats: Detection[]): Detection => PRIORITY.find((p) => cats.includes(p)) ?? 'clean';

const BASE_SEVERITY: Record<Detection, Severity> = {
    malware: 'high', phishing: 'high', bec: 'high', impersonation: 'medium', malicious_url: 'high',
    suspicious_attachment: 'medium', spoofing: 'medium', auth_failure: 'low', spam: 'informational', clean: 'informational',
};
const ORDER: Severity[] = ['informational', 'low', 'medium', 'high', 'critical'];
const bump = (s: Severity, n = 1): Severity => ORDER[Math.min(ORDER.length - 1, ORDER.indexOf(s) + n)];

/**
 * Severity from what was detected and what happened to it. A threat that was DELIVERED (allow /
 * flag) is one step more severe than the same threat stopped by the provider; a threat-intel
 * match on a delivered phishing / malware message is critical.
 */
export function eventSeverity(cats: Detection[], action: Action, tiMatches: number): Severity {
    const primary = primaryDetection(cats);
    if (primary === 'clean') return 'informational';
    let s = BASE_SEVERITY[primary];
    const delivered = action === 'allow' || action === 'flag';
    if (delivered && primary !== 'spam') s = bump(s);
    if (tiMatches > 0) s = bump(s);
    if (!delivered && ORDER.indexOf(s) > ORDER.indexOf('high')) s = 'high';
    return s;
}

const domainOf = (addr: string | null | undefined) => {
    const m = /@([^@>\s]+)>?\s*$/.exec(addr ?? '');
    return m ? m[1].toLowerCase() : null;
};
const lc = (v: unknown) => (typeof v === 'string' && v ? v.toLowerCase() : null);
const urlDomain = (u: string) => { try { return new URL(u).hostname.toLowerCase(); } catch { return null; } };

function finish(e: Omit<NormalizedEmailEvent, 'detection' | 'severity'>): NormalizedEmailEvent {
    const categories = [...new Set(e.categories)].filter((c) => c !== 'clean') as Detection[];
    const cats: Detection[] = categories.length ? categories : ['clean'];
    return { ...e, categories: cats, detection: primaryDetection(cats), severity: eventSeverity(cats, e.action, e.ti_matches.length) };
}

// ── NovrSOC mail gateway (Postfix + Amavis → /api/email-proxy/verdict → email_logs) ────────

export interface GatewayLogRow {
    id?: string; message_id: string; org_id: string; from_address: string; to_address: string; subject?: string | null;
    verdict: string; score?: number | null; reasons?: string[] | null; received_at?: string | null; has_attachment?: boolean | null;
    attachment_names?: string[] | null; source_ip?: string | null; dmarc_result?: string | null; spf_result?: string | null; dkim_result?: string | null;
    action?: string | null;
}

export function fromGateway(row: GatewayLogRow): NormalizedEmailEvent {
    const verdict = (row.verdict ?? '').toLowerCase();
    const cats: Detection[] = [];
    if (verdict === 'phishing') cats.push('phishing');
    if (verdict === 'malware') cats.push('malware');
    if (verdict === 'spam') cats.push('spam');
    if (verdict === 'suspicious') cats.push('suspicious_attachment');
    const dmarc = lc(row.dmarc_result);
    if (dmarc === 'fail') cats.push('auth_failure');
    // The gateway reports a verdict; unless it also reports what it did, NovrSOC records the
    // message as flagged — not blocked.
    const gwAction = lc(row.action);
    const action: Action = gwAction === 'reject' || gwAction === 'block' || gwAction === 'discard' ? 'block'
        : gwAction === 'quarantine' || gwAction === 'hold' ? 'quarantine'
        : cats.length ? 'flag' : 'allow';
    return finish({
        provider: 'gateway',
        provider_event_id: row.id ?? row.message_id,
        message_id: row.message_id,
        sender: lc(row.from_address),
        sender_domain: domainOf(row.from_address),
        recipient: lc(row.to_address),
        subject: row.subject ?? null,
        received_at: row.received_at ?? new Date().toISOString(),
        source_ip: row.source_ip ?? null,
        spf: lc(row.spf_result), dkim: lc(row.dkim_result), dmarc,
        urls: [],
        attachments: (row.attachment_names ?? []).map((n) => ({ filename: n, sha256: null, size: null, content_type: null })),
        ti_matches: [],
        categories: cats,
        action,
        action_by: action === 'allow' || action === 'flag' ? 'none' : 'NovrSOC mail gateway',
        mailbox: lc(row.to_address),
        tenant: row.org_id,
    });
}

// ── Microsoft 365 (Graph security alerts_v2, Defender for Office 365 message evidence) ─────

export interface GraphAlert {
    id: string; title?: string; category?: string; severity?: string; createdDateTime?: string; serviceSource?: string; tenantId?: string;
    evidence?: Array<Record<string, unknown>>;
}

const M365_CATEGORY: Record<string, Detection> = {
    phish: 'phishing', phishing: 'phishing', malware: 'malware', spam: 'spam', bulk: 'spam', spoof: 'spoofing',
    impersonation: 'impersonation', userimpersonation: 'impersonation', domainimpersonation: 'impersonation',
    malicious_url: 'malicious_url', maliciousurl: 'malicious_url', credentialaccess: 'phishing', initialaccess: 'phishing',
};

/** One Graph alert can carry several messages; each analysed message becomes one event. */
export function fromMicrosoftAlert(alert: GraphAlert): NormalizedEmailEvent[] {
    const messages = (alert.evidence ?? []).filter((e) => String(e['@odata.type'] ?? '').endsWith('analyzedMessageEvidence'));
    const urls = (alert.evidence ?? []).filter((e) => String(e['@odata.type'] ?? '').endsWith('urlEvidence')).map((e) => String(e.url ?? ''));
    return messages.map((m, i) => {
        const cats: Detection[] = [];
        for (const t of [...((m.threats as string[]) ?? []), alert.category ?? '']) {
            const key = String(t).toLowerCase().replace(/[\s_-]/g, '');
            const hit = M365_CATEGORY[key] ?? M365_CATEGORY[String(t).toLowerCase()];
            if (hit) cats.push(hit);
        }
        // authenticationDetails is not a documented v1.0 property of analyzedMessageEvidence
        // (checked 2026-09-29); read only if Microsoft includes it, otherwise SPF/DKIM/DMARC stay null.
        const auth = (m.authenticationDetails as Record<string, string> | undefined) ?? {};
        if (lc(auth.dmarc) === 'fail') cats.push('auth_failure');
        // Documented values — deliveryAction: delivered | deliveredAsSpam | junked | blocked | replaced;
        // deliveryLocation: inbox | external | junkFolder | quarantine | failed | dropped | deletedFolder | forwarded.
        const location = lc(m.deliveryLocation) ?? '';
        const delivery = lc(m.deliveryAction) ?? '';
        const junked = delivery === 'junked' || delivery === 'deliveredasspam' || location === 'junkfolder';
        const action: Action = location === 'quarantine' ? 'quarantine'
            : delivery === 'blocked' || location === 'dropped' || location === 'failed' ? 'block'
            : cats.length ? 'flag' : 'allow';
        const sender = (m.p1Sender as { emailAddress?: string } | undefined)?.emailAddress ?? (m.p2Sender as { emailAddress?: string } | undefined)?.emailAddress ?? null;
        const recipient = lc(m.recipientEmailAddress);
        return finish({
            provider: 'microsoft365',
            provider_event_id: `${alert.id}:${String(m.networkMessageId ?? i)}`,
            message_id: (m.internetMessageId as string) ?? null,
            sender: lc(sender), sender_domain: domainOf(sender),
            recipient,
            subject: (m.subject as string) ?? null,
            received_at: (m.receivedDateTime as string) ?? alert.createdDateTime ?? new Date().toISOString(),
            source_ip: (m.senderIp as string) ?? null,
            spf: lc(auth.senderPolicyFramework), dkim: lc(auth.dkim), dmarc: lc(auth.dmarc),
            urls: [...((m.urls as string[]) ?? []), ...urls].filter(Boolean).map((u) => ({ url: u, domain: urlDomain(u) })),
            attachments: [],
            ti_matches: [],
            categories: cats.length ? cats : ['phishing'], // an alert on a message is a detection even if the category is unmapped
            action,
            action_by: action === 'allow' || action === 'flag' ? (junked ? 'Microsoft 365 (delivered to Junk)' : 'none') : 'Microsoft 365 (Defender for Office 365)',
            mailbox: recipient,
            tenant: alert.tenantId ?? null,
        });
    });
}

// ── Google Workspace (Admin SDK Reports API, applicationName=gmail) ─────────────────────────

export interface GmailActivity {
    id?: { time?: string; uniqueQualifier?: string; customerId?: string };
    events?: Array<{ name?: string; parameters?: Array<{ name: string; value?: string; boolValue?: boolean; messageValue?: { parameter?: Array<{ name: string; value?: string; boolValue?: boolean; multiValue?: string[]; messageValue?: unknown }> } }> }>;
}

// UNVERIFIED FIELD MAPPING. Google documents applicationName=gmail, the "delivery" event and
// event_info.mail_event_type for the Reports API, but not the nested message fields. The names
// below (message_info, source, destination, spam_info, connection_info, link_domain) follow
// Google's Gmail-log schema for the BigQuery export. Every field is optional here, so a
// mismatch yields events with missing metadata rather than wrong data — confirm against a live
// Workspace tenant before relying on it.
export function fromGmailActivity(a: GmailActivity): NormalizedEmailEvent | null {
    const ev = a.events?.[0];
    const info = ev?.parameters?.find((p) => p.name === 'message_info')?.messageValue?.parameter ?? [];
    const get = (name: string) => info.find((p) => p.name === name);
    const val = (name: string) => get(name)?.value ?? null;
    const sub = (name: string) => ((get(name)?.messageValue as { parameter?: Array<{ name: string; value?: string; boolValue?: boolean }> } | undefined)?.parameter ?? []);
    const subVal = (name: string, key: string) => sub(name).find((p) => p.name === key);
    const msgId = val('rfc2822_message_id');
    if (!msgId && !a.id?.uniqueQualifier) return null;

    const sender = subVal('source', 'from_header_address')?.value ?? subVal('source', 'address')?.value ?? null;
    const recipient = subVal('destination', 'address')?.value ?? null;
    const spamClass = lc(subVal('spam_info', 'classification')?.value) ?? '';
    const disposition = lc(subVal('spam_info', 'disposition')?.value) ?? '';
    const cats: Detection[] = [];
    if (spamClass.includes('phish')) cats.push('phishing');
    if (spamClass.includes('malware')) cats.push('malware');
    if (spamClass.includes('spoof')) cats.push('spoofing');
    if (spamClass.includes('spam') || spamClass.includes('bulk')) cats.push('spam');
    if (subVal('connection_info', 'dmarc_pass')?.boolValue === false) cats.push('auth_failure');
    const action: Action = disposition.includes('quarantine') ? 'quarantine' : disposition.includes('reject') || disposition.includes('bounce') ? 'block' : cats.length ? 'flag' : 'allow';
    const linkDomains = info.filter((p) => p.name === 'link_domain').flatMap((p) => p.multiValue ?? (p.value ? [p.value] : []));
    return finish({
        provider: 'google_workspace',
        provider_event_id: a.id?.uniqueQualifier ?? msgId!,
        message_id: msgId,
        sender: lc(sender), sender_domain: domainOf(sender),
        recipient: lc(recipient),
        subject: val('subject'),
        received_at: a.id?.time ?? new Date().toISOString(),
        source_ip: subVal('connection_info', 'client_ip')?.value ?? null,
        spf: subVal('connection_info', 'spf_pass')?.boolValue === undefined ? null : subVal('connection_info', 'spf_pass')!.boolValue ? 'pass' : 'fail',
        dkim: sub('connection_info').some((p) => p.name === 'dkim_pass') ? (subVal('connection_info', 'dkim_pass')!.boolValue ? 'pass' : 'fail') : null,
        dmarc: subVal('connection_info', 'dmarc_pass')?.boolValue === undefined ? null : subVal('connection_info', 'dmarc_pass')!.boolValue ? 'pass' : 'fail',
        urls: linkDomains.map((d) => ({ url: `http://${d}/`, domain: d.toLowerCase() })),
        attachments: [],
        ti_matches: [],
        categories: cats,
        action,
        action_by: action === 'allow' || action === 'flag' ? 'none' : 'Google Workspace (Gmail)',
        mailbox: lc(recipient),
        tenant: a.id?.customerId ?? null,
    });
}
