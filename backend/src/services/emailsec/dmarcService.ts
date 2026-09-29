// DMARC SaaS: protected domains, DNS inspection history, aggregate-report ingestion, sending
// sources, analytics and spoofing alerts.
//
// Report pipeline: receive (upload or Mailgun inbound) → unpack → parse → normalise → store
// report + records → roll up sending sources → classify → alert on suspicious sources.
import type { Db } from './db';
import { f } from './db';
import { inspectDomain, dnsClient, type DomainInspection } from './dnsInspect';
import { unpackReport, parseDmarcReport, type DmarcReport } from './dmarcReport';
import { correlateOrRaise, recordIndicators } from './alerts';
import { emailsecConfig } from './config';

export interface EmailDomain {
    id: string; org_id: string; domain: string; status: string; dmarc_policy: string | null; spf_status: string | null; dkim_status: string | null;
    dmarc_status: string | null; dkim_selectors: string[]; health_score: number | null; sending_sources: number; last_checked: string | null;
    last_error: string | null; created_by: string | null; created_at: string; updated_at: string;
}
export interface SendingSource {
    id: string; org_id: string; domain: string; source_ip: string; provider: string | null; ptr: string | null;
    classification: 'known' | 'unknown' | 'suspicious'; classification_reason: string | null; classified_by: string;
    message_count: number; spf_pass: number; dkim_pass: number; dmarc_pass: number; first_seen: string; last_seen: string;
}

// ── Domains + DNS checks ───────────────────────────────────────────────────────────────────

export async function runDomainCheck(db: Db, d: EmailDomain): Promise<DomainInspection | null> {
    const now = new Date().toISOString();
    let result: DomainInspection;
    try {
        result = await inspectDomain(d.domain, d.dkim_selectors ?? []);
    } catch (err) {
        await db.update('email_domains', [f.eq('id', d.id)], { status: 'error', last_error: (err as Error).message, last_checked: now, updated_at: now });
        return null;
    }
    const [prev] = await db.select<{ result: DomainInspection }>('email_dns_checks', { filters: [f.eq('org_id', d.org_id), f.eq('domain_id', d.id)], order: { col: 'created_at' }, limit: 1 });
    await db.insert('email_dns_checks', { org_id: d.org_id, domain_id: d.id, domain: d.domain, result });
    await db.update('email_domains', [f.eq('id', d.id)], {
        status: result.lookup_errors.length && !result.spf.exists && !result.dmarc.exists ? 'error' : result.health.status,
        dmarc_policy: result.dmarc.policy, spf_status: result.statuses.spf, dkim_status: result.statuses.dkim, dmarc_status: result.statuses.dmarc,
        health_score: result.health.score, last_checked: now, last_error: result.lookup_errors.join('; ') || null, updated_at: now,
    });

    // Alert only on a regression against the previous check — a domain that has never had DMARC
    // is a posture finding shown on the page, not an incident.
    const p = prev?.result;
    if (p) {
        const regressions: string[] = [];
        if (p.dmarc.policy && result.dmarc.policy && ['none', 'quarantine', 'reject'].indexOf(result.dmarc.policy) < ['none', 'quarantine', 'reject'].indexOf(p.dmarc.policy)) {
            regressions.push(`DMARC policy weakened from p=${p.dmarc.policy} to p=${result.dmarc.policy}`);
        }
        if (p.dmarc.exists && !result.dmarc.exists) regressions.push('DMARC record removed');
        if (p.spf.exists && !result.spf.exists) regressions.push('SPF record removed');
        if (p.statuses.spf === 'pass' && result.statuses.spf === 'fail') regressions.push(`SPF record broke: ${result.spf.errors[0] ?? 'now invalid'}`);
        if (regressions.length) {
            await correlateOrRaise(db, d.org_id, [{ type: 'domain', value: d.domain }], {
                correlation_key: `dmarc-config:${d.domain}`, severity: 'medium', module: 'dmarc', detection_type: 'authentication_regression', entity: d.domain,
                title: `Email authentication weakened for ${d.domain}`, description: regressions.join('. '),
                evidence: { summary: regressions.join('; '), ref: { kind: 'domain', id: d.id } }, indicators: [{ type: 'domain', value: d.domain }],
            });
        }
    }
    return result;
}

// ── Report ingestion ───────────────────────────────────────────────────────────────────────

export type IngestResult =
    | { ok: true; duplicate: boolean; report_id: string; domain: string; org_ids: string[]; records: number; messages: number; suspicious_sources: number }
    | { ok: false; status: number; error: string };

/**
 * Store one aggregate report. `orgId` restricts it to that tenant (uploads); null means "every
 * tenant monitoring this domain" (Mailgun inbound, where the report names only the domain).
 */
export async function ingestReport(db: Db, raw: Buffer, via: 'upload' | 'mailgun', orgId: string | null): Promise<IngestResult> {
    let report: DmarcReport;
    try { report = parseDmarcReport(unpackReport(raw)); } catch (err) { return { ok: false, status: 400, error: (err as Error).message }; }

    const owners = await db.select<EmailDomain>('email_domains', { filters: [f.eq('domain', report.domain), ...(orgId ? [f.eq('org_id', orgId)] : [])] });
    if (!owners.length) {
        return { ok: false, status: 422, error: `${report.domain} is not a monitored domain${orgId ? ' in this organisation' : ''}. Add it under DMARC SaaS first.` };
    }
    let stored_for = 0;
    let suspicious = 0;
    for (const owner of owners) {
        // Receivers resend reports; (reporter, report_id) identifies one.
        const [dupe] = await db.select('dmarc_reports', {
            filters: [f.eq('org_id', owner.org_id), f.eq('reporter', report.reporter), f.eq('report_id', report.report_id)], limit: 1,
        });
        if (dupe) continue;
        stored_for++;
        const [stored] = await db.insert<{ id: string }>('dmarc_reports', {
            org_id: owner.org_id, domain: report.domain, report_id: report.report_id, reporter: report.reporter, reporter_email: report.reporter_email,
            date_begin: report.date_begin, date_end: report.date_end, policy_published: report.policy_published,
            record_count: report.records.length, message_count: report.message_count, pass_count: report.pass_count, received_via: via,
        });
        for (let i = 0; i < report.records.length; i += 500) {
            await db.insert('dmarc_records', report.records.slice(i, i + 500).map((r) => ({
                org_id: owner.org_id, report_id: stored.id, domain: report.domain, date_begin: report.date_begin, ...r,
            })));
        }
        suspicious += await rollUpSources(db, owner, report, stored.id);
    }
    return {
        ok: true, duplicate: stored_for === 0, report_id: report.report_id, domain: report.domain,
        org_ids: owners.map((o) => o.org_id), records: report.records.length, messages: report.message_count, suspicious_sources: suspicious,
    };
}

// Reverse-DNS suffixes of services that commonly send on a customer's behalf.
const PROVIDERS: [RegExp, string][] = [
    [/\.google\.com$|\.googlemail\.com$/, 'Google'], [/\.outlook\.com$|\.protection\.outlook\.com$|\.microsoft\.com$/, 'Microsoft 365'],
    [/\.amazonses\.com$/, 'Amazon SES'], [/\.sendgrid\.net$/, 'SendGrid'], [/\.mailgun\.(net|org)$/, 'Mailgun'], [/\.mandrillapp\.com$/, 'Mailchimp / Mandrill'],
    [/\.mcsv\.net$|\.rsgsv\.net$/, 'Mailchimp'], [/\.sparkpostmail\.com$/, 'SparkPost'], [/\.zoho\.(com|eu|in)$/, 'Zoho Mail'], [/\.sendinblue\.com$|\.brevo\.com$/, 'Brevo'],
    [/\.postmarkapp\.com$/, 'Postmark'], [/\.mailjet\.com$/, 'Mailjet'], [/\.salesforce\.com$|\.exacttarget\.com$/, 'Salesforce'], [/\.hubspot(email)?\.(com|net)$/, 'HubSpot'],
    [/\.resend\.(com|dev)$/, 'Resend'], [/\.protonmail\.ch$/, 'Proton Mail'], [/\.yahoo\.com$/, 'Yahoo'], [/\.icloud\.com$|\.apple\.com$/, 'Apple iCloud'],
];
export function providerForPtr(ptr: string | null): string | null {
    if (!ptr) return null;
    const p = ptr.toLowerCase().replace(/\.$/, '');
    return PROVIDERS.find(([re]) => re.test(p))?.[1] ?? null;
}

/**
 * Classification. "Unknown" is the honest default: a source that fails DMARC is not
 * necessarily malicious (mailing lists and forwarders break SPF/DKIM all the time).
 */
export function classifySource(s: { message_count: number; dmarc_pass: number; provider: string | null }): { classification: SendingSource['classification']; reason: string } {
    const ratio = s.message_count ? s.dmarc_pass / s.message_count : 0;
    if (ratio >= 0.9) return { classification: 'known', reason: `${Math.round(ratio * 100)}% of its messages pass DMARC with alignment — it is authorised to send for this domain.` };
    if (s.dmarc_pass === 0 && s.message_count >= emailsecConfig.spoofMinMessages() && !s.provider) {
        return { classification: 'suspicious', reason: `All ${s.message_count} messages failed both SPF and DKIM alignment, from a server that is not a recognised mail provider.` };
    }
    if (s.provider && ratio < 0.9) return { classification: 'unknown', reason: `${s.provider} infrastructure, but only ${Math.round(ratio * 100)}% passes DMARC — likely forwarding or a service not yet set up with SPF/DKIM for this domain.` };
    return { classification: 'unknown', reason: ratio > 0 ? `Mixed results: ${Math.round(ratio * 100)}% pass DMARC.` : `Fails DMARC, but has sent too few messages (${s.message_count}) to call it suspicious.` };
}

const ptrCache = new Map<string, string | null>();
async function ptrFor(ip: string): Promise<string | null> {
    if (ptrCache.has(ip)) return ptrCache.get(ip)!;
    const name = await Promise.race([dnsClient().reverse(ip), new Promise<null>((r) => setTimeout(() => r(null), 3000).unref())]);
    ptrCache.set(ip, name);
    if (ptrCache.size > 5000) ptrCache.delete(ptrCache.keys().next().value as string);
    return name;
}

async function rollUpSources(db: Db, owner: EmailDomain, report: DmarcReport, storedId: string): Promise<number> {
    const agg = new Map<string, { messages: number; spf: number; dkim: number; dmarc: number; delivered: number }>();
    for (const r of report.records) {
        const a = agg.get(r.source_ip) ?? { messages: 0, spf: 0, dkim: 0, dmarc: 0, delivered: 0 };
        a.messages += r.message_count;
        if (r.spf_aligned) a.spf += r.message_count;
        if (r.dkim_aligned) a.dkim += r.message_count;
        if (r.dmarc_pass) a.dmarc += r.message_count;
        if (!r.dmarc_pass && (r.disposition ?? 'none') === 'none') a.delivered += r.message_count;
        agg.set(r.source_ip, a);
    }
    const ips = [...agg.keys()];
    const existing = await db.select<SendingSource>('email_sending_sources', { filters: [f.eq('org_id', owner.org_id), f.eq('domain', owner.domain), f.in('source_ip', ips)], limit: 1000 });
    const newIps = ips.filter((ip) => !existing.some((e) => e.source_ip === ip)).slice(0, 100);
    const ptrs = new Map<string, string | null>();
    for (let i = 0; i < newIps.length; i += 10) {
        const batch = await Promise.all(newIps.slice(i, i + 10).map(async (ip) => [ip, await ptrFor(ip)] as const));
        for (const [ip, p] of batch) ptrs.set(ip, p);
    }

    let suspicious = 0;
    const rows = [];
    for (const [ip, a] of agg) {
        const e = existing.find((x) => x.source_ip === ip);
        const ptr = e?.ptr ?? ptrs.get(ip) ?? null;
        const provider = e?.provider ?? providerForPtr(ptr);
        const totals = { message_count: (e?.message_count ?? 0) + a.messages, spf_pass: (e?.spf_pass ?? 0) + a.spf, dkim_pass: (e?.dkim_pass ?? 0) + a.dkim, dmarc_pass: (e?.dmarc_pass ?? 0) + a.dmarc };
        // An analyst's classification is never overwritten by the system.
        const auto = classifySource({ ...totals, provider });
        const keepManual = e && e.classified_by !== 'system';
        const classification = keepManual ? e.classification : auto.classification;
        rows.push({
            org_id: owner.org_id, domain: owner.domain, source_ip: ip, ptr, provider, ...totals,
            classification, classification_reason: keepManual ? e.classification_reason : auto.reason, classified_by: keepManual ? e.classified_by : 'system',
            first_seen: e?.first_seen && e.first_seen < report.date_begin ? e.first_seen : report.date_begin,
            last_seen: e?.last_seen && e.last_seen > report.date_end ? e.last_seen : report.date_end,
        });
        if (classification === 'suspicious') {
            suspicious++;
            const high = totals.message_count >= emailsecConfig.spoofHighMessages() || a.delivered > 0;
            await correlateOrRaise(db, owner.org_id, [{ type: 'ip', value: ip }], {
                correlation_key: `dmarc-spoof:${owner.domain}:${ip}`,
                severity: high ? 'high' : 'medium', module: 'dmarc', detection_type: 'spoofing', entity: ip,
                title: `Unauthorised source sending as ${owner.domain}`,
                description: `Multiple messages claiming ${owner.domain} were observed from an unauthorised sending source (${ip}${ptr ? `, ${ptr}` : ''}). ${auto.reason}`,
                evidence: {
                    summary: `${report.reporter} reported ${a.messages} message${a.messages === 1 ? '' : 's'} from ${ip} failing DMARC${a.delivered ? ` — ${a.delivered} delivered because the policy did not block them` : ''}.`,
                    ref: { kind: 'dmarc_report', id: storedId }, data: { reporter: report.reporter, messages: a.messages, delivered: a.delivered, window: [report.date_begin, report.date_end] },
                },
                indicators: [{ type: 'ip', value: ip }, { type: 'domain', value: owner.domain }],
            });
        } else {
            await recordIndicators(db, owner.org_id, [{ type: 'ip', value: ip }], { module: 'dmarc', kind: 'sending_source', id: `${owner.domain}:${ip}` });
        }
    }
    await db.upsert('email_sending_sources', rows, ['org_id', 'domain', 'source_ip']);
    const total = await db.count('email_sending_sources', [f.eq('org_id', owner.org_id), f.eq('domain', owner.domain)]);
    await db.update('email_domains', [f.eq('id', owner.id)], { sending_sources: total, updated_at: new Date().toISOString() });
    return suspicious;
}

// ── Analytics ──────────────────────────────────────────────────────────────────────────────

export interface DmarcAnalytics {
    days: number; domain: string | null; reports: number;
    totals: { messages: number; pass: number; fail: number; spf_fail: number; dkim_fail: number; pass_rate: number | null };
    sources: { known: number; unknown: number; suspicious: number };
    series: { day: string; pass: number; fail: number }[];
    top_failing: { source_ip: string; messages: number }[];
}

export async function dmarcAnalytics(db: Db, orgId: string, domain: string | null, days: number): Promise<DmarcAnalytics> {
    const since = new Date(Date.now() - days * 86_400_000).toISOString();
    const scope = [f.eq('org_id', orgId), ...(domain ? [f.eq('domain', domain)] : [])];
    const [records, reports, sources] = await Promise.all([
        db.select<{ message_count: number; dmarc_pass: boolean; spf_aligned: boolean; dkim_aligned: boolean; date_begin: string; source_ip: string }>('dmarc_records', {
            filters: [...scope, f.gte('date_begin', since)], limit: 1000, select: 'message_count, dmarc_pass, spf_aligned, dkim_aligned, date_begin, source_ip',
        }),
        db.count('dmarc_reports', [...scope, f.gte('date_begin', since)]),
        db.select<{ classification: string }>('email_sending_sources', { filters: scope, limit: 1000, select: 'classification' }),
    ]);
    const totals = { messages: 0, pass: 0, fail: 0, spf_fail: 0, dkim_fail: 0, pass_rate: null as number | null };
    const byDay = new Map<string, { pass: number; fail: number }>();
    const failing = new Map<string, number>();
    for (const r of records) {
        const n = Number(r.message_count) || 0;
        totals.messages += n;
        if (r.dmarc_pass) totals.pass += n; else { totals.fail += n; failing.set(r.source_ip, (failing.get(r.source_ip) ?? 0) + n); }
        if (!r.spf_aligned) totals.spf_fail += n;
        if (!r.dkim_aligned) totals.dkim_fail += n;
        const day = r.date_begin.slice(0, 10);
        const d = byDay.get(day) ?? { pass: 0, fail: 0 };
        if (r.dmarc_pass) d.pass += n; else d.fail += n;
        byDay.set(day, d);
    }
    totals.pass_rate = totals.messages ? Math.round((totals.pass / totals.messages) * 1000) / 10 : null;
    return {
        days, domain, reports,
        totals,
        sources: {
            known: sources.filter((s) => s.classification === 'known').length,
            unknown: sources.filter((s) => s.classification === 'unknown').length,
            suspicious: sources.filter((s) => s.classification === 'suspicious').length,
        },
        series: [...byDay.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([day, v]) => ({ day, ...v })),
        top_failing: [...failing.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([source_ip, messages]) => ({ source_ip, messages })),
    };
}
