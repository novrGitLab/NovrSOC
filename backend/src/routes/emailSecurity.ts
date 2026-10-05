// Email Security API — /api/email-security. DMARC SaaS, Intellicode Phish ID, Messaging Suite,
// shared alerts and URL intelligence.
//
// Access: every route needs a NovrSOC staff token except the Microsoft 365 admin-consent
// callback (Microsoft redirects the customer's admin there; it is authenticated by a signed,
// expiring state token instead). Reads: any staff role. Analyst actions (status changes,
// notes, inspections, cases): analyst and above. Configuration (domains, brand, connections,
// policy plans): managers. Every write is audit-logged. Tenant isolation: org_id always comes
// from the caller's token, never from the request.
import { Router, type Response } from 'express';
import multer from 'multer';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import { randomUUID } from 'crypto';
import { requireAuth, requireRole, type AuthRequest } from '../middleware/auth';
import { logAudit } from '../lib/audit';
import { DEFAULT_ORG_ID, isUuid } from '../services/cases';
import { getDb, f, SchemaMissingError, SCHEMA_FILE, type Db } from '../services/emailsec/db';
import { normalizeDomain, inspectDomain } from '../services/emailsec/dnsInspect';
import { verificationRecord } from '../services/emailsec/verification';
import { POLICY_EXPLANATIONS, buildDmarcRecord, type DmarcPolicy } from '../services/emailsec/authRecords';
import { runDomainCheck, ingestReport, dmarcAnalytics, type EmailDomain, type SendingSource } from '../services/emailsec/dmarcService';
import {
    cleanBrandInput, getBrand, discover, addManualDomain, enrichDomain, setPhishStatus, addPhishNote, PHISH_STATUSES,
    type PhishingDomain, type PhishStatus,
} from '../services/emailsec/phishService';
import { RISK_ORDER, type Risk } from '../services/emailsec/phishRisk';
import { listConnections, upsertAndVerify, verifyConnection, syncConnection, isProvider, CONNECTORS } from '../services/emailsec/messagingService';
import { signInUrl, tenantConsentUrl, redeemSignInCode, isTenantId, M365IdentityError } from '../services/emailsec/connectors/m365Onboarding';
import type { Connection } from '../services/emailsec/connectors/types';
import { ALERT_STATUSES, updateAlert, escalateToCase, indicatorSightings, type EmailAlert, type AlertStatus } from '../services/emailsec/alerts';
import { analyzeUrl } from '../services/emailsec/urlIntel';
import { analyzeAttachment } from '../services/emailsec/attachmentIntel';
import { integrationStatuses, openctiHealth, pushDomainToOpenCti, relatedSocAlerts } from '../services/emailsec/integrations';

const router = Router();
const MANAGER = requireRole('super_admin', 'soc_manager');
const ANALYST = requireRole('super_admin', 'soc_manager', 'analyst');
const STAFF = requireRole('super_admin', 'soc_manager', 'analyst', 'executive');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024, files: 1 } });
// Inspections reach out to DNS / websites / feeds — bounded per user.
const inspectLimiter = rateLimit({
    windowMs: 60_000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false,
    keyGenerator: (req) => (req as AuthRequest).user?.email ?? 'anonymous',
    message: { error: 'Too many inspection requests — try again in a minute.' },
});

const orgOf = (req: AuthRequest) => req.user?.org_id ?? DEFAULT_ORG_ID;
const actorOf = (req: AuthRequest) => req.user?.email || 'unknown';
const str = (v: unknown, max = 500) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

function audit(req: AuthRequest, action: string, details: string, resourceId?: string, severity: 'info' | 'warning' | 'critical' = 'info') {
    logAudit({ user: actorOf(req), action, resource: 'email_security', ip: req.ip ?? '', result: 'success', details, resource_id: resourceId, severity });
}

type Handler = (db: Db, req: AuthRequest, res: Response) => Promise<unknown>;
/** Resolves the store and turns "tables not created yet" into a 503 the UI shows as setup. */
const h = (fn: Handler) => async (req: AuthRequest, res: Response) => {
    const db = getDb();
    if (!db) return res.status(503).json({ error: 'Database not configured (SUPABASE_URL / SUPABASE_SERVICE_KEY).', setup_required: true });
    try {
        await fn(db, req, res);
    } catch (err) {
        if (err instanceof SchemaMissingError) return res.status(503).json({ error: err.message, setup_required: true, schema_file: SCHEMA_FILE });
        console.error('[email-security]', req.method, req.path, err);
        if (!res.headersSent) res.status(500).json({ error: err instanceof Error ? err.message : 'Internal error' });
    }
};

// ── Microsoft 365 admin-consent callback (no staff token — see header) ──────────────────────

const stateSecret = () => process.env.JWT_SECRET || process.env.DEV_TOKEN_SECRET || '';

// Two steps share this redirect URI, told apart by the signed state (see m365Onboarding.ts):
//   p = 'm365-signin'  → OpenID Connect sign-in: redeem the code, validate the ID token, take the
//                        tenant from its tid claim, then send the admin to THAT tenant's consent.
//   p = 'm365-consent' → admin consent: the query `tenant` must equal the verified tid in the
//                        signed state; the stored tenant is always the verified one.
type SignInState = { org: string; sub: string; p: 'm365-signin'; nonce: string };
type ConsentState = { org: string; sub: string; p: 'm365-consent'; tid: string; oid: string | null };

router.get('/messaging/connections/microsoft365/callback', h(async (db, req, res) => {
    const back = (result: string, detail: string) => {
        const base = process.env.FRONTEND_URL?.replace(/\/$/, '');
        const q = new URLSearchParams({ provider: 'microsoft365', result, detail: detail.slice(0, 300) });
        if (base) return res.redirect(`${base}/admin/email/messaging?${q}`);
        return res.type('text/plain').send(`Microsoft 365 connection: ${result}. ${detail} You can close this window.`);
    };
    const refuse = (sub: string, detail: string, auditDetail: string) => {
        logAudit({ user: sub, action: 'EMAILSEC_CONNECT_M365', resource: 'email_security', ip: req.ip ?? '', result: 'failed', details: auditDetail, severity: 'critical' });
        return back('error', detail);
    };

    let state: SignInState | ConsentState;
    try {
        state = jwt.verify(String(req.query.state ?? ''), stateSecret()) as SignInState | ConsentState;
        if (state.p !== 'm365-signin' && state.p !== 'm365-consent') throw new Error('wrong flow');
    } catch {
        return back('error', 'The link expired or was not issued by NovrSOC. Start the connection again.');
    }
    if (req.query.error) return back('error', `${String(req.query.error)}: ${String(req.query.error_description ?? '').slice(0, 200)}`);

    if (state.p === 'm365-signin') {
        const code = String(req.query.code ?? '');
        if (!code) return back('error', 'Microsoft did not return a sign-in code.');
        let identity;
        try {
            identity = await redeemSignInCode(code, state.nonce);
        } catch (err) {
            return refuse(state.sub, err instanceof M365IdentityError ? err.message : 'Microsoft sign-in failed.', `sign-in rejected: ${(err as Error).message}`);
        }
        const consentState = jwt.sign({ org: state.org, sub: state.sub, p: 'm365-consent', tid: identity.tid, oid: identity.oid } satisfies ConsentState, stateSecret(), { expiresIn: '15m' });
        logAudit({ user: state.sub, action: 'EMAILSEC_CONNECT_M365_SIGNIN', resource: 'email_security', ip: req.ip ?? '', result: 'success', details: `verified tenant ${identity.tid} (${identity.username ?? 'unknown user'})` });
        return res.redirect(tenantConsentUrl(identity.tid, consentState));
    }

    // Consent step: Microsoft's tenant parameter is only compared, never trusted.
    const returned = req.query.tenant;
    if (req.query.admin_consent !== 'True') return back('error', 'Microsoft did not confirm admin consent.');
    if (!isTenantId(returned)) return refuse(state.sub, 'Microsoft did not return a tenant.', 'consent callback without tenant');
    if (returned.toLowerCase() !== state.tid.toLowerCase()) {
        return refuse(state.sub, 'The consent was for a different tenant than the account that signed in. Start the connection again.', `tenant mismatch: signed-in ${state.tid}, callback ${returned}`);
    }
    const tenant = state.tid;
    const claimed = await db.select<Connection>('messaging_connections', { filters: [f.eq('provider', 'microsoft365'), f.eq('tenant_id', tenant)], limit: 5 });
    if (claimed.some((c) => c.org_id !== state.org)) {
        return refuse(state.sub, 'This Microsoft 365 tenant is already connected to a different organisation.', `tenant ${tenant} belongs to another organisation`);
    }
    const conn = await upsertAndVerify(db, state.org, 'microsoft365', { tenant_id: tenant, scopes: CONNECTORS.microsoft365.permissions }, state.sub);
    logAudit({ user: state.sub, action: 'EMAILSEC_CONNECT_M365', resource: 'email_security', ip: req.ip ?? '', result: conn.status === 'connected' ? 'success' : 'failed', details: `tenant ${tenant}: ${conn.status}`, severity: 'warning' });
    return back(conn.status, conn.status === 'connected' ? 'Connected.' : conn.last_error ?? conn.status);
}));

router.use(requireAuth, STAFF);

// ── Overview + health ──────────────────────────────────────────────────────────────────────

router.get('/overview', h(async (db, req, res) => {
    const org = orgOf(req);
    const since30 = new Date(Date.now() - 30 * 86_400_000).toISOString();
    const since7 = new Date(Date.now() - 7 * 86_400_000).toISOString();
    const MALICIOUS = ['phishing', 'malware', 'bec', 'impersonation', 'malicious_url', 'suspicious_attachment', 'spoofing'];
    const OPEN = ['new', 'investigating'];
    const [domains, brand, connections, analytics, suspiciousSources, phishOpen, phishNew, phishHigh, phishOpenRows,
        malicious, quarantined, malUrls, malAttach, threats, criticalAlerts, recentAlerts] = await Promise.all([
        db.count('email_domains', [f.eq('org_id', org)]),
        getBrand(db, org),
        db.select<Connection>('messaging_connections', { filters: [f.eq('org_id', org)] }),
        dmarcAnalytics(db, org, null, 30),
        db.select<{ source_ip: string }>('email_sending_sources', { filters: [f.eq('org_id', org), f.eq('classification', 'suspicious')], select: 'source_ip', limit: 1000 }),
        db.count('phishing_domains', [f.eq('org_id', org), f.in('status', ['discovered', 'under_investigation', 'suspicious', 'confirmed_phishing'])]),
        db.count('phishing_domains', [f.eq('org_id', org), f.gte('first_observed', since7)]),
        db.count('phishing_domains', [f.eq('org_id', org), f.in('risk', ['high', 'critical']), f.in('status', ['discovered', 'under_investigation', 'suspicious', 'confirmed_phishing'])]),
        // Active threats: open domains that are confirmed phishing or rated high / critical (ids, so the union isn't double-counted).
        db.select<{ id: string; status: string; risk: string }>('phishing_domains', { filters: [f.eq('org_id', org), f.in('status', ['discovered', 'under_investigation', 'suspicious', 'confirmed_phishing'])], select: 'id, status, risk', limit: 1000 }),
        db.count('email_events', [f.eq('org_id', org), f.gte('received_at', since30), f.in('detection', MALICIOUS)]),
        db.count('email_events', [f.eq('org_id', org), f.gte('received_at', since30), f.eq('action', 'quarantine')]),
        db.count('email_events', [f.eq('org_id', org), f.gte('received_at', since30), f.eq('detection', 'malicious_url')]),
        db.count('email_events', [f.eq('org_id', org), f.gte('received_at', since30), f.in('detection', ['malware', 'suspicious_attachment'])]),
        db.count('email_events', [f.eq('org_id', org), f.gte('received_at', since30), f.neq('detection', 'clean')]),
        db.count('email_alerts', [f.eq('org_id', org), f.eq('severity', 'critical'), f.in('status', OPEN)]),
        db.select<EmailAlert>('email_alerts', { filters: [f.eq('org_id', org)], order: { col: 'last_seen' }, limit: 10 }),
    ]);
    // Spoofing attempts: failing messages in the window from sources classified suspicious.
    const spoofIps = [...new Set(suspiciousSources.map((s) => s.source_ip))];
    const spoofRows = spoofIps.length
        ? await db.select<{ message_count: number }>('dmarc_records', { filters: [f.eq('org_id', org), f.gte('date_begin', since30), f.eq('dmarc_pass', false), f.in('source_ip', spoofIps.slice(0, 500))], select: 'message_count', limit: 1000 })
        : [];
    const spoofing = spoofRows.reduce((s, r) => s + (Number(r.message_count) || 0), 0);
    const phishActive = phishOpenRows.filter((r) => r.status === 'confirmed_phishing' || r.risk === 'high' || r.risk === 'critical').length;
    const phishLive = phishOpenRows.filter((r) => r.status === 'confirmed_phishing').length;
    const connected = connections.filter((c) => c.status === 'connected');
    res.json({
        setup: { domains: domains > 0, reports: analytics.reports > 0, brand: !!brand, providers: connected.length > 0 },
        kpis: {
            protected_domains: domains,
            dmarc_compliance: analytics.totals.pass_rate,
            spoofing_attempts: analytics.reports > 0 ? spoofing : null,
            phishing_domains: brand ? phishOpen : null,
            active_phishing_threats: brand ? phishActive : null,
            malicious_emails: connected.length ? malicious : null,
            quarantined_emails: connected.length ? quarantined : null,
            critical_alerts: criticalAlerts,
        },
        dmarc: { passing: analytics.totals.pass, failing: analytics.totals.fail, unknown_senders: analytics.sources.unknown + analytics.sources.suspicious, sending_sources: analytics.sources.known + analytics.sources.unknown + analytics.sources.suspicious, reports: analytics.reports },
        phishing: { new_7d: phishNew, high_risk: phishHigh, active_sites: phishLive, suspicious_urls: malUrls },
        messaging: { threats, quarantined, malicious_urls: malUrls, malicious_attachments: malAttach, providers: connected.map((c) => c.provider) },
        recent_alerts: recentAlerts.map(({ evidence: _e, timeline: _t, ...a }) => a),
        generated_at: new Date().toISOString(),
    });
}));

router.get('/integrations', async (_req, res) => {
    res.json({ integrations: integrationStatuses(), opencti: await openctiHealth() });
});

// ── DMARC: domains ─────────────────────────────────────────────────────────────────────────

router.get('/dmarc/domains', h(async (db, req, res) => {
    const org = orgOf(req);
    const [domains, checks, reports] = await Promise.all([
        db.select<EmailDomain>('email_domains', { filters: [f.eq('org_id', org)], order: { col: 'domain', asc: true } }),
        db.select<{ domain_id: string; created_at: string; verification?: unknown; result?: { verification?: unknown } }>('email_dns_checks', {
            filters: [f.eq('org_id', org)], order: { col: 'created_at' }, limit: 1000, select: 'domain_id, created_at, verification:result->verification',
        }),
        db.select<{ domain: string; created_at: string }>('dmarc_aggregate_reports', { filters: [f.eq('org_id', org)], order: { col: 'created_at' }, limit: 1000, select: 'domain, created_at' }),
    ]);
    // Newest first, so the first match per domain is its latest check / report.
    res.json({
        domains: domains.map((d) => {
            const check = checks.find((c) => c.domain_id === d.id);
            return {
                ...d,
                verification: check ? (check.verification ?? check.result?.verification ?? null) : null,
                last_report_at: reports.find((r) => r.domain === d.domain)?.created_at ?? null,
            };
        }),
    });
}));

router.post('/dmarc/domains', MANAGER, inspectLimiter, h(async (db, req, res) => {
    const domain = normalizeDomain(str(req.body?.domain, 253));
    if (!domain) return res.status(400).json({ error: 'Enter a valid domain, e.g. company.com' });
    const selectors = (Array.isArray(req.body?.dkim_selectors) ? req.body.dkim_selectors : []).map((s: unknown) => str(s, 63)).filter((s: string) => /^[a-z0-9._-]+$/i.test(s)).slice(0, 20);
    const org = orgOf(req);
    const [existing] = await db.select<EmailDomain>('email_domains', { filters: [f.eq('org_id', org), f.eq('domain', domain)], limit: 1 });
    if (existing) return res.status(409).json({ error: `${domain} is already monitored.`, domain: existing });
    const [row] = await db.insert<EmailDomain>('email_domains', { org_id: org, domain, dkim_selectors: selectors, created_by: actorOf(req), updated_at: new Date().toISOString() });
    audit(req, 'EMAILSEC_ADD_DOMAIN', domain, row.id);
    const inspection = await runDomainCheck(db, row);
    const [fresh] = await db.select<EmailDomain>('email_domains', { filters: [f.eq('id', row.id)], limit: 1 });
    res.status(201).json({ domain: fresh ?? row, inspection, verification_record: verificationRecord(org, domain) });
}));

router.get('/dmarc/domains/:id', h(async (db, req, res) => {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Domain not found' });
    const org = orgOf(req);
    const [d] = await db.select<EmailDomain>('email_domains', { filters: [f.eq('org_id', org), f.eq('id', req.params.id)], limit: 1 });
    if (!d) return res.status(404).json({ error: 'Domain not found' });
    const [checks, sources, reports] = await Promise.all([
        db.select<{ result: unknown; created_at: string }>('email_dns_checks', { filters: [f.eq('org_id', org), f.eq('domain_id', d.id)], order: { col: 'created_at' }, limit: 10 }),
        db.select<SendingSource>('email_sending_sources', { filters: [f.eq('org_id', org), f.eq('domain', d.domain)], order: { col: 'message_count' }, limit: 200 }),
        db.select('dmarc_aggregate_reports', { filters: [f.eq('org_id', org), f.eq('domain', d.domain)], order: { col: 'date_begin' }, limit: 20 }),
    ]);
    res.json({ domain: d, latest: checks[0]?.result ?? null, history: checks.map((c) => ({ at: c.created_at })), sources, reports, policies: POLICY_EXPLANATIONS, verification_record: verificationRecord(org, d.domain) });
}));

router.patch('/dmarc/domains/:id', MANAGER, h(async (db, req, res) => {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Domain not found' });
    const selectors = (Array.isArray(req.body?.dkim_selectors) ? req.body.dkim_selectors : []).map((s: unknown) => str(s, 63)).filter((s: string) => /^[a-z0-9._-]+$/i.test(s)).slice(0, 20);
    const [d] = await db.update<EmailDomain>('email_domains', [f.eq('org_id', orgOf(req)), f.eq('id', req.params.id)], { dkim_selectors: selectors, updated_at: new Date().toISOString() });
    if (!d) return res.status(404).json({ error: 'Domain not found' });
    audit(req, 'EMAILSEC_UPDATE_DOMAIN', `${d.domain} DKIM selectors: ${selectors.join(', ') || '(none)'}`, d.id);
    res.json({ domain: d });
}));

router.delete('/dmarc/domains/:id', MANAGER, h(async (db, req, res) => {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Domain not found' });
    const [d] = await db.select<EmailDomain>('email_domains', { filters: [f.eq('org_id', orgOf(req)), f.eq('id', req.params.id)], limit: 1 });
    if (!d) return res.status(404).json({ error: 'Domain not found' });
    await db.remove('email_domains', [f.eq('id', d.id)]);
    audit(req, 'EMAILSEC_REMOVE_DOMAIN', d.domain, d.id, 'warning');
    res.json({ success: true });
}));

router.post('/dmarc/domains/:id/inspect', ANALYST, inspectLimiter, h(async (db, req, res) => {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Domain not found' });
    const [d] = await db.select<EmailDomain>('email_domains', { filters: [f.eq('org_id', orgOf(req)), f.eq('id', req.params.id)], limit: 1 });
    if (!d) return res.status(404).json({ error: 'Domain not found' });
    const inspection = await runDomainCheck(db, d);
    if (!inspection) return res.status(502).json({ error: 'DNS inspection failed — see the domain status for the error.' });
    res.json({ inspection });
}));

/** Ownership check: looks up the _novrsoc-verification TXT record (with a full inspection). */
router.post('/dmarc/domains/:id/verify', ANALYST, inspectLimiter, h(async (db, req, res) => {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Domain not found' });
    const [d] = await db.select<EmailDomain>('email_domains', { filters: [f.eq('org_id', orgOf(req)), f.eq('id', req.params.id)], limit: 1 });
    if (!d) return res.status(404).json({ error: 'Domain not found' });
    const inspection = await runDomainCheck(db, d);
    if (!inspection) return res.status(502).json({ error: 'DNS inspection failed — see the domain status for the error.' });
    audit(req, 'EMAILSEC_VERIFY_DOMAIN', `${d.domain}: ${inspection.verification?.state}`, d.id);
    res.json({ verification: inspection.verification, verification_record: verificationRecord(d.org_id, d.domain), inspection });
}));

/** Ad-hoc inspection of any domain — nothing stored. */
router.post('/dmarc/inspect', ANALYST, inspectLimiter, async (req: AuthRequest, res) => {
    const domain = normalizeDomain(str(req.body?.domain, 253));
    if (!domain) return res.status(400).json({ error: 'Enter a valid domain' });
    res.json({ inspection: await inspectDomain(domain) });
});

/**
 * Policy change plan. NovrSOC does not (and cannot) edit the customer's DNS: this produces the
 * exact record an administrator would publish, and audit-logs that it was requested.
 */
router.post('/dmarc/domains/:id/policy-plan', MANAGER, h(async (db, req, res) => {
    const policy = str(req.body?.policy) as DmarcPolicy;
    if (!['none', 'quarantine', 'reject'].includes(policy)) return res.status(400).json({ error: 'policy must be none, quarantine or reject' });
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Domain not found' });
    const org = orgOf(req);
    const [d] = await db.select<EmailDomain>('email_domains', { filters: [f.eq('org_id', org), f.eq('id', req.params.id)], limit: 1 });
    if (!d) return res.status(404).json({ error: 'Domain not found' });
    const [check] = await db.select<{ result: { dmarc: Parameters<typeof buildDmarcRecord>[0] } }>('email_dns_checks', { filters: [f.eq('org_id', org), f.eq('domain_id', d.id)], order: { col: 'created_at' }, limit: 1 });
    const current = check?.result?.dmarc ?? null;
    const record = buildDmarcRecord(current?.exists ? current : null, policy, process.env.DMARC_RUA_ADDRESS);
    audit(req, 'EMAILSEC_DMARC_POLICY_PLAN', `${d.domain}: plan to publish p=${policy} (current ${d.dmarc_policy ?? 'none published'})`, d.id, 'warning');
    const existing = (current as { records?: string[] } | null)?.records ?? (current?.raw ? [current.raw] : []);
    res.json({ host: `_dmarc.${d.domain}`, type: 'TXT', value: record, current: existing.join('  |  ') || null, explanation: POLICY_EXPLANATIONS[policy],
        note: `${existing.length > 1 ? `Delete all ${existing.length} existing DMARC records and publish only this one. ` : existing.length ? 'Replace the existing DMARC record with this one. ' : ''}Publish this at your DNS provider. NovrSOC does not change DNS; re-run the inspection after publishing to confirm.` });
}));

// ── DMARC: reports, sources, analytics ─────────────────────────────────────────────────────

router.get('/dmarc/reports', h(async (db, req, res) => {
    const domain = normalizeDomain(str(req.query.domain));
    res.json({ reports: await db.select('dmarc_aggregate_reports', { filters: [f.eq('org_id', orgOf(req)), ...(domain ? [f.eq('domain', domain)] : [])], order: { col: 'date_begin' }, limit: 200 }) });
}));

router.get('/dmarc/reports/:id', h(async (db, req, res) => {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Report not found' });
    const org = orgOf(req);
    const [report] = await db.select('dmarc_aggregate_reports', { filters: [f.eq('org_id', org), f.eq('id', req.params.id)], limit: 1 });
    if (!report) return res.status(404).json({ error: 'Report not found' });
    res.json({ report, records: await db.select('dmarc_records', { filters: [f.eq('org_id', org), f.eq('report_id', req.params.id)], order: { col: 'message_count' }, limit: 1000 }) });
}));

router.post('/dmarc/reports/upload', MANAGER, upload.single('report'), h(async (db, req, res) => {
    const file = (req as AuthRequest & { file?: Express.Multer.File }).file;
    if (!file) return res.status(400).json({ error: 'Attach the report file (.xml, .xml.gz or .zip) as "report".' });
    const r = await ingestReport(db, file.buffer, 'upload', orgOf(req));
    if (!r.ok) return res.status(r.status).json({ error: r.error });
    audit(req, 'EMAILSEC_DMARC_REPORT_UPLOAD', `${r.domain} report ${r.report_id}: ${r.records} records, ${r.messages} messages${r.duplicate ? ' (duplicate — already stored)' : ''}${r.domain_verified ? '' : ' — domain ownership NOT verified'}`, undefined, r.domain_verified ? 'info' : 'warning');
    res.status(r.duplicate ? 200 : 201).json(r);
}));

router.get('/dmarc/sources', h(async (db, req, res) => {
    const domain = normalizeDomain(str(req.query.domain));
    const cls = str(req.query.classification);
    res.json({ sources: await db.select<SendingSource>('email_sending_sources', {
        filters: [f.eq('org_id', orgOf(req)), ...(domain ? [f.eq('domain', domain)] : []), ...(['known', 'unknown', 'suspicious'].includes(cls) ? [f.eq('classification', cls)] : [])],
        order: { col: 'message_count' }, limit: 1000,
    }) });
}));

router.patch('/dmarc/sources/:id', MANAGER, h(async (db, req, res) => {
    const cls = str(req.body?.classification);
    if (!['known', 'unknown', 'suspicious'].includes(cls)) return res.status(400).json({ error: 'classification must be known, unknown or suspicious' });
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Source not found' });
    const reason = str(req.body?.reason, 500) || `Classified ${cls} by ${actorOf(req)}`;
    const [s] = await db.update<SendingSource>('email_sending_sources', [f.eq('org_id', orgOf(req)), f.eq('id', req.params.id)], { classification: cls, classification_reason: reason, classified_by: actorOf(req) });
    if (!s) return res.status(404).json({ error: 'Source not found' });
    audit(req, 'EMAILSEC_CLASSIFY_SOURCE', `${s.source_ip} for ${s.domain} → ${cls}`, s.id);
    res.json({ source: s });
}));

router.get('/dmarc/analytics', h(async (db, req, res) => {
    const days = Math.min(365, Math.max(1, Number(req.query.days) || 30));
    res.json(await dmarcAnalytics(db, orgOf(req), normalizeDomain(str(req.query.domain)), days));
}));

// ── Phish ID ───────────────────────────────────────────────────────────────────────────────

router.get('/phishid/brand', h(async (db, req, res) => { res.json({ brand: await getBrand(db, orgOf(req)) }); }));

router.put('/phishid/brand', MANAGER, h(async (db, req, res) => {
    const v = cleanBrandInput(req.body ?? {});
    if (!v.ok) return res.status(400).json({ error: v.error });
    const now = new Date().toISOString();
    const [brand] = await db.upsert('brand_profiles', { org_id: orgOf(req), ...v.value, updated_by: actorOf(req), updated_at: now }, ['org_id']);
    audit(req, 'EMAILSEC_BRAND_SAVE', `${v.value.organization_name}: ${v.value.primary_domains.join(', ')}`);
    res.json({ brand });
}));

router.post('/phishid/discover', MANAGER, inspectLimiter, h(async (db, req, res) => {
    const r = await discover(db, orgOf(req), actorOf(req));
    if (!r) return res.status(409).json({ error: 'Configure your brand (organisation name and domains) first.' });
    audit(req, 'EMAILSEC_PHISH_DISCOVERY', `${r.candidates_checked} candidates, ${r.registered} registered, ${r.new_domains.length} new`);
    res.json(r);
}));

router.get('/phishid/domains', h(async (db, req, res) => {
    const status = str(req.query.status);
    const risk = str(req.query.risk);
    const q = str(req.query.q, 100).toLowerCase();
    const rows = await db.select<PhishingDomain>('phishing_domains', {
        filters: [f.eq('org_id', orgOf(req)), ...(PHISH_STATUSES.includes(status as PhishStatus) ? [f.eq('status', status)] : []), ...(RISK_ORDER.includes(risk as Risk) ? [f.eq('risk', risk)] : []),
            ...(q ? [f.ilike('domain', `%${q.replace(/[%_]/g, '')}%`)] : [])],
        order: { col: 'last_observed' }, limit: 1000,
        select: 'id, domain, brand_domain, techniques, similarity, discovered_via, status, risk, risk_score, risk_signals, resolves, assigned_to, alert_id, first_observed, last_observed, last_enriched',
    });
    res.json({ domains: rows });
}));

router.post('/phishid/domains', ANALYST, h(async (db, req, res) => {
    const r = await addManualDomain(db, orgOf(req), str(req.body?.domain, 253), actorOf(req));
    if (!r.ok) return res.status(400).json({ error: r.error });
    if (r.created) audit(req, 'EMAILSEC_PHISH_ADD', r.row.domain, r.row.id);
    res.status(r.created ? 201 : 200).json({ domain: r.row, created: r.created });
}));

router.get('/phishid/domains/:id', h(async (db, req, res) => {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Domain not found' });
    const org = orgOf(req);
    const [row] = await db.select<PhishingDomain>('phishing_domains', { filters: [f.eq('org_id', org), f.eq('id', req.params.id)], limit: 1 });
    if (!row) return res.status(404).json({ error: 'Domain not found' });
    const ips = row.intel?.dns.a ?? [];
    const [timeline, sightings, alert, soc] = await Promise.all([
        db.select('phishing_observations', { filters: [f.eq('org_id', org), f.eq('phishing_domain_id', row.id)], order: { col: 'created_at' }, limit: 200 }),
        indicatorSightings(db, org, [row.domain, ...ips]),
        row.alert_id ? db.select<EmailAlert>('email_alerts', { filters: [f.eq('org_id', org), f.eq('id', row.alert_id)], limit: 1 }).then((a) => a[0] ?? null) : Promise.resolve(null),
        relatedSocAlerts([row.domain, ...ips]),
    ]);
    res.json({ domain: row, timeline, related_indicators: sightings, alert, soc_alerts: soc });
}));

router.post('/phishid/domains/:id/refresh', ANALYST, inspectLimiter, h(async (db, req, res) => {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Domain not found' });
    const [row] = await db.select<PhishingDomain>('phishing_domains', { filters: [f.eq('org_id', orgOf(req)), f.eq('id', req.params.id)], limit: 1 });
    if (!row) return res.status(404).json({ error: 'Domain not found' });
    audit(req, 'EMAILSEC_PHISH_REFRESH', row.domain, row.id);
    res.json({ domain: await enrichDomain(db, row, actorOf(req)) });
}));

router.patch('/phishid/domains/:id', ANALYST, h(async (db, req, res) => {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Domain not found' });
    const status = req.body?.status === undefined ? undefined : str(req.body.status) as PhishStatus;
    if (status !== undefined && !PHISH_STATUSES.includes(status)) return res.status(400).json({ error: `status must be one of ${PHISH_STATUSES.join(', ')}` });
    const assigned = req.body?.assigned_to === undefined ? undefined : (str(req.body.assigned_to, 200) || null);
    const row = await setPhishStatus(db, orgOf(req), req.params.id, actorOf(req), { status, assigned_to: assigned });
    if (!row) return res.status(404).json({ error: 'Domain not found' });
    audit(req, 'EMAILSEC_PHISH_STATUS', `${row.domain}: ${status ?? ''}${assigned !== undefined ? ` assigned ${assigned ?? 'none'}` : ''}`, row.id);
    res.json({ domain: row });
}));

router.post('/phishid/domains/:id/notes', ANALYST, h(async (db, req, res) => {
    const body = str(req.body?.body, 4000);
    if (!body) return res.status(400).json({ error: 'Note is empty' });
    if (!isUuid(req.params.id) || !(await addPhishNote(db, orgOf(req), req.params.id, actorOf(req), body))) return res.status(404).json({ error: 'Domain not found' });
    audit(req, 'EMAILSEC_PHISH_NOTE', body.slice(0, 120), req.params.id);
    res.status(201).json({ success: true });
}));

router.post('/phishid/domains/:id/opencti', MANAGER, h(async (db, req, res) => {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Domain not found' });
    const org = orgOf(req);
    const [row] = await db.select<PhishingDomain>('phishing_domains', { filters: [f.eq('org_id', org), f.eq('id', req.params.id)], limit: 1 });
    if (!row) return res.status(404).json({ error: 'Domain not found' });
    if (row.status !== 'confirmed_phishing') return res.status(409).json({ error: 'Only domains an analyst has marked "Confirmed phishing" are shared to OpenCTI.' });
    const confidence = Math.min(100, 70 + Math.round(row.risk_score / 4));
    const r = await pushDomainToOpenCti(row.domain, confidence, `Phishing domain impersonating ${row.brand_domain ?? 'a protected brand'}. ${row.risk_signals.map((s) => s.label).join('; ')}`, ['phishing', 'novrsoc-phishid']);
    if (!r.ok) return res.status(502).json({ error: r.error });
    await db.update('phishing_domains', [f.eq('id', row.id)], { opencti_id: r.id, updated_at: new Date().toISOString() });
    await db.insert('phishing_observations', { org_id: org, phishing_domain_id: row.id, kind: 'opencti', actor: actorOf(req), summary: `Shared to OpenCTI (confidence ${confidence}).`, data: { opencti_id: r.id } });
    audit(req, 'EMAILSEC_OPENCTI_PUSH', row.domain, row.id);
    res.json({ success: true, opencti_id: r.id });
}));

// ── Messaging Suite ────────────────────────────────────────────────────────────────────────

router.get('/messaging/connections', h(async (db, req, res) => { res.json({ connections: await listConnections(db, orgOf(req)) }); }));

router.post('/messaging/connections/microsoft365/start', MANAGER, (req: AuthRequest, res) => {
    const missing = CONNECTORS.microsoft365.missingConfig();
    if (missing.length) return res.status(409).json({ error: `Microsoft 365 is not available on this NovrSOC deployment yet: ${missing.join(', ')} not set.`, missing });
    const nonce = randomUUID();
    const state = jwt.sign({ org: orgOf(req), sub: actorOf(req), p: 'm365-signin', nonce }, stateSecret(), { expiresIn: '15m' });
    audit(req, 'EMAILSEC_CONNECT_M365_START', 'Microsoft sign-in link issued');
    // Step 1 is sign-in (to prove the tenant); consent for that tenant follows automatically.
    res.json({ authorize_url: signInUrl(state, nonce), permissions: CONNECTORS.microsoft365.permissions, expires_in_minutes: 15 });
});

router.post('/messaging/connections/google_workspace', MANAGER, h(async (db, req, res) => {
    const missing = CONNECTORS.google_workspace.missingConfig();
    if (missing.length) return res.status(409).json({ error: `Google Workspace is not available on this NovrSOC deployment yet: ${missing.join(', ')} not set.`, missing });
    const admin = str(req.body?.admin_email, 254).toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(admin)) return res.status(400).json({ error: 'Enter the Workspace super-admin address the service account will act as.' });
    const conn = await upsertAndVerify(db, orgOf(req), 'google_workspace', { admin_email: admin, scopes: CONNECTORS.google_workspace.permissions }, actorOf(req));
    audit(req, 'EMAILSEC_CONNECT_GOOGLE', `${admin}: ${conn.status}`, conn.id, 'warning');
    res.status(conn.status === 'connected' ? 200 : 502).json({ connection: conn });
}));

router.post('/messaging/connections/gateway', MANAGER, h(async (db, req, res) => {
    const conn = await upsertAndVerify(db, orgOf(req), 'gateway', { scopes: CONNECTORS.gateway.permissions }, actorOf(req));
    audit(req, 'EMAILSEC_CONNECT_GATEWAY', conn.status, conn.id);
    res.status(conn.status === 'connected' ? 200 : 502).json({ connection: conn });
}));

router.post('/messaging/connections/:provider/verify', ANALYST, h(async (db, req, res) => {
    const provider = String(req.params.provider);
    if (!isProvider(provider)) return res.status(404).json({ error: 'Unknown provider' });
    const [conn] = await db.select<Connection>('messaging_connections', { filters: [f.eq('org_id', orgOf(req)), f.eq('provider', provider)], limit: 1 });
    if (!conn) return res.status(404).json({ error: 'Not connected' });
    res.json({ connection: await verifyConnection(db, conn) });
}));

router.post('/messaging/connections/:provider/sync', ANALYST, inspectLimiter, h(async (db, req, res) => {
    const provider = String(req.params.provider);
    if (!isProvider(provider)) return res.status(404).json({ error: 'Unknown provider' });
    const [conn] = await db.select<Connection>('messaging_connections', { filters: [f.eq('org_id', orgOf(req)), f.eq('provider', provider)], limit: 1 });
    if (!conn) return res.status(404).json({ error: 'Not connected' });
    const r = await syncConnection(db, conn);
    audit(req, 'EMAILSEC_SYNC', `${provider}: ${r.ok ? `${r.fetched} fetched, ${r.stored} stored` : r.error}`);
    res.status(r.ok ? 200 : 502).json(r);
}));

router.delete('/messaging/connections/:provider', MANAGER, h(async (db, req, res) => {
    const provider = String(req.params.provider);
    if (!isProvider(provider)) return res.status(404).json({ error: 'Unknown provider' });
    await db.remove('messaging_connections', [f.eq('org_id', orgOf(req)), f.eq('provider', provider)]);
    audit(req, 'EMAILSEC_DISCONNECT', provider, undefined, 'warning');
    res.json({
        success: true,
        note: provider === 'microsoft365' ? 'NovrSOC has stopped syncing. To revoke access completely, remove the NovrSOC enterprise application in Microsoft Entra ID.'
            : provider === 'google_workspace' ? 'NovrSOC has stopped syncing. To revoke access completely, remove the service account\'s domain-wide delegation in the Google Admin console.'
            : 'NovrSOC has stopped importing gateway verdicts.',
    });
}));

const EVENT_LIST_COLS = 'id, provider, message_id, sender, sender_domain, recipient, subject, received_at, source_ip, spf, dkim, dmarc, detection, categories, severity, action, action_by, alert_id';

router.get('/messaging/events', h(async (db, req, res) => {
    const view = str(req.query.view);
    const filters = [f.eq('org_id', orgOf(req))];
    if (view === 'threats') filters.push(f.neq('detection', 'clean'));
    if (view === 'quarantine') filters.push(f.eq('action', 'quarantine'));
    for (const k of ['severity', 'detection', 'provider', 'action'] as const) { const v = str(req.query[k], 40); if (v) filters.push(f.eq(k, v)); }
    const from = str(req.query.from, 40); const to = str(req.query.to, 40);
    if (from && !Number.isNaN(Date.parse(from))) filters.push(f.gte('received_at', new Date(from).toISOString()));
    if (to && !Number.isNaN(Date.parse(to))) filters.push(f.lte('received_at', new Date(to).toISOString()));
    // risk: threat (high/critical detections) | suspicious (lower-severity detections) | clean
    const risk = str(req.query.risk, 20);
    if (risk === 'threat') { filters.push(f.neq('detection', 'clean')); filters.push(f.in('severity', ['high', 'critical'])); }
    if (risk === 'suspicious') { filters.push(f.neq('detection', 'clean')); filters.push(f.in('severity', ['informational', 'low', 'medium'])); }
    if (risk === 'clean') filters.push(f.eq('detection', 'clean'));
    // Search sender, recipient, subject and message id. Only a conservative character set is kept,
    // so the value can never alter the filter expression.
    const q = str(req.query.q, 200).toLowerCase().replace(/[^a-z0-9@._+\-<> ]/g, '').trim();
    if (q) filters.push(f.anyIlike(['sender', 'recipient', 'subject', 'message_id'], `%${q}%`));
    res.json({ events: await db.select('email_events', { filters, order: { col: 'received_at' }, limit: Math.min(1000, Number(req.query.limit) || 200), select: EVENT_LIST_COLS }) });
}));

router.get('/messaging/events/:id', h(async (db, req, res) => {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Event not found' });
    const org = orgOf(req);
    const [event] = await db.select<{ id: string; alert_id: string | null; source_ip: string | null; sender_domain: string | null; urls: { domain: string | null }[] }>('email_events', { filters: [f.eq('org_id', org), f.eq('id', req.params.id)], limit: 1 });
    if (!event) return res.status(404).json({ error: 'Event not found' });
    const values = [event.source_ip, event.sender_domain, ...event.urls.map((u) => u.domain)].filter((v): v is string => !!v);
    const [alert, sightings] = await Promise.all([
        event.alert_id ? db.select<EmailAlert>('email_alerts', { filters: [f.eq('org_id', org), f.eq('id', event.alert_id)], limit: 1 }).then((a) => a[0] ?? null) : Promise.resolve(null),
        indicatorSightings(db, org, values),
    ]);
    res.json({ event, alert, related_indicators: sightings });
}));

router.post('/messaging/events/:id/analyze', ANALYST, inspectLimiter, h(async (db, req, res) => {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Event not found' });
    const [event] = await db.select<{ id: string; urls: { url: string }[]; attachments: Parameters<typeof analyzeAttachment>[0][] }>('email_events', { filters: [f.eq('org_id', orgOf(req)), f.eq('id', req.params.id)], limit: 1 });
    if (!event) return res.status(404).json({ error: 'Event not found' });
    const analysis = {
        urls: await Promise.all(event.urls.slice(0, 10).map((u) => analyzeUrl(u.url))),
        attachments: await Promise.all(event.attachments.slice(0, 5).map((a) => analyzeAttachment(a))),
        analyzed_at: new Date().toISOString(),
    };
    await db.update('email_events', [f.eq('id', event.id)], { analysis });
    res.json({ analysis });
}));

// ── Alerts ─────────────────────────────────────────────────────────────────────────────────

router.get('/alerts', h(async (db, req, res) => {
    const filters = [f.eq('org_id', orgOf(req))];
    const status = str(req.query.status); const sev = str(req.query.severity); const mod = str(req.query.module);
    if (status === 'open') filters.push(f.in('status', ['new', 'investigating']));
    else if (ALERT_STATUSES.includes(status as AlertStatus)) filters.push(f.eq('status', status));
    if (sev) filters.push(f.eq('severity', sev));
    if (['dmarc', 'phishid', 'messaging'].includes(mod)) filters.push(f.eq('source_module', mod));
    const alerts = await db.select<EmailAlert>('email_alerts', { filters, order: { col: 'last_seen' }, limit: 500 });
    res.json({ alerts: alerts.map(({ evidence: _e, timeline: _t, ...a }) => a) });
}));

router.get('/alerts/:id', h(async (db, req, res) => {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Alert not found' });
    const org = orgOf(req);
    const [alert] = await db.select<EmailAlert>('email_alerts', { filters: [f.eq('org_id', org), f.eq('id', req.params.id)], limit: 1 });
    if (!alert) return res.status(404).json({ error: 'Alert not found' });
    const events = alert.related_events.length
        ? await db.select('email_events', { filters: [f.eq('org_id', org), f.in('id', alert.related_events.slice(-50))], order: { col: 'received_at' }, select: EVENT_LIST_COLS })
        : [];
    const soc = await relatedSocAlerts(alert.indicators.filter((i) => i.type === 'ip' || i.type === 'domain').map((i) => i.value));
    res.json({ alert, events, soc_alerts: soc });
}));

router.patch('/alerts/:id', ANALYST, h(async (db, req, res) => {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Alert not found' });
    const status = req.body?.status === undefined ? undefined : str(req.body.status) as AlertStatus;
    if (status !== undefined && !ALERT_STATUSES.includes(status)) return res.status(400).json({ error: `status must be one of ${ALERT_STATUSES.join(', ')}` });
    const assigned = req.body?.assigned_to === undefined ? undefined : (str(req.body.assigned_to, 200) || null);
    const note = str(req.body?.note, 4000) || undefined;
    const a = await updateAlert(db, orgOf(req), req.params.id, actorOf(req), { status, assigned_to: assigned, note });
    if (!a) return res.status(404).json({ error: 'Alert not found' });
    audit(req, 'EMAILSEC_ALERT_UPDATE', `${a.title}: ${[status && `status ${status}`, assigned !== undefined && `assigned ${assigned ?? 'none'}`, note && 'note'].filter(Boolean).join(', ')}`, a.id);
    res.json({ alert: a });
}));

router.post('/alerts/:id/case', ANALYST, h(async (db, req, res) => {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'Alert not found' });
    const caseId = str(req.body?.case_id, 64) || undefined;
    const r = await escalateToCase(db, orgOf(req), req.params.id, actorOf(req), caseId);
    if (!r.ok) return res.status(r.status).json({ error: r.error });
    audit(req, caseId ? 'EMAILSEC_ALERT_LINK_CASE' : 'EMAILSEC_ALERT_CASE', `case ${r.case_number}`, req.params.id);
    res.status(r.created ? 201 : 200).json(r);
}));

// ── Reusable URL intelligence (also for SOC alerts) ────────────────────────────────────────

router.post('/url/analyze', ANALYST, inspectLimiter, async (req: AuthRequest, res) => {
    const url = str(req.body?.url, 4000);
    if (!url) return res.status(400).json({ error: 'url is required' });
    res.json({ analysis: await analyzeUrl(url, { fetch: req.body?.fetch === true }) });
});

export default router;
