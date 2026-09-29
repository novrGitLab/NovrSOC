// End-to-end API tests: the real routers on an ephemeral port, with the in-memory store, a fake
// DNS resolver, stubbed provider APIs and a stub case system — no network, no Supabase.
process.env.JWT_SECRET = 'integration-test-secret';
process.env.EMAILSEC_JOBS_DISABLED = 'true';
for (const k of ['M365_CLIENT_ID', 'M365_CLIENT_SECRET', 'M365_REDIRECT_URI', 'GOOGLE_WORKSPACE_SA_KEY', 'EMAIL_PROXY_TOKEN', 'OPENCTI_URL', 'OPENCTI_TOKEN', 'MAILGUN_WEBHOOK_SIGNING_KEY', 'WAZUH_INDEXER_HOST', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY']) delete process.env[k];

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { createHmac, generateKeyPairSync, randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import emailSecurityRouter from '../../../routes/emailSecurity';
import emailRouter from '../../../routes/email';
import { createMemoryDb, setDb, SchemaMissingError, type Db } from '../db';
import { setDnsClient } from '../dnsInspect';
import { setAnalyzers, ingestEvents } from '../messagingService';
import { setCaseApi } from '../alerts';
import { setConnectorFetch } from '../connectors/http';
import { fromGateway } from '../eventModel';
import { pushDomainToOpenCti } from '../integrations';
import type { UrlAnalysis } from '../urlIntel';
import { SAMPLE_REPORT, zipOf } from './fixtures';

const db = createMemoryDb();
const dkimKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
const TXT: Record<string, string[]> = {
    'example.com': ['v=spf1 include:_spf.google.com ~all'],
    '_spf.google.com': ['v=spf1 ip4:209.85.128.0/17 ~all'],
    '_dmarc.example.com': ['v=DMARC1; p=none; rua=mailto:reports@example.com'],
    'google._domainkey.example.com': [`v=DKIM1; k=rsa; p=${dkimKey}`],
};
const cases = new Map<string, { id: string; case_number: string }>();
let base = '';
let server: Server;

const token = (role: string, org = 'org-a') => jwt.sign({ sub: randomUUID(), email: `${role}@novrsoc.test`, role, org_id: org }, process.env.JWT_SECRET!);
const api = async (method: string, path: string, opts: { role?: string; org?: string; body?: unknown; form?: FormData; redirect?: RequestRedirect } = {}) => {
    const headers: Record<string, string> = {};
    if (opts.role) headers.Authorization = `Bearer ${token(opts.role, opts.org)}`;
    let body: BodyInit | undefined;
    if (opts.form) body = opts.form;
    else if (opts.body !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(opts.body); }
    const res = await fetch(`${base}${path}`, { method, headers, body, redirect: opts.redirect ?? 'follow' });
    const data = await res.json().catch(() => null);
    return { status: res.status, data, res };
};
const reportForm = (buf: Buffer, field = 'report') => { const fd = new FormData(); fd.append(field, new Blob([new Uint8Array(buf)]), 'google.com!example.com.zip'); return fd; };

before(async () => {
    setDb(db);
    setDnsClient({
        txt: async (n) => TXT[n] ?? [],
        mx: async (n) => (n === 'example.com' ? [{ exchange: 'aspmx.l.google.com', priority: 1 }] : []),
        reverse: async (ip) => (ip === '209.85.220.41' ? 'mail-sor-f41.google.com' : null),
    });
    setAnalyzers({
        url: async (u: string) => ({ input: u, normalized: null, analyzed_at: '', verdict: 'no_known_threat', reasons: [], signals: [], sources: [], domain_age_days: null, registrar: null, fetch: null }) as UrlAnalysis,
    });
    setCaseApi({
        createCase: async (input) => {
            const existing = cases.get(input.source_id ?? '');
            if (existing) return { ok: true, created: false, case: existing as never };
            const c = { id: randomUUID(), case_number: `CASE-${String(cases.size + 1).padStart(4, '0')}` };
            cases.set(input.source_id ?? c.id, c);
            return { ok: true, created: true, case: c as never };
        },
        addTimeline: async () => {},
    });
    const app = express();
    app.use(express.json());
    app.use('/api/email-security', emailSecurityRouter);
    app.use('/api/email', emailRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => { server.close(); setDb(null); setDnsClient(null); setAnalyzers(null); setCaseApi(null); setConnectorFetch(null); });

// ── Access control + domain onboarding ──

test('requires a staff token; portal users and unknown roles are refused', async () => {
    assert.equal((await api('GET', '/api/email-security/overview')).status, 401);
    assert.equal((await api('GET', '/api/email-security/overview', { role: 'portal_user' })).status, 403);
});

test('domain onboarding: validation, RBAC, live inspection, duplicate, tenant isolation', async () => {
    assert.equal((await api('POST', '/api/email-security/dmarc/domains', { role: 'analyst', body: { domain: 'example.com' } })).status, 403);
    assert.equal((await api('POST', '/api/email-security/dmarc/domains', { role: 'soc_manager', body: { domain: 'not a domain' } })).status, 400);

    const r = await api('POST', '/api/email-security/dmarc/domains', { role: 'soc_manager', body: { domain: 'https://Example.com/' } });
    assert.equal(r.status, 201);
    assert.equal(r.data.domain.domain, 'example.com');
    assert.equal(r.data.inspection.statuses.spf, 'pass');
    assert.equal(r.data.inspection.statuses.dmarc, 'warn'); // p=none
    assert.equal(r.data.inspection.statuses.dkim, 'pass');
    assert.equal(r.data.inspection.spf.total_lookups, 1);
    assert.equal(r.data.domain.dmarc_policy, 'none');
    assert.equal(r.data.domain.health_score, 80);

    assert.equal((await api('POST', '/api/email-security/dmarc/domains', { role: 'soc_manager', body: { domain: 'example.com' } })).status, 409);
    assert.equal((await api('GET', '/api/email-security/dmarc/domains', { role: 'analyst' })).data.domains.length, 1);
    assert.equal((await api('GET', '/api/email-security/dmarc/domains', { role: 'soc_manager', org: 'org-b' })).data.domains.length, 0);
    const detail = await api('GET', `/api/email-security/dmarc/domains/${r.data.domain.id}`, { role: 'executive' });
    assert.equal(detail.status, 200);
    assert.ok(detail.data.latest.dmarc.warnings.length);
    assert.equal((await api('GET', `/api/email-security/dmarc/domains/${r.data.domain.id}`, { role: 'soc_manager', org: 'org-b' })).status, 404);
});

test('policy change is a plan for an administrator, never an automatic DNS change', async () => {
    const [d] = await db.select<{ id: string }>('email_domains', {});
    const r = await api('POST', `/api/email-security/dmarc/domains/${d.id}/policy-plan`, { role: 'soc_manager', body: { policy: 'reject' } });
    assert.equal(r.status, 200);
    assert.equal(r.data.host, '_dmarc.example.com');
    assert.equal(r.data.value, 'v=DMARC1; p=reject; rua=mailto:reports@example.com');
    const [after] = await db.select<{ dmarc_policy: string }>('email_domains', {});
    assert.equal(after.dmarc_policy, 'none', 'stored policy is what DNS publishes, untouched');
});

// ── DMARC report ingestion ──

test('report ingestion: store, roll up sources, classify, raise one spoofing alert', async () => {
    const r = await api('POST', '/api/email-security/dmarc/reports/upload', { role: 'soc_manager', form: reportForm(zipOf('r.xml', SAMPLE_REPORT)) });
    assert.equal(r.status, 201);
    assert.equal(r.data.records, 2);
    assert.equal(r.data.suspicious_sources, 1);

    const sources = (await api('GET', '/api/email-security/dmarc/sources', { role: 'analyst' })).data.sources;
    const google = sources.find((s: { source_ip: string }) => s.source_ip === '209.85.220.41');
    const bad = sources.find((s: { source_ip: string }) => s.source_ip === '203.0.113.9');
    assert.equal(google.classification, 'known');
    assert.equal(google.provider, 'Google');
    assert.equal(bad.classification, 'suspicious');

    const alerts = (await api('GET', '/api/email-security/alerts', { role: 'analyst' })).data.alerts;
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].detection_type, 'spoofing');
    assert.equal(alerts[0].severity, 'high'); // delivered under p=none
    assert.equal(alerts[0].entity, '203.0.113.9');

    const again = await api('POST', '/api/email-security/dmarc/reports/upload', { role: 'soc_manager', form: reportForm(zipOf('r.xml', SAMPLE_REPORT)) });
    assert.equal(again.status, 200);
    assert.equal(again.data.duplicate, true);
    assert.equal((await api('GET', '/api/email-security/alerts', { role: 'analyst' })).data.alerts[0].occurrences, 1, 'duplicate report adds nothing');

    const analytics = (await api('GET', '/api/email-security/dmarc/analytics?days=3650', { role: 'analyst' })).data;
    assert.equal(analytics.totals.messages, 134);
    assert.equal(analytics.totals.pass_rate, 89.6);
    assert.equal(analytics.sources.suspicious, 1);
});

test('report ingestion refuses other tenants and unmonitored domains', async () => {
    const other = await api('POST', '/api/email-security/dmarc/reports/upload', { role: 'soc_manager', org: 'org-b', form: reportForm(Buffer.from(SAMPLE_REPORT)) });
    assert.equal(other.status, 422);
    const junk = await api('POST', '/api/email-security/dmarc/reports/upload', { role: 'soc_manager', form: reportForm(Buffer.from('not xml')) });
    assert.equal(junk.status, 400);
});

// ── Cross-module correlation ──

test('email events correlate with Phish ID domains and DMARC sources — no duplicate alerts', async () => {
    const added = await api('POST', '/api/email-security/phishid/domains', { role: 'analyst', body: { domain: 'company-login.example' } });
    assert.equal(added.status, 201);

    const ev = (id: string, extra: Record<string, unknown> = {}) => fromGateway({
        id, message_id: `<${id}@x>`, org_id: 'org-a', from_address: 'it@evil-sender.example', to_address: 'staff@example.com', verdict: 'clean', received_at: new Date().toISOString(), ...extra,
    });
    const e1 = { ...ev('e1'), urls: [{ url: 'https://company-login.example/reset', domain: 'company-login.example' }] };
    const e2 = { ...ev('e2'), urls: [{ url: 'https://company-login.example/other', domain: 'company-login.example' }] };
    assert.equal(await ingestEvents(db, 'org-a', [e1, e2]), 2);

    let alerts = (await api('GET', '/api/email-security/alerts', { role: 'analyst' })).data.alerts;
    const phish = alerts.filter((a: { correlation_key: string }) => a.correlation_key === 'phish:company-login.example');
    assert.equal(phish.length, 1, 'one alert for the domain');
    assert.equal(phish[0].occurrences, 2);
    assert.equal(phish[0].severity, 'high'); // delivered

    // A message from the IP DMARC flagged attaches to the existing spoofing alert.
    await ingestEvents(db, 'org-a', [ev('e3', { source_ip: '203.0.113.9' })]);
    alerts = (await api('GET', '/api/email-security/alerts', { role: 'analyst' })).data.alerts;
    const spoof = alerts.find((a: { detection_type: string }) => a.detection_type === 'spoofing');
    assert.deepEqual([...spoof.modules].sort(), ['dmarc', 'messaging']);
    assert.equal(spoof.occurrences, 2);

    // An unrelated clean message raises nothing.
    await ingestEvents(db, 'org-a', [ev('e4', { from_address: 'news@shop.example' })]);
    assert.equal((await api('GET', '/api/email-security/alerts', { role: 'analyst' })).data.alerts.length, 2);

    // Phish ID investigation shows the email observations.
    const inv = await api('GET', `/api/email-security/phishid/domains/${added.data.domain.id}`, { role: 'analyst' });
    assert.equal(inv.data.timeline.filter((t: { kind: string }) => t.kind === 'email').length, 2);
    assert.equal(inv.data.soc_alerts.available, false); // Wazuh not configured → said so, not empty-as-clean
});

test('malicious events from freemail senders do not merge on the provider domain', async () => {
    const mk = (id: string, from: string) => ({ ...fromGateway({ id, message_id: `<${id}@x>`, org_id: 'org-a', from_address: from, to_address: 'a@example.com', verdict: 'phishing', received_at: new Date().toISOString() }) });
    await ingestEvents(db, 'org-a', [mk('f1', 'one@gmail.com'), mk('f2', 'two@gmail.com')]);
    const keys = (await api('GET', '/api/email-security/alerts', { role: 'analyst' })).data.alerts.map((a: { correlation_key: string }) => a.correlation_key);
    assert.ok(keys.includes('msg:phishing:one@gmail.com'));
    assert.ok(keys.includes('msg:phishing:two@gmail.com'));
});

// ── Alert workflow + cases ──

test('alert workflow: status, RBAC, case creation through the SOC case system', async () => {
    const [a] = (await api('GET', '/api/email-security/alerts?status=open', { role: 'analyst' })).data.alerts;
    assert.equal((await api('PATCH', `/api/email-security/alerts/${a.id}`, { role: 'executive', body: { status: 'resolved' } })).status, 403);
    assert.equal((await api('PATCH', `/api/email-security/alerts/${a.id}`, { role: 'analyst', body: { status: 'bogus' } })).status, 400);
    const up = await api('PATCH', `/api/email-security/alerts/${a.id}`, { role: 'analyst', body: { status: 'investigating', note: 'Checking with IT' } });
    assert.equal(up.data.alert.status, 'investigating');

    const c = await api('POST', `/api/email-security/alerts/${a.id}/case`, { role: 'analyst' });
    assert.equal(c.status, 201);
    assert.match(c.data.case_number, /^CASE-/);
    const again = await api('POST', `/api/email-security/alerts/${a.id}/case`, { role: 'analyst' });
    assert.equal(again.status, 200);
    assert.equal(again.data.case_number, c.data.case_number, 'same alert → same case');
    const detail = (await api('GET', `/api/email-security/alerts/${a.id}`, { role: 'analyst' })).data.alert;
    assert.equal(detail.case_id, c.data.case_id);
    assert.ok(detail.timeline.some((t: { action: string }) => /Case CASE-/.test(t.action)));
});

// ── Provider connections ──

test('Microsoft 365: not configured → honest refusal; consent → verified connection → sync', async () => {
    const off = await api('POST', '/api/email-security/messaging/connections/microsoft365/start', { role: 'soc_manager' });
    assert.equal(off.status, 409);
    assert.deepEqual(off.data.missing, ['M365_CLIENT_ID', 'M365_CLIENT_SECRET', 'M365_REDIRECT_URI']);

    Object.assign(process.env, { M365_CLIENT_ID: 'app-id', M365_CLIENT_SECRET: 'secret', M365_REDIRECT_URI: 'https://api.test/cb', FRONTEND_URL: 'https://app.test' });
    const start = await api('POST', '/api/email-security/messaging/connections/microsoft365/start', { role: 'soc_manager' });
    const url = new URL(start.data.consent_url);
    assert.equal(url.searchParams.get('client_id'), 'app-id');
    const state = url.searchParams.get('state')!;

    const bad = await api('GET', `/api/email-security/messaging/connections/microsoft365/callback?state=forged&admin_consent=True&tenant=${randomUUID()}`, { redirect: 'manual' });
    assert.equal(bad.res.status, 302);
    assert.match(bad.res.headers.get('location')!, /result=error/);

    const alertBody = { value: [{ id: 'm1', category: 'Phish', createdDateTime: new Date().toISOString(), evidence: [{ '@odata.type': '#microsoft.graph.security.analyzedMessageEvidence', networkMessageId: 'n1', p1Sender: { emailAddress: 'x@bad.example' }, recipientEmailAddress: 'u@example.com', deliveryAction: 'Blocked', deliveryLocation: 'Quarantine', threats: ['Phish'] }] }] };
    let alertsPayload: unknown = { value: [] };
    setConnectorFetch(async (input) => {
        const u = String(input);
        if (u.includes('/oauth2/v2.0/token')) return Response.json({ access_token: jwt.sign({ roles: ['SecurityAlert.Read.All'] }, 'k'), expires_in: 3600 });
        if (u.includes('/security/alerts_v2')) return Response.json(alertsPayload);
        return new Response('{}', { status: 404 });
    });
    const tenant = randomUUID();
    const ok = await api('GET', `/api/email-security/messaging/connections/microsoft365/callback?state=${state}&admin_consent=True&tenant=${tenant}`, { redirect: 'manual' });
    assert.match(ok.res.headers.get('location')!, /result=connected/);
    const conns = (await api('GET', '/api/email-security/messaging/connections', { role: 'analyst' })).data.connections;
    const m = conns.find((c: { provider: string }) => c.provider === 'microsoft365');
    assert.equal(m.status, 'connected');
    assert.equal(m.connection.tenant_id, tenant);

    alertsPayload = alertBody;
    const sync = await api('POST', '/api/email-security/messaging/connections/microsoft365/sync', { role: 'analyst' });
    assert.equal(sync.status, 200);
    assert.equal(sync.data.stored, 1);
    const q = (await api('GET', '/api/email-security/messaging/events?view=quarantine', { role: 'analyst' })).data.events;
    assert.equal(q.length, 1);
    assert.match(q[0].action_by, /Microsoft 365/);
});

test('Microsoft 365: consent without SecurityAlert.Read.All is a permission error', async () => {
    const start = await api('POST', '/api/email-security/messaging/connections/microsoft365/start', { role: 'soc_manager', org: 'org-c' });
    const state = new URL(start.data.consent_url).searchParams.get('state')!;
    setConnectorFetch(async (input) => String(input).includes('/token') ? Response.json({ access_token: jwt.sign({ roles: [] }, 'k'), expires_in: 3600 }) : Response.json({ value: [] }));
    const r = await api('GET', `/api/email-security/messaging/connections/microsoft365/callback?state=${state}&admin_consent=True&tenant=${randomUUID()}`, { redirect: 'manual' });
    assert.match(r.res.headers.get('location')!, /result=permission_error/);
});

test('Google Workspace: delegation verified, and refusal reported as a permission error', async () => {
    const key = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    process.env.GOOGLE_WORKSPACE_SA_KEY = JSON.stringify({ client_email: 'novrsoc@proj.iam.gserviceaccount.com', private_key: key });
    setConnectorFetch(async (input) => String(input).includes('oauth2.googleapis.com') ? Response.json({ access_token: 'g', expires_in: 3600 }) : Response.json({ items: [] }));
    assert.equal((await api('POST', '/api/email-security/messaging/connections/google_workspace', { role: 'soc_manager', body: { admin_email: 'nope' } })).status, 400);
    const ok = await api('POST', '/api/email-security/messaging/connections/google_workspace', { role: 'soc_manager', body: { admin_email: 'admin@example.com' } });
    assert.equal(ok.status, 200);
    assert.equal(ok.data.connection.status, 'connected');

    setConnectorFetch(async () => Response.json({ error: 'unauthorized_client', error_description: 'Client is unauthorized to retrieve access tokens using this method.' }, { status: 401 }));
    const denied = await api('POST', '/api/email-security/messaging/connections/google_workspace', { role: 'soc_manager', org: 'org-d', body: { admin_email: 'admin@other.example' } });
    assert.equal(denied.status, 502);
    assert.equal(denied.data.connection.status, 'permission_error');
});

test('mail gateway: without its token the connection is an auth error, not "connected"', async () => {
    const r = await api('POST', '/api/email-security/messaging/connections/gateway', { role: 'soc_manager' });
    assert.equal(r.status, 502);
    assert.equal(r.data.connection.status, 'auth_error');
    assert.match(r.data.connection.last_error, /EMAIL_PROXY_TOKEN/);
});

// ── OpenCTI ──

test('OpenCTI: unconfigured and low-confidence pushes are refused; confirmed findings are sent', async () => {
    const off = await pushDomainToOpenCti('x.example', 90, '', []);
    assert.equal(off.ok, false);
    assert.match((off as { error: string }).error, /not configured/);
    Object.assign(process.env, { OPENCTI_URL: 'https://opencti.test', OPENCTI_TOKEN: 't' });
    const low = await pushDomainToOpenCti('x.example', 40, '', []);
    assert.equal(low.ok, false);
    const realFetch = globalThis.fetch;
    let sent: { query: string; variables: { value: string } } | null = null;
    globalThis.fetch = (async (_u: unknown, init?: RequestInit) => { sent = JSON.parse(String(init?.body)); return Response.json({ data: { stixCyberObservableAdd: { id: 'octi-1' } } }); }) as typeof fetch;
    try {
        const r = await pushDomainToOpenCti('company-login.example', 90, 'confirmed', ['phishing']);
        assert.deepEqual(r, { ok: true, id: 'octi-1' });
        assert.equal(sent!.variables.value, 'company-login.example');
        assert.match(sent!.query, /createIndicator: true/);
    } finally { globalThis.fetch = realFetch; }

    const [pd] = await db.select<{ id: string }>('phishing_domains', {});
    assert.equal((await api('POST', `/api/email-security/phishid/domains/${pd.id}/opencti`, { role: 'soc_manager' })).status, 409, 'only confirmed phishing is shared');
});

// ── Mailgun DMARC inbox ──

test('Mailgun inbox: refuses unsigned reports, accepts signed ones', async () => {
    const form = (sig?: { timestamp: string; token: string; signature: string }) => {
        const fd = reportForm(zipOf('r.xml', SAMPLE_REPORT.replace('1234567890', 'mg-1')), 'attachment-1');
        if (sig) for (const [k, v] of Object.entries(sig)) fd.append(k, v);
        return fd;
    };
    assert.equal((await api('POST', '/api/email/dmarc-inbound', { form: form() })).status, 503);
    process.env.MAILGUN_WEBHOOK_SIGNING_KEY = 'mg-key';
    assert.equal((await api('POST', '/api/email/dmarc-inbound', { form: form({ timestamp: String(Math.floor(Date.now() / 1000)), token: 't', signature: 'wrong' }) })).status, 401);
    const ts = String(Math.floor(Date.now() / 1000));
    const good = await api('POST', '/api/email/dmarc-inbound', { form: form({ timestamp: ts, token: 'tok', signature: createHmac('sha256', 'mg-key').update(`${ts}tok`).digest('hex') }) });
    assert.equal(good.status, 200);
    assert.equal(good.data.accepted, true);
    assert.equal(good.data.duplicate, false);
});

// ── Overview + setup state ──

test('overview reports real counts and null (not zero) where nothing is connected', async () => {
    const o = (await api('GET', '/api/email-security/overview', { role: 'executive' })).data;
    assert.equal(o.kpis.protected_domains, 1);
    assert.equal(typeof o.kpis.dmarc_compliance, 'number');
    assert.equal(o.kpis.phishing_domains, null, 'no brand configured → not available, not 0');
    assert.equal(o.setup.brand, false);
    assert.ok(o.recent_alerts.length >= 2);

    const fresh = await api('GET', '/api/email-security/overview', { role: 'executive', org: 'org-z' });
    assert.equal(fresh.data.kpis.dmarc_compliance, null);
    assert.equal(fresh.data.kpis.malicious_emails, null);
});

test('missing schema is a 503 with setup instructions', async () => {
    const broken: Db = new Proxy({} as Db, { get: (_t, p) => (p === 'kind' ? 'supabase' : async () => { throw new SchemaMissingError('email_domains'); }) });
    setDb(broken);
    try {
        const r = await api('GET', '/api/email-security/dmarc/domains', { role: 'analyst' });
        assert.equal(r.status, 503);
        assert.equal(r.data.setup_required, true);
        assert.match(r.data.schema_file, /2026-09-email-security\.sql/);
    } finally { setDb(db); }
});

test('Microsoft 365: a tenant already connected to another organisation cannot be claimed by editing the callback', async () => {
    const [owned] = await db.select<{ tenant_id: string }>('messaging_connections', { filters: [{ col: 'provider', op: 'eq', value: 'microsoft365' }, { col: 'org_id', op: 'eq', value: 'org-a' }], limit: 1 });
    assert.ok(owned?.tenant_id, 'org-a connected earlier in this file');
    const start = await api('POST', '/api/email-security/messaging/connections/microsoft365/start', { role: 'soc_manager', org: 'org-evil' });
    const state = new URL(start.data.consent_url).searchParams.get('state')!;
    setConnectorFetch(async (input) => String(input).includes('/token') ? Response.json({ access_token: jwt.sign({ roles: ['SecurityAlert.Read.All'] }, 'k'), expires_in: 3600 }) : Response.json({ value: [] }));
    const r = await api('GET', `/api/email-security/messaging/connections/microsoft365/callback?state=${state}&admin_consent=True&tenant=${owned.tenant_id}`, { redirect: 'manual' });
    assert.match(r.res.headers.get('location')!, /result=error/);
    const evil = await db.select('messaging_connections', { filters: [{ col: 'org_id', op: 'eq', value: 'org-evil' }] });
    assert.equal(evil.length, 0);
});

test('shared infrastructure does not merge unrelated alerts: docs.google.com links, a provider MTA IP', async () => {
    const mk = (id: string, from: string, extra: Record<string, unknown> = {}) => ({
        ...fromGateway({ id, message_id: `<${id}@x>`, org_id: 'org-s', from_address: from, to_address: 'a@example.com', verdict: 'phishing', received_at: new Date().toISOString(), source_ip: '209.85.220.41' }),
        ...extra,
    });
    await ingestEvents(db, 'org-s', [
        mk('g1', 'billing@alpha-invoices.test', { urls: [{ url: 'https://docs.google.com/forms/d/aaa/viewform', domain: 'docs.google.com' }] }),
        mk('g2', 'hr@beta-payroll.test', { urls: [{ url: 'https://docs.google.com/forms/d/bbb/viewform', domain: 'docs.google.com' }] }),
    ]);
    const alerts = (await api('GET', '/api/email-security/alerts', { role: 'analyst', org: 'org-s' })).data.alerts;
    assert.deepEqual(alerts.map((a: { entity: string }) => a.entity).sort(), ['alpha-invoices.test', 'beta-payroll.test'], 'two senders → two alerts despite shared Google link domain and MTA IP');
    // …while the SAME malicious URL does correlate.
    await ingestEvents(db, 'org-s', [mk('g3', 'other@gamma.test', { urls: [{ url: 'https://docs.google.com/forms/d/aaa/viewform', domain: 'docs.google.com' }] })]);
    const after = (await api('GET', '/api/email-security/alerts', { role: 'analyst', org: 'org-s' })).data.alerts;
    assert.equal(after.length, 2);
    assert.equal(after.find((a: { entity: string }) => a.entity === 'alpha-invoices.test').occurrences, 2);
});
