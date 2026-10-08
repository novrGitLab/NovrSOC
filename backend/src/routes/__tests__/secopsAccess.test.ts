// Phase S1 access control for the SecOps routers: 401 without a token, 403 for roles without the
// permission (executive, portal_user), 403 for a token without an org, and org isolation against
// an in-memory PostgREST (fakePostgrest.ts). Outbound fetch is stubbed: anything that isn't the
// local fake is refused, so no external service is ever called.
process.env.JWT_SECRET = 'secops-access-test-secret';
for (const k of [
    'SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'WAZUH_HOST', 'WAZUH_API_URL', 'WAZUH_INDEXER_HOST', 'WAZUH_INDEXER_PASS', 'WAZUH_INDEXER_PASSWORD',
    'EMAIL_ENABLED', 'BREVO_API_KEY', 'RESEND_API_KEY', 'SENDGRID_API_KEY', 'SMTP_HOST', 'SMTP_USER', 'SMTP_PASS',
    'ABUSEIPDB_API_KEY', 'URLHAUS_API_KEY', 'VIRUSTOTAL_API_KEY', 'VT_API_KEY', 'GREYNOISE_API_KEY', 'LEAKIX_API_KEY', 'MISP_URL', 'MISP_API_KEY',
    'OPNSENSE_URL', 'OPNSENSE_KEY', 'OPNSENSE_SECRET', 'CISO_EMAIL', 'ALERT_EMAIL_TO', 'COMMS_ALLOWED_DOMAINS',
]) delete process.env[k];
process.env.THREATFOX_API_KEY = 'test-only';

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import wazuhRouter from '../wazuh';
import mitreRouter from '../mitre';
import alertsRouter from '../alerts';
import threatManagementRouter from '../threatManagement';
import notificationsRouter from '../notifications';
import casesRouter from '../cases';
import soarRouter from '../soar';
import searchRouter from '../search';
import communicationsRouter from '../communications';
import secopsRouter from '../secops';
import handoverRouter from '../handover';
import { clientRouter as securityAssessmentClientRouter } from '../securityAssessment';

const A = 'org-a';
const B = 'org-b';
const caseA = randomUUID();
const caseB = randomUUID();
const taskB = randomUUID();
const ago = (h: number) => new Date(Date.now() - h * 3600_000).toISOString();

let db: FakePostgrest;
let server: Server;
let base = '';
const realFetch = globalThis.fetch;

const tok = (role: string, org?: string) =>
    jwt.sign({ sub: randomUUID(), email: `${role}@${org ?? 'none'}.test`, role, ...(org ? { org_id: org } : {}) }, process.env.JWT_SECRET!);

async function call(method: string, path: string, opts: { role?: string; org?: string; body?: unknown; asOrg?: string } = {}) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (opts.role) headers.Authorization = `Bearer ${tok(opts.role, opts.org)}`;
    if (opts.asOrg) headers['X-Org-Id'] = opts.asOrg;
    const r = await realFetch(`${base}${path}`, { method, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}

before(async () => {
    db = await startFakePostgrest({
        organisations: [
            { id: 'oa', slug: A, name: 'Org A', is_active: true, contact_name: 'Ann', contact_email: 'contact@a.test', ciso_name: 'Ada', ciso_email: 'ciso@a.test' },
            { id: 'ob', slug: B, name: 'Org B', is_active: true, contact_name: 'Bob', contact_email: 'contact@b.test', ciso_name: 'Bea', ciso_email: 'ciso@b.test' },
        ],
        platform_users: [
            { id: randomUUID(), org_id: 'oa', email: 'analyst@a.test', name: 'A Analyst', role: 'analyst', status: 'active' },
            { id: randomUUID(), org_id: 'ob', email: 'analyst@b.test', name: 'B Analyst', role: 'analyst', status: 'active' },
        ],
        cases: [
            { id: caseA, org_id: A, case_number: 'CASE-A-1', title: 'Shared phrase alpha', severity: 'high', status: 'open', tier: 2, auto_closed: false, escalated: false, source: 'wazuh', source_id: 'a-1', created_at: ago(2) },
            { id: caseB, org_id: B, case_number: 'CASE-B-1', title: 'Shared phrase bravo', severity: 'critical', status: 'open', tier: 2, auto_closed: false, escalated: false, source: 'wazuh', source_id: 'b-1', created_at: ago(1) },
        ],
        case_notes: [{ id: randomUUID(), case_id: caseB, author: 'b', content: 'org B note', created_at: ago(1) }],
        case_tasks: [{ id: taskB, case_id: caseB, title: 'org B task', status: 'pending', created_at: ago(1) }],
        case_timeline: [],
        case_iocs: [],
        soar_log: [
            { id: randomUUID(), case_id: caseA, tier: 2, action: 'Block IP a', result: 'SUCCESS', executed_at: ago(2) },
            { id: randomUUID(), case_id: caseB, tier: 2, action: 'Block IP b', result: 'SUCCESS', executed_at: ago(1) },
        ],
        handover_logs: [
            { id: randomUUID(), org_id: A, shift: 'a', summary: 'org A handover', open_incidents: {}, pending_actions: [], escalations: [], submitted_by: 'a', created_at: ago(2) },
            { id: randomUUID(), org_id: B, shift: 'b', summary: 'org B handover', open_incidents: {}, pending_actions: [], escalations: [], submitted_by: 'b', created_at: ago(1) },
        ],
        alert_communications: [
            { id: randomUUID(), org_id: A, subject: 'org A message', created_at: ago(2) },
            { id: randomUUID(), org_id: B, subject: 'org B message', created_at: ago(1) },
        ],
        nigeria_advisories: [],
        ioc_enrichments: [],
        threat_triage: [],
    });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';

    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
        const url = String(input instanceof Request ? input.url : input);
        if (url.startsWith('http://127.0.0.1')) return realFetch(input, init);
        if (url.startsWith('https://threatfox-api.abuse.ch/')) return Response.json({ query_status: 'no_result', data: 'no results' });
        throw new Error(`external call blocked in tests: ${url}`);
    }) as typeof fetch;

    const app = express();
    app.use(express.json());
    // Same mounts as index.ts.
    app.use('/api/wazuh', wazuhRouter);
    app.use('/api/mitre', mitreRouter);
    app.use('/api/alerts', alertsRouter);
    app.use('/api/threats', threatManagementRouter);
    app.use('/api/notifications', notificationsRouter);
    app.use('/api/cases', requireAuth, casesRouter);
    app.use('/api/soar', soarRouter);
    app.use('/api/search', searchRouter);
    app.use('/api/communications', requireAuth, communicationsRouter);
    app.use('/api/secops', requireAuth, secopsRouter);
    app.use('/api/handover', requireAuth, handoverRouter);
    app.use('/api/client/security-assessment', requireAuth, securityAssessmentClientRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
    server.close();
    await db.close();
    globalThis.fetch = realFetch;
});

// ── 401 / 403 on every route ─────────────────────────────────────────────────────────────────

const X = randomUUID();
const ROUTES: Record<string, [string, string, unknown?][]> = {
    wazuh: [['GET', '/api/wazuh/status'], ['GET', '/api/wazuh/agents'], ['GET', '/api/wazuh/incidents'], ['GET', '/api/wazuh/alerts-indexer'], ['GET', '/api/wazuh/enrollment'], ['POST', '/api/wazuh/hunt', {}]],
    mitre: [['GET', '/api/mitre/techniques'], ['GET', '/api/mitre/defend'], ['GET', '/api/mitre/technique/T1110']],
    alerts: [['GET', '/api/alerts/status']],
    threats: [
        ['GET', '/api/threats/alerts'], ['GET', '/api/threats/alerts/x'], ['PATCH', '/api/threats/alerts/x', {}], ['POST', '/api/threats/alerts/x/create-incident', {}],
        ['GET', '/api/threats/global-map'], ['GET', '/api/threats/stats'], ['GET', '/api/threats/actors'], ['GET', '/api/threats/live-ioc'],
        ['GET', '/api/threats'], ['POST', '/api/threats/x/contain', {}], ['POST', '/api/threats/x/escalate', {}], ['POST', '/api/threats/x/resolve', {}], ['POST', '/api/threats/x/assign', {}],
    ],
    notifications: [['GET', '/api/notifications'], ['POST', '/api/notifications/send', { subject: 's', message: 'm' }]],
    cases: [
        ['GET', '/api/cases'], ['POST', '/api/cases', {}], ['GET', `/api/cases/${X}`], ['POST', `/api/cases/${X}/assign`, {}], ['POST', `/api/cases/${X}/close`, {}],
        ['PATCH', `/api/cases/${X}`, {}], ['POST', `/api/cases/${X}/notes`, {}], ['POST', `/api/cases/${X}/tasks`, {}], ['PATCH', `/api/cases/${X}/tasks/${X}`, {}],
        ['POST', `/api/cases/${X}/escalate`, {}], ['POST', `/api/cases/${X}/execute-step`, {}], ['GET', `/api/cases/${X}/report`],
    ],
    secops: [['POST', '/api/secops/broadcast', {}], ['POST', '/api/secops/hunting/escalate', {}], ['POST', '/api/secops/actions/isolate', {}], ['POST', '/api/secops/actions/block-ip', {}]],
    soar: [['GET', '/api/soar/stats'], ['GET', '/api/soar/cases?tier=1'], ['GET', '/api/soar/log']],
    handover: [['GET', '/api/handover'], ['POST', '/api/handover', {}]],
    search: [['GET', '/api/search?q=shared']],
    communications: [['GET', '/api/communications/recipients'], ['GET', '/api/communications'], ['POST', '/api/communications/send', {}]],
};

for (const [router, routes] of Object.entries(ROUTES)) {
    test(`${router}: 401 without a token`, async () => {
        for (const [m, p, body] of routes) assert.equal((await call(m, p, { body })).status, 401, `${m} ${p}`);
    });
    test(`${router}: 403 for executive and portal_user`, async () => {
        for (const role of ['executive', 'portal_user']) {
            for (const [m, p, body] of routes) {
                const r = await call(m, p, { role, org: A, body });
                assert.equal(r.status, 403, `${role} ${m} ${p}`);
                assert.equal(r.data.error, 'Insufficient permissions');
            }
        }
    });
    test(`${router}: 403 for a token without an org (no default organisation)`, async () => {
        for (const [m, p, body] of routes) {
            const r = await call(m, p, { role: 'super_admin', body });
            assert.equal(r.status, 403, `${m} ${p}`);
            assert.match(r.data.error, /No organisation/);
        }
    });
}

test('an analyst with an org gets through the gate on read routes', async () => {
    for (const p of ['/api/cases', '/api/soar/stats', '/api/soar/log', '/api/handover', '/api/search?q=shared', '/api/communications/recipients', '/api/communications', '/api/notifications']) {
        const r = await call('GET', p, { role: 'analyst', org: A });
        assert.equal(r.status, 200, `${p}: ${JSON.stringify(r.data)}`);
    }
});

// ── Cross-org reads return nothing ───────────────────────────────────────────────────────────

test('cases: org A never sees org B cases, notes, tasks or reports', async () => {
    const list = await call('GET', '/api/cases', { role: 'analyst', org: A });
    assert.deepEqual(list.data.cases.map((c: Row) => c.id), [caseA]);
    assert.equal(list.data.total, 1);
    assert.equal((await call('GET', `/api/cases/${caseB}`, { role: 'analyst', org: A })).status, 404);
    assert.equal((await call('GET', `/api/cases/${caseB}/report`, { role: 'analyst', org: A })).status, 404);
});

test('cases: org A cannot add notes or tasks to org B cases, or change org B tasks', async () => {
    const notesBefore = db.tables.case_notes.length;
    const tasksBefore = db.tables.case_tasks.length;
    assert.equal((await call('POST', `/api/cases/${caseB}/notes`, { role: 'analyst', org: A, body: { content: 'cross-org note' } })).status, 404);
    assert.equal((await call('POST', `/api/cases/${caseB}/tasks`, { role: 'analyst', org: A, body: { title: 'cross-org task' } })).status, 404);
    assert.equal((await call('PATCH', `/api/cases/${caseB}/tasks/${taskB}`, { role: 'analyst', org: A, body: { status: 'completed' } })).status, 404);
    assert.equal(db.tables.case_notes.length, notesBefore);
    assert.equal(db.tables.case_tasks.length, tasksBefore);
    assert.equal(db.tables.case_tasks.find((t) => t.id === taskB)?.status, 'pending');
    // Its own case still works.
    assert.equal((await call('POST', `/api/cases/${caseA}/notes`, { role: 'analyst', org: A, body: { content: 'own note' } })).status, 200);
});

test('cases: a case created through the API belongs to the token org, whatever the body says', async () => {
    const r = await call('POST', '/api/cases', { role: 'analyst', org: A, body: { title: 'Manual case', severity: 'low', org_id: B } });
    assert.equal(r.status, 201, JSON.stringify(r.data));
    assert.equal(db.tables.cases.find((c) => c.id === r.data.id)?.org_id, A);
});

test('soar: stats, cases and log only cover the caller\'s org', async () => {
    const stats = await call('GET', '/api/soar/stats', { role: 'analyst', org: B });
    assert.equal(stats.data.total, 1);
    const cases = await call('GET', '/api/soar/cases?tier=2', { role: 'analyst', org: B });
    assert.deepEqual(cases.data.cases.map((c: Row) => c.id), [caseB]);
    const log = await call('GET', '/api/soar/log', { role: 'analyst', org: B });
    assert.deepEqual(log.data.entries.map((e: Row) => e.action), ['Block IP b']);
});

test('handover: org A reads only org A logs', async () => {
    const r = await call('GET', '/api/handover', { role: 'analyst', org: A });
    assert.deepEqual(r.data.logs.map((l: Row) => l.notes), ['org A handover']);
});

test('search: cases from another org never match', async () => {
    const r = await call('GET', '/api/search?q=shared phrase', { role: 'analyst', org: A });
    const cases = r.data.results.filter((x: Row) => x.type === 'case').map((x: Row) => x.title);
    assert.deepEqual(cases, ['CASE-A-1 — Shared phrase alpha']);
});

test('notifications: only the caller\'s org cases', async () => {
    const r = await call('GET', '/api/notifications', { role: 'analyst', org: A });
    const cases = r.data.notifications.filter((n: Row) => n.type === 'case').map((n: Row) => n.id);
    assert.deepEqual(cases, [caseA]);
});

test('communications: recipients and log are the caller\'s org only; another org\'s contact cannot be mailed', async () => {
    const rec = await call('GET', '/api/communications/recipients', { role: 'analyst', org: A });
    assert.deepEqual(rec.data.analysts.map((a: Row) => a.email), ['analyst@a.test']);
    assert.deepEqual(rec.data.clients.map((c: Row) => c.email).sort(), ['ciso@a.test', 'contact@a.test']);
    const log = await call('GET', '/api/communications', { role: 'analyst', org: A });
    assert.deepEqual(log.data.entries.map((e: Row) => e.subject), ['org A message']);
    const send = await call('POST', '/api/communications/send', { role: 'analyst', org: A, body: { recipient_type: 'client', client_email: 'contact@b.test', subject: 's', body: 'b', severity: 'high' } });
    assert.equal(send.status, 400);
    assert.match(send.data.error, /not on file/);
});

test('communications custom address: soc_manager/super_admin only, and only to COMMS_ALLOWED_DOMAINS', async () => {
    const send = (role: string, custom_email: string) => call('POST', '/api/communications/send', {
        role, org: A, body: { recipient_type: 'custom', custom_email, subject: 's', body: 'b', severity: 'low' },
    });
    delete process.env.COMMS_ALLOWED_DOMAINS;
    assert.equal((await send('soc_manager', 'someone@partner.test')).status, 403, 'unset list allows no custom address');
    process.env.COMMS_ALLOWED_DOMAINS = ' partner.test, @Other.test ';
    try {
        const analyst = await send('analyst', 'someone@partner.test');
        assert.equal(analyst.status, 403);
        assert.match(analyst.data.error, /SOC manager/);
        const outside = await send('soc_manager', 'someone@evil.test');
        assert.equal(outside.status, 403);
        assert.match(outside.data.error, /domain is not allowed/);
        assert.equal((await send('soc_manager', 'someone@sub.partner.test')).status, 403, 'exact domain match only');
        assert.equal((await send('super_admin', 'not-an-address')).status, 400);
        for (const [role, addr] of [['soc_manager', 'someone@partner.test'], ['super_admin', 'x@other.test']]) {
            const ok = await send(role, addr);
            // Past both checks; the send itself fails only because email is not configured in tests.
            assert.notEqual(ok.status, 403, `${role} ${addr}`);
            assert.deepEqual(ok.data.entry.recipients, [addr]);
        }
    } finally {
        delete process.env.COMMS_ALLOWED_DOMAINS;
    }
    // Recipients on file stay allowed for analysts, as before.
    const onFile = await call('POST', '/api/communications/send', {
        role: 'analyst', org: A, body: { recipient_type: 'client', client_email: 'contact@a.test', subject: 's', body: 'b', severity: 'low' },
    });
    assert.deepEqual(onFile.data.entry.recipients, ['contact@a.test']);
});

test('notifications/send: explicit recipients must be the caller\'s org contacts', async () => {
    const out = await call('POST', '/api/notifications/send', { role: 'analyst', org: A, body: { subject: 's', message: 'm', to: ['contact@b.test'] } });
    assert.equal(out.status, 400);
    assert.match(out.data.error, /Not a contact of your organisation: contact@b\.test/);
    const own = await call('POST', '/api/notifications/send', { role: 'analyst', org: A, body: { subject: 's', message: 'm', to: ['CISO@a.test'] } });
    // Allowed past the recipient check; email itself is not configured in tests.
    assert.equal(own.status, 200);
    assert.equal(own.data.outcome, 'skipped');
});

test('security assessment: client roles always get their own org; staff pick with X-Org-Id', async () => {
    const path = '/api/client/security-assessment';
    assert.equal((await call('GET', path, { asOrg: B })).status, 401);
    assert.equal((await call('GET', path, { role: 'portal_user', asOrg: B })).status, 403);
    for (const role of ['portal_user', 'executive']) {
        const client = await call('GET', `${path}?org=${B}`, { role, org: A, asOrg: B });
        assert.equal(client.status, 200, JSON.stringify(client.data));
        assert.equal(client.data.org_id, A, role);
        assert.deepEqual(client.data.orgs.map((o: Row) => o.slug), [A]);
    }
    const staff = await call('GET', path, { role: 'analyst', org: A, asOrg: B });
    assert.equal(staff.data.org_id, B);
    assert.equal(staff.data.orgs.length, 2);
    assert.equal((await call('GET', `${path}?org=${B}`, { role: 'analyst', org: A })).data.org_id, A, '?org is no longer read');
});

test('ioc_enrichments: a second org escalating the same IOC does not take over its org_id', async () => {
    const body = { ioc_value: '8.8.4.4', ioc_type: 'ip', finding: 'beaconing' };
    const first = await call('POST', '/api/secops/hunting/escalate', { role: 'analyst', org: A, body });
    assert.equal(first.status, 200, JSON.stringify(first.data));
    assert.equal(first.data.ioc_saved, true, JSON.stringify(first.data));
    const second = await call('POST', '/api/secops/hunting/escalate', { role: 'analyst', org: B, body });
    assert.equal(second.data.ioc_saved, true, JSON.stringify(second.data));
    const rows = db.tables.ioc_enrichments.filter((r) => r.ioc_value === '8.8.4.4');
    assert.equal(rows.length, 1);
    assert.equal(rows[0].org_id, A);
    assert.ok((rows[0].tags as string[]).includes('analyst-confirmed'), 'enrichment fields are still refreshed');
});

test('hunt escalate: a second org gets a NEW case of its own; the same org still gets its existing case', async () => {
    const body = { ioc_value: '9.9.9.9', ioc_type: 'ip', finding: 'scan' };
    const a = await call('POST', '/api/secops/hunting/escalate', { role: 'analyst', org: A, body });
    assert.equal(a.status, 200, JSON.stringify(a.data));
    assert.equal(a.data.created, true);
    const b = await call('POST', '/api/secops/hunting/escalate', { role: 'analyst', org: B, body });
    assert.equal(b.status, 200, JSON.stringify(b.data));
    assert.equal(b.data.created, true, 'org B opened its own case');
    assert.notEqual(b.data.case_id, a.data.case_id);
    assert.equal(db.tables.cases.find((c) => c.id === b.data.case_id)?.org_id, B);
    const again = await call('POST', '/api/secops/hunting/escalate', { role: 'analyst', org: A, body });
    assert.equal(again.data.created, false);
    assert.equal(again.data.case_id, a.data.case_id, 'dedup still works within one org');
});

// ── CISO_EMAIL has no fallback address ───────────────────────────────────────────────────────

async function capturingWarnings<T>(fn: () => Promise<T>): Promise<{ result: T; warnings: string[] }> {
    const warnings: string[] = [];
    const realWarn = console.warn;
    console.warn = (...args: unknown[]) => { warnings.push(args.map(String).join(' ')); };
    try {
        return { result: await fn(), warnings };
    } finally {
        console.warn = realWarn;
    }
}

test('CISO_EMAIL unset: CISO and SOC-mailbox notifications are skipped with a warning, not sent to a default', async () => {
    assert.equal(process.env.CISO_EMAIL, undefined);
    const ciso = await capturingWarnings(() => call('POST', '/api/notifications/send', { role: 'analyst', org: A, body: { subject: 's', message: 'm', recipient: 'ciso' } }));
    assert.equal(ciso.result.status, 200);
    assert.equal(ciso.result.data.outcome, 'skipped');
    assert.match(ciso.result.data.message, /CISO_EMAIL is not set/);
    assert.ok(ciso.warnings.some((w) => /CISO_EMAIL is not set/.test(w)), ciso.warnings.join('\n'));

    const soc = await call('POST', '/api/notifications/send', { role: 'analyst', org: A, body: { subject: 's', message: 'm' } });
    assert.equal(soc.status, 200);
    assert.equal(soc.data.outcome, 'skipped');

    const step = await capturingWarnings(() => call('POST', `/api/cases/${caseA}/execute-step`, { role: 'analyst', org: A, body: { step_id: 'notify_ciso' } }));
    assert.equal(step.result.status, 200);
    assert.equal(step.result.data.outcome, 'skipped');
    assert.match(step.result.data.message, /CISO_EMAIL is not set/);
    assert.ok(step.warnings.some((w) => /CISO email skipped/.test(w)));
});

test('cisoEmail() / socNotificationRecipients(): no fallback address', async () => {
    const { cisoEmail, socNotificationRecipients } = await import('../../services/email');
    assert.equal(cisoEmail(), null);
    assert.deepEqual(socNotificationRecipients(), []);
    process.env.CISO_EMAIL = ' ciso@example.test ';
    try {
        assert.equal(cisoEmail(), 'ciso@example.test');
        assert.deepEqual(socNotificationRecipients(), ['ciso@example.test']);
        process.env.ALERT_EMAIL_TO = 'soc@example.test';
        assert.deepEqual(socNotificationRecipients(), ['soc@example.test']);
    } finally {
        delete process.env.CISO_EMAIL;
        delete process.env.ALERT_EMAIL_TO;
    }
});
