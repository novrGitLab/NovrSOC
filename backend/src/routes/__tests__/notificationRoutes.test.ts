// Platform notification routes (routes/email.ts, routes/alerts.ts): authentication, RBAC,
// validation, rate limiting and honest failure. Email delivery is stubbed at the Brevo HTTP API,
// so these tests prove what WOULD be sent without sending anything.
process.env.JWT_SECRET = 'notification-test-secret';
for (const k of ['RESEND_API_KEY', 'SENDGRID_API_KEY', 'SMTP_HOST', 'SMTP_USER', 'SMTP_PASS', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY']) delete process.env[k];
process.env.CISO_EMAIL = 'ciso@example.test';
process.env.ALERT_EMAIL_TO = 'soc@example.test';

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import emailRouter from '../email';
import alertsRouter from '../alerts';
import { getAuditLog } from '../../lib/audit';

let base = '';
let server: Server;
const realFetch = globalThis.fetch;
let sent: { to: { email: string }[]; subject: string }[] = [];

const token = (role: string, email = `${role}-${randomUUID()}@novrsoc.test`) => jwt.sign({ sub: randomUUID(), email, role }, process.env.JWT_SECRET!);
async function call(method: string, path: string, opts: { role?: string; email?: string; body?: unknown } = {}) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (opts.role) headers.Authorization = `Bearer ${token(opts.role, opts.email)}`;
    const r = await realFetch(`${base}${path}`, { method, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const enableEmail = () => { process.env.EMAIL_ENABLED = 'true'; process.env.BREVO_API_KEY = 'test-key'; };
const disableEmail = () => { delete process.env.EMAIL_ENABLED; delete process.env.BREVO_API_KEY; };

before(() => {
    // Stub only the outbound Brevo call; everything else (incl. our own server) is real.
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
        if (String(input).startsWith('https://api.brevo.com/')) {
            sent.push(JSON.parse(String(init?.body)));
            return Response.json({ messageId: `<${randomUUID()}@brevo>` }, { status: 201 });
        }
        return realFetch(input, init);
    }) as typeof fetch;
    const app = express();
    app.set('trust proxy', 1);
    app.use(express.json());
    app.use('/api/email', emailRouter);
    app.use('/api/alerts', alertsRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => { server.close(); globalThis.fetch = realFetch; disableEmail(); });
beforeEach(() => { sent = []; });

// ── Removed routes ──

test('the anonymous send routes /api/email/test and /api/email/alert no longer exist', async () => {
    for (const role of [undefined, 'super_admin']) {
        assert.equal((await call('POST', '/api/email/test', { role, body: { to: 'victim@example.test' } })).status, 404);
        assert.equal((await call('POST', '/api/email/alert', { role, body: { to: ['victim@example.test'] } })).status, 404);
    }
    assert.equal(sent.length, 0);
});

test('the weekly report route /api/email/weekly-report no longer exists (it sent hardcoded figures)', async () => {
    enableEmail();
    for (const role of [undefined, 'super_admin', 'soc_manager']) {
        assert.equal((await call('POST', '/api/email/weekly-report', { role, body: { to: ['ciso@example.test'] } })).status, 404);
    }
    assert.equal(sent.length, 0);
    disableEmail();
});

test('email status needs a staff token', async () => {
    assert.equal((await call('GET', '/api/email/status')).status, 401);
    assert.equal((await call('GET', '/api/email/status', { role: 'portal_user' })).status, 403);
    assert.equal((await call('GET', '/api/email/status', { role: 'analyst' })).status, 200);
});

// ── /api/alerts/test ──

test('alert test: 401 / 403, and a caller-chosen recipient is ignored', async () => {
    enableEmail();
    assert.equal((await call('POST', '/api/alerts/test', { body: {} })).status, 401);
    assert.equal((await call('POST', '/api/alerts/test', { role: 'analyst', body: {} })).status, 403);
    const r = await call('POST', '/api/alerts/test', { role: 'soc_manager', body: { email: 'attacker@evil.test' } });
    assert.equal(r.status, 200);
    assert.equal(r.data.results.email, 'sent');
    assert.equal(sent.length, 1);
    assert.deepEqual(sent[0].to, [{ email: 'soc@example.test' }], 'always the configured SOC address');
});

// ── /api/alerts/incident ──

test('incident alert: 401 / 403 / 400, analyst → sent to SOC recipients and audited', async () => {
    enableEmail();
    const body = { title: 'Test incident', severity: 'high', description: 'harmless test' };
    assert.equal((await call('POST', '/api/alerts/incident', { body })).status, 401);
    assert.equal((await call('POST', '/api/alerts/incident', { role: 'executive', body })).status, 403);
    assert.equal((await call('POST', '/api/alerts/incident', { role: 'analyst', body: { title: '' } })).status, 400);
    assert.equal((await call('POST', '/api/alerts/incident', { role: 'analyst', body: { ...body, severity: 'apocalyptic' } })).status, 400);
    const r = await call('POST', '/api/alerts/incident', { role: 'analyst', email: 'an@novrsoc.test', body });
    assert.equal(r.status, 200);
    assert.deepEqual(r.data.dispatched, ['email']);
    assert.equal(sent.length, 1);
    assert.ok(sent[0].to.every((t) => t.email !== 'attacker@evil.test'));
    assert.ok(getAuditLog(20).some((e) => e.action === 'ALERT_INCIDENT_SEND' && e.user === 'an@novrsoc.test'));
});
