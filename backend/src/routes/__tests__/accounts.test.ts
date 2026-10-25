// Phase P2: per-person staff sign-in, lockout, break-glass control, one-time password links and
// the durable audit log — against the local fake PostgREST. All accounts and data are synthetic.
process.env.JWT_SECRET = 'accounts-test-secret';
// EMAIL_ENABLED/BREVO_API_KEY etc. are cleared explicitly (not just left unset) so this suite
// can never fire a real email, regardless of what a developer's own shell happens to have set.
for (const k of ['DEV_ADMIN_EMAIL', 'DEV_ADMIN_PASSWORD', 'DEV_ADMIN_LOGIN_ENABLED', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'FRONTEND_URL', 'DEV_TOKEN_SECRET', 'EMAIL_ENABLED', 'BREVO_API_KEY', 'RESEND_API_KEY', 'SENDGRID_API_KEY', 'SMTP_HOST']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { randomUUID, createHash } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import { requireAuth, requireRole } from '../../middleware/auth';
import authRouter, { MAX_FAILED_LOGINS } from '../auth';
import usersRouter from '../users';
import { flushAuditForTests } from '../../lib/audit';
import { DEFAULT_ORG_ID } from '../../services/cases';

let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const ORG = { id: randomUUID(), slug: 'acme', name: 'Acme Ltd' };
const HOME = { id: randomUUID(), slug: DEFAULT_ORG_ID, name: 'Cybernovr' };
const PW = 'correct horse battery staple';
let alice: Row;

async function http(method: string, path: string, body?: unknown, bearer?: string) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const r = await fetch(`${base}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const signin = (email: string, password: string) => http('POST', '/api/auth/signin', { email, password });
const admin = () => jwt.sign({ sub: randomUUID(), email: 'root@acme.test', role: 'super_admin', org_id: 'acme' }, process.env.JWT_SECRET!);

before(async () => {
    db = await startFakePostgrest({ organisations: [ORG, HOME], platform_users: [], auth_links: [], audit_log: [] }, {}, { auth_links: { used_at: null } });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    process.env.FRONTEND_URL = 'https://novr-soc.example.test';
    const app = express();
    app.use(express.json());
    app.use('/api/auth', authRouter);
    app.use('/api/admin/users', requireAuth, requireRole('super_admin'), usersRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(async () => {
    for (const t of ['platform_users', 'auth_links', 'audit_log']) db.tables[t].length = 0;
    alice = { id: randomUUID(), org_id: ORG.id, email: 'alice@acme.test', name: 'Alice Analyst', role: 'analyst', status: 'active', password_hash: await bcrypt.hash(PW, 4), failed_logins: 0, locked_until: null };
    db.tables.platform_users.push(alice);
    for (const k of ['DEV_ADMIN_EMAIL', 'DEV_ADMIN_PASSWORD', 'DEV_ADMIN_LOGIN_ENABLED']) delete process.env[k];
    process.env.JWT_SECRET = 'accounts-test-secret';
});

test('an account signs in with its own identity, role and organisation', async () => {
    const r = await signin('Alice@Acme.test', PW);
    assert.equal(r.status, 200);
    const claims = jwt.verify(r.data.token, process.env.JWT_SECRET!) as jwt.JwtPayload;
    assert.deepEqual([claims.sub, claims.email, claims.role, claims.org_id, claims.dev], [alice.id, 'alice@acme.test', 'analyst', 'acme', undefined]);
    assert.equal(claims.exp! - claims.iat!, 12 * 3600);
    assert.deepEqual(r.data.user, { email: 'alice@acme.test', name: 'Alice Analyst', company: 'Acme Ltd', role: 'analyst' });
});

test('wrong passwords lock the account; a locked account refuses even the right password', async () => {
    for (let i = 1; i < MAX_FAILED_LOGINS; i++) {
        assert.equal((await signin(alice.email as string, 'wrong-password-xx')).status, 401);
        assert.equal(alice.failed_logins, i);
    }
    assert.equal((await signin(alice.email as string, 'wrong-password-xx')).status, 401);
    assert.ok(alice.locked_until && Date.parse(alice.locked_until as string) > Date.now());
    const locked = await signin(alice.email as string, PW);
    assert.equal(locked.status, 429);
    alice.locked_until = null;
    assert.equal((await signin(alice.email as string, PW)).status, 200);
    assert.equal(alice.failed_logins, 0);
});

test('a disabled account, an account without a password and an unknown email cannot sign in', async () => {
    alice.status = 'disabled';
    assert.equal((await signin(alice.email as string, PW)).status, 403);
    db.tables.platform_users.push({ id: randomUUID(), org_id: ORG.id, email: 'bob@acme.test', role: 'analyst', status: 'active', password_hash: null });
    assert.equal((await signin('bob@acme.test', 'anything-at-all')).status, 401);
    assert.equal((await signin('nobody@acme.test', 'anything-at-all')).status, 401);
});

test('break-glass works only when configured and enabled, and is audited as a warning', async () => {
    process.env.DEV_ADMIN_EMAIL = 'breakglass@acme.test';
    process.env.DEV_ADMIN_PASSWORD = 'break-glass-secret-123';
    const r = await signin('breakglass@acme.test', 'break-glass-secret-123');
    assert.equal(r.status, 200);
    assert.equal((jwt.decode(r.data.token) as jwt.JwtPayload).dev, true);
    process.env.DEV_ADMIN_LOGIN_ENABLED = 'false';
    assert.equal((await signin('breakglass@acme.test', 'break-glass-secret-123')).status, 401);
    await flushAuditForTests();
    assert.ok(db.tables.audit_log.some((a) => a.action === 'LOGIN' && a.result === 'success' && a.severity === 'warning' && /break-glass/.test(String(a.details))));
});

test('with no signing secret, sign-in is refused (no built-in fallback secret)', async () => {
    delete process.env.JWT_SECRET;
    assert.equal((await signin(alice.email as string, PW)).status, 503);
});

test('password link: never sends a real email in this suite (EMAIL_ENABLED unset) and says so honestly, without failing the request', async () => {
    const bob = { id: randomUUID(), org_id: ORG.id, email: 'bob2@acme.test', name: 'Bob', role: 'soc_manager', status: 'invited', password_hash: null };
    db.tables.platform_users.push(bob);
    assert.equal(process.env.EMAIL_ENABLED, undefined, 'sanity: this suite never configures email sending');
    const r = await http('POST', `/api/admin/users/${bob.id}/password-link`, {}, admin());
    assert.equal(r.status, 201, 'the link is issued regardless of whether an email could be sent');
    assert.equal(r.data.email_sent, false);
    assert.equal(r.data.email_error, undefined, 'isEmailEnabled() is false, so sendAccountLinkEmail no-ops rather than erroring');
    assert.ok(r.data.url, 'the link is still returned for the admin to deliver manually');
});

test('password link: super_admin only, shown once, only its hash stored, works exactly once', async () => {
    const bob = { id: randomUUID(), org_id: ORG.id, email: 'bob@acme.test', name: 'Bob', role: 'soc_manager', status: 'invited', password_hash: null };
    db.tables.platform_users.push(bob);
    const analyst = jwt.sign({ sub: randomUUID(), email: 'x@acme.test', role: 'analyst', org_id: 'acme' }, process.env.JWT_SECRET!);
    assert.equal((await http('POST', `/api/admin/users/${bob.id}/password-link`, {}, analyst)).status, 403);
    const first = await http('POST', `/api/admin/users/${bob.id}/password-link`, {}, admin());
    const r = await http('POST', `/api/admin/users/${bob.id}/password-link`, {}, admin());
    assert.equal(r.status, 201);
    assert.match(r.data.url, /^https:\/\/novr-soc\.example\.test\/set-password#token=[A-Za-z0-9_-]{43}$/);
    const token = r.data.url.split('#token=')[1];
    const oldToken = first.data.url.split('#token=')[1];
    assert.ok(!JSON.stringify(db.tables.auth_links).includes(token), 'plaintext token never stored');
    assert.ok(db.tables.auth_links.some((l) => l.token_hash === createHash('sha256').update(token).digest('hex')));

    assert.equal((await http('POST', '/api/auth/set-password', { token: oldToken, password: 'a-long-enough-pass' })).status, 400, 'older link no longer works');
    assert.equal((await http('POST', '/api/auth/set-password', { token, password: 'short' })).status, 400);
    assert.equal((await http('POST', '/api/auth/set-password', { token, password: 'bob-is-my-password-1' })).status, 400, 'no email name in the password');
    // The failed attempts above consumed nothing: validation happens before the link is used.
    const ok = await http('POST', '/api/auth/set-password', { token, password: 'a-long-enough-pass' });
    assert.equal(ok.status, 200);
    assert.equal(bob.status, 'active');
    assert.equal((await http('POST', '/api/auth/set-password', { token, password: 'another-long-pass-1' })).status, 400, 'single use');
    assert.equal((await signin('bob@acme.test', 'a-long-enough-pass')).status, 200);
});

test('provisioning a staff account: created under the home org, status invited, duplicate emails refused', async () => {
    const r = await http('POST', '/api/admin/users', { email: 'Nora@Acme.test', name: 'Nora', role: 'soc_manager' }, admin());
    assert.equal(r.status, 201);
    assert.deepEqual([r.data.user.email, r.data.user.role, r.data.user.status, r.data.user.org_id], ['nora@acme.test', 'soc_manager', 'invited', HOME.id]);
    assert.equal((await http('POST', '/api/admin/users', { email: 'nora@acme.test', role: 'analyst' }, admin())).status, 409, 'an existing email, any case, is refused');
    assert.equal((await http('POST', '/api/admin/users', { email: 'x@acme.test', role: 'portal_user' }, admin())).status, 400, 'portal_user is not a staff role — created per-organisation instead');
    assert.equal((await http('POST', '/api/admin/users', { email: 'not-an-email', role: 'analyst' }, admin())).status, 400);
});

test('provisioning another super_admin is only reachable by an existing super_admin (the whole router is super_admin-only), and is audited at warning level', async () => {
    const r = await http('POST', '/api/admin/users', { email: 'root2@acme.test', name: 'Second Root', role: 'super_admin' }, admin());
    assert.equal(r.status, 201);
    assert.equal(r.data.user.role, 'super_admin');
    await flushAuditForTests();
    const entry = db.tables.audit_log.find((a) => a.action === 'STAFF_ACCOUNT_CREATED' && /super_admin/.test(String(a.details)));
    assert.equal(entry?.severity, 'warning');
    // A non-super_admin bearer never reaches the handler at all — requireRole('super_admin') on the mount rejects it first.
    const manager = jwt.sign({ sub: randomUUID(), email: 'mgr@acme.test', role: 'soc_manager', org_id: 'acme' }, process.env.JWT_SECRET!);
    assert.equal((await http('POST', '/api/admin/users', { email: 'sneaky@acme.test', role: 'super_admin' }, manager)).status, 403);
});

test('an expired link is refused', async () => {
    const token = 'A'.repeat(43);
    db.tables.auth_links.push({ id: randomUUID(), user_id: alice.id, token_hash: createHash('sha256').update(token).digest('hex'), purpose: 'reset', created_by: 'x', expires_at: new Date(Date.now() - 1000).toISOString(), used_at: null });
    assert.equal((await http('POST', '/api/auth/set-password', { token, password: 'a-long-enough-pass' })).status, 400);
});

test('disabling an account blocks sign-in and cancels its open links; nobody can disable themselves', async () => {
    await http('POST', `/api/admin/users/${alice.id}/password-link`, { purpose: 'reset' }, admin());
    const r = await http('PATCH', `/api/admin/users/${alice.id}`, { status: 'disabled' }, admin());
    assert.equal(r.status, 200);
    assert.ok(db.tables.auth_links.every((l) => l.used_at));
    assert.equal((await signin(alice.email as string, PW)).status, 403);
    const self = jwt.sign({ sub: alice.id, email: alice.email, role: 'super_admin', org_id: 'acme' }, process.env.JWT_SECRET!);
    assert.equal((await http('PATCH', `/api/admin/users/${alice.id}`, { status: 'disabled' }, self)).status, 409);
    assert.equal((await http('PATCH', `/api/admin/users/${alice.id}`, { status: 'superuser' }, admin())).status, 400);
});

test('audit entries reach the durable audit_log table', async () => {
    await signin(alice.email as string, 'wrong-password-xx');
    await signin(alice.email as string, PW);
    await flushAuditForTests();
    const rows = db.tables.audit_log.filter((a) => a.actor === 'alice@acme.test');
    assert.deepEqual(rows.map((a) => a.result), ['failed', 'success']);
    assert.ok(rows.every((a) => a.action === 'LOGIN' && a.at));
    assert.equal(rows[1].org_id, 'acme');
    assert.ok(!JSON.stringify(db.tables.audit_log).includes(PW), 'no password in the audit log');
});
