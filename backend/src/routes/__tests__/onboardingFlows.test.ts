// Release 2 Part C: end-to-end verification that a newly invited account can actually complete
// setup and use the product — through the real HTTP endpoints an admin and that account would
// call, not by seeding platform_users directly. Fake PostgREST only; every account here is
// synthetic and exists only for this test process's lifetime (nothing to revoke afterwards).
process.env.JWT_SECRET = 'onboarding-e2e-secret';
for (const k of ['DEV_ADMIN_EMAIL', 'DEV_ADMIN_PASSWORD', 'DEV_ADMIN_LOGIN_ENABLED', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'EMAIL_ENABLED', 'BREVO_API_KEY']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { startFakePostgrest, type FakePostgrest } from './fakePostgrest';
import { requireAuth, requireRole } from '../../middleware/auth';
import authRouter from '../auth';
import portalRouter from '../portal';
import usersRouter from '../users';
import organisationsRouter from '../organisations';
import vmsClientRouter from '../vmsClient';
import { DEFAULT_ORG_ID } from '../../services/cases';

const HOME = { id: randomUUID(), slug: DEFAULT_ORG_ID, name: 'Cybernovr' };
const CLIENT_ORG = { id: randomUUID(), slug: 'acme-bank', name: 'Acme Bank' };
const OTHER_ORG = { id: randomUUID(), slug: 'other-bank', name: 'Other Bank' };
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };

async function http(method: string, path: string, body?: unknown, bearer?: string) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const r = await fetch(`${base}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const root = () => jwt.sign({ sub: randomUUID(), email: 'root@cybernovr.test', role: 'super_admin', org_id: HOME.slug }, process.env.JWT_SECRET!);
/** Pulls the one-time token out of a password-link response's URL fragment. */
const tokenFrom = (url: string) => url.split('#token=')[1];

before(async () => {
    db = await startFakePostgrest(
        { organisations: [HOME, CLIENT_ORG, OTHER_ORG], platform_users: [], auth_links: [], audit_log: [], org_setup: [], vms_assets: [], vms_findings: [], vms_remediation_tasks: [], cve_intel: [] },
        {}, { auth_links: { used_at: null } },
    );
    // One asset each, in different organisations — the proof that a client sees only its own.
    db.tables.vms_assets.push(
        { id: randomUUID(), org_id: CLIENT_ORG.slug, value: 'acme-web-1', asset_type: 'host', exposure: 'internet', criticality: 'high', status: 'active' },
        { id: randomUUID(), org_id: OTHER_ORG.slug, value: 'other-web-1', asset_type: 'host', exposure: 'internet', criticality: 'high', status: 'active' },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    process.env.FRONTEND_URL = 'https://novr-soc.example.test';
    const app = express();
    app.use(express.json());
    app.use('/api/auth', authRouter);
    app.use('/api/portal', portalRouter);
    app.use('/api/admin/users', requireAuth, requireRole('super_admin'), usersRouter);
    app.use('/api/organisations', requireAuth, organisationsRouter);
    app.use('/api/client/vms', requireAuth, vmsClientRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => { for (const t of ['platform_users', 'auth_links', 'audit_log']) db.tables[t].length = 0; });

test('a newly invited client portal_user: no access before setup, completes setup, signs in, sees only its own org, and an admin-issued recovery link works afterwards', async () => {
    // 1. Invite — the first user of this client organisation.
    const invite = await http('POST', `/api/organisations/${CLIENT_ORG.id}/users`, { email: 'ciso@acme-bank.test', name: 'Acme CISO', role: 'portal_user' }, root());
    assert.equal(invite.status, 201);
    const userId = invite.data.id;
    assert.equal(invite.data.status, 'invited');

    // 2. No access at all before setup — not even a wrong-password answer, a no-password one.
    assert.equal((await http('POST', '/api/portal/auth/signin', { email: 'ciso@acme-bank.test', password: 'anything' }, undefined)).status, 401);

    // 3. The admin issues the one-time invite link, and only the link's hash is ever stored.
    const link = await http('POST', `/api/admin/users/${userId}/password-link`, { purpose: 'invite' }, root());
    assert.equal(link.status, 201);
    assert.equal(link.data.purpose, 'invite');
    assert.ok(!JSON.stringify(db.tables.auth_links).includes(tokenFrom(link.data.url)), 'plaintext token never stored');

    // 4. The client completes setup with the link.
    const setup = await http('POST', '/api/auth/set-password', { token: tokenFrom(link.data.url), password: 'a client set password 1' });
    assert.equal(setup.status, 200);
    assert.equal(setup.data.portal, true, 'the set-password page knows to send this account to the client portal, not /login');

    // 5. Signs in at the client portal with the new password; the token carries its own organisation.
    const signin = await http('POST', '/api/portal/auth/signin', { email: 'ciso@acme-bank.test', password: 'a client set password 1' });
    assert.equal(signin.status, 200);
    const token: string = signin.data.token;
    assert.deepEqual([signin.data.user.orgId, signin.data.user.email], [CLIENT_ORG.slug, 'ciso@acme-bank.test']);

    // 6. Reaches its permitted dashboard data (the client VMS summary) — exactly its own
    // organisation's one asset, never the other organisation's, and a client-sent X-Org-Id
    // changes nothing (resolveOrg.ts ignores it for portal_user; the header is sent here
    // specifically to prove an attempted org switch has no effect).
    const summary = await http('GET', '/api/client/vms/summary', undefined, token);
    assert.equal(summary.status, 200, JSON.stringify(summary.data));
    assert.equal(summary.data.kpis.assets, 1);
    const asOther = await fetch(`${base}/api/client/vms/summary`, { headers: { Authorization: `Bearer ${token}`, 'X-Org-Id': OTHER_ORG.slug } });
    const otherBody = await asOther.json().catch(() => null);
    assert.equal(otherBody?.kpis?.assets, 1, 'still exactly its own one asset — the X-Org-Id header did not switch it to the other organisation');

    // 7. An administrator later issues a RESET link (not invite) — the account is active, this is a recovery, not a first-time setup.
    const resetLink = await http('POST', `/api/admin/users/${userId}/password-link`, { purpose: 'reset' }, root());
    assert.equal(resetLink.status, 201);
    assert.equal(resetLink.data.purpose, 'reset');
    const reset = await http('POST', '/api/auth/set-password', { token: tokenFrom(resetLink.data.url), password: 'a new recovered password 2' });
    assert.equal(reset.status, 200);
    assert.equal((await http('POST', '/api/portal/auth/signin', { email: 'ciso@acme-bank.test', password: 'a client set password 1' })).status, 401, 'the old password no longer works');
    assert.equal((await http('POST', '/api/portal/auth/signin', { email: 'ciso@acme-bank.test', password: 'a new recovered password 2' })).status, 200, 'signs back in with the recovered password');

    // Logout itself is client-side token clearing (lib/portal-auth.ts's portalSignOut, covered by
    // scripts/auth-session.test.mjs) — there is no server-side session to end.
});

test('a newly invited staff super_admin: no access before setup, then reaches a super_admin-only staff area — never before', async () => {
    const invite = await http('POST', '/api/admin/users', { email: 'second-root@cybernovr.test', name: 'Second Root', role: 'super_admin' }, root());
    assert.equal(invite.status, 201);
    const userId = invite.data.user.id;
    assert.equal(invite.data.user.org_id, HOME.id, 'provisioned under the home organisation, not a client tenant');

    // Not reachable at the staff portal before setup.
    assert.equal((await http('POST', '/api/auth/signin', { email: 'second-root@cybernovr.test', password: 'anything' })).status, 401);
    // Nor, obviously, at the client portal — it isn't a client account.
    assert.equal((await http('POST', '/api/portal/auth/signin', { email: 'second-root@cybernovr.test', password: 'anything' })).status, 401);

    const link = await http('POST', `/api/admin/users/${userId}/password-link`, { purpose: 'invite' }, root());
    assert.equal(link.status, 201);
    const setup = await http('POST', '/api/auth/set-password', { token: tokenFrom(link.data.url), password: 'a new super admins password' });
    assert.equal(setup.status, 200);
    assert.equal(setup.data.portal, false, 'a staff account is sent to /login, not the client portal');

    const signin = await http('POST', '/api/auth/signin', { email: 'second-root@cybernovr.test', password: 'a new super admins password' });
    assert.equal(signin.status, 200);
    assert.equal(signin.data.user.role, 'super_admin');
    const token: string = signin.data.token;

    // Reaches a super_admin-only staff area (the organisation list) only now, with its own token.
    const orgs = await http('GET', '/api/organisations', undefined, token);
    assert.equal(orgs.status, 200);
    assert.ok(Array.isArray(orgs.data.organisations));
});
