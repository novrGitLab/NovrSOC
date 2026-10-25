// Phase P29 (Release 3.1): the client onboarding wizard's backend — org_onboarding draft
// persistence/resume, org_service_grants and the requirePermission()/requireService() gate it
// gives every VMS/CNII/Threat-Intel/SOAR route, the duplicate-organisation warning, and
// activation's mandatory-account gate. Fake PostgREST only.
process.env.JWT_SECRET = 'onboarding-wizard-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'DEV_ADMIN_EMAIL', 'DEV_ADMIN_PASSWORD']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { startFakePostgrest, type FakePostgrest } from './fakePostgrest';
import { requireAuth, requireRole } from '../../middleware/auth';
import organisationsRouter from '../organisations';
import onboardingRouter from '../onboarding';
import vmsRouter from '../vms';
import cniiRouter from '../cnii';
import usersRouter from '../users';

const HOME = { id: randomUUID(), slug: 'cybernovr', name: 'Cybernovr' };
const CLIENT = { id: randomUUID(), slug: 'zenith-bank', name: 'Zenith Bank', domain: 'zenithbank.com' };
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };

async function http(method: string, path: string, bearer?: string, body?: unknown) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const r = await fetch(`${base}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const root = () => jwt.sign({ sub: randomUUID(), email: 'root@cybernovr.test', role: 'super_admin', org_id: HOME.slug }, process.env.JWT_SECRET!);
const manager = () => jwt.sign({ sub: randomUUID(), email: 'mgr@cybernovr.test', role: 'soc_manager', org_id: HOME.slug }, process.env.JWT_SECRET!);
const analyst = () => jwt.sign({ sub: randomUUID(), email: 'an@cybernovr.test', role: 'analyst', org_id: HOME.slug }, process.env.JWT_SECRET!);
const clientVms = () => jwt.sign({ sub: randomUUID(), email: 'staff@cybernovr.test', role: 'soc_manager', org_id: CLIENT.slug }, process.env.JWT_SECRET!);

before(async () => {
    db = await startFakePostgrest(
        { organisations: [HOME, CLIENT], platform_users: [], org_onboarding: [], org_service_grants: [], audit_log: [], vms_assets: [], vms_findings: [], auth_links: [] },
        {}, { org_onboarding: { status: 'draft', current_step: 1, completed_steps: [], steps: {} }, auth_links: { used_at: null } },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    process.env.FRONTEND_URL = 'https://novr-soc.example.test';
    const app = express();
    app.use(express.json());
    app.use('/api/organisations', requireAuth, organisationsRouter);
    app.use('/api/admin/onboarding', requireAuth, requireRole('super_admin', 'soc_manager'), onboardingRouter);
    app.use('/api/admin/users', requireAuth, requireRole('super_admin'), usersRouter);
    app.use('/api/vms', requireAuth, vmsRouter);
    app.use('/api/cnii', requireAuth, cniiRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => { for (const t of ['org_onboarding', 'org_service_grants', 'platform_users', 'audit_log', 'auth_links']) db.tables[t].length = 0; });

// ── Duplicate warning ────────────────────────────────────────────────────────────────────────
test('check-duplicate: an existing name-derived slug or domain is reported; analyst cannot even ask', async () => {
    assert.equal((await http('GET', '/api/organisations/check-duplicate?name=Zenith+Bank', analyst())).status, 403);
    const byName = await http('GET', '/api/organisations/check-duplicate?name=Zenith+Bank', root());
    assert.equal(byName.status, 200);
    assert.equal(byName.data.matches[0]?.slug, CLIENT.slug);
    const byDomain = await http('GET', '/api/organisations/check-duplicate?domain=zenithbank.com', root());
    assert.equal(byDomain.data.matches[0]?.slug, CLIENT.slug);
    const none = await http('GET', '/api/organisations/check-duplicate?name=Totally+New+Co', root());
    assert.deepEqual(none.data.matches, []);
});

// ── Draft persistence and resume ────────────────────────────────────────────────────────────
test('starting onboarding is idempotent; step data persists and is resumable; analyst is refused entirely', async () => {
    assert.equal((await http('POST', `/api/admin/onboarding/${CLIENT.id}/start`, analyst())).status, 403);
    const first = await http('POST', `/api/admin/onboarding/${CLIENT.id}/start`, root());
    assert.equal(first.status, 201);
    assert.equal(first.data.record.status, 'draft');
    const second = await http('POST', `/api/admin/onboarding/${CLIENT.id}/start`, manager());
    assert.equal(second.status, 200, 'starting again just returns the existing draft, not a duplicate');
    assert.equal(second.data.record.org_id, CLIENT.slug);

    const saved = await http('PATCH', `/api/admin/onboarding/${CLIENT.id}/step/1`, manager(), { data: { sector: 'banking', primary_executive_email: 'ciso@zenithbank.com' }, advance_to: 2 });
    assert.equal(saved.status, 200);
    assert.deepEqual(saved.data.record.completed_steps, [1]);
    assert.equal(saved.data.record.current_step, 2);

    // Resuming: a fresh GET sees exactly what was saved, including after a second step.
    await http('PATCH', `/api/admin/onboarding/${CLIENT.id}/step/3`, manager(), { data: { invited: ['ciso@zenithbank.com'] }, advance_to: 4 });
    const resumed = await http('GET', `/api/admin/onboarding/${CLIENT.id}`, root());
    assert.equal(resumed.status, 200);
    assert.deepEqual(resumed.data.record.completed_steps, [1, 3]);
    assert.equal(resumed.data.record.steps['1'].sector, 'banking');
    assert.equal(resumed.data.record.current_step, 4);

    // Listed among in-progress records.
    const list = await http('GET', '/api/admin/onboarding', root());
    assert.ok(list.data.records.some((r: { org_id: string }) => r.org_id === CLIENT.slug));
});

// ── Invitation visibility ───────────────────────────────────────────────────────────────────
test('an invited user\'s active link shows its purpose and expiry, with no token or hash ever in the response; a used link stops counting', async () => {
    const invited = await http('POST', `/api/organisations/${CLIENT.id}/users`, root(), { email: 'ciso2@zenithbank.com', name: 'CISO Two', role: 'executive' });
    assert.equal(invited.status, 201);
    const before = await http('GET', `/api/organisations/${CLIENT.id}/users`, root());
    assert.equal(before.data.users.find((u: { id: string }) => u.id === invited.data.id).active_invite, null, 'no link issued yet');

    const link = await http('POST', `/api/admin/users/${invited.data.id}/password-link`, root(), { purpose: 'invite' });
    assert.equal(link.status, 201);
    const token = link.data.url.split('#token=')[1];

    const after = await http('GET', `/api/organisations/${CLIENT.id}/users`, root());
    const row = after.data.users.find((u: { id: string }) => u.id === invited.data.id);
    assert.equal(row.active_invite.purpose, 'invite');
    assert.equal(row.active_invite.expires_at, link.data.expires_at);
    assert.ok(!JSON.stringify(after.data).includes(token), 'the raw token never appears in this response');
    assert.ok(!('token_hash' in row.active_invite), 'not even the stored hash is exposed');
    assert.ok(!JSON.stringify(after.data).includes('token_hash'));

    // The link is consumed by set-password; once used it no longer counts as "active".
    db.tables.auth_links[0].used_at = new Date().toISOString();
    const afterUse = await http('GET', `/api/organisations/${CLIENT.id}/users`, root());
    assert.equal(afterUse.data.users.find((u: { id: string }) => u.id === invited.data.id).active_invite, null);
});

// ── Service provisioning + backend enforcement ──────────────────────────────────────────────
test('a confirmed-legacy organisation (never touched by the wizard, both tables healthy and empty) keeps access', async () => {
    db.tables.vms_assets.push({ id: randomUUID(), org_id: CLIENT.slug, value: 'web-1', asset_type: 'host', status: 'active', exposure: 'unknown', criticality: 'medium', hostnames: [], ips: [], discovery_sources: [] });
    const r = await http('GET', '/api/vms/assets', clientVms());
    assert.equal(r.status, 200, JSON.stringify(r.data));
});

test('an organisation the wizard has started onboarding, but not yet granted a service to, is DENIED that service — not treated as legacy', async () => {
    db.tables.vms_assets.push({ id: randomUUID(), org_id: CLIENT.slug, value: 'web-2', asset_type: 'host', status: 'active', exposure: 'unknown', criticality: 'medium', hostnames: [], ips: [], discovery_sources: [] });
    await http('POST', `/api/admin/onboarding/${CLIENT.id}/start`, root()); // org_onboarding row now exists; zero grants
    const r = await http('GET', '/api/vms/assets', clientVms());
    assert.equal(r.status, 403, 'a draft onboarding record is enough to require explicit entitlements, before any grant is set');
});

test('partial configuration: a granted service works, an ungranted one on the same organisation is still denied', async () => {
    await http('POST', `/api/admin/onboarding/${CLIENT.id}/start`, root());
    await http('PUT', `/api/admin/onboarding/${CLIENT.id}/services`, root(), { service: 'vms', status: 'enabled' });
    const vms = await http('GET', '/api/vms/assets', clientVms());
    assert.equal(vms.status, 200);
    db.tables.vms_assets.length = 0;
    // cnii_watch was never granted on this same, now-configured organisation.
    const cniiToken = jwt.sign({ sub: randomUUID(), email: 'staff2@cybernovr.test', role: 'soc_manager', org_id: CLIENT.slug }, process.env.JWT_SECRET!);
    const cnii = await http('GET', '/api/cnii/profile', cniiToken);
    assert.equal(cnii.status, 403);
});

test('missing entitlement tables (P29 not yet applied) fail closed, not open — every organisation, including a true legacy one', async () => {
    db.tables.org_service_grants = null as unknown as typeof db.tables.org_service_grants;
    db.tables.org_onboarding = null as unknown as typeof db.tables.org_onboarding;
    try {
        db.tables.vms_assets.push({ id: randomUUID(), org_id: CLIENT.slug, value: 'web-3', asset_type: 'host', status: 'active', exposure: 'unknown', criticality: 'medium', hostnames: [], ips: [], discovery_sources: [] });
        const r = await http('GET', '/api/vms/assets', clientVms());
        assert.equal(r.status, 403, 'an ambiguous state (table missing) must never be read as "legacy, allow"');
    } finally {
        db.tables.org_service_grants = [];
        db.tables.org_onboarding = [];
    }
});

test('a database error reading grants fails closed the same way as a missing table', async () => {
    // org_service_grants exists and is healthy; org_onboarding (the legacy-vs-new disambiguator)
    // is the one that is unreadable here — still an ambiguous state, still denied.
    db.tables.org_onboarding = null as unknown as typeof db.tables.org_onboarding;
    try {
        db.tables.vms_assets.push({ id: randomUUID(), org_id: CLIENT.slug, value: 'web-4', asset_type: 'host', status: 'active', exposure: 'unknown', criticality: 'medium', hostnames: [], ips: [], discovery_sources: [] });
        const r = await http('GET', '/api/vms/assets', clientVms());
        assert.equal(r.status, 403);
    } finally {
        db.tables.org_onboarding = [];
    }
});

test('activation counts only a correctly provisioned, non-disabled executive/portal_user — a disabled one alone does not qualify', async () => {
    await http('POST', `/api/admin/onboarding/${CLIENT.id}/start`, root());
    await http('PATCH', `/api/admin/onboarding/${CLIENT.id}/step/1`, root(), { data: { sector: 'banking' } });
    await http('PATCH', `/api/admin/onboarding/${CLIENT.id}/step/2`, root(), { data: { confirmed: true } });
    db.tables.platform_users.push({ id: randomUUID(), org_id: CLIENT.id, email: 'disabled-exec@zenithbank.com', name: 'Former CISO', role: 'executive', status: 'disabled' });
    const blocked = await http('POST', `/api/admin/onboarding/${CLIENT.id}/activate`, root());
    assert.equal(blocked.status, 409);
    assert.match(blocked.data.problems.join(' '), /non-disabled/);
    db.tables.platform_users.push({ id: randomUUID(), org_id: CLIENT.id, email: 'new-exec@zenithbank.com', name: 'Current CISO', role: 'executive', status: 'active' });
    assert.equal((await http('POST', `/api/admin/onboarding/${CLIENT.id}/activate`, root())).status, 200);
});

test('activation refuses an organisation that is not itself active', async () => {
    db.tables.organisations.find((o) => o.id === CLIENT.id)!.status = 'disabled';
    try {
        await http('POST', `/api/admin/onboarding/${CLIENT.id}/start`, root());
        await http('PATCH', `/api/admin/onboarding/${CLIENT.id}/step/1`, root(), { data: {} });
        await http('PATCH', `/api/admin/onboarding/${CLIENT.id}/step/2`, root(), { data: { confirmed: true } });
        db.tables.platform_users.push({ id: randomUUID(), org_id: CLIENT.id, email: 'exec3@zenithbank.com', role: 'executive', status: 'active' });
        const r = await http('POST', `/api/admin/onboarding/${CLIENT.id}/activate`, root());
        assert.equal(r.status, 409);
        assert.match(r.data.problems.join(' '), /not active/);
    } finally {
        db.tables.organisations.find((o) => o.id === CLIENT.id)!.status = 'active';
    }
});

test('a service denial for one organisation never affects another organisation\'s access to the same service', async () => {
    const other = { id: randomUUID(), slug: 'other-co2', name: 'Other Co 2' };
    db.tables.organisations.push(other);
    db.tables.vms_assets.push(
        { id: randomUUID(), org_id: CLIENT.slug, value: 'client-web', asset_type: 'host', status: 'active', exposure: 'unknown', criticality: 'medium', hostnames: [], ips: [], discovery_sources: [] },
        { id: randomUUID(), org_id: other.slug, value: 'other-web', asset_type: 'host', status: 'active', exposure: 'unknown', criticality: 'medium', hostnames: [], ips: [], discovery_sources: [] },
    );
    await http('POST', `/api/admin/onboarding/${CLIENT.id}/start`, root());
    await http('PUT', `/api/admin/onboarding/${CLIENT.id}/services`, root(), { service: 'vms', status: 'disabled' });
    assert.equal((await http('GET', '/api/vms/assets', clientVms())).status, 403);
    const otherToken = jwt.sign({ sub: randomUUID(), email: 'staff3@cybernovr.test', role: 'soc_manager', org_id: other.slug }, process.env.JWT_SECRET!);
    const otherResult = await http('GET', '/api/vms/assets', otherToken);
    assert.equal(otherResult.status, 200, 'the other, untouched organisation is unaffected — it is still confirmed-legacy');
});

test('service grants: setting one module to disabled denies only that module on the backend — not just the nav', async () => {
    await http('POST', `/api/admin/onboarding/${CLIENT.id}/start`, root());
    const before = await http('GET', `/api/admin/onboarding/${CLIENT.id}/services`, root());
    assert.equal(before.status, 200);
    assert.ok(before.data.services.every((s: { status: string }) => s.status === 'pending'), 'no grants saved yet — every module shows as pending');

    assert.equal((await http('PUT', `/api/admin/onboarding/${CLIENT.id}/services`, analyst(), { service: 'vms', status: 'disabled' })).status, 403, 'analyst cannot change grants');
    const set = await http('PUT', `/api/admin/onboarding/${CLIENT.id}/services`, root(), { service: 'vms', status: 'disabled', notes: 'not purchased' });
    assert.equal(set.status, 200);

    // Now that the organisation has ANY grant row, VMS is explicitly denied...
    const denied = await http('GET', '/api/vms/assets', clientVms());
    assert.equal(denied.status, 403);
    assert.match(denied.data.error, /Vulnerability Management.*not enabled/);

    // ...enabling it again lifts the block immediately, no restart needed.
    await http('PUT', `/api/admin/onboarding/${CLIENT.id}/services`, root(), { service: 'vms', status: 'enabled' });
    const allowed = await http('GET', '/api/vms/assets', clientVms());
    assert.equal(allowed.status, 200);

    await new Promise((r) => setTimeout(r, 10));
    assert.ok(db.tables.audit_log.some((a) => a.action === 'ORG_SERVICE_GRANT_CHANGED' && a.resource_id === CLIENT.slug));
});

// ── Activation ───────────────────────────────────────────────────────────────────────────────
test('activation is blocked until the profile step is saved and at least one executive/portal_user exists; then it succeeds and is audited', async () => {
    await http('POST', `/api/admin/onboarding/${CLIENT.id}/start`, root());
    const early = await http('POST', `/api/admin/onboarding/${CLIENT.id}/activate`, root());
    assert.equal(early.status, 409);
    assert.ok(early.data.problems.length >= 2);

    await http('PATCH', `/api/admin/onboarding/${CLIENT.id}/step/1`, root(), { data: { sector: 'banking' } });
    const stillMissingPeople = await http('POST', `/api/admin/onboarding/${CLIENT.id}/activate`, root());
    assert.equal(stillMissingPeople.status, 409);
    assert.match(stillMissingPeople.data.problems.join(' '), /executive or client user/);
    assert.match(stillMissingPeople.data.problems.join(' '), /Step 2/, 'service provisioning must also be reviewed before activation');

    await http('PATCH', `/api/admin/onboarding/${CLIENT.id}/step/2`, root(), { data: { confirmed: true } });
    db.tables.platform_users.push({ id: randomUUID(), org_id: CLIENT.id, email: 'ciso@zenithbank.com', name: 'CISO', role: 'executive', status: 'invited' });
    const ok = await http('POST', `/api/admin/onboarding/${CLIENT.id}/activate`, manager());
    assert.equal(ok.status, 200, JSON.stringify(ok.data));
    assert.equal(ok.data.record.status, 'active');
    assert.equal(ok.data.record.activated_by, 'mgr@cybernovr.test');
    assert.equal(db.tables.organisations.find((o) => o.id === CLIENT.id)?.setup_complete, true);

    assert.equal((await http('POST', `/api/admin/onboarding/${CLIENT.id}/activate`, root())).status, 409, 'activating twice is refused');
    // Steps stay editable after activation — reviewing/updating a live organisation's setup.
    assert.equal((await http('PATCH', `/api/admin/onboarding/${CLIENT.id}/step/2`, root(), { data: { note: 'updated after go-live' } })).status, 200);

    await new Promise((r) => setTimeout(r, 10));
    assert.ok(db.tables.audit_log.some((a) => a.action === 'ONBOARDING_ACTIVATED' && a.resource_id === CLIENT.slug));
});

test('onboarding records and grants never cross organisations', async () => {
    const other = { id: randomUUID(), slug: 'other-co', name: 'Other Co' };
    db.tables.organisations.push(other);
    await http('POST', `/api/admin/onboarding/${CLIENT.id}/start`, root());
    await http('POST', `/api/admin/onboarding/${other.id}/start`, root());
    await http('PATCH', `/api/admin/onboarding/${CLIENT.id}/step/1`, root(), { data: { secret: 'zenith-only' } });
    const otherRecord = await http('GET', `/api/admin/onboarding/${other.id}`, root());
    assert.deepEqual(otherRecord.data.record.steps, {}, 'the other organisation\'s draft is untouched');
    await http('PUT', `/api/admin/onboarding/${CLIENT.id}/services`, root(), { service: 'cnii_watch', status: 'disabled' });
    const otherServices = await http('GET', `/api/admin/onboarding/${other.id}/services`, root());
    assert.ok(otherServices.data.services.every((s: { status: string }) => s.status === 'pending'), 'the other organisation\'s services are untouched');
});
