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
        { organisations: [HOME, CLIENT], platform_users: [], org_onboarding: [], org_service_grants: [], audit_log: [], vms_assets: [], vms_findings: [] },
        {}, { org_onboarding: { status: 'draft', current_step: 1, completed_steps: [], steps: {} } },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use(express.json());
    app.use('/api/organisations', requireAuth, organisationsRouter);
    app.use('/api/admin/onboarding', requireAuth, requireRole('super_admin', 'soc_manager'), onboardingRouter);
    app.use('/api/vms', requireAuth, vmsRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => { for (const t of ['org_onboarding', 'org_service_grants', 'platform_users', 'audit_log']) db.tables[t].length = 0; });

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

// ── Service provisioning + backend enforcement ──────────────────────────────────────────────
test('an organisation with no grants at all is fully enabled (every pre-P29 organisation, unchanged)', async () => {
    db.tables.vms_assets.push({ id: randomUUID(), org_id: CLIENT.slug, value: 'web-1', asset_type: 'host', status: 'active', exposure: 'unknown', criticality: 'medium', hostnames: [], ips: [], discovery_sources: [] });
    const r = await http('GET', '/api/vms/assets', clientVms());
    assert.equal(r.status, 200, JSON.stringify(r.data));
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

    db.tables.platform_users.push({ id: randomUUID(), org_id: CLIENT.id, email: 'ciso@zenithbank.com', name: 'CISO', role: 'executive', status: 'invited' });
    const ok = await http('POST', `/api/admin/onboarding/${CLIENT.id}/activate`, manager());
    assert.equal(ok.status, 200, JSON.stringify(ok.data));
    assert.equal(ok.data.record.status, 'active');
    assert.equal(ok.data.record.activated_by, 'mgr@cybernovr.test');
    assert.equal(db.tables.organisations.find((o) => o.id === CLIENT.id)?.setup_complete, true);

    assert.equal((await http('POST', `/api/admin/onboarding/${CLIENT.id}/activate`, root())).status, 409, 'activating twice is refused');
    // A step can no longer be edited once active.
    assert.equal((await http('PATCH', `/api/admin/onboarding/${CLIENT.id}/step/2`, root(), { data: {} })).status, 409);

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
