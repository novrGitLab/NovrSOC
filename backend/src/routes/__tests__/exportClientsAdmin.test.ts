// Phase X2: PATCH /api/admin/export-clients/:id and GET /:id/access-log — validation, audit, and
// that no token or hash ever comes back. Local fake PostgREST only; all data is synthetic.
process.env.JWT_SECRET = 'export-admin-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY']) delete process.env[k];

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth, requireRole } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest } from './fakePostgrest';
import exportClientsRouter from '../exportClients';
import { getAuditLog } from '../../lib/audit';

let db: FakePostgrest;
let server: Server;
let base = '';
let clientId = '';
let token = '';

const tok = (role = 'super_admin') => jwt.sign({ sub: randomUUID(), email: `${role}@x.test`, role, org_id: 'org-a' }, process.env.JWT_SECRET!);
async function http(method: string, path: string, body?: unknown, role = 'super_admin') {
    const r = await fetch(`${base}/api/admin/export-clients${path}`, {
        method, headers: { 'Content-Type': 'application/json', ...(role ? { Authorization: `Bearer ${tok(role)}` } : {}) },
        body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await r.text();
    return { status: r.status, text, data: (() => { try { return JSON.parse(text); } catch { return null; } })() };
}

before(async () => {
    db = await startFakePostgrest({ organisations: [{ id: 'oa', slug: 'org-a' }], export_clients: [], export_access_log: [] },
        {}, { export_clients: { enabled: true, redaction_profile: 'standard' } });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use(express.json());
    app.use('/api/admin/export-clients', requireAuth, requireRole('super_admin'), exportClientsRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const created = await http('POST', '', { name: 'Vendor', org_ids: ['org-a'], allowed_cidrs: ['192.0.2.1/32'] });
    assert.equal(created.status, 201);
    clientId = created.data.client.id;
    token = created.data.token;
});
after(async () => { server.close(); await db.close(); });

const tokenHash = () => String(db.tables.export_clients.find((c) => c.id === clientId)!.token_hash);
const assertNoSecrets = (text: string) => {
    assert.ok(!text.includes(token), 'token leaked');
    assert.ok(!text.includes(tokenHash()), 'hash leaked');
    assert.ok(!text.includes('token_hash'), 'hash field leaked');
};

test('PATCH: super_admin only', async () => {
    assert.equal((await http('PATCH', `/${clientId}`, { name: 'x' }, '')).status, 401);
    for (const role of ['soc_manager', 'analyst', 'executive', 'portal_user']) {
        assert.equal((await http('PATCH', `/${clientId}`, { name: 'x' }, role)).status, 403, role);
    }
    assert.equal(db.tables.export_clients.find((c) => c.id === clientId)!.name, 'Vendor');
});

test('PATCH: updates name and allowed_cidrs; response has no token or hash', async () => {
    const r = await http('PATCH', `/${clientId}`, { name: 'Vendor Renamed', allowed_cidrs: ['198.51.100.0/29', '2001:db8::/48', '198.51.100.0/29'] });
    assert.equal(r.status, 200, r.text);
    assert.equal(r.data.client.name, 'Vendor Renamed');
    assert.deepEqual(r.data.client.allowed_cidrs, ['198.51.100.0/29', '2001:db8::/48'], 'deduplicated');
    assertNoSecrets(r.text);
    assert.ok(!('token' in r.data), 'PATCH never returns a token');
    const name = await http('PATCH', `/${clientId}`, { name: 'Only Name' });
    assert.equal(name.status, 200);
    assert.deepEqual(name.data.client.allowed_cidrs, ['198.51.100.0/29', '2001:db8::/48'], 'untouched field kept');
});

test('PATCH: same validation as create — non-empty, valid, never /0; nothing else changeable', async () => {
    const before = JSON.stringify(db.tables.export_clients.find((c) => c.id === clientId));
    for (const body of [
        {}, { allowed_cidrs: [] }, { allowed_cidrs: ['0.0.0.0/0'] }, { allowed_cidrs: ['::/0'] }, { allowed_cidrs: ['10.0.0.0/33'] },
        { allowed_cidrs: ['not-an-ip'] }, { allowed_cidrs: ['192.0.2.1/32', 'bad'] }, { name: '' }, { name: 'x'.repeat(101) },
        { org_ids: ['org-b'] }, { token_hash: 'abc' }, { enabled: false }, { redaction_profile: 'no_raw' }, { name: 'ok', extra: 1 },
    ]) {
        const r = await http('PATCH', `/${clientId}`, body);
        assert.equal(r.status, 400, JSON.stringify(body));
        assertNoSecrets(r.text);
    }
    assert.equal(JSON.stringify(db.tables.export_clients.find((c) => c.id === clientId)), before, 'nothing changed');
    assert.equal((await http('PATCH', `/${randomUUID()}`, { name: 'x' })).status, 404);
    assert.equal((await http('PATCH', '/not-a-uuid', { name: 'x' })).status, 404);
});

test('PATCH: audited, without secrets', async () => {
    await http('PATCH', `/${clientId}`, { allowed_cidrs: ['203.0.113.0/28'] });
    const entry = getAuditLog(50).find((e) => e.action === 'EXPORT_CLIENT_UPDATED' && e.resource_id === clientId && /203\.0\.113\.0\/28/.test(e.details ?? ''));
    assert.ok(entry, 'audit entry written');
    assert.equal(entry!.user, 'super_admin@x.test');
    assertNoSecrets(JSON.stringify(getAuditLog(200)));
});

test('list and access log: no secrets; access log newest first, scoped to the client', async () => {
    const other = randomUUID();
    db.tables.export_access_log.push(
        { id: randomUUID(), client_id: clientId, at: '2026-10-09T10:00:00+00:00', source_ip: '203.0.113.2', org_ids: ['org-a'], row_count: 5, cursor_from: null, cursor_to: 'c1', status_code: 200 },
        { id: randomUUID(), client_id: clientId, at: '2026-10-09T11:00:00+00:00', source_ip: '198.51.100.9', org_ids: null, row_count: 0, cursor_from: 'c1', cursor_to: null, status_code: 403 },
        { id: randomUUID(), client_id: other, at: '2026-10-09T12:00:00+00:00', source_ip: '203.0.113.3', org_ids: ['org-a'], row_count: 1, cursor_from: null, cursor_to: 'x', status_code: 200 },
    );
    const log = await http('GET', `/${clientId}/access-log`);
    assert.equal(log.status, 200);
    assert.deepEqual(log.data.entries.map((e: { status_code: number }) => e.status_code), [403, 200]);
    assert.equal((await http('GET', `/${clientId}/access-log`, undefined, 'soc_manager')).status, 403);
    const list = await http('GET', '');
    assertNoSecrets(list.text);
    assertNoSecrets(log.text);
});
