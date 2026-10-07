process.env.JWT_SECRET = 'permissions-test-secret';

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requirePermission, hasPermission, permissionsFor, PERMISSIONS, ROLE_PERMISSIONS } from '../permissions';

let base = '';
let server: Server;

const token = (claims: Record<string, unknown>) => jwt.sign({ sub: 'u1', email: 'u1@example.test', ...claims }, process.env.JWT_SECRET!);

async function get(path: string, auth?: string) {
    const r = await fetch(`${base}${path}`, { headers: auth ? { Authorization: `Bearer ${auth}` } : {} });
    return { status: r.status, body: await r.json() };
}

before(() => {
    const app = express();
    app.get('/cases', requirePermission('cases:read'), (_req, res) => { res.json({ ok: true }); });
    app.get('/approve', requirePermission('response:approve'), (_req, res) => { res.json({ ok: true }); });
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => { server.close(); });

test('role map: managers hold every SecOps permission; executive and portal_user hold none', () => {
    assert.deepEqual([...ROLE_PERMISSIONS.super_admin], [...PERMISSIONS]);
    assert.deepEqual([...ROLE_PERMISSIONS.soc_manager], [...PERMISSIONS]);
    assert.deepEqual([...ROLE_PERMISSIONS.executive], []);
    assert.deepEqual([...ROLE_PERMISSIONS.portal_user], []);
    assert.equal(hasPermission('analyst', 'response:contain'), true);
    assert.equal(hasPermission('analyst', 'response:approve'), false);
});

test('unknown or missing roles hold no permissions', () => {
    assert.deepEqual([...permissionsFor('viewer')], []);
    assert.deepEqual([...permissionsFor('Administrator')], []);
    assert.deepEqual([...permissionsFor(undefined)], []);
    assert.deepEqual([...permissionsFor('constructor')], []);
});

test('no token or a bad token is 401 (from requireAuth)', async () => {
    assert.equal((await get('/cases')).status, 401);
    assert.equal((await get('/cases', 'not-a-jwt')).status, 401);
});

test('role with the permission and an org passes', async () => {
    const r = await get('/cases', token({ role: 'analyst', org_id: 'acme' }));
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, { ok: true });
});

test('role without the permission is 403', async () => {
    assert.equal((await get('/cases', token({ role: 'executive', org_id: 'acme' }))).status, 403);
    assert.equal((await get('/cases', token({ role: 'portal_user', org_id: 'acme' }))).status, 403);
    const r = await get('/approve', token({ role: 'analyst', org_id: 'acme' }));
    assert.equal(r.status, 403);
    assert.equal(r.body.required, 'response:approve');
});

test('manager can approve', async () => {
    assert.equal((await get('/approve', token({ role: 'soc_manager', org_id: 'acme' }))).status, 200);
});

test('token without org_id is 403, never defaulted', async () => {
    const r = await get('/cases', token({ role: 'super_admin' }));
    assert.equal(r.status, 403);
    assert.match(r.body.error, /No organisation/);
});
