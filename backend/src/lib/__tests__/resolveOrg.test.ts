// lib/resolveOrg.ts through requirePermission / requireOrg: which organisation each role acts on,
// X-Org-Id for staff only (analysts only for organisations they are assigned to, P21), unknown
// orgs, and the cross-org audit trail. `organisations` and
// `org_access_audit` live in a local fake PostgREST — no real database.
process.env.JWT_SECRET = 'resolve-org-test-secret';

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { requirePermission, requireOrg, requestOrg } from '../permissions';
import { getAuditLog } from '../audit';
import { startFakePostgrest, type FakePostgrest } from '../../routes/__tests__/fakePostgrest';

let db: FakePostgrest;
let server: Server;
let base = '';

// sub is stable per role and org so an analyst can be assigned (staff_org_assignments.user_id).
const tok = (role: string, org?: string, sub = `${role}-${org ?? 'none'}`) =>
    jwt.sign({ sub, email: `${role}@${org ?? 'none'}.test`, role, ...(org ? { org_id: org } : {}) }, process.env.JWT_SECRET!);

async function get(path: string, role: string, org?: string, asOrg?: string) {
    const headers: Record<string, string> = { Authorization: `Bearer ${tok(role, org)}` };
    if (asOrg !== undefined) headers['X-Org-Id'] = asOrg;
    const r = await fetch(`${base}${path}`, { headers });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const crossOrgAudit = () => getAuditLog(1000).filter((e) => e.action === 'CROSS_ORG_ACCESS');
const deniedAudit = () => getAuditLog(1000).filter((e) => e.action === 'CROSS_ORG_DENIED');

before(async () => {
    db = await startFakePostgrest({
        organisations: [{ id: 'oa', slug: 'org-a' }, { id: 'ob', slug: 'org-b' }, { id: 'oc', slug: 'org-c' }], org_access_audit: [],
        // The org-a analyst is assigned to org-b only.
        staff_org_assignments: [{ id: randomUUID(), user_id: 'analyst-org-a', user_email: 'analyst@org-a.test', org_slug: 'org-b', assigned_by: 'root', assigned_at: new Date().toISOString() }],
    });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.get('/perm', requirePermission('alerts:read'), (req, res) => { res.json({ org: requestOrg(req) }); });
    app.get('/any', requireAuth, requireOrg, (req, res) => { res.json({ org: requestOrg(req) }); });
    // Client portal accounts may only reach /api/client/ (middleware/auth.ts, P21).
    app.get('/api/client/any', requireAuth, requireOrg, (req, res) => { res.json({ org: requestOrg(req) }); });
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(async () => { server.close(); await db.close(); });

for (const role of ['super_admin', 'soc_manager', 'analyst']) {
    test(`${role}: own org by default; another existing org with X-Org-Id, audited`, async () => {
        assert.deepEqual((await get('/perm', role, 'org-a')).data, { org: 'org-a' });

        const auditBefore = crossOrgAudit().length;
        const rowsBefore = db.tables.org_access_audit.length;
        const r = await get('/perm?x=1', role, 'org-a', 'org-b');
        assert.equal(r.status, 200);
        assert.deepEqual(r.data, { org: 'org-b' });

        const entry = crossOrgAudit()[0];
        assert.equal(crossOrgAudit().length, auditBefore + 1);
        assert.equal(entry.user, `${role}@org-a.test`);
        assert.equal(entry.resource, 'GET /perm');
        assert.equal(entry.resource_id, 'org-b');
        assert.match(entry.details ?? '', new RegExp(`^${role} from org-a`));

        assert.equal(db.tables.org_access_audit.length, rowsBefore + 1);
        const row = db.tables.org_access_audit.at(-1)!;
        assert.equal(row.actor, `${role}@org-a.test`);
        assert.equal(row.role, role);
        assert.equal(row.home_org, 'org-a');
        assert.equal(row.target_org, 'org-b');
        assert.equal(row.route, '/perm');
        assert.ok(!Number.isNaN(Date.parse(String(row.accessed_at))));
    });

    test(`${role}: X-Org-Id naming an unknown org is 400 and is not audited`, async () => {
        const rowsBefore = db.tables.org_access_audit.length;
        const r = await get('/perm', role, 'org-a', 'org-nope');
        assert.equal(r.status, 400);
        assert.match(r.data.error, /Unknown organisation: org-nope/);
        assert.equal(db.tables.org_access_audit.length, rowsBefore);
    });

    test(`${role}: X-Org-Id equal to its own org is not a cross-org access`, async () => {
        const rowsBefore = db.tables.org_access_audit.length;
        assert.deepEqual((await get('/perm', role, 'org-a', 'org-a')).data, { org: 'org-a' });
        assert.equal(db.tables.org_access_audit.length, rowsBefore);
    });
}

for (const role of ['portal_user', 'executive']) {
    test(`${role}: X-Org-Id (even an unknown one) is ignored — always the token's org, never audited`, async () => {
        const path = role === 'portal_user' ? '/api/client/any' : '/any';
        const rowsBefore = db.tables.org_access_audit.length;
        assert.deepEqual((await get(path, role, 'org-a', 'org-b')).data, { org: 'org-a' });
        assert.deepEqual((await get(path, role, 'org-a', 'org-nope')).data, { org: 'org-a' });
        assert.equal(db.tables.org_access_audit.length, rowsBefore);
    });
}

test('portal_user tokens are refused outside /api/client/, whatever the route checks', async () => {
    for (const path of ['/perm', '/any']) {
        const r = await get(path, 'portal_user', 'org-a');
        assert.equal(r.status, 403, path);
        assert.match(r.data.error, /client portal/);
    }
    assert.equal((await get('/api/client/any', 'portal_user', 'org-a')).status, 200);
});

test('analyst: an organisation it is not assigned to is 403, audited as a denial, never as access', async () => {
    const accessBefore = crossOrgAudit().length;
    const deniedBefore = deniedAudit().length;
    const rowsBefore = db.tables.org_access_audit.length;
    const r = await get('/perm', 'analyst', 'org-a', 'org-c');
    assert.equal(r.status, 403);
    assert.match(r.data.error, /not assigned to organisation org-c/);
    assert.equal(crossOrgAudit().length, accessBefore);
    assert.equal(db.tables.org_access_audit.length, rowsBefore);
    assert.equal(deniedAudit().length, deniedBefore + 1);
    assert.equal(deniedAudit()[0].resource_id, 'org-c');
    // Another analyst of the same organisation has no assignment at all.
    assert.equal((await get('/perm', 'analyst', 'org-a', 'org-b')).status, 200, 'the assigned organisation works');
    const other = await fetch(`${base}/perm`, { headers: { Authorization: `Bearer ${tok('analyst', 'org-a', 'someone-else')}`, 'X-Org-Id': 'org-b' } });
    assert.equal(other.status, 403);
});

test('analyst: removing the assignment takes effect on the next request', async () => {
    const row = db.tables.staff_org_assignments[0];
    db.tables.staff_org_assignments.length = 0;
    try {
        assert.equal((await get('/perm', 'analyst', 'org-a', 'org-b')).status, 403);
        assert.deepEqual((await get('/perm', 'analyst', 'org-a')).data, { org: 'org-a' }, 'own organisation still works');
    } finally { db.tables.staff_org_assignments.push(row); }
});

test('analyst: without the assignments table, only the own organisation (fail closed); super_admin unaffected', async () => {
    const saved = db.tables.staff_org_assignments;
    delete (db.tables as Record<string, unknown>).staff_org_assignments;
    try {
        const deniedBefore = deniedAudit().length;
        const r = await get('/perm', 'analyst', 'org-a', 'org-b');
        assert.equal(r.status, 403);
        assert.equal(deniedAudit().length, deniedBefore + 1, 'the denial is audited');
        assert.deepEqual((await get('/perm', 'super_admin', 'org-a', 'org-c')).data, { org: 'org-c' });
    } finally { db.tables.staff_org_assignments = saved; }
});

test('an unknown role is treated as a client role', async () => {
    assert.deepEqual((await get('/any', 'viewer', 'org-a', 'org-b')).data, { org: 'org-a' });
});

test('an org in the query string is never read', async () => {
    assert.deepEqual((await get('/perm?org=org-b&org_id=org-b', 'super_admin', 'org-a')).data, { org: 'org-a' });
});

test('no org on the token is 403, with or without X-Org-Id', async () => {
    for (const path of ['/perm', '/any']) {
        assert.equal((await get(path, 'super_admin')).status, 403);
        assert.equal((await get(path, 'super_admin', undefined, 'org-b')).status, 403);
    }
});
