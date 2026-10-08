// lib/resolveOrg.ts through requirePermission / requireOrg: which organisation each role acts on,
// X-Org-Id for staff only, unknown orgs, and the cross-org audit trail. `organisations` and
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

const tok = (role: string, org?: string) =>
    jwt.sign({ sub: randomUUID(), email: `${role}@${org ?? 'none'}.test`, role, ...(org ? { org_id: org } : {}) }, process.env.JWT_SECRET!);

async function get(path: string, role: string, org?: string, asOrg?: string) {
    const headers: Record<string, string> = { Authorization: `Bearer ${tok(role, org)}` };
    if (asOrg !== undefined) headers['X-Org-Id'] = asOrg;
    const r = await fetch(`${base}${path}`, { headers });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const crossOrgAudit = () => getAuditLog(1000).filter((e) => e.action === 'CROSS_ORG_ACCESS');

before(async () => {
    db = await startFakePostgrest({ organisations: [{ id: 'oa', slug: 'org-a' }, { id: 'ob', slug: 'org-b' }], org_access_audit: [] });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.get('/perm', requirePermission('alerts:read'), (req, res) => { res.json({ org: requestOrg(req) }); });
    app.get('/any', requireAuth, requireOrg, (req, res) => { res.json({ org: requestOrg(req) }); });
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
        const rowsBefore = db.tables.org_access_audit.length;
        assert.deepEqual((await get('/any', role, 'org-a', 'org-b')).data, { org: 'org-a' });
        assert.deepEqual((await get('/any', role, 'org-a', 'org-nope')).data, { org: 'org-a' });
        assert.equal(db.tables.org_access_audit.length, rowsBefore);
    });
}

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
