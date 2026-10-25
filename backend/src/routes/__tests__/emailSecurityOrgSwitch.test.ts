// F-11: Email Security used to resolve its organisation as req.user.org_id only — never through
// requireOrg (lib/permissions.ts) — so staff could never work on a client's email security data,
// and the client `executive` role's own isolation was never actually exercised against a real
// X-Org-Id attempt (there was nothing to ignore it with). This file proves the fix end to end,
// against a real organisation/staff_org_assignments table (fakePostgrest) alongside Email
// Security's own in-memory data store (services/emailsec/db.ts — a separate, pluggable layer for
// email data only; organisation and assignment lookups go through lib/resolveOrg.ts's own
// Supabase client, which is why both are needed here, unlike roleMatrix.test.ts which runs with
// no Supabase configured at all and so cannot exercise a successful cross-org switch):
//   - super_admin / soc_manager can switch to another organisation's email security with
//     X-Org-Id, see ITS domains, and the access is recorded in org_access_audit;
//   - an analyst with no assignment to that organisation is refused (403), fails closed;
//   - an analyst who IS assigned reaches it;
//   - the client `executive` role's X-Org-Id is always ignored, even naming a real organisation.
process.env.JWT_SECRET = 'emailsec-org-switch-test-secret';
process.env.EMAILSEC_JOBS_DISABLED = 'true';
for (const k of ['WAZUH_INDEXER_HOST', 'EMAILSEC_VERIFICATION_SECRET', 'NOVRSOC_ENV', 'RAILWAY_ENVIRONMENT_NAME', 'RAILWAY_ENVIRONMENT', 'RAILWAY_PROJECT_ID', 'M365_CLIENT_ID', 'GOOGLE_WORKSPACE_SA_KEY']) delete process.env[k];

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import emailSecurityRouter from '../emailSecurity';
import { createMemoryDb, setDb } from '../../services/emailsec/db';
import { setDnsClient } from '../../services/emailsec/dnsInspect';
import { startFakePostgrest, type FakePostgrest } from './fakePostgrest';

const A = 'org-a';
const B = 'org-b';
const emailDb = createMemoryDb();
let fake: FakePostgrest;
let base = '';
let server: Server;
const tok = (role: string, org: string) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
async function call(method: string, path: string, bearer: string, orgHeader?: string, body?: unknown) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` };
    if (orgHeader) headers['X-Org-Id'] = orgHeader;
    const r = await fetch(`${base}/api/email-security${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
let domainB = '';

before(async () => {
    setDb(emailDb);
    setDnsClient({ txt: async () => [], mx: async () => [], reverse: async () => null });
    fake = await startFakePostgrest({
        organisations: [{ id: 'oa', slug: A, name: 'Org A' }, { id: 'ob', slug: B, name: 'Org B' }],
        staff_org_assignments: [], org_access_audit: [],
    });
    process.env.SUPABASE_URL = fake.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';

    const app = express();
    app.use(express.json());
    app.use('/api/email-security', emailSecurityRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    const created = await call('POST', '/dmarc/domains', tok('soc_manager', B), undefined, { domain: 'theirs.test' });
    domainB = created.data?.domain?.id;
    assert.ok(domainB, `seed: org-b domain created (got ${JSON.stringify(created.data)})`);
});
after(async () => { server.close(); setDb(null); setDnsClient(null); await fake.close(); });

test('super_admin reaches another organisation\'s email security with X-Org-Id, and it is audited', async () => {
    const r = await call('GET', '/dmarc/domains', tok('super_admin', A), B);
    assert.equal(r.status, 200);
    assert.deepEqual(r.data.domains.map((d: { domain: string }) => d.domain), ['theirs.test']);
    assert.ok(fake.tables.org_access_audit.some((a) => a.home_org === A && a.target_org === B), 'cross-org access recorded');
});

test('soc_manager can also switch, and can act (not just read) on the target organisation', async () => {
    const insp = await call('POST', `/dmarc/domains/${domainB}/inspect`, tok('soc_manager', A), B);
    assert.equal(insp.status, 200);
});

test('an analyst with no assignment to the target organisation is refused — fails closed', async () => {
    const r = await call('GET', '/dmarc/domains', tok('analyst', A), B);
    assert.equal(r.status, 403);
    assert.match(r.data.error, /not assigned/);
});

test('an analyst assigned to the target organisation reaches it', async () => {
    const analystToken = tok('analyst', A);
    const { sub } = jwt.decode(analystToken) as { sub: string };
    fake.tables.staff_org_assignments.push({ id: randomUUID(), user_id: sub, org_slug: B, assigned_at: new Date().toISOString() });
    const r = await call('GET', '/dmarc/domains', analystToken, B);
    assert.equal(r.status, 200);
    assert.deepEqual(r.data.domains.map((d: { domain: string }) => d.domain), ['theirs.test']);
});

test('the client executive role\'s X-Org-Id is always ignored, even naming a real organisation', async () => {
    const r = await call('GET', '/dmarc/domains', tok('executive', A), B);
    assert.equal(r.status, 200);
    assert.deepEqual(r.data.domains.map((d: { domain: string }) => d.domain), [], 'org-a has no domains of its own here — never org-b\'s');
});

test('switching organisation does not need a different token — the same staff session can read its own org again by omitting the header', async () => {
    const admin = tok('super_admin', A);
    const other = await call('GET', '/dmarc/domains', admin, B);
    assert.deepEqual(other.data.domains.map((d: { domain: string }) => d.domain), ['theirs.test']);
    const own = await call('GET', '/dmarc/domains', admin);
    assert.deepEqual(own.data.domains.map((d: { domain: string }) => d.domain), [], 'back to org-a, with no domains of its own');
});
