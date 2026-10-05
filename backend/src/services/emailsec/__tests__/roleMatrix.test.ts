// Email Security authorization matrix: what an analyst may and may not do, read-only roles,
// non-staff roles, anonymous callers, and that an organisation can never be chosen by the client.
// Real router, in-memory store, stubbed DNS — no network, no Supabase.
process.env.JWT_SECRET = 'role-matrix-test-secret';
process.env.EMAILSEC_JOBS_DISABLED = 'true';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'WAZUH_INDEXER_HOST', 'EMAILSEC_VERIFICATION_SECRET', 'NOVRSOC_ENV', 'RAILWAY_ENVIRONMENT_NAME', 'RAILWAY_ENVIRONMENT', 'RAILWAY_PROJECT_ID', 'EMAIL_PROXY_TOKEN', 'M365_CLIENT_ID', 'GOOGLE_WORKSPACE_SA_KEY']) delete process.env[k];

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import emailSecurityRouter from '../../../routes/emailSecurity';
import { createMemoryDb, setDb } from '../db';
import { setDnsClient } from '../dnsInspect';
import { setAnalyzers } from '../messagingService';
import { verificationRecord } from '../verification';
import type { UrlAnalysis } from '../urlIntel';

const db = createMemoryDb();
const TXT: Record<string, string[]> = { 'mine.test': ['v=spf1 -all'], '_dmarc.mine.test': ['v=DMARC1; p=none; rua=mailto:r@mine.test'] };
let base = '';
let server: Server;
const tok = (role: string, org: string) => jwt.sign({ sub: randomUUID(), email: `${role}-${randomUUID().slice(0, 6)}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
async function call(method: string, path: string, role: string | null, org = 'org-a', body?: unknown) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (role) headers.Authorization = `Bearer ${tok(role, org)}`;
    const r = await fetch(`${base}/api/email-security${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
let domainA = '';
let domainB = '';

before(async () => {
    setDb(db);
    setDnsClient({ txt: async (n) => TXT[n] ?? [], mx: async () => [], reverse: async () => null });
    setAnalyzers({ url: async (u: string) => ({ input: u, normalized: null, analyzed_at: '', verdict: 'no_known_threat', reasons: [], signals: [], sources: [], domain_age_days: null, registrar: null, fetch: null }) as UrlAnalysis });
    const app = express();
    app.use(express.json());
    app.use('/api/email-security', emailSecurityRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    TXT['_novrsoc-verification.mine.test'] = [verificationRecord('org-a', 'mine.test')!.value];
    domainA = (await call('POST', '/dmarc/domains', 'soc_manager', 'org-a', { domain: 'mine.test' })).data.domain.id;
    domainB = (await call('POST', '/dmarc/domains', 'soc_manager', 'org-b', { domain: 'theirs.test' })).data.domain.id;
});
after(() => { server.close(); setDb(null); setDnsClient(null); setAnalyzers(null); });

test('analyst: every Email Security page\'s data loads', async () => {
    for (const p of ['/overview', '/dmarc/domains', `/dmarc/domains/${domainA}`, '/dmarc/sources', '/dmarc/reports', '/dmarc/analytics', '/phishid/brand', '/phishid/domains', '/messaging/connections', '/messaging/events', '/alerts', '/integrations']) {
        assert.equal((await call('GET', p, 'analyst')).status, 200, p);
    }
});

test('analyst: analyst+ actions are allowed (verify, inspect, report a suspicious domain)', async () => {
    const v = await call('POST', `/dmarc/domains/${domainA}/verify`, 'analyst');
    assert.equal(v.status, 200);
    assert.equal(v.data.verification.state, 'verified', 'domain verification is analyst+');
    assert.equal((await call('POST', `/dmarc/domains/${domainA}/inspect`, 'analyst')).status, 200);
    assert.equal((await call('POST', '/phishid/domains', 'analyst', 'org-a', { domain: 'mine-login.test' })).status, 201);
});

test('analyst: manager-only actions are refused (403) and change nothing', async () => {
    const refused: [string, string, unknown?][] = [
        ['POST', '/dmarc/domains', { domain: 'new.test' }],
        ['PATCH', `/dmarc/domains/${domainA}`, { dkim_selectors: ['s1'] }],
        ['DELETE', `/dmarc/domains/${domainA}`],
        ['POST', `/dmarc/domains/${domainA}/policy-plan`, { policy: 'reject' }],
        ['PUT', '/phishid/brand', { organization_name: 'X', primary_domains: ['mine.test'] }],
        ['POST', '/phishid/discover'],
        ['POST', '/messaging/connections/microsoft365/start'],
        ['POST', '/messaging/connections/google_workspace', { admin_email: 'a@mine.test' }],
        ['POST', '/messaging/connections/gateway'],
        ['DELETE', '/messaging/connections/gateway'],
    ];
    for (const [m, p, b] of refused) assert.equal((await call(m, p, 'analyst', 'org-a', b)).status, 403, `${m} ${p}`);
    const domains = (await call('GET', '/dmarc/domains', 'analyst')).data.domains;
    assert.deepEqual(domains.map((d: { domain: string }) => d.domain), ['mine.test'], 'nothing was added or removed');
    assert.deepEqual(domains[0].dkim_selectors, []);
});

test('executive: read-only — can view, cannot verify or change anything', async () => {
    assert.equal((await call('GET', '/dmarc/domains', 'executive')).status, 200);
    assert.equal((await call('POST', `/dmarc/domains/${domainA}/verify`, 'executive')).status, 403);
    assert.equal((await call('POST', '/phishid/domains', 'executive', 'org-a', { domain: 'x-login.test' })).status, 403);
});

test('non-staff and anonymous callers are refused everywhere', async () => {
    for (const p of ['/overview', '/dmarc/domains', '/messaging/events']) {
        assert.equal((await call('GET', p, 'portal_user')).status, 403, `portal_user ${p}`);
        assert.equal((await call('GET', p, null)).status, 401, `anonymous ${p}`);
    }
    assert.equal((await call('POST', `/dmarc/domains/${domainA}/verify`, 'portal_user')).status, 403);
});

test('tenant isolation: another org\'s ids are 404, and org_id from the client is ignored', async () => {
    assert.equal((await call('GET', `/dmarc/domains/${domainB}`, 'analyst', 'org-a')).status, 404);
    assert.equal((await call('POST', `/dmarc/domains/${domainB}/verify`, 'analyst', 'org-a')).status, 404);
    assert.equal((await call('POST', `/dmarc/domains/${domainB}/inspect`, 'analyst', 'org-a')).status, 404);
    // Query string and body org parameters have no effect: the token's organisation is used.
    for (const q of ['org_id=org-b', 'org=org-b', 'orgId=org-b']) {
        const list = (await call('GET', `/dmarc/domains?${q}`, 'analyst', 'org-a')).data.domains;
        assert.deepEqual(list.map((d: { domain: string }) => d.domain), ['mine.test'], q);
    }
    const added = await call('POST', '/dmarc/domains', 'soc_manager', 'org-a', { domain: 'planted.test', org_id: 'org-b' });
    assert.equal(added.status, 201);
    assert.equal(added.data.domain.org_id, 'org-a', 'body org_id ignored');
    const bList = (await call('GET', '/dmarc/domains', 'analyst', 'org-b')).data.domains;
    assert.deepEqual(bList.map((d: { domain: string }) => d.domain), ['theirs.test'], 'org-b sees only its own domain');
    // The verification record is issued for the caller's org, never one named in the request.
    const rec = (await call('GET', `/dmarc/domains/${added.data.domain.id}?org_id=org-b`, 'analyst', 'org-a')).data.verification_record;
    assert.equal(rec.value, verificationRecord('org-a', 'planted.test')!.value);
});
