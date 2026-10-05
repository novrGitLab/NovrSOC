// DMARC report ingestion vs domain ownership verification, and the verification-secret policy.
// Real routers (Email Security + the Mailgun inbox), in-memory store, stubbed DNS — no network,
// no Supabase.
process.env.JWT_SECRET = 'ingest-verification-test-secret';
process.env.EMAILSEC_JOBS_DISABLED = 'true';
process.env.MAILGUN_WEBHOOK_SIGNING_KEY = 'mg-key';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'WAZUH_INDEXER_HOST', 'EMAILSEC_VERIFICATION_SECRET', 'NOVRSOC_ENV', 'RAILWAY_ENVIRONMENT_NAME', 'RAILWAY_ENVIRONMENT', 'RAILWAY_PROJECT_ID']) delete process.env[k];

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { createHmac, randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import emailSecurityRouter from '../../../routes/emailSecurity';
import emailRouter from '../../../routes/email';
import { createMemoryDb, setDb } from '../db';
import { setDnsClient } from '../dnsInspect';
import { setCaseApi } from '../alerts';
import { verificationRecord, verificationSecretPolicy, checkVerification } from '../verification';
import { getAuditLog } from '../../../lib/audit';
import { SAMPLE_REPORT, zipOf } from './fixtures';

const db = createMemoryDb();
const TXT: Record<string, string[]> = {};
let base = '';
let server: Server;

const tok = (role: string, org: string) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
async function api(method: string, path: string, role: string, org: string, body?: unknown) {
    const r = await fetch(`${base}/api/email-security${path}`, { method, headers: { Authorization: `Bearer ${tok(role, org)}`, 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const reportFor = (domain: string, reportId: string) => zipOf('r.xml', SAMPLE_REPORT.split('<domain>example.com</domain>').join(`<domain>${domain}</domain>`).replace('1234567890', reportId));
let n = 0;
async function inbound(zip: Buffer) {
    const ts = String(Math.floor(Date.now() / 1000));
    const token = `t-${++n}-${randomUUID()}`;
    const fd = new FormData();
    fd.append('attachment-1', new Blob([new Uint8Array(zip)]), 'report.zip');
    fd.append('timestamp', ts); fd.append('token', token);
    fd.append('signature', createHmac('sha256', 'mg-key').update(`${ts}${token}`).digest('hex'));
    const r = await fetch(`${base}/api/email/dmarc-inbound`, { method: 'POST', body: fd });
    return { status: r.status, data: await r.json() };
}
async function upload(org: string, zip: Buffer) {
    const fd = new FormData();
    fd.append('report', new Blob([new Uint8Array(zip)]), 'report.zip');
    const r = await fetch(`${base}/api/email-security/dmarc/reports/upload`, { method: 'POST', headers: { Authorization: `Bearer ${tok('soc_manager', org)}` }, body: fd });
    return { status: r.status, data: await r.json() };
}
const reportsOf = async (org: string) => db.select<{ report_id: string; domain: string }>('dmarc_aggregate_reports', { filters: [{ col: 'org_id', op: 'eq', value: org }] as never });
async function addDomain(org: string, domain: string, verify: boolean, expectState = verify ? 'verified' : 'not_found') {
    if (verify) TXT[`_novrsoc-verification.${domain}`] = [...(TXT[`_novrsoc-verification.${domain}`] ?? []), verificationRecord(org, domain)!.value];
    const r = await api('POST', '/dmarc/domains', 'soc_manager', org, { domain });
    assert.equal(r.status, 201);
    assert.equal(r.data.inspection.verification.state, expectState);
    return r.data.domain.id as string;
}

before(() => {
    setDb(db);
    setDnsClient({ txt: async (name) => TXT[name] ?? [], mx: async () => [], reverse: async () => null });
    setCaseApi({ createCase: async () => ({ ok: true, created: true, case: { id: randomUUID(), case_number: 'CASE-T' } as never }), addTimeline: async () => {} });
    const app = express();
    app.use(express.json());
    app.use('/api/email-security', emailSecurityRouter);
    app.use('/api/email', emailRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => { server.close(); setDb(null); setDnsClient(null); setCaseApi(null); });

// ── Ingestion ──

test('1. verified domain: a Mailgun-delivered report is stored for the verified owner', async () => {
    await addDomain('org-v', 'verified.test', true);
    const r = await inbound(reportFor('verified.test', 'v-1'));
    assert.equal(r.status, 200);
    assert.equal(r.data.accepted, true);
    assert.deepEqual((await reportsOf('org-v')).map((x) => x.report_id), ['v-1']);
});

test('2. unverified domain: Mailgun report is refused with a clear reason, not stored, and audited', async () => {
    await addDomain('org-u', 'unverified.test', false);
    const r = await inbound(reportFor('unverified.test', 'u-1'));
    assert.equal(r.status, 200, 'answered 200: a retry cannot succeed until the domain is verified');
    assert.equal(r.data.accepted, false);
    assert.match(r.data.reason, /ownership has not been verified/);
    assert.equal((await reportsOf('org-u')).length, 0);
    const entry = getAuditLog(50).find((e) => e.action === 'EMAILSEC_DMARC_REPORT_WITHHELD' && e.details?.includes('unverified.test'));
    assert.ok(entry, 'withholding is audit-logged');
    assert.equal(entry!.severity, 'warning');
    assert.match(entry!.details!, /org-u/);

    // Once the TXT record is published and the domain is re-verified, the next report flows.
    TXT['_novrsoc-verification.unverified.test'] = [verificationRecord('org-u', 'unverified.test')!.value];
    const [d] = await db.select<{ id: string }>('email_domains', { filters: [{ col: 'org_id', op: 'eq', value: 'org-u' }] as never });
    assert.equal((await api('POST', `/dmarc/domains/${d.id}/verify`, 'analyst', 'org-u')).data.verification.state, 'verified');
    assert.equal((await inbound(reportFor('unverified.test', 'u-2'))).data.accepted, true);

    // An upload by the tenant itself is accepted for an unverified domain (it already holds the
    // report — nothing is disclosed) but is flagged as unverified in the response and the audit.
    await addDomain('org-u', 'upload-only.test', false);
    const up = await upload('org-u', reportFor('upload-only.test', 'up-1'));
    assert.equal(up.status, 201);
    assert.equal(up.data.domain_verified, false);
    assert.ok(getAuditLog(50).some((e) => e.action === 'EMAILSEC_DMARC_REPORT_UPLOAD' && /NOT verified/.test(e.details ?? '') && e.severity === 'warning'));
    // …and the domain is still shown as not verified: reports never imply ownership.
    const list = (await api('GET', '/dmarc/domains', 'analyst', 'org-u')).data.domains;
    assert.notEqual(list.find((x: { domain: string }) => x.domain === 'upload-only.test').verification?.state, 'verified');
});

test('3. unknown domain: refused through both paths, nothing stored', async () => {
    const r = await inbound(reportFor('nobody.test', 'n-1'));
    assert.equal(r.data.accepted, false);
    assert.match(r.data.reason, /not a monitored domain/);
    const up = await upload('org-v', reportFor('nobody.test', 'n-2'));
    assert.equal(up.status, 422);
    const all = await db.select<{ report_id: string }>('dmarc_aggregate_reports', {});
    assert.ok(!all.some((x) => /^n-/.test(x.report_id)));
});

test('4. cross-organisation: only the verifying tenant receives reports; another tenant registering the same domain gets nothing', async () => {
    await addDomain('org-owner', 'shared.test', true);
    // The owner's record is already published: for the squatter it is the wrong value.
    await addDomain('org-squatter', 'shared.test', false, 'incorrect_value');
    const r = await inbound(reportFor('shared.test', 's-1'));
    assert.equal(r.data.accepted, true);
    assert.deepEqual((await reportsOf('org-owner')).map((x) => x.report_id), ['s-1']);
    assert.equal((await reportsOf('org-squatter')).length, 0, 'registering a domain is not enough to receive its reports');
    assert.equal((await api('GET', '/dmarc/sources?domain=shared.test', 'analyst', 'org-squatter')).data.sources.length, 0);
    assert.ok(getAuditLog(50).some((e) => e.action === 'EMAILSEC_DMARC_REPORT_WITHHELD' && /org-squatter/.test(e.details ?? '') && /org-owner/.test(e.details ?? '')));

    // Another tenant's published token does not verify: tokens are per organisation.
    const [sq] = await db.select<{ id: string }>('email_domains', { filters: [{ col: 'org_id', op: 'eq', value: 'org-squatter' }] as never });
    assert.equal((await api('POST', `/dmarc/domains/${sq.id}/verify`, 'soc_manager', 'org-squatter')).data.verification.state, 'incorrect_value');

    // Uploads are scoped to the uploader's organisation: org-v cannot push data into org-owner.
    const up = await upload('org-v', reportFor('shared.test', 's-2'));
    assert.equal(up.status, 422);
    assert.ok(!(await reportsOf('org-owner')).some((x) => x.report_id === 's-2'));
});

test('5. duplicate / replayed report: stored once; a replayed Mailgun request is refused', async () => {
    const zip = reportFor('verified.test', 'dup-1');
    assert.equal((await inbound(zip)).data.duplicate, false);
    const again = await inbound(zip);
    assert.equal(again.data.accepted, true);
    assert.equal(again.data.duplicate, true, 'same (reporter, report_id) → not stored twice');
    assert.equal((await reportsOf('org-v')).filter((x) => x.report_id === 'dup-1').length, 1);

    // The exact same signed Mailgun request (same token) is a replay.
    const ts = String(Math.floor(Date.now() / 1000));
    const mk = () => { const fd = new FormData(); fd.append('attachment-1', new Blob([new Uint8Array(zip)]), 'r.zip'); fd.append('timestamp', ts); fd.append('token', 'replay-tok'); fd.append('signature', createHmac('sha256', 'mg-key').update(`${ts}replay-tok`).digest('hex')); return fd; };
    assert.equal((await fetch(`${base}/api/email/dmarc-inbound`, { method: 'POST', body: mk() })).status, 200);
    assert.equal((await fetch(`${base}/api/email/dmarc-inbound`, { method: 'POST', body: mk() })).status, 401);
});

// ── Verification secret policy ──

const STRONG = 'a'.repeat(40);
test('secret: production with a dedicated EMAILSEC_VERIFICATION_SECRET uses it', () => {
    const p = verificationSecretPolicy({ NOVRSOC_ENV: 'production', EMAILSEC_VERIFICATION_SECRET: STRONG, JWT_SECRET: 'jwt' });
    assert.equal(p.source, 'dedicated');
    assert.equal(p.secret, STRONG);
    // Railway production is detected the same way.
    assert.equal(verificationSecretPolicy({ RAILWAY_ENVIRONMENT_NAME: 'production', EMAILSEC_VERIFICATION_SECRET: STRONG, JWT_SECRET: 'jwt' }).source, 'dedicated');
});

test('secret: production/staging without a dedicated secret fail closed — no JWT_SECRET fallback', () => {
    for (const env of [{ NOVRSOC_ENV: 'production' }, { RAILWAY_ENVIRONMENT_NAME: 'production' }, { NOVRSOC_ENV: 'staging' }]) {
        const p = verificationSecretPolicy({ ...env, JWT_SECRET: 'jwt-secret-present' });
        assert.equal(p.secret, null, JSON.stringify(env));
        assert.match(p.reason, /required/);
    }
    assert.equal(verificationSecretPolicy({ NOVRSOC_ENV: 'production', EMAILSEC_VERIFICATION_SECRET: 'short', JWT_SECRET: 'x' }).secret, null, 'too short');
    assert.equal(verificationSecretPolicy({ NOVRSOC_ENV: 'production', EMAILSEC_VERIFICATION_SECRET: STRONG, JWT_SECRET: STRONG }).secret, null, 'must differ from JWT_SECRET');
});

test('secret: production without one → no record is issued and nothing can become verified', async () => {
    const saved = { ...process.env };
    process.env.NOVRSOC_ENV = 'production';
    delete process.env.EMAILSEC_VERIFICATION_SECRET;
    try {
        assert.equal(verificationRecord('org-v', 'verified.test'), null);
        // verified.test still has org-v's (dev-secret) record published — it must NOT verify.
        assert.equal((await checkVerification('org-v', 'verified.test')).state, 'unavailable');
    } finally { process.env = saved; }
});

test('secret: development and test fall back to JWT_SECRET; a dedicated one still wins', () => {
    assert.equal(verificationSecretPolicy({ JWT_SECRET: 'jwt' }).source, 'jwt_fallback');
    assert.equal(verificationSecretPolicy({ NOVRSOC_ENV: 'test', JWT_SECRET: 'jwt' }).source, 'jwt_fallback');
    assert.equal(verificationSecretPolicy({ NOVRSOC_ENV: 'development', EMAILSEC_VERIFICATION_SECRET: 'dev', JWT_SECRET: 'jwt' }).secret, 'dev', 'no length rule outside deployed environments');
    assert.equal(verificationSecretPolicy({}).source, 'none');
});
