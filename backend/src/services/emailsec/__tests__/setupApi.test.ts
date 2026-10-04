// Backend additions for the Email Security frontend redesign: domain ownership verification,
// enriched domain list, multi-field message search / risk filters, Phish ID detection reasons.
// Real router, in-memory store, stubbed DNS — no network, no Supabase.
process.env.JWT_SECRET = 'setup-api-test-secret';
process.env.EMAILSEC_JOBS_DISABLED = 'true';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'WAZUH_INDEXER_HOST', 'EMAILSEC_VERIFICATION_SECRET']) delete process.env[k];

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
import { setAnalyzers, ingestEvents } from '../messagingService';
import { fromGateway } from '../eventModel';
import { verificationRecord, checkVerification } from '../verification';
import type { UrlAnalysis } from '../urlIntel';

const db = createMemoryDb();
const TXT: Record<string, string[]> = { 'example.com': ['v=spf1 -all'], '_dmarc.example.com': ['v=DMARC1; p=none'] };
let base = '';
let server: Server;
const tok = (role: string, org: string) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
async function api(method: string, path: string, role: string, org: string, body?: unknown) {
    const r = await fetch(`${base}/api/email-security${path}`, { method, headers: { Authorization: `Bearer ${tok(role, org)}`, 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}

before(() => {
    setDb(db);
    setDnsClient({ txt: async (n) => { if (n === '_novrsoc-verification.broken.com') throw new Error('SERVFAIL'); return TXT[n] ?? []; }, mx: async () => [], reverse: async () => null });
    setAnalyzers({ url: async (u: string) => ({ input: u, normalized: null, analyzed_at: '', verdict: 'no_known_threat', reasons: [], signals: [], sources: [], domain_age_days: null, registrar: null, fetch: null }) as UrlAnalysis });
    const app = express();
    app.use(express.json());
    app.use('/api/email-security', emailSecurityRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => { server.close(); setDb(null); setDnsClient(null); setAnalyzers(null); });

test('verification record: stable per (org, domain), different for every tenant, unguessable without the secret', () => {
    const a = verificationRecord('org-a', 'example.com')!;
    assert.equal(a.type, 'TXT');
    assert.equal(a.name, '_novrsoc-verification.example.com');
    assert.match(a.value, /^novrsoc-verification=[0-9a-f]{32}$/);
    assert.deepEqual(verificationRecord('org-a', 'EXAMPLE.com'), { ...a, name: '_novrsoc-verification.EXAMPLE.com' }, 'case-insensitive token');
    assert.notEqual(verificationRecord('org-b', 'example.com')!.value, a.value);
    const saved = process.env.JWT_SECRET;
    delete process.env.JWT_SECRET;
    try { assert.equal(verificationRecord('org-a', 'example.com'), null); } finally { process.env.JWT_SECRET = saved; }
});

test('verification states: not found, incorrect value (e.g. another tenant\'s token), verified, DNS error', async () => {
    assert.equal((await checkVerification('org-a', 'example.com')).state, 'not_found');
    TXT['_novrsoc-verification.example.com'] = [verificationRecord('org-b', 'example.com')!.value];
    assert.equal((await checkVerification('org-a', 'example.com')).state, 'incorrect_value');
    TXT['_novrsoc-verification.example.com'].push(verificationRecord('org-a', 'example.com')!.value);
    assert.equal((await checkVerification('org-a', 'example.com')).state, 'verified');
    assert.equal((await checkVerification('org-a', 'broken.com')).state, 'dns_error');
    delete TXT['_novrsoc-verification.example.com'];
});

test('add domain returns its record; verify endpoint and domain list reflect the real lookup', async () => {
    const add = await api('POST', '/dmarc/domains', 'soc_manager', 'org-a', { domain: 'example.com' });
    assert.equal(add.status, 201);
    assert.equal(add.data.verification_record.name, '_novrsoc-verification.example.com');
    let list = (await api('GET', '/dmarc/domains', 'analyst', 'org-a')).data.domains;
    assert.equal(list[0].verification.state, 'not_found');
    assert.equal(list[0].last_report_at, null);

    TXT['_novrsoc-verification.example.com'] = [add.data.verification_record.value];
    assert.equal((await api('POST', `/dmarc/domains/${add.data.domain.id}/verify`, 'executive', 'org-a')).status, 403, 'read-only roles cannot trigger checks');
    const v = await api('POST', `/dmarc/domains/${add.data.domain.id}/verify`, 'analyst', 'org-a');
    assert.equal(v.status, 200);
    assert.equal(v.data.verification.state, 'verified');
    list = (await api('GET', '/dmarc/domains', 'analyst', 'org-a')).data.domains;
    assert.equal(list[0].verification.state, 'verified');
    assert.equal((await api('POST', `/dmarc/domains/${add.data.domain.id}/verify`, 'analyst', 'org-b')).status, 404, 'other tenants cannot check it');
    const detail = await api('GET', `/dmarc/domains/${add.data.domain.id}`, 'analyst', 'org-a');
    assert.equal(detail.data.latest.verification.state, 'verified');
    assert.equal(detail.data.verification_record.value, add.data.verification_record.value);
});

test('message search covers sender, recipient, subject and message id; risk filters split threats / suspicious / clean', async () => {
    const ev = (id: string, over: Record<string, unknown>) => fromGateway({ id, message_id: `<${id}@mail.test>`, org_id: 'org-m', from_address: 'news@shop.test', to_address: 'staff@example.com', verdict: 'clean', received_at: new Date().toISOString(), ...over });
    await ingestEvents(db, 'org-m', [
        ev('m1', { verdict: 'phishing', from_address: 'it@evil.test', subject: 'Password reset required' }),
        ev('m2', { verdict: 'spam', subject: 'Weekly deals' }),
        ev('m3', { to_address: 'ceo@example.com', subject: 'Board pack' }),
    ]);
    const q = async (qs: string) => (await api('GET', `/messaging/events?${qs}`, 'analyst', 'org-m')).data.events.map((e: { message_id: string }) => e.message_id).sort();
    assert.deepEqual(await q('q=evil.test'), ['<m1@mail.test>'], 'sender');
    assert.deepEqual(await q('q=ceo%40example.com'), ['<m3@mail.test>'], 'recipient');
    assert.deepEqual(await q('q=password'), ['<m1@mail.test>'], 'subject');
    assert.deepEqual(await q('q=%3Cm2%40mail'), ['<m2@mail.test>'], 'message id');
    assert.deepEqual(await q('risk=threat'), ['<m1@mail.test>']);
    assert.deepEqual(await q('risk=suspicious'), ['<m2@mail.test>'], 'spam is a lower-severity detection');
    assert.deepEqual(await q('risk=clean'), ['<m3@mail.test>']);
    // Hostile input is reduced to the safe character set — it can't change the filter.
    assert.deepEqual(await q(`q=${encodeURIComponent('evil.test),sender.ilike.*')}`), []);
    assert.equal((await api('GET', '/messaging/events?q=evil.test', 'analyst', 'org-other')).data.events.length, 0, 'tenant isolation holds');
});

test('Phish ID list carries the explainable detection signals', async () => {
    const add = await api('POST', '/phishid/domains', 'analyst', 'org-p', { domain: 'example-login.test' });
    await db.update('phishing_domains', [{ col: 'id', op: 'eq', value: add.data.domain.id }], { risk_signals: [{ id: 'login_form', label: 'Login form (password field)', detail: 'x', points: 20 }], last_enriched: new Date().toISOString() });
    const list = (await api('GET', '/phishid/domains', 'analyst', 'org-p')).data.domains;
    assert.equal(list[0].risk_signals[0].label, 'Login form (password field)');
});
