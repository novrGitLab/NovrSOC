// NovrSOC mail gateway (Postfix + Amavis) → /api/email-proxy/verdict → email_logs →
// Messaging Suite event → alert. Storage is in memory; the HTTP routes are the real ones.
process.env.JWT_SECRET = 'gateway-test-secret';
process.env.EMAILSEC_JOBS_DISABLED = 'true';
for (const k of ['EMAIL_PROXY_TOKEN', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'WAZUH_INDEXER_HOST']) delete process.env[k];

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import emailProxyRouter from '../emailProxy';
import emailSecurityRouter from '../emailSecurity';
import { setEmailProxyStore } from '../../services/emailProxy';
import { createMemoryDb, setDb } from '../../services/emailsec/db';
import { syncConnection } from '../../services/emailsec/messagingService';
import type { Connection } from '../../services/emailsec/connectors/types';

const logs: Record<string, unknown>[] = [];
const domains: Record<string, string> = { 'example.com': 'org-a', 'other.example': 'org-b' };
const db = createMemoryDb();
let base = '';
let server: Server;
const TOKEN = 'gw-shared-secret-value';

const staff = (role: string, org = 'org-a') => jwt.sign({ sub: randomUUID(), email: `${role}@novrsoc.test`, role, org_id: org }, process.env.JWT_SECRET!);
async function verdict(body: unknown, token: string | null = TOKEN) {
    const r = await fetch(`${base}/api/email-proxy/verdict`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', ...(token !== null ? { 'x-novrsoc-proxy-token': token } : {}) }, body: JSON.stringify(body),
    });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const harmless = (over: Record<string, unknown> = {}) => ({
    message_id: `<${randomUUID()}@test.local>`, from_address: 'Test Sender <sender@harmless.test>', to_address: 'user@example.com',
    subject: 'Gateway test message', verdict: 'clean', received_at: new Date().toISOString(), ...over,
});

before(() => {
    setEmailProxyStore({
        orgForDomain: async (d) => ({ org_id: domains[d] ?? null }),
        upsertLog: async (row) => { const i = logs.findIndex((l) => l.message_id === row.message_id); if (i >= 0) logs[i] = row; else logs.push(row); return {}; },
        logsSince: async (org, since, limit) => ({ rows: logs.filter((l) => l.org_id === org && String(l.received_at) > since).sort((a, b) => String(a.received_at).localeCompare(String(b.received_at))).slice(0, limit) }),
    });
    setDb(db);
    const app = express();
    app.use(express.json());
    app.use('/api/email-proxy', emailProxyRouter);
    app.use('/api/email-security', emailSecurityRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => { server.close(); setEmailProxyStore(null); setDb(null); delete process.env.EMAIL_PROXY_TOKEN; });

test('without EMAIL_PROXY_TOKEN configured the endpoint refuses everything', async () => {
    const r = await verdict(harmless(), 'anything');
    assert.equal(r.status, 401);
    assert.match(r.data.detail, /EMAIL_PROXY_TOKEN is not configured/);
    assert.equal(logs.length, 0);
});

test('token: missing / wrong → 401; correct → stored', async () => {
    process.env.EMAIL_PROXY_TOKEN = TOKEN;
    assert.equal((await verdict(harmless(), null)).status, 401);
    assert.equal((await verdict(harmless(), 'wrong-token-value-xx')).status, 401);
    assert.equal((await verdict(harmless(), TOKEN + 'x')).status, 401);
    assert.equal((await verdict(harmless())).status, 200);
    assert.equal(logs.length, 1);
});

test('malformed payloads → 400, nothing stored', async () => {
    const before = logs.length;
    for (const bad of [
        harmless({ message_id: '' }), harmless({ from_address: 'not an address' }), harmless({ to_address: undefined }),
        harmless({ verdict: 'probably-bad' }), harmless({ received_at: 'yesterday-ish' }), 'plain string',
    ]) assert.equal((await verdict(bad)).status, 400, JSON.stringify(bad).slice(0, 60));
    assert.equal(logs.length, before);
});

test('the tenant comes from the recipient domain — a body org_id cannot spoof it', async () => {
    const r = await verdict(harmless({ org_id: 'org-b', message_id: '<spoof@test>' }));
    assert.equal(r.status, 200);
    assert.equal(logs.find((l) => l.message_id === '<spoof@test>')!.org_id, 'org-a');
    const unregistered = await verdict(harmless({ to_address: 'user@not-registered.test' }));
    assert.equal(unregistered.status, 422);
});

test('normalisation: verdict case, display-name addresses, auth results, future timestamps', async () => {
    const future = new Date(Date.now() + 86_400_000).toISOString();
    await verdict(harmless({ message_id: '<norm@test>', verdict: ' PHISHING ', to_address: 'Staff Member <STAFF@Example.com>', dmarc_result: 'FAIL', spf_result: 'weird', received_at: future }));
    const row = logs.find((l) => l.message_id === '<norm@test>')!;
    assert.equal(row.verdict, 'phishing');
    assert.equal(row.to_address, 'staff@example.com');
    assert.equal(row.from_address, 'sender@harmless.test');
    assert.equal(row.dmarc_result, 'fail');
    assert.equal(row.spf_result, null);
    assert.ok(Date.parse(String(row.received_at)) <= Date.now(), 'future timestamp clamped');
});

test('the staff routes need a login; email logs are not public', async () => {
    for (const p of ['/logs', '/stats', '/domains']) assert.equal((await fetch(`${base}/api/email-proxy${p}`)).status, 401, p);
    const r = await fetch(`${base}/api/email-proxy/domains`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${staff('analyst')}` }, body: '{}' });
    assert.equal(r.status, 403);
});

test('end to end: gateway verdict → email_logs → Messaging event → alert, shown as the gateway\'s verdict', async () => {
    await verdict(harmless({ message_id: '<e2e@test>', verdict: 'phishing', from_address: 'it-support@evil-sender.test', subject: 'Harmless phishing-verdict test', received_at: new Date(Date.now() - 1000).toISOString() }));
    const [conn] = await db.insert<Connection>('messaging_connections', { org_id: 'org-a', provider: 'gateway', status: 'connected', scopes: [] });
    const r = await syncConnection(db, conn);
    assert.equal(r.ok, true);
    assert.ok(r.stored >= 3);

    const events = await (await fetch(`${base}/api/email-security/messaging/events?view=threats`, { headers: { Authorization: `Bearer ${staff('analyst')}` } })).json();
    const e = events.events.find((x: { message_id: string }) => x.message_id === '<e2e@test>');
    assert.equal(e.provider, 'gateway');
    assert.equal(e.detection, 'phishing');
    assert.equal(e.action, 'flag', 'a verdict is not a block');
    assert.equal(e.action_by, 'none');
    assert.ok(e.alert_id);
    const other = await (await fetch(`${base}/api/email-security/messaging/events`, { headers: { Authorization: `Bearer ${staff('analyst', 'org-b')}` } })).json();
    assert.equal(other.events.length, 0, 'org-b sees none of org-a\'s mail');
});
