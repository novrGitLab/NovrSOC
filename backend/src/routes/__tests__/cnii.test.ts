// CNII Watch routes: auth, role checks, input validation, the not-connected answers when a
// dependency isn't configured, and a full scan against a local sfwebui-compatible SpiderFoot.
process.env.JWT_SECRET = 'cnii-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'SPIDERFOOT_URL', 'OPENCTI_URL', 'OPENCTI_TOKEN', 'WAZUH_HOST', 'WAZUH_INDEXER_HOST']) delete process.env[k];

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import cniiRouter from '../cnii';

let base = '';
let server: Server;

const token = (role: string) => jwt.sign({ sub: randomUUID(), email: `${role}@novrsoc.test`, role, org_id: 'org-a' }, process.env.JWT_SECRET!);

async function call(method: string, path: string, role: string | null, body?: unknown) {
    const r = await fetch(`${base}/api/cnii${path}`, {
        method,
        headers: {
            ...(role ? { Authorization: `Bearer ${token(role)}` } : {}),
            ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    return { status: r.status, data: await r.json().catch(() => null) };
}

before(async () => {
    const app = express();
    app.use(express.json());
    app.use('/api/cnii', requireAuth, cniiRouter);
    server = app.listen(0);
    await new Promise(r => server.once('listening', r));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => { server.close(); });

test('requires a signed-in staff user', async () => {
    assert.equal((await call('GET', '/assets', null)).status, 401);
    assert.equal((await call('GET', '/assets', 'portal_user')).status, 403);
});

test('read feeds answer not_connected when Supabase is not configured', async () => {
    for (const path of ['/assets', '/alerts', '/vulns', '/alerts?sector=finance', '/vulns?ip=196.46.244.1']) {
        const r = await call('GET', path, 'executive');
        assert.equal(r.status, 503, path);
        assert.equal(r.data.error, 'not_connected', path);
    }
});

test('filters are validated', async () => {
    assert.equal((await call('GET', '/alerts?sector=nope', 'analyst')).status, 400);
    assert.equal((await call('GET', '/assets?ip=999.1.1.1', 'analyst')).status, 400);
});

test('scan validates the IP and says when SpiderFoot is not configured', async () => {
    assert.equal((await call('POST', '/scan', 'analyst', { ip: 'not-an-ip' })).status, 400);
    assert.equal((await call('POST', '/scan', 'analyst', {})).status, 400);
    const r = await call('POST', '/scan', 'analyst', { ip: '2001:db8::1' });
    assert.equal(r.status, 503);
    assert.equal(r.data.error, 'not_connected');
});

test('scan runs SpiderFoot, classifies, and reports OpenCTI being unavailable', async () => {
    const sf = express();
    sf.use(express.urlencoded({ extended: false }));
    sf.post('/startscan', (_req, res) => res.json(['SUCCESS', 'S1']));
    sf.get('/scanstatus', (_req, res) => res.json(['n', 't', 'c', 's', 'e', 'FINISHED', {}]));
    sf.get('/scaneventresults', (_req, res) => res.json([
        ['t', 'portal.inec.gov.ng', '', 'sfp_dnsresolve', 100, 100, 0, 'h', 0, 0, 'INTERNET_NAME'],
        ['t', '196.46.244.1:443', '', 'sfp_portscan_tcp', 100, 100, 0, 'h', 0, 0, 'TCP_PORT_OPEN'],
    ]));
    const sfServer = sf.listen(0);
    await new Promise((r) => sfServer.once('listening', r));
    process.env.SPIDERFOOT_URL = `http://127.0.0.1:${(sfServer.address() as AddressInfo).port}`;
    try {
        const r = await call('POST', '/scan', 'analyst', { ip: '196.46.244.1' });
        assert.equal(r.status, 200);
        assert.equal(r.data.hostname, 'portal.inec.gov.ng');
        assert.deepEqual(r.data.openPorts, [443]);
        assert.equal(r.data.suggestedSectorId, 'publicadmin');
        assert.equal(r.data.suggestedSubfield, 'INEC');
        assert.deepEqual(r.data.rawSpiderfoot, {}); // raw output stays server-side
        assert.ok(r.data.warnings.some((w: string) => /OpenCTI/.test(w)));
    } finally {
        delete process.env.SPIDERFOOT_URL;
        sfServer.close();
    }
});

test('adding an asset never reports success without storing it', async () => {
    assert.equal((await call('POST', '/assets', 'analyst', { ip: '10.0.0.1', sectorId: 'bogus' })).status, 400);
    assert.equal((await call('POST', '/assets', 'analyst', { ip: '10.0.0.1', sectorId: 'power', subfield: 'INEC' })).status, 400);
    const r = await call('POST', '/assets', 'analyst', { ip: '10.0.0.1', sectorId: 'power' });
    assert.equal(r.status, 503);
    assert.notEqual(r.data?.success, true);
});

test('executives can read but not scan or add assets', async () => {
    assert.equal((await call('POST', '/scan', 'executive', { ip: '10.0.0.1' })).status, 403);
    assert.equal((await call('POST', '/assets', 'executive', { ip: '10.0.0.1', sectorId: 'power' })).status, 403);
});
