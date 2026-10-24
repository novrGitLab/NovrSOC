// Phase P26: the IOC lookup cache (ioc_enrichments) is per organisation. Every reader —
// /api/cti/feed, /api/cti/stats, /api/intelligence/stix (+summary), /api/search — returns only the
// requester's organisation's rows; legacy rows with no organisation are shown to nobody; a lookup
// writes the requester's own row and never overwrites another organisation's. External enrichment
// sources are stubbed (nothing leaves the process); all data synthetic.
process.env.JWT_SECRET = 'ioc-cache-tenancy-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'MISP_URL', 'MISP_API_KEY', 'WAZUH_INDEXER_HOST', 'WAZUH_HOST']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest } from './fakePostgrest';
import ctiRouter from '../cti';
import intelligenceRouter from '../intelligence';
import searchRouter from '../search';

const A = 'org-a';
const B = 'org-b';
let db: FakePostgrest;
let server: Server;
let base = '';
const realFetch = globalThis.fetch;
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org: string) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
async function call(method: string, path: string, role: string, org: string, body?: unknown) {
    const r = await realFetch(`${base}${path}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tok(role, org)}` }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, text: await r.text() };
}
const row = (org: string | null, value: string, score: number) => ({ id: randomUUID(), org_id: org, ioc_value: value, ioc_type: 'ip', risk_score: score, tags: [], source: 'manual_lookup', last_seen: new Date().toISOString(), first_seen: null, country_name: null, isp: null });

before(async () => {
    db = await startFakePostgrest({ ioc_enrichments: [], organisations: [{ id: 'oa', slug: A, name: 'A' }, { id: 'ob', slug: B, name: 'B' }], cases: [], nigeria_advisories: [], staff_org_assignments: [], ti_indicators: [], ti_indicator_sources: [] });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test';
    // Only the fake database and this server are reachable; every external source fails fast.
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
        const url = String(input instanceof Request ? input.url : input);
        if (url.startsWith(db.url) || url.startsWith(base)) return realFetch(input, init);
        return new Response('{}', { status: 503 });
    }) as typeof fetch;
    const app = express();
    app.use(express.json());
    app.use('/api/cti', requireAuth, ctiRouter);
    app.use('/api/intelligence', requireAuth, intelligenceRouter);
    app.use('/api/search', requireAuth, searchRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); globalThis.fetch = realFetch; server.close(); await db.close(); });
beforeEach(() => {
    db.tables.ioc_enrichments.length = 0;
    db.tables.ioc_enrichments.push(row(A, '198.51.100.7', 90), row(B, '203.0.113.99', 80), row(null, '192.0.2.55', 70));
});

test('feed: only the requester\'s organisation; legacy unattributed rows are shown to nobody', async () => {
    const a = await call('GET', '/api/cti/feed', 'analyst', A);
    assert.equal(a.status, 200);
    assert.ok(a.text.includes('198.51.100.7'));
    assert.ok(!a.text.includes('203.0.113.99') && !a.text.includes('192.0.2.55'));
    const b = await call('GET', '/api/cti/feed', 'executive', B);
    assert.ok(b.text.includes('203.0.113.99') && !b.text.includes('198.51.100.7'));
});

test('stats count only the requester\'s organisation', async () => {
    const r = JSON.parse((await call('GET', '/api/cti/stats', 'analyst', A)).text);
    assert.equal(r.total, 1);
});

test('STIX export and its summary contain only the requester\'s organisation', async () => {
    const stix = await call('GET', '/api/intelligence/stix', 'analyst', A);
    assert.equal(stix.status, 200);
    assert.ok(stix.text.includes('198.51.100.7'));
    assert.ok(!stix.text.includes('203.0.113.99') && !stix.text.includes('192.0.2.55'));
    const sum = JSON.parse((await call('GET', '/api/intelligence/stix/summary', 'analyst', B)).text);
    assert.equal(sum.total, 1);
});

test('global search finds only the requester\'s organisation\'s cached IOCs', async () => {
    const a = await call('GET', '/api/search?q=203.0.113', 'analyst', A);
    assert.equal(a.status, 200, a.text);
    assert.ok(!a.text.includes('203.0.113.99'), 'org B\'s lookup is not searchable by org A');
    const b = await call('GET', '/api/search?q=203.0.113', 'analyst', B);
    assert.ok(b.text.includes('203.0.113.99'));
});

test('a lookup writes the requester\'s own row; the same value in another organisation is untouched', async () => {
    const before = { ...db.tables.ioc_enrichments.find((r) => r.org_id === B)! };
    const r = await call('POST', '/api/cti/lookup', 'analyst', A, { value: '203.0.113.99', type: 'ip' });
    assert.equal(r.status, 200, r.text);
    const rows = db.tables.ioc_enrichments.filter((x) => x.ioc_value === '203.0.113.99');
    assert.deepEqual(rows.map((x) => x.org_id).sort(), [A, B]);
    assert.deepEqual(rows.find((x) => x.org_id === B), before, 'org B\'s row was not overwritten');
    await call('POST', '/api/cti/lookup', 'analyst', A, { value: '203.0.113.99', type: 'ip' });
    assert.equal(db.tables.ioc_enrichments.filter((x) => x.ioc_value === '203.0.113.99').length, 2, 'repeat lookups refresh, never duplicate');
    assert.ok(!(rows.find((x) => x.org_id === A)!.tags as string[]).some((t) => t === 'in-misp' || t === 'in-platform-ti'));
});

test('a token without an organisation is refused, never shown a default', async () => {
    const r = await realFetch(`${base}/api/cti/feed`, { headers: { Authorization: `Bearer ${jwt.sign({ sub: 'x', email: 'x@y.test', role: 'analyst' }, process.env.JWT_SECRET!)}` } });
    assert.equal(r.status, 403);
});
