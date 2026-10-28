// Collector V1 (phase P31): the staff management API (routes/collectors.ts) and the collector
// ingestion gateway (routes/collectorIngest.ts) together — enrollment, per-collector auth, tenant
// isolation, revocation, heartbeat activation, malformed/oversized/duplicate event handling, and
// the "secret is shown exactly once" rule. Fake PostgREST only; no real network, no Vector, no
// Docker involved — see the task's final report for why that's an honest limitation here.
process.env.JWT_SECRET = 'collector-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest } from './fakePostgrest';
import collectorsRouter from '../collectors';
import collectorIngestRouter from '../collectorIngest';
import { effectiveStatus } from '../../services/collectors';

const A = 'org-a';
const B = 'org-b';
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org: string) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const SUPER = tok('super_admin', A);
const MGR = tok('soc_manager', A);
const AN = tok('analyst', A);

async function http(method: string, path: string, bearer?: string, body?: unknown) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const r = await fetch(`${base}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}

before(async () => {
    db = await startFakePostgrest(
        { organisations: [{ id: randomUUID(), slug: A, name: 'Org A' }, { id: randomUUID(), slug: B, name: 'Org B' }], collectors: [], collector_sources: [], collector_heartbeats: [], collector_log_events: [] },
        {},
        { collectors: { config_version: 1, status: 'enrolling', last_events_received: 0, last_events_forwarded: 0, last_delivery_failures: 0 } },
        {},
        { collectors: [['org_id', 'name']], collector_log_events: [['collector_id', 'dedup_key']] },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use('/api/collectors/ingest', collectorIngestRouter);
    app.use(express.json());
    app.use('/api/collectors', requireAuth, collectorsRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => { for (const t of Object.keys(db.tables)) if (t !== 'organisations') db.tables[t].length = 0; });

async function enroll(bearer: string, name = 'site-a-collector'): Promise<{ id: string; token: string }> {
    const r = await http('POST', '/api/collectors', bearer, { name });
    assert.equal(r.status, 201, JSON.stringify(r.data));
    return { id: r.data.collector.id, token: r.data.enrollment_token };
}

test('enrollment: the secret is returned once and never again — not even to the owner', async () => {
    const { id } = await enroll(MGR);
    const got = await http('GET', `/api/collectors/${id}`, MGR);
    assert.equal(got.status, 200);
    assert.equal(JSON.stringify(got.data).includes('enrollment_token'), false);
    assert.equal(got.data.collector.status, 'enrolling');
    assert.equal(got.data.collector.effective_status, 'enrolling');
    // analyst holds neither collectors:read nor collectors:manage (manager-tier infrastructure access)
    assert.equal((await http('GET', '/api/collectors', AN)).status, 403);
    assert.equal((await http('POST', '/api/collectors', AN, { name: 'x' })).status, 403);
});

test('enrollment: duplicate name for the same org is refused; names can repeat across organisations', async () => {
    await enroll(MGR, 'dup');
    const again = await http('POST', '/api/collectors', MGR, { name: 'dup' });
    assert.equal(again.status, 400);
    const otherOrg = await http('POST', '/api/collectors', tok('soc_manager', B), { name: 'dup' });
    assert.equal(otherOrg.status, 201);
});

test('tenant isolation: another organisation cannot see, inspect, revoke or rotate this collector', async () => {
    const { id } = await enroll(MGR);
    const other = tok('soc_manager', B);
    assert.equal((await http('GET', `/api/collectors/${id}`, other)).status, 404);
    assert.equal((await http('GET', '/api/collectors', other)).data.collectors.length, 0);
    assert.equal((await http('POST', `/api/collectors/${id}/revoke`, other)).status, 400);
    assert.equal((await http('POST', `/api/collectors/${id}/rotate`, other)).status, 400);
    assert.equal((await http('POST', `/api/collectors/${id}/revoke`, MGR)).status, 200, 'the owning org can still act on it');
});

test('gateway auth: unknown collector, wrong secret, malformed header and a revoked collector all authenticate to nothing', async () => {
    const { id, token } = await enroll(MGR);
    assert.equal((await fetch(`${base}/api/collectors/ingest/heartbeat`, { method: 'POST', headers: { Authorization: 'Bearer not-a-real-token', 'Content-Type': 'application/json' }, body: '{}' })).status, 401);
    assert.equal((await fetch(`${base}/api/collectors/ingest/heartbeat`, { method: 'POST', headers: { Authorization: `Bearer ${id}.${'0'.repeat(64)}`, 'Content-Type': 'application/json' }, body: '{}' })).status, 401, 'right id, wrong secret');
    const good = await fetch(`${base}/api/collectors/ingest/heartbeat`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ events_received: 0, events_forwarded: 0, delivery_failures: 0, sources: [] }) });
    assert.equal(good.status, 200, await good.text());
    await http('POST', `/api/collectors/${id}/revoke`, MGR);
    const afterRevoke = await fetch(`${base}/api/collectors/ingest/heartbeat`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ events_received: 0, events_forwarded: 0, delivery_failures: 0, sources: [] }) });
    assert.equal(afterRevoke.status, 401);
    assert.match((await afterRevoke.json()).error, /revoked/i);
});

test('heartbeat activates an enrolling collector and records a throughput sample; its own org_id is never trusted from the payload', async () => {
    const { id, token } = await enroll(MGR);
    const r = await fetch(`${base}/api/collectors/ingest/heartbeat`, {
        method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ vector_version: '0.40.0', events_received: 120, events_forwarded: 118, delivery_failures: 2, buffer_pct: 4.5, sources: [{ source_key: 'syslog_514', kind: 'syslog_udp', label: 'OPNsense' }] }),
    });
    assert.equal(r.status, 200);
    const got = await http('GET', `/api/collectors/${id}`, MGR);
    assert.equal(got.data.collector.status, 'connected');
    assert.ok(got.data.collector.activated_at);
    assert.equal(got.data.sources.length, 1);
    assert.equal(got.data.sources[0].kind, 'syslog_udp');
    assert.equal(got.data.heartbeats.length, 1);
    assert.equal(got.data.heartbeats[0].events_received, 120);
});

test('events: malformed events are rejected individually without failing the batch; oversized batches are refused outright', async () => {
    const { token } = await enroll(MGR);
    const send = (events: unknown[]) => fetch(`${base}/api/collectors/ingest/events`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ events }) });
    const mixed = await send([
        { source_key: 'syslog_514', message: 'a real log line' },
        { source_key: 'syslog_514' }, // missing message: invalid
        { message: 'no source key' }, // missing source_key: invalid
    ]);
    assert.equal(mixed.status, 200);
    const body = await mixed.json();
    assert.equal(body.accepted, 1);
    assert.equal(body.invalid, 2);
    const tooMany = await send(Array.from({ length: 501 }, (_, i) => ({ source_key: 's', message: `line ${i}` })));
    assert.equal(tooMany.status, 400);
});

test('events: an oversized message is truncated and stored, never rejected outright; duplicates are counted, not stored twice', async () => {
    const { id, token } = await enroll(MGR);
    const huge = 'x'.repeat(40_000); // over the 32KB storage cap
    const send = (events: unknown[]) => fetch(`${base}/api/collectors/ingest/events`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ events }) });
    const first = await send([{ source_key: 's', message: huge }]);
    assert.equal((await first.json()).accepted, 1);
    const stored = await http('GET', `/api/collectors/${id}/events`, MGR);
    assert.equal(stored.data.events.length, 1);
    assert.equal(stored.data.events[0].truncated, true);
    assert.ok(stored.data.events[0].message.length < huge.length);
    const replay = await send([{ source_key: 's', message: huge }]); // same collector + source + message after a simulated outage
    const r2 = await replay.json();
    assert.equal(r2.accepted, 0);
    assert.equal(r2.duplicates, 1);
    assert.equal((await http('GET', `/api/collectors/${id}/events`, MGR)).data.events.length, 1, 'no duplicate row was written');
});

test('events: two different organisations\' collectors never mix log events, even if both exist', async () => {
    const a = await enroll(MGR, 'collector-a');
    const b = await enroll(tok('soc_manager', B), 'collector-b');
    const send = (token: string, msg: string) => fetch(`${base}/api/collectors/ingest/events`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ events: [{ source_key: 's', message: msg }] }) });
    await send(a.token, 'from org a');
    await send(b.token, 'from org b');
    const aEvents = await http('GET', `/api/collectors/${a.id}/events`, MGR);
    assert.equal(aEvents.data.events.length, 1);
    assert.equal(aEvents.data.events[0].message, 'from org a');
    // org A staff cannot even address org B's collector id to read its events.
    assert.equal((await http('GET', `/api/collectors/${b.id}/events`, MGR)).status, 404);
});

test('events: a bare array and newline-delimited JSON are both accepted — the shapes Vector\'s own http sink can produce, not just { events: [...] }', async () => {
    const { id, token } = await enroll(MGR);
    const post = (body: string) => fetch(`${base}/api/collectors/ingest/events`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body });
    const bareArray = await post(JSON.stringify([{ source_key: 's', message: 'from a bare array' }]));
    assert.equal((await bareArray.json()).accepted, 1);
    const ndjson = await post([{ source_key: 's', message: 'ndjson line 1' }, { source_key: 's', message: 'ndjson line 2' }].map((e) => JSON.stringify(e)).join('\n'));
    assert.equal((await ndjson.json()).accepted, 2);
    const malformedLine = await post('not json\n{"source_key":"s","message":"a real one"}');
    const r = await malformedLine.json();
    assert.equal(r.accepted, 1);
    assert.equal(r.invalid, 1);
    assert.equal((await http('GET', `/api/collectors/${id}/events`, MGR)).data.events.length, 4);
});

// Sprint 3 (Workstream B2): the secret must never appear anywhere other than the one-time
// issuance response — not in server logs (console output), and not in any other route's
// response body, even ones that identify the same collector by id.
test('security: the plaintext secret never appears in logs or in any response other than its one-time issuance', async () => {
    const { id, token } = await enroll(MGR);
    const secret = token.split('.')[1];
    const captured: string[] = [];
    console.log = (...a: unknown[]) => { captured.push(a.map(String).join(' ')); };
    console.warn = (...a: unknown[]) => { captured.push(a.map(String).join(' ')); };
    console.error = (...a: unknown[]) => { captured.push(a.map(String).join(' ')); };
    try {
        await fetch(`${base}/api/collectors/ingest/heartbeat`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ events_received: 1, events_forwarded: 1, delivery_failures: 0, sources: [] }) });
        await fetch(`${base}/api/collectors/ingest/events`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ events: [{ source_key: 's', message: 'm' }] }) });
        const list = await http('GET', '/api/collectors', MGR);
        const detail = await http('GET', `/api/collectors/${id}`, MGR);
        const rotated = await http('POST', `/api/collectors/${id}/rotate`, MGR);
        await http('POST', `/api/collectors/${id}/revoke`, MGR);
        assert.equal(captured.some((line) => line.includes(secret)), false, 'the secret must never be logged, under any outcome');
        assert.equal(JSON.stringify(list.data).includes(secret), false);
        assert.equal(JSON.stringify(detail.data).includes(secret), false);
        // The rotate response legitimately carries the NEW secret (one-time issuance) — only the
        // OLD one, already shown once by enroll(), must never reappear anywhere.
        assert.ok(rotated.data.enrollment_token, 'rotate does issue a new one-time secret, by design');
    } finally {
        for (const k of ['log', 'warn', 'error'] as const) console[k] = realLog[k];
    }
});

// Sprint 3 (Workstream B2): "connected" is read from the one real observed signal (heartbeat
// recency), not held at whatever status was last written — a collector that goes quiet reads as
// disconnected on its own, with no sweep job required to notice.
test('effectiveStatus: derived only from observed heartbeat recency, never frozen at a stale "connected"', () => {
    const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();
    assert.equal(effectiveStatus({ status: 'connected', last_heartbeat_at: minutesAgo(1) }), 'connected');
    assert.equal(effectiveStatus({ status: 'connected', last_heartbeat_at: minutesAgo(30) }), 'disconnected', 'quiet past the staleness window reads as disconnected, even though the stored status column still says connected');
    assert.equal(effectiveStatus({ status: 'connected', last_heartbeat_at: null }), 'disconnected', 'connected with no heartbeat ever recorded is not trusted at face value');
    assert.equal(effectiveStatus({ status: 'enrolling', last_heartbeat_at: null }), 'enrolling');
    assert.equal(effectiveStatus({ status: 'revoked', last_heartbeat_at: minutesAgo(1) }), 'revoked', 'revocation is authoritative regardless of how recent the last heartbeat was');
});

test('rotate: issues a new secret that works and invalidates the old one', async () => {
    const { id, token } = await enroll(MGR);
    const rotated = await http('POST', `/api/collectors/${id}/rotate`, MGR);
    assert.equal(rotated.status, 200);
    const newToken = rotated.data.enrollment_token;
    assert.notEqual(newToken, token);
    const oldStillWorks = await fetch(`${base}/api/collectors/ingest/heartbeat`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ events_received: 0, events_forwarded: 0, delivery_failures: 0, sources: [] }) });
    assert.equal(oldStillWorks.status, 401, 'the old secret must stop working immediately');
    const newWorks = await fetch(`${base}/api/collectors/ingest/heartbeat`, { method: 'POST', headers: { Authorization: `Bearer ${newToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ events_received: 0, events_forwarded: 0, delivery_failures: 0, sources: [] }) });
    assert.equal(newWorks.status, 200);
});
