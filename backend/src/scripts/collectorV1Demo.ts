// Collector V1 — local end-to-end demonstration.
//
// Runs the REAL Express routers (routes/collectors.ts, routes/collectorIngest.ts) and the REAL
// service layer (services/collectors.ts) against the same in-memory PostgREST stand-in the test
// suite uses (routes/__tests__/fakePostgrest.ts) — not a mock of the ingestion logic, a fake
// database underneath genuine code. This is NOT a live Docker/Vector/Supabase run: no Docker
// engine was available in the environment this was built in. It exercises the backend half of
// Collector V1 for real; it does not exercise Vector, syslog parsing, or disk buffering, which
// need the actual appliance (infra/novrsoc-collector/) against a real Vector instance.
//
// Scenario, two simulated client organisations, several synthetic log sources — all data below
// is explicitly synthetic/test data, not real, not scanned or collected from any real device:
//   1. Enroll a collector for each organisation.
//   2. Each collector's first heartbeat activates it (enrolling -> connected).
//   3. Each collector forwards a small batch of synthetic syslog-shaped events, in the three
//      wire shapes a real Vector http sink can produce: { events: [...] }, a bare array, and
//      newline-delimited JSON.
//   4. A malformed event and an oversized message are both sent, to show per-item handling.
//   5. The exact same batch is resent (simulating a network-outage retry) — duplicates, not
//      double-stored rows.
//   6. Tenant isolation is demonstrated: organisation A's staff token cannot see or read
//      organisation B's collector or its events.
//   7. The collector for organisation B is revoked; its next heartbeat is refused.
//
// Run with: npm run demo:collector-v1

import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import { startFakePostgrest } from '../routes/__tests__/fakePostgrest';
import { requireAuth } from '../middleware/auth';
import collectorsRouter from '../routes/collectors';
import collectorIngestRouter from '../routes/collectorIngest';

process.env.JWT_SECRET = process.env.JWT_SECRET ?? 'collector-v1-demo-secret';

const results: { step: string; ok: boolean; detail: string }[] = [];
const record = (step: string, ok: boolean, detail: string) => { results.push({ step, ok, detail }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${step} — ${detail}`); };

async function main() {
    const ORG_A = 'demo-org-a';
    const ORG_B = 'demo-org-b';
    const db = await startFakePostgrest(
        {
            organisations: [{ id: randomUUID(), slug: ORG_A, name: 'Demo Org A (synthetic)' }, { id: randomUUID(), slug: ORG_B, name: 'Demo Org B (synthetic)' }],
            collectors: [], collector_sources: [], collector_heartbeats: [], collector_log_events: [],
        },
        {},
        { collectors: { config_version: 1, status: 'enrolling', last_events_received: 0, last_events_forwarded: 0, last_delivery_failures: 0 } },
        {},
        { collectors: [['org_id', 'name']], collector_log_events: [['collector_id', 'dedup_key']] },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'demo-service-key';

    const app = express();
    app.use('/api/collectors/ingest', collectorIngestRouter);
    app.use(express.json());
    app.use('/api/collectors', requireAuth, collectorsRouter);
    const server = app.listen(0);
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const tok = (role: string, org: string) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.demo`, role, org_id: org }, process.env.JWT_SECRET!);
    const staffA = tok('soc_manager', ORG_A);
    const staffB = tok('soc_manager', ORG_B);
    const http = async (method: string, path: string, bearer?: string, body?: unknown) => {
        const headers: Record<string, string> = {};
        if (bearer) headers.Authorization = `Bearer ${bearer}`;
        if (body !== undefined) headers['Content-Type'] = 'application/json';
        const r = await fetch(`${base}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
        return { status: r.status, data: await r.json().catch(() => null) };
    };
    const ingest = async (path: string, token: string, body: string) => {
        const r = await fetch(`${base}/api/collectors/ingest${path}`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body });
        return { status: r.status, data: await r.json().catch(() => null) };
    };

    try {
        // 1. Enroll.
        const enrollA = await http('POST', '/api/collectors', staffA, { name: 'demo-site-a' });
        const enrollB = await http('POST', '/api/collectors', staffB, { name: 'demo-site-b' });
        record('Enroll collector A', enrollA.status === 201, `collector ${enrollA.data?.collector?.id}`);
        record('Enroll collector B', enrollB.status === 201, `collector ${enrollB.data?.collector?.id}`);
        const idA: string = enrollA.data.collector.id;
        const tokenA: string = enrollA.data.enrollment_token;
        const idB: string = enrollB.data.collector.id;
        const tokenB: string = enrollB.data.enrollment_token;

        // 2. First heartbeat activates.
        const hbA = await ingest('/heartbeat', tokenA, JSON.stringify({ vector_version: '0.60.0', events_received: 0, events_forwarded: 0, delivery_failures: 0, sources: [] }));
        const afterHbA = await http('GET', `/api/collectors/${idA}`, staffA);
        record('Heartbeat activates collector A', hbA.status === 200 && afterHbA.data.collector.status === 'connected', `status is now "${afterHbA.data.collector.status}"`);

        // 3. Three wire shapes, synthetic syslog-like content.
        const wrapped = await ingest('/events', tokenA, JSON.stringify({ events: [{ source_key: 'syslog_udp', host: 'demo-firewall-1', message: '<134>Oct 28 09:00:00 demo-firewall-1 kernel: [TEST] synthetic firewall block event #1' }] }));
        const bareArray = await ingest('/events', tokenA, JSON.stringify([{ source_key: 'syslog_tcp', host: 'demo-switch-1', message: '[TEST] synthetic switch port-flap event #2' }]));
        const ndjson = await ingest('/events', tokenA, [{ source_key: 'syslog_tcp', host: 'demo-switch-1', message: '[TEST] synthetic event #3' }, { source_key: 'syslog_tcp', host: 'demo-switch-1', message: '[TEST] synthetic event #4' }].map((e) => JSON.stringify(e)).join('\n'));
        record('Events: { events: [...] } shape', wrapped.data?.accepted === 1, JSON.stringify(wrapped.data));
        record('Events: bare JSON array shape', bareArray.data?.accepted === 1, JSON.stringify(bareArray.data));
        record('Events: newline-delimited JSON shape', ndjson.data?.accepted === 2, JSON.stringify(ndjson.data));

        // 4. Malformed + oversized, same batch.
        const huge = 'x'.repeat(40_000);
        const mixed = await ingest('/events', tokenA, JSON.stringify({ events: [
            { source_key: 'syslog_udp', message: 'a fine event' },
            { source_key: 'syslog_udp' }, // missing message
            { source_key: 'syslog_udp', message: huge },
        ] }));
        record('Malformed event rejected without failing the batch', mixed.data?.accepted === 2 && mixed.data?.invalid === 1, JSON.stringify(mixed.data));
        const stored = await http('GET', `/api/collectors/${idA}/events?limit=10`, staffA);
        const storedHuge = stored.data.events.find((e: { truncated: boolean }) => e.truncated);
        record('Oversized message truncated, not rejected', !!storedHuge && storedHuge.message.length < huge.length, storedHuge ? `stored at ${storedHuge.message.length} chars` : 'not found');

        // 5. Retry after a simulated outage: exact same batch resent.
        const retry = await ingest('/events', tokenA, JSON.stringify({ events: [{ source_key: 'syslog_udp', host: 'demo-firewall-1', message: '<134>Oct 28 09:00:00 demo-firewall-1 kernel: [TEST] synthetic firewall block event #1' }] }));
        record('Outage-retry resend is deduplicated', retry.data?.accepted === 0 && retry.data?.duplicates === 1, JSON.stringify(retry.data));

        // 6. Tenant isolation.
        const crossRead = await http('GET', `/api/collectors/${idA}`, staffB);
        const crossList = await http('GET', '/api/collectors', staffB);
        record('Org B cannot read org A\'s collector by id', crossRead.status === 404, `HTTP ${crossRead.status}`);
        record('Org B\'s own collector list never includes org A\'s collector', !crossList.data.collectors.some((c: { id: string }) => c.id === idA), `${crossList.data.collectors.length} collector(s) visible, all org B's own`);

        // 7. Revocation.
        const revoke = await http('POST', `/api/collectors/${idB}/revoke`, staffB);
        const hbAfterRevoke = await ingest('/heartbeat', tokenB, JSON.stringify({ events_received: 0, events_forwarded: 0, delivery_failures: 0, sources: [] }));
        record('Revoked collector B is refused on its next heartbeat', revoke.status === 200 && hbAfterRevoke.status === 401, `heartbeat after revoke: HTTP ${hbAfterRevoke.status}`);
    } finally {
        server.close();
        await db.close();
    }

    const failed = results.filter((r) => !r.ok);
    console.log(`\n${results.length - failed.length}/${results.length} checks passed.`);
    if (failed.length) { console.error(`FAILED: ${failed.map((f) => f.step).join(', ')}`); process.exitCode = 1; }
}

void main();
