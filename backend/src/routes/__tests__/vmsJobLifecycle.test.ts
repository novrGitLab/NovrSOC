// VMS job lifecycle repair: the exact completion bodies the Python worker sends (error/summary as
// null), invalid bodies, worker identity, idempotent completion retries, a completion racing queue
// upkeep, results persisted before completion, queue-unavailable errors that say why (and are
// logged), and a job lost by its worker being re-sent instead of lost or duplicated.
// Fake PostgREST only; no worker or scanner runs; targets are reserved test names/ranges.
process.env.JWT_SECRET = 'vms-lifecycle-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'VMS_WORKER_TOKEN']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import vmsWorkerRouter, { queueFailure } from '../vmsWorker';

const WT = 'w'.repeat(40);
const W = 'vps3-demo-worker';
const ORG = 'org-a';
let db: FakePostgrest;
let server: Server;
let base = '';
let rpcFailure: { __status: number; __error: Row } | null = null;
const errors: string[] = [];
const realLog = { log: console.log, warn: console.warn, error: console.error };
const post = async (path: string, body: unknown, bearer = WT) => {
    const r = await fetch(`${base}/api/vms/worker${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` }, body: JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
};
const future = new Date(Date.now() + 30 * 86_400_000).toISOString();
let seq = 0;
const queue = (b: Row = {}): Row => {
    const j = { id: randomUUID(), org_id: ORG, scope_id: 'scope-1', kind: 'discovery', targets: ['192.0.2.10'], options: {}, status: 'queued', attempts: 0, cancel_requested: false, purpose: 'assessment', requested_at: new Date(Date.now() + ++seq).toISOString(), ...b };
    db.tables.vms_scan_jobs.push(j);
    return j;
};
const claim = () => post('/claim', { worker_id: W, kinds: ['discovery', 'ports'] });

before(async () => {
    db = await startFakePostgrest(
        { vms_workers: [], vms_scopes: [], vms_scan_jobs: [], vms_assets: [], vms_services: [], vms_technologies: [], vms_asset_events: [] },
        {},
        { vms_assets: { status: 'active', exposure: 'unknown', criticality: 'medium', confidence: 'confirmed', hostnames: [], ips: [], dns: {}, discovery_sources: [] }, vms_workers: { kinds: [], tools: {} } },
        {
            vms_claim_job: (args, tables) => {
                if (rpcFailure) return rpcFailure;
                const j = tables.vms_scan_jobs.filter((x) => x.status === 'queued' && (args.p_kinds as string[]).includes(String(x.kind)) && !x.cancel_requested)
                    .sort((a, b) => String(a.requested_at).localeCompare(String(b.requested_at)))[0];
                if (!j) return [];
                const now = new Date().toISOString();
                Object.assign(j, { status: 'running', worker_id: args.p_worker, claimed_at: now, heartbeat_at: now, started_at: now, attempts: Number(j.attempts ?? 0) + 1 });
                return [j];
            },
        },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    process.env.VMS_WORKER_TOKEN = WT;
    const app = express();
    app.use('/api/vms/worker', express.json(), vmsWorkerRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    console.log = () => undefined;
    console.warn = () => undefined;
    console.error = (...a: unknown[]) => { errors.push(a.map(String).join(' ')); };
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => {
    rpcFailure = null;
    errors.length = 0;
    for (const t of ['vms_workers', 'vms_scan_jobs', 'vms_assets', 'vms_asset_events', 'vms_technologies']) db.tables[t].length = 0;
    db.tables.vms_scopes.length = 0;
    db.tables.vms_scopes.push({ id: 'scope-1', org_id: ORG, kind: 'cidr', value: '192.0.2.0/28', include_subdomains: false, allow_discovery: true, allow_port_scan: false, allow_vuln_scan: false, status: 'active', expires_at: future });
});

test('the worker\'s own completion bodies are accepted: error and summary as null', async () => {
    const j = queue();
    assert.equal((await claim()).data.job.id, j.id);
    // Exactly what worker.py up to 1.1.0 sends for a successful job (json.dumps of None -> null).
    const r = await post(`/jobs/${j.id}/complete`, { worker_id: W, status: 'succeeded', error: null, summary: { observations: 0, accepted: 0, rejected_out_of_scope: 0, rejected_invalid: 0 } });
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.deepEqual([j.status, j.error], ['succeeded', null]);
    assert.ok(j.finished_at);
    const k = queue();
    await claim();
    assert.equal((await post(`/jobs/${k.id}/complete`, { worker_id: W, status: 'failed', error: null, summary: null })).status, 200);
    assert.equal(k.status, 'failed');
    assert.equal(k.error, 'No reason given by the worker', 'a failure never looks like a success');
});

test('invalid completions are refused with the field that is wrong', async () => {
    const j = queue();
    await claim();
    for (const [body, field] of [
        [{ worker_id: W, status: 'done' }, 'status'],
        [{ status: 'succeeded' }, 'worker_id'],
        [{ worker_id: W, status: 'succeeded', error: 42 }, 'error'],
        [{ worker_id: W, status: 'succeeded', summary: 'ok' }, 'summary'],
        [{ worker_id: W, status: 'succeeded', extra: true }, 'body'],
    ] as [Row, string][]) {
        const r = await post(`/jobs/${j.id}/complete`, body);
        assert.equal(r.status, 400, JSON.stringify(body));
        assert.match(r.data.error, new RegExp(`Invalid completion: ${field === 'body' ? '' : field}`));
    }
    assert.equal(j.status, 'running', 'nothing moved');
});

test('worker identity: another worker cannot report, send results for or complete a job', async () => {
    const j = queue();
    await claim();
    assert.equal((await post(`/jobs/${j.id}/complete`, { worker_id: 'other-worker', status: 'succeeded' })).status, 409);
    assert.equal((await post(`/jobs/${j.id}/results`, { worker_id: 'other-worker', observations: [] })).status, 409);
    assert.equal((await post(`/jobs/${j.id}/complete`, { worker_id: W, status: 'succeeded' }, 'x'.repeat(40))).status, 401);
    assert.equal(j.status, 'running');
});

test('completion retries are safe; a completion racing queue upkeep is refused, not applied', async () => {
    const j = queue();
    await claim();
    const body = { worker_id: W, status: 'succeeded', summary: { accepted: 1 } };
    assert.equal((await post(`/jobs/${j.id}/complete`, body)).status, 200);
    const finished = j.finished_at;
    const again = await post(`/jobs/${j.id}/complete`, { ...body, status: 'failed', error: 'late retry' });
    assert.deepEqual([again.status, again.data.already_completed, again.data.status], [200, true, 'succeeded']);
    assert.deepEqual([j.status, j.finished_at, j.error], ['succeeded', finished, null], 'the first outcome stands');

    const k = queue();
    await claim();
    Object.assign(k, { status: 'queued' });   // queue upkeep requeued it meanwhile
    assert.equal((await post(`/jobs/${k.id}/complete`, body)).status, 409);
    assert.equal(k.status, 'queued');
});

test('results are stored before completion and stay with the job', async () => {
    const j = queue();
    await claim();
    const r = await post(`/jobs/${j.id}/results`, { worker_id: W, observations: [{ type: 'host', host: '192.0.2.10', ips: ['192.0.2.10'], source: 'httpx' }, { type: 'host', host: '198.51.100.1', ips: [], source: 'httpx' }] });
    assert.deepEqual([r.data.accepted, r.data.rejected_out_of_scope], [1, 1]);
    assert.equal(db.tables.vms_assets.length, 1);
    assert.equal(db.tables.vms_asset_events[0].job_id, j.id);
    assert.equal((await post(`/jobs/${j.id}/complete`, { worker_id: W, status: 'succeeded', error: null, summary: { accepted: 1 } })).status, 200);
    assert.equal((await post(`/jobs/${j.id}/results`, { worker_id: W, observations: [] })).status, 409, 'no results after completion');
});

test('queue unavailable: the reply says why, the log has the database error, nothing is claimed', async () => {
    queue();
    for (const [err, reason] of [
        [{ code: 'PGRST202', message: 'Could not find the function public.vms_claim_job(p_kinds, p_worker) in the schema cache' }, 'claim_function_missing'],
        [{ code: '42501', message: 'permission denied for function vms_claim_job' }, 'permission_denied'],
        [{ code: '57014', message: 'canceling statement due to statement timeout' }, 'database_timeout'],
        [{ code: 'XX000', message: 'something else' }, 'database_error'],
    ] as [Row, string][]) {
        rpcFailure = { __status: 400, __error: err };
        const r = await claim();
        assert.equal(r.status, 503);
        assert.deepEqual([r.data.error, r.data.reason], ['Queue unavailable', reason]);
        assert.ok(!JSON.stringify(r.data).includes(WT));
    }
    assert.ok(errors.some((e) => e.includes('PGRST202') && e.includes(W)), 'the underlying error is logged');
    assert.equal(db.tables.vms_scan_jobs[0].status, 'queued');
    assert.equal(queueFailure({ message: 'TypeError: fetch failed' }).reason, 'database_unreachable');
});

test('a job the worker lost (restart, lost reply) is re-sent to it — not lost, not doubled', async () => {
    const a = queue();
    const b = queue();
    assert.equal((await claim()).data.job.id, a.id);
    // The worker never saw that reply and asks again.
    const again = await claim();
    assert.deepEqual([again.data.job.id, again.data.redelivered], [a.id, true]);
    assert.equal(b.status, 'queued', 'no second job taken while the first is still assigned');
    assert.equal(a.attempts, 1);
    assert.ok(again.data.scopes.length, 'scopes come with it, so the worker can re-check targets');
    // Cancelled while the worker was away: closed as cancelled, and the next job is claimed.
    a.cancel_requested = true;
    const next = await claim();
    assert.equal(a.status, 'cancelled');
    assert.equal(next.data.job.id, b.id);
});
