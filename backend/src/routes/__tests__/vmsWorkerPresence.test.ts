// Phase P10 scanner worker presence: the worker heartbeat (token, validation, rate limit), presence
// recorded on every authenticated claim including an empty queue, nothing recorded for a rejected
// token, the status derivation (online / offline / never, and the fallback before the SQL), and what
// the VMS overview and Platform Health show. Fake PostgREST only; no worker or scanner runs.
process.env.JWT_SECRET = 'vms-presence-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'VMS_WORKER_TOKEN']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import vmsRouter from '../vms';
import vmsWorkerRouter from '../vmsWorker';
import { deriveScannerStatus, WORKER_ONLINE_SECONDS, type WorkerRow } from '../../services/vmsWorkers';
import { vmsChecks } from '../../services/pipelineHealth';

const WT = 'w'.repeat(40);
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = 'org-a') => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
async function http(method: string, path: string, bearer?: string, body?: unknown) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const r = await fetch(`${base}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const hb = (body: unknown, bearer = WT) => http('POST', '/api/vms/worker/heartbeat', bearer, body);
const claim = (body: unknown, bearer = WT) => http('POST', '/api/vms/worker/claim', bearer, body);
const GOOD = { worker_id: 'vps3-demo-worker', kinds: ['discovery', 'ports'], version: '1.1.0', tools: { subfinder: true, dnsx: true, httpx: true, nmap: true, nuclei: false, openvas: false } };
const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();

before(async () => {
    db = await startFakePostgrest(
        { vms_workers: [], vms_scopes: [], vms_scan_jobs: [], vms_assets: [], vms_services: [], vms_asset_events: [], vms_scan_schedules: [], cve_intel: [], vms_wazuh_sync: [] },
        {},
        { vms_workers: { kinds: [], tools: {}, first_seen_at: new Date().toISOString() } },
        {
            vms_claim_job: (args, tables) => {
                const j = tables.vms_scan_jobs.find((x) => x.status === 'queued' && (args.p_kinds as string[]).includes(String(x.kind)));
                if (!j) return [];
                Object.assign(j, { status: 'running', worker_id: args.p_worker, heartbeat_at: new Date().toISOString(), started_at: new Date().toISOString(), attempts: 1 });
                return [j];
            },
        },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use('/api/vms/worker', express.json(), vmsWorkerRouter);
    app.use(express.json());
    app.use('/api/vms', requireAuth, vmsRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => {
    db.tables.vms_workers = [];
    for (const t of ['vms_scopes', 'vms_scan_jobs']) db.tables[t].length = 0;
    process.env.VMS_WORKER_TOKEN = WT;
});

test('heartbeat: accepted with the worker token, recorded with kinds, version and tools', async () => {
    db.tables.vms_scan_jobs.push({ id: randomUUID(), kind: 'ports', status: 'queued' }, { id: randomUUID(), kind: 'vuln_nuclei', status: 'queued' });
    const r = await hb(GOOD);
    assert.equal(r.status, 200);
    assert.equal(r.data.ok, true);
    assert.equal(r.data.queued, 1, 'only jobs of the kinds this worker runs');
    assert.equal(r.data.online_window_seconds, WORKER_ONLINE_SECONDS);
    const w = db.tables.vms_workers[0];
    assert.equal(w.worker_id, 'vps3-demo-worker');
    assert.deepEqual(w.kinds, ['discovery', 'ports']);
    assert.equal((w.tools as Row).nmap, true);
    assert.ok(w.last_seen_at && w.last_heartbeat_at);
    const again = await hb(GOOD);
    assert.equal(again.status, 200);
    assert.equal(db.tables.vms_workers.length, 1, 'one row per worker');
});

test('heartbeat: a wrong or missing token is refused and records nothing; an unset backend token is 503', async () => {
    assert.equal((await hb(GOOD, 'x'.repeat(40))).status, 401);
    assert.equal((await hb(GOOD, '')).status, 401);
    assert.equal(db.tables.vms_workers.length, 0);
    delete process.env.VMS_WORKER_TOKEN;
    const r = await hb(GOOD);
    assert.equal(r.status, 503);
    assert.match(r.data.error, /not configured/);
    assert.equal(db.tables.vms_workers.length, 0);
});

test('heartbeat: invalid bodies are rejected', async () => {
    for (const bad of [
        { ...GOOD, worker_id: 'bad id!' },
        { ...GOOD, kinds: [] },
        { ...GOOD, kinds: ['passive_osint'] },
        { ...GOOD, tools: { metasploit: true } },
        { ...GOOD, version: 'x'.repeat(41) },
        { ...GOOD, extra: 1 },
    ]) assert.equal((await hb(bad)).status, 400, JSON.stringify(bad).slice(0, 60));
    assert.equal(db.tables.vms_workers.length, 0);
});

test('claim: an empty queue still records the worker; a claimed job is recorded too', async () => {
    const empty = await claim({ worker_id: 'vps3-demo-worker', kinds: ['discovery', 'ports'] });
    assert.equal(empty.status, 200);
    assert.equal(empty.data.job, null);
    const w = db.tables.vms_workers[0];
    assert.ok(w.last_claim_at && w.last_seen_at);
    assert.equal(w.last_job_id ?? null, null);
    const scope = { id: randomUUID(), org_id: 'org-a', kind: 'domain', value: 'a.test', status: 'active', allow_discovery: true, expires_at: new Date(Date.now() + 86_400_000).toISOString() };
    db.tables.vms_scopes.push(scope);
    const job = { id: randomUUID(), org_id: 'org-a', scope_id: scope.id, kind: 'discovery', status: 'queued', targets: ['a.test'], cancel_requested: false };
    db.tables.vms_scan_jobs.push(job);
    const got = await claim({ worker_id: 'vps3-demo-worker', kinds: ['discovery'] });
    assert.equal(got.data.job.id, job.id);
    assert.equal(db.tables.vms_workers[0].last_job_id, job.id);
    assert.equal((await claim({ worker_id: 'vps3-demo-worker', kinds: ['discovery'] }, 'x'.repeat(40))).status, 401);
});

test('before the presence SQL: heartbeat says what to run; claims keep working', async () => {
    (db.tables as Record<string, Row[] | null>).vms_workers = null;
    const r = await hb(GOOD);
    assert.equal(r.status, 503);
    assert.match(r.data.error, /2026-10-18_p10_vms_worker_presence\.sql/);
    const c = await claim({ worker_id: 'vps3-demo-worker', kinds: ['discovery'] });
    assert.equal(c.status, 200);
    assert.equal(c.data.job, null);
});

test('status derivation: online within the window, offline after it, never without any record', () => {
    const now = Date.now();
    const row = (seen: string): WorkerRow => ({ worker_id: 'w1', kinds: ['discovery'], version: '1.1.0', tools: {}, first_seen_at: seen, last_seen_at: seen, last_heartbeat_at: seen, last_claim_at: null, last_job_id: null, last_job_at: null });
    assert.deepEqual([deriveScannerStatus([], null, now).state, deriveScannerStatus([], null, now).source], ['never', 'none']);
    const on = deriveScannerStatus([row(ago(20))], null, now);
    assert.deepEqual([on.state, on.source, on.online_workers, on.workers[0].online], ['online', 'presence', 1, true]);
    const off = deriveScannerStatus([row(ago(WORKER_ONLINE_SECONDS + 5))], null, now);
    assert.deepEqual([off.state, off.online_workers], ['offline', 0]);
    // Before the SQL: only job heartbeats, with the old 15-minute window, and it says so.
    const fb = deriveScannerStatus(null, ago(300), now);
    assert.deepEqual([fb.state, fb.source], ['online', 'job_heartbeat']);
    assert.equal(deriveScannerStatus(null, null, now).state, 'never');
});

test('overview and Platform Health: an idle worker that heartbeats shows as connected; a silent one does not', async () => {
    const MGR = tok('soc_manager');
    let o = await http('GET', '/api/vms/overview', MGR);
    assert.deepEqual([o.data.worker.state, o.data.worker.seen_recently, o.data.worker.last_heartbeat_at], ['never', false, null]);
    assert.equal((await vmsChecks()).find((c) => c.name === 'VMS scanner')!.status, 'off');

    await hb(GOOD);   // empty queue: no job, no job heartbeat
    o = await http('GET', '/api/vms/overview', MGR);
    assert.deepEqual([o.data.worker.state, o.data.worker.seen_recently, o.data.worker.source], ['online', true, 'presence']);
    assert.equal(o.data.worker.workers[0].worker_id, 'vps3-demo-worker');
    const health = (await vmsChecks()).find((c) => c.name === 'VMS scanner')!;
    assert.equal(health.status, 'up');
    assert.match(health.detail, /1 worker\(s\) online: vps3-demo-worker/);

    // Client roles get the state, not the worker list.
    const ex = await http('GET', '/api/vms/overview', tok('executive'));
    assert.equal(ex.data.worker.state, 'online');
    assert.equal(ex.data.worker.workers, undefined);

    // Silent for longer than the window: offline, with when it was last seen.
    db.tables.vms_workers[0].last_seen_at = ago(WORKER_ONLINE_SECONDS + 60);
    o = await http('GET', '/api/vms/overview', MGR);
    assert.deepEqual([o.data.worker.state, o.data.worker.seen_recently], ['offline', false]);
    assert.ok(o.data.worker.last_heartbeat_at);
    assert.equal((await vmsChecks()).find((c) => c.name === 'VMS scanner')!.status, 'degraded');

    // The backend's passive runner heartbeating its own job never makes the scanner look online.
    db.tables.vms_scan_jobs.push({ id: randomUUID(), kind: 'passive_osint', status: 'running', worker_id: 'novrsoc-passive', heartbeat_at: new Date().toISOString() });
    o = await http('GET', '/api/vms/overview', MGR);
    assert.equal(o.data.worker.state, 'offline');
});

// Last: it uses up this minute's heartbeat allowance for the test process.
test('heartbeat: rate limited per minute', async () => {
    let limited = false;
    for (let i = 0; i < 31 && !limited; i++) limited = (await hb(GOOD)).status === 429;
    assert.ok(limited);
});
