// P12 trustworthy outcomes and evidence: host-level assessments stored on IP assets (unreachable
// never marks a host offline or moves last_seen), the pre-migration fallback, raw evidence
// (redacted, capped, org-scoped, expired after 30 days without touching structured records),
// release on worker shutdown, queue capability warnings (kind or private-network route), worker
// networks in presence, sanitised result errors and Platform Health. Fake PostgREST; no network.
process.env.JWT_SECRET = 'vms-outcomes-test-secret';
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
import vmsWorkerRouter, { EVIDENCE_PER_JOB, MAX_RELEASES } from '../vmsWorker';
import { purgeExpiredEvidence } from '../../jobs/vmsMaintenance';
import { jobAttention, deriveScannerStatus, type WorkerRow } from '../../services/vmsWorkers';
import { isNonPublicIp, workerCanReach } from '../../lib/netClass';
import { vmsChecks } from '../../services/pipelineHealth';

const WT = 'w'.repeat(40);
const W = 'vps3-demo-worker';
const ORG = 'org-a';
const SCOPE = '5c0e5c0e-0000-4000-8000-000000000001';
let db: FakePostgrest;
let server: Server;
let base = '';
const logs: string[] = [];
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = ORG) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
async function http(method: string, path: string, bearer: string, body?: unknown) {
    const r = await fetch(`${base}${path}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const wpost = (path: string, body: unknown) => http('POST', `/api/vms/worker${path}`, WT, body);
const future = new Date(Date.now() + 30 * 86_400_000).toISOString();
const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();

function runningJob(b: Row = {}): Row {
    const j = { id: randomUUID(), org_id: ORG, scope_id: SCOPE, kind: 'ports', targets: ['10.88.1.139'], options: { ports: 'top-1000' }, status: 'running', worker_id: W, attempts: 1, cancel_requested: false, purpose: 'assessment', requested_at: ago(300), claimed_at: ago(200), heartbeat_at: ago(10), started_at: ago(200), ...b };
    db.tables.vms_scan_jobs.push(j);
    return j;
}
const assessment = (outcome: string, extra: Row = {}) => ({ outcome, reason: `test ${outcome}`, method: 'nmap', host_status: 'up', host_status_reason: 'user-set', port_states: { filtered: 1000 }, ports_scanned: 1000, ...extra });
const hostObs = (a: Row, extra: Row = {}) => ({ type: 'host', host: '10.88.1.139', ips: ['10.88.1.139'], source: 'nmap', assessment: a, ...extra });

before(async () => {
    db = await startFakePostgrest(
        { vms_workers: [], vms_scopes: [], vms_scan_jobs: [], vms_assets: [], vms_services: [], vms_technologies: [], vms_asset_events: [], vms_job_evidence: [], vms_findings: [], vms_scan_schedules: [], cve_intel: [], vms_wazuh_sync: [] },
        {},
        {
            vms_assets: { status: 'active', exposure: 'unknown', criticality: 'medium', confidence: 'confirmed', hostnames: [], ips: [], dns: {}, discovery_sources: [] },
            vms_workers: { kinds: [], tools: {}, networks: [] },
            vms_job_evidence: { truncated: false, get created_at() { return new Date().toISOString(); }, get expires_at() { return new Date(Date.now() + 30 * 86_400_000).toISOString(); } } as Row,
            vms_scan_jobs: { status: 'queued', attempts: 0, cancel_requested: false, progress: {}, purpose: 'assessment', get requested_at() { return new Date().toISOString(); } } as Row,
        },
        { vms_claim_job: () => [] },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    process.env.VMS_WORKER_TOKEN = WT;
    const app = express();
    app.use('/api/vms/worker', express.json({ limit: '2mb' }), vmsWorkerRouter);
    app.use(express.json());
    app.use('/api/vms', requireAuth, vmsRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    console.log = () => undefined;
    console.warn = (...a: unknown[]) => { logs.push(a.map(String).join(' ')); };
    console.error = (...a: unknown[]) => { logs.push(a.map(String).join(' ')); };
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => {
    logs.length = 0;
    for (const t of Object.keys(db.tables)) db.tables[t] = [];
    for (const k of Object.keys(db.missingColumns)) delete db.missingColumns[k];
    db.tables.vms_scopes.push({ id: SCOPE, org_id: ORG, kind: 'ip', value: '10.88.1.139', include_subdomains: false, allow_discovery: true, allow_port_scan: true, allow_vuln_scan: false, status: 'active', expires_at: future, approved_at: ago(1000) });
});

test('an unreachable target becomes an IP asset with its assessment — not offline, no services, no findings', async () => {
    const j = runningJob();
    const r = await wpost(`/jobs/${j.id}/results`, { worker_id: W, observations: [hostObs(assessment('unreachable'))] });
    assert.deepEqual([r.status, r.data.accepted], [200, 1]);
    const a = db.tables.vms_assets[0];
    assert.deepEqual([a.asset_type, a.value, a.exposure], ['ip', '10.88.1.139', 'internal']);
    assert.equal((a.last_assessment as Row).outcome, 'unreachable');
    assert.equal((a.last_assessment as Row).job_id, j.id);
    assert.deepEqual((a.last_assessment as Row).port_states, { filtered: 1000 });
    assert.ok(a.last_assessed_at);
    assert.notEqual(a.alive, false, 'no answer never marks a host offline');
    assert.equal(db.tables.vms_services.length, 0);
    assert.equal(db.tables.vms_findings.length, 0);
    assert.equal((db.tables.vms_asset_events[0].details as Row).assessment, 'unreachable');
});

test('only an answer moves last_seen or revives a gone asset; outcome changes are events', async () => {
    const old = ago(86_400);
    db.tables.vms_assets.push({ id: randomUUID(), org_id: ORG, asset_type: 'ip', value: '10.88.1.139', ips: ['10.88.1.139'], status: 'gone', last_seen: old, discovery_sources: ['nmap'], last_assessment: { outcome: 'reachable_open' } });
    const a = db.tables.vms_assets[0];
    const j = runningJob();
    await wpost(`/jobs/${j.id}/results`, { worker_id: W, observations: [hostObs(assessment('unreachable'))] });
    assert.deepEqual([a.last_seen, a.status], [old, 'gone'], 'no answer: neither seen nor revived');
    assert.deepEqual((db.tables.vms_asset_events.at(-1)!.details as Row).reachability, { from: 'reachable_open', to: 'unreachable' });
    await wpost(`/jobs/${j.id}/results`, { worker_id: W, observations: [hostObs(assessment('reachable_no_open', { port_states: { closed: 1000 } }), { alive: true })] });
    assert.notEqual(a.last_seen, old);
    assert.deepEqual([a.status, a.alive, (a.last_assessment as Row).outcome], ['active', true, 'reachable_no_open']);
    assert.equal(db.tables.vms_asset_events.length, 2, 'one event per change of reachability');
});

test('assessments are validated; before the P12 SQL the asset is still written and the gap is said once', async () => {
    const j = runningJob();
    const bad = await wpost(`/jobs/${j.id}/results`, { worker_id: W, observations: [hostObs({ outcome: 'offline', reason: 'x', method: 'nmap' })] });
    assert.deepEqual([bad.data.accepted, bad.data.rejected_invalid], [0, 1]);
    db.missingColumns.vms_assets = ['last_assessment'];
    const r = await wpost(`/jobs/${j.id}/results`, { worker_id: W, observations: [hostObs(assessment('unreachable'))] });
    assert.deepEqual([r.status, r.data.accepted, r.data.assessments_not_stored], [200, 1, 1]);
    assert.equal(db.tables.vms_assets.length, 1);
    assert.ok(logs.some((l) => /2026-10-19_p12_vms_outcomes_evidence\.sql/.test(l)));
});

test('result storage errors reach the worker as a category, not the database text', async () => {
    const j = runningJob();
    db.missingColumns.vms_assets = ['scope_id'];   // any insert fails, with a database message
    const r = await wpost(`/jobs/${j.id}/results`, { worker_id: W, observations: [hostObs(assessment('unreachable'))] });
    assert.equal(r.status, 502);
    assert.equal(r.data.error, 'Could not store results; retry or check the backend log');
    assert.ok(!JSON.stringify(r.data).includes('schema cache'), 'no database text in the reply');
    assert.ok(logs.some((l) => l.includes('schema cache') && l.includes(String(j.id))), 'the log keeps it');
});

test('raw evidence: redacted, hashed, capped per job, org-scoped on read', async () => {
    const j = runningJob();
    const content = '<nmaprun args="nmap -Pn 10.88.1.139"><host><status state="up"/></host></nmaprun>\npassword=hunter2 Authorization: Bearer abc.def';
    const r = await wpost(`/jobs/${j.id}/evidence`, { worker_id: W, target: '10.88.1.139', tool: 'nmap', content, truncated: false });
    assert.equal(r.status, 201);
    const e = db.tables.vms_job_evidence[0];
    assert.ok(!String(e.content).includes('hunter2') && !String(e.content).includes('abc.def'));
    assert.ok(String(e.content).includes('<nmaprun'), 'tool output itself is kept');
    assert.match(String(e.sha256), /^[0-9a-f]{64}$/);
    assert.equal(e.org_id, ORG);
    assert.equal((await wpost(`/jobs/${j.id}/evidence`, { worker_id: W, target: 'not a target!', tool: 'nmap', content: 'x' })).status, 400);
    assert.equal((await wpost(`/jobs/${j.id}/evidence`, { worker_id: W, target: '10.88.1.139', tool: 'bash', content: 'x' })).status, 400);
    assert.equal((await wpost(`/jobs/${j.id}/evidence`, { worker_id: 'other', target: '10.88.1.139', tool: 'nmap', content: 'x' })).status, 409);
    for (let i = 1; i < EVIDENCE_PER_JOB; i++) db.tables.vms_job_evidence.push({ id: randomUUID(), job_id: j.id, org_id: ORG });
    assert.equal((await wpost(`/jobs/${j.id}/evidence`, { worker_id: W, target: '10.88.1.139', tool: 'nmap', content: 'x' })).status, 409);

    db.tables.vms_job_evidence.splice(1);
    const read = await http('GET', `/api/vms/scans/${j.id}/evidence`, tok('analyst'));
    assert.deepEqual([read.data.available, read.data.evidence.length, read.data.retention_days], [true, 1, 30]);
    assert.equal((await http('GET', `/api/vms/scans/${j.id}/evidence`, tok('analyst', 'org-b'))).status, 404);
    e.expires_at = ago(1);
    assert.equal((await http('GET', `/api/vms/scans/${j.id}/evidence`, tok('analyst'))).data.evidence.length, 0, 'expired evidence is never served');
});

test('evidence before the P12 SQL: 503 naming the file; the job is unaffected', async () => {
    const j = runningJob();
    (db.tables as Record<string, Row[] | null>).vms_job_evidence = null;
    const r = await wpost(`/jobs/${j.id}/evidence`, { worker_id: W, target: '10.88.1.139', tool: 'nmap', content: 'x' });
    assert.equal(r.status, 503);
    assert.match(r.data.error, /2026-10-19_p12/);
    assert.equal(j.status, 'running');
    db.tables.vms_job_evidence = [];
});

test('expiry after 30 days removes only raw evidence — never assets, services, findings or jobs', async () => {
    const j = runningJob({ status: 'succeeded' });
    db.tables.vms_assets.push({ id: 'a1', org_id: ORG, asset_type: 'ip', value: '10.88.1.139' });
    db.tables.vms_services.push({ id: 's1', asset_id: 'a1', port: 22 });
    db.tables.vms_findings.push({ id: 'f1', org_id: ORG });
    db.tables.vms_job_evidence.push(
        { id: 'old', job_id: j.id, org_id: ORG, created_at: ago(31 * 86_400), expires_at: ago(86_400) },
        { id: 'new', job_id: j.id, org_id: ORG, created_at: ago(29 * 86_400), expires_at: ago(-86_400) },
    );
    assert.equal(await purgeExpiredEvidence(), 1);
    assert.deepEqual(db.tables.vms_job_evidence.map((e) => e.id), ['new']);
    assert.deepEqual([db.tables.vms_assets.length, db.tables.vms_services.length, db.tables.vms_findings.length, db.tables.vms_scan_jobs.length], [1, 1, 1, 1]);
    (db.tables as Record<string, Row[] | null>).vms_job_evidence = null;
    assert.equal(await purgeExpiredEvidence(), 0, 'before the SQL: nothing to purge, no error');
    db.tables.vms_job_evidence = [];
});

test('release on worker shutdown: back to the queue; failed after repeated hand-backs; owner only', async () => {
    const j = runningJob();
    assert.equal((await wpost(`/jobs/${j.id}/release`, { worker_id: 'other', reason: 'stopping' })).status, 409);
    const r = await wpost(`/jobs/${j.id}/release`, { worker_id: W, reason: 'the worker is stopping (service stop or restart)' });
    assert.deepEqual([r.status, r.data.status], [200, 'queued']);
    assert.deepEqual([j.status, j.worker_id, j.heartbeat_at], ['queued', null, null]);
    assert.match(String((j.progress as Row).message), /Handed back by vps3-demo-worker/);
    const k = runningJob({ attempts: MAX_RELEASES });
    const f = await wpost(`/jobs/${k.id}/release`, { worker_id: W, reason: 'stopping again' });
    assert.equal(f.data.status, 'failed');
    assert.match(String(k.error), /stopped 3 times before finishing/);
    assert.equal((await wpost(`/jobs/${k.id}/release`, { worker_id: W, reason: 'x' })).status, 409, 'not running any more');
});

test('network classes and routes', () => {
    for (const ip of ['10.88.1.139', '172.20.10.2', '192.168.1.5', '100.64.1.1', '127.0.0.1', '169.254.1.1', 'fd00::1', 'fe80::1']) assert.equal(isNonPublicIp(ip), true, ip);
    for (const ip of ['8.8.8.8', '2606:4700::1', 'example.com']) assert.equal(isNonPublicIp(ip), false, ip);
    assert.equal(workerCanReach('10.88.1.139', []), false);
    assert.equal(workerCanReach('10.88.1.139', ['10.88.0.0/16']), true);
    assert.equal(workerCanReach('10.88.4.0/24', ['10.88.0.0/16']), true);
    assert.equal(workerCanReach('8.8.8.8', []), true);
});

test('queue capability: kind with no worker, private target with no route, or nothing in the way', () => {
    const now = Date.now();
    const w = (kinds: string[], networks: string[] = [], seen = 10): WorkerRow => ({ worker_id: 'w', kinds, networks, version: '1.3.0', tools: {}, first_seen_at: ago(seen), last_seen_at: ago(seen), last_heartbeat_at: ago(seen), last_claim_at: null, last_job_id: null, last_job_at: null });
    const q = (kind: string, targets: string[]) => ({ kind, status: 'queued', targets });
    const vps = deriveScannerStatus([w(['discovery', 'ports'])], null, now);
    assert.match(String(jobAttention(q('vuln_nuclei', ['8.8.8.8']), vps)), /No scanner worker runs vuln_nuclei/);
    assert.match(String(jobAttention(q('ports', ['10.88.1.139']), vps)), /10\.88\.1\.139: private address that no connected ports worker declares a route to/);
    assert.equal(jobAttention(q('ports', ['8.8.8.8']), vps), null);
    assert.equal(jobAttention(q('ports', ['10.88.1.139']), deriveScannerStatus([w(['ports'], ['10.88.0.0/16'])], null, now)), null);
    assert.match(String(jobAttention(q('ports', ['8.8.8.8']), deriveScannerStatus([w(['ports'], [], 3600)], null, now))), /No connected scanner worker runs ports/);
    assert.equal(jobAttention({ ...q('ports', ['10.88.1.139']), status: 'running' }, vps), null, 'only queued scans');
    assert.equal(jobAttention(q('ports', ['10.88.1.139']), deriveScannerStatus(null, null, now)), null, 'presence unknown: no judgement');
});

test('scans list and queueing carry the capability warning; heartbeat records networks; health flags orphan kinds', async () => {
    assert.equal((await wpost('/heartbeat', { worker_id: W, kinds: ['discovery', 'ports'], networks: ['not-a-cidr'] })).status, 400);
    assert.equal((await wpost('/heartbeat', { worker_id: W, kinds: ['discovery', 'ports'], version: '1.3.0', networks: [] })).status, 200);
    assert.deepEqual(db.tables.vms_workers[0].networks, []);
    const q = await http('POST', '/api/vms/scans', tok('soc_manager'), { scope_id: SCOPE, kind: 'ports' });
    assert.equal(q.status, 201);
    assert.match(String(q.data.warning), /private address that no connected ports worker declares a route to/);
    db.tables.vms_scan_jobs.push({ id: randomUUID(), org_id: ORG, scope_id: SCOPE, kind: 'vuln_nuclei', targets: ['10.88.1.139'], status: 'queued', requested_at: new Date().toISOString() });
    const list = await http('GET', '/api/vms/scans', tok('analyst'));
    const byKind = Object.fromEntries(list.data.scans.map((s: Row) => [s.kind, s.attention]));
    assert.match(String(byKind.vuln_nuclei), /No scanner worker runs vuln_nuclei/);
    assert.match(String(byKind.ports), /private address/);
    const queue = (await vmsChecks()).find((c) => c.name === 'VMS scan queue')!;
    assert.equal(queue.status, 'degraded');
    assert.match(queue.detail, /queued with no connected worker for: vuln_nuclei/);
    // Before the P12 SQL the networks column is missing: the heartbeat still lands.
    db.missingColumns.vms_workers = ['networks'];
    assert.equal((await wpost('/heartbeat', { worker_id: W, kinds: ['ports'], networks: ['10.88.0.0/16'] })).status, 200);
});
