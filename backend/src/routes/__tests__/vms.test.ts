// Phase P4 VMS Release 1: scope rules, scope approval, scan queueing (scope + permission checks,
// dedupe), the worker API (token, claim, heartbeat/cancel, results re-checked against scope,
// new/changed/gone tracking), revocation, queue upkeep and tenant isolation. Fake PostgREST only;
// no scanner runs and nothing on the network is touched. All targets are reserved test names.
process.env.JWT_SECRET = 'vms-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'VMS_WORKER_TOKEN']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { approveIfPending } from './vmsApproveHelper';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import vmsRouter from '../vms';
import vmsWorkerRouter from '../vmsWorker';
import { runVmsMaintenance } from '../../jobs/vmsMaintenance';
import { validateScopeValue, inScope, normalizeHostname, type ScopeEntry } from '../../lib/vmsScope';
import { portsCovered } from '../../services/vmsIngest';

const A = 'org-a';
const B = 'org-b';
const WT = 'w'.repeat(40);
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = A) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const MGR = tok('soc_manager');
const AN = tok('analyst');
async function http(method: string, path: string, bearer?: string, body?: unknown) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const r = await fetch(`${base}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const future = (d = 30) => new Date(Date.now() + d * 86_400_000).toISOString();
const worker = (path: string, body: unknown) => http('POST', `/api/vms/worker${path}`, WT, body);

before(async () => {
    db = await startFakePostgrest(
        { vms_scopes: [], vms_scan_jobs: [], vms_assets: [], vms_services: [], vms_technologies: [], vms_asset_events: [], vms_scope_approvals: [], vms_scan_schedules: [] },
        { 'vms_asset_events.vms_assets': 'asset_id', 'vms_scan_jobs.vms_scopes': 'scope_id' },
        {
            vms_scopes: { status: 'active', approved_at: new Date().toISOString() },
            vms_scan_jobs: { status: 'queued', attempts: 0, cancel_requested: false, progress: {}, requested_at: new Date().toISOString() },
            vms_assets: { status: 'active', exposure: 'unknown', criticality: 'medium', hostnames: [], ips: [], dns: {}, discovery_sources: [], first_seen: new Date().toISOString(), last_seen: new Date().toISOString() },
            vms_services: { status: 'active', state: 'open', last_seen: new Date().toISOString() },
            vms_technologies: { version: '' },
            vms_asset_events: { at: new Date().toISOString() },
        },
        {
            vms_claim_job: (args, tables) => {
                const kinds = args.p_kinds as string[];
                const j = tables.vms_scan_jobs.filter((x) => x.status === 'queued' && kinds.includes(String(x.kind)) && !x.cancel_requested)
                    .sort((a, b) => String(a.requested_at).localeCompare(String(b.requested_at)))[0];
                if (!j) return [];
                Object.assign(j, { status: 'running', worker_id: args.p_worker, claimed_at: new Date().toISOString(), heartbeat_at: new Date().toISOString(), started_at: new Date().toISOString(), attempts: Number(j.attempts ?? 0) + 1 });
                return [j];
            },
        },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use('/api/vms/worker', express.json({ limit: '2mb' }), vmsWorkerRouter);
    app.use(express.json());
    app.use('/api/vms', requireAuth, vmsRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => {
    for (const t of ['vms_scopes', 'vms_scan_jobs', 'vms_assets', 'vms_services', 'vms_technologies', 'vms_asset_events']) db.tables[t].length = 0;
    process.env.VMS_WORKER_TOKEN = WT;
});
const requestScope = (body: Record<string, unknown>, bearer = MGR) =>
    http('POST', '/api/vms/scopes', bearer, { authorization_reference: 'LOA-2026-014 signed by Acme CISO', expires_at: future(), ...body });
// P27: active entries are approved by the organisation's administrator (executive) before use.
const newScope = async (body: Record<string, unknown>, bearer = MGR) => {
    const org = (JSON.parse(Buffer.from(bearer.split('.')[1], 'base64url').toString()) as { org_id: string }).org_id;
    return approveIfPending(http, await requestScope(body, bearer), tok('executive', org));
};

// ── Scope rules ──────────────────────────────────────────────────────────────────────────────
test('scope values: plain names and bounded ranges only', () => {
    assert.equal(normalizeHostname('Example.COM.'), 'example.com');
    for (const bad of ['*.example.com', 'https://example.com', 'example.com:443', 'localhost', 'user@example.com', '-bad.example.com', '10.0.0.1']) assert.equal(normalizeHostname(bad), null, bad);
    assert.deepEqual(validateScopeValue('cidr', '203.0.113.0/24'), { ok: true, value: '203.0.113.0/24' });
    assert.equal(validateScopeValue('cidr', '203.0.112.0/21').ok, false, 'larger than /22 refused');
    assert.equal(validateScopeValue('cidr', '203.0.113.5').ok, false, 'a bare IP is kind ip, not cidr');
    const entries = [
        { id: '1', org_id: A, kind: 'domain', value: 'example.test', include_subdomains: true, allow_port_scan: false, allow_vuln_scan: false, status: 'active', expires_at: future() },
        { id: '2', org_id: A, kind: 'cidr', value: '203.0.113.0/28', include_subdomains: false, allow_port_scan: true, allow_vuln_scan: false, status: 'active', expires_at: future() },
        { id: '3', org_id: A, kind: 'domain', value: 'old.test', include_subdomains: true, allow_port_scan: true, allow_vuln_scan: true, status: 'active', expires_at: new Date(Date.now() - 1000).toISOString() },
    ] as ScopeEntry[];
    assert.equal(inScope('api.example.test', entries, 'discovery'), true);
    assert.equal(inScope('notexample.test', entries, 'discovery'), false, 'suffix match is on a dot boundary');
    assert.equal(inScope('api.example.test', entries, 'ports'), false, 'port scans need allow_port_scan');
    assert.equal(inScope('203.0.113.9', entries, 'ports'), true);
    assert.equal(inScope('203.0.113.20', entries, 'ports'), false);
    assert.equal(inScope('www.old.test', entries, 'discovery'), false, 'expired scope covers nothing');
    assert.equal(portsCovered('top-1000')(22), false);
    assert.equal(portsCovered('22,80,8000-8100')(8050), true);
    assert.equal(portsCovered('1-65535')(31337), true);
});

// ── Scope approval ───────────────────────────────────────────────────────────────────────────
// P27: managers request scope; an entry that permits active scanning is pending until the
// organisation's administrator approves it (vmsAuthorisation.test.ts covers the approval itself).
test('only managers request scope; a reference and a bounded expiry are required; active entries wait for organisation approval', async () => {
    assert.equal((await requestScope({ kind: 'domain', value: 'example.test' }, AN)).status, 403);
    assert.equal((await requestScope({ kind: 'domain', value: 'example.test', authorization_reference: '' })).status, 400);
    assert.equal((await requestScope({ kind: 'domain', value: 'example.test', expires_at: future(500) })).status, 400);
    assert.equal((await requestScope({ kind: 'domain', value: '*.example.test' })).status, 400);
    const r = await requestScope({ kind: 'domain', value: 'Example.Test' });
    assert.equal(r.status, 201);
    assert.deepEqual([r.data.scope.value, r.data.scope.status, r.data.scope.requested_by, r.data.scope.approved_by, r.data.approval_required], ['example.test', 'pending', 'soc_manager@org-a.test', null, true]);
    assert.equal((await http('POST', '/api/vms/scans', AN, { scope_id: r.data.scope.id, kind: 'discovery' })).status, 400, 'a pending scope authorises nothing');
    const ok = await approveIfPending(http, r, tok('executive'));
    assert.deepEqual([ok.data.scope.status, ok.data.scope.approved_by, ok.data.scope.approval_method], ['active', 'executive@org-a.test', 'in_platform']);
});

// ── Scans ────────────────────────────────────────────────────────────────────────────────────
test('scans: targets must be in the chosen scope; ports need permission; duplicates return the open job', async () => {
    const dom = (await newScope({ kind: 'domain', value: 'example.test' })).data.scope;
    const net = (await newScope({ kind: 'cidr', value: '203.0.113.0/28', allow_port_scan: true })).data.scope;
    assert.equal((await http('POST', '/api/vms/scans', AN, { scope_id: dom.id, kind: 'discovery', targets: ['evil.test'] })).status, 400);
    assert.equal((await http('POST', '/api/vms/scans', AN, { scope_id: dom.id, kind: 'ports' })).status, 403);
    assert.equal((await http('POST', '/api/vms/scans', AN, { scope_id: net.id, kind: 'ports', targets: ['203.0.113.99'] })).status, 400);
    const ok = await http('POST', '/api/vms/scans', AN, { scope_id: dom.id, kind: 'discovery' });
    assert.equal(ok.status, 201);
    assert.deepEqual(ok.data.scan.targets, ['example.test']);
    const again = await http('POST', '/api/vms/scans', AN, { scope_id: dom.id, kind: 'discovery' });
    assert.deepEqual([again.status, again.data.existing, again.data.scan.id], [200, true, ok.data.scan.id]);
    assert.equal((await http('POST', '/api/vms/scans', tok('executive'), { scope_id: dom.id, kind: 'discovery' })).status, 403);
    assert.equal((await http('POST', '/api/vms/scans', tok('analyst', B), { scope_id: dom.id, kind: 'discovery' })).status, 400, 'another org\'s scope is not usable');
});

// ── Worker ───────────────────────────────────────────────────────────────────────────────────
test('worker token: unset = 503, wrong = 401', async () => {
    delete process.env.VMS_WORKER_TOKEN;
    assert.equal((await worker('/claim', { worker_id: 'w1', kinds: ['discovery'] })).status, 503);
    process.env.VMS_WORKER_TOKEN = WT;
    assert.equal((await http('POST', '/api/vms/worker/claim', 'x'.repeat(40), { worker_id: 'w1', kinds: ['discovery'] })).status, 401);
});

test('discovery: claim, progress, results re-checked against scope, new and changed assets recorded', async () => {
    const dom = (await newScope({ kind: 'domain', value: 'example.test' })).data.scope;
    await http('POST', '/api/vms/scans', AN, { scope_id: dom.id, kind: 'discovery' });
    const c = await worker('/claim', { worker_id: 'w1', kinds: ['discovery'] });
    assert.equal(c.data.job.status, 'running');
    assert.deepEqual(c.data.scopes.map((s: Row) => s.value), ['example.test']);
    assert.equal((await worker('/claim', { worker_id: 'w2', kinds: ['discovery'] })).data.job, null, 'one worker per job');
    const id = c.data.job.id;
    const hb = await worker(`/jobs/${id}/heartbeat`, { worker_id: 'w1', progress: { phase: 'subfinder', done: 1, total: 3 } });
    assert.equal(hb.data.cancel, false);
    assert.equal((await worker(`/jobs/${id}/heartbeat`, { worker_id: 'w2' })).status, 409, 'not your job');

    const r = await worker(`/jobs/${id}/results`, { worker_id: 'w1', observations: [
        { type: 'host', host: 'api.example.test', ips: ['203.0.113.5'], alive: true, http: { url: 'https://api.example.test', status: 200, title: 'API' }, technologies: [{ name: 'Nginx', version: '1.25.3' }], source: 'httpx' },
        { type: 'host', host: 'intranet.other.test', ips: ['10.0.0.5'], source: 'subfinder' },
        { type: 'host', host: 'x', source: 'subfinder' },
        { type: 'service', host: 'api.example.test', port: 22, protocol: 'tcp', source: 'nmap' },
    ] });
    assert.deepEqual([r.data.accepted, r.data.rejected_out_of_scope, r.data.rejected_invalid], [1, 1, 2], 'an out-of-scope host is dropped; a malformed host and a service result from a discovery job are invalid');
    assert.deepEqual([...r.data.invalid_reasons].sort(), ['host host: not a hostname or IP address', 'service not allowed in a discovery job'], 'each rejection says why, without the submitted value');
    const asset = db.tables.vms_assets[0];
    assert.deepEqual([asset.value, asset.exposure, db.tables.vms_assets.length], ['api.example.test', 'internet', 1]);
    assert.deepEqual(db.tables.vms_technologies.map((t) => [t.name, t.version]), [['nginx', '1.25.3']]);
    assert.deepEqual(db.tables.vms_asset_events.map((e) => e.event).sort(), ['asset_new', 'technology_new']);

    await worker(`/jobs/${id}/results`, { worker_id: 'w1', observations: [{ type: 'host', host: 'api.example.test', ips: ['203.0.113.6'], http: { url: 'https://api.example.test', status: 403, title: 'API' }, source: 'httpx' }] });
    const changed = db.tables.vms_asset_events.find((e) => e.event === 'asset_changed')!;
    assert.deepEqual((changed.details as Row).http_status, { from: 200, to: 403 });
    assert.equal((await worker(`/jobs/${id}/complete`, { worker_id: 'w1', status: 'succeeded', summary: { hosts: 1 } })).status, 200);
    assert.equal(db.tables.vms_scan_jobs[0].status, 'succeeded');
});

test('ports: services tracked; a full-range rescan marks missing ones gone, a top-N scan does not', async () => {
    const net = (await newScope({ kind: 'cidr', value: '203.0.113.0/28', allow_port_scan: true })).data.scope;
    const run = async (ports: string, obs: Row[]) => {
        await http('POST', '/api/vms/scans', AN, { scope_id: net.id, kind: 'ports', targets: ['203.0.113.5'], ports });
        const id = (await worker('/claim', { worker_id: 'w1', kinds: ['ports'] })).data.job.id;
        await worker(`/jobs/${id}/results`, { worker_id: 'w1', observations: obs });
        return (await worker(`/jobs/${id}/complete`, { worker_id: 'w1', status: 'succeeded' })).data;
    };
    await run('1-65535', [
        { type: 'service', host: '203.0.113.5', port: 22, protocol: 'tcp', service: 'ssh', product: 'OpenSSH', version: '8.9p1', source: 'nmap' },
        { type: 'service', host: '203.0.113.5', port: 8443, protocol: 'tcp', service: 'https', source: 'nmap' },
    ]);
    assert.equal(db.tables.vms_services.length, 2);
    assert.ok(db.tables.vms_services.every((s) => s.status === 'active'), 'a scan never marks what it just found as gone');
    for (const s of db.tables.vms_services) s.last_seen = '2000-01-01T00:00:00Z'; // as if seen long ago
    const top = await run('top-1000', [{ type: 'service', host: '203.0.113.5', port: 22, protocol: 'tcp', service: 'ssh', product: 'OpenSSH', version: '9.6p1', source: 'nmap' }]);
    assert.equal(top.services_gone, 0, '8443 may simply not be in nmap\'s top list');
    assert.ok(db.tables.vms_asset_events.some((e) => e.event === 'service_changed' && JSON.stringify(e.details).includes('9.6p1')));
    for (const s of db.tables.vms_services) s.last_seen = '2000-01-01T00:00:00Z';
    const full = await run('1-65535', [{ type: 'service', host: '203.0.113.5', port: 22, protocol: 'tcp', service: 'ssh', source: 'nmap' }]);
    assert.equal(full.services_gone, 1);
    assert.equal(db.tables.vms_services.find((s) => s.port === 8443)!.status, 'gone');
});

test('ports: a worker 1.7.0 batch with cpe: null is accepted (was 4 of 5 rejected as invalid)', async () => {
    const net = (await newScope({ kind: 'ip', value: '203.0.113.9', allow_port_scan: true })).data.scope;
    await http('POST', '/api/vms/scans', AN, { scope_id: net.id, kind: 'ports', targets: ['203.0.113.9'] });
    const id = (await worker('/claim', { worker_id: 'w1', kinds: ['ports'] })).data.job.id;
    // Exactly what worker 1.7.0 builds from nmap -oX for one host (parse_nmap_xml + host_observation).
    const batch = [
        { type: 'host', host: '203.0.113.9', ips: ['203.0.113.9'], source: 'nmap', alive: true, assessment: { outcome: 'reachable_open', reason: '3 open of 1000 port(s) scanned', method: 'nmap', host_status: 'up', host_status_reason: 'user-set', port_states: { open: 3, closed: 1, filtered: 996 }, ports_scanned: 1000 } },
        { type: 'service', host: '203.0.113.9', port: 22, protocol: 'tcp', state: 'open', source: 'nmap', service: 'ssh', product: 'OpenSSH', version: '8.9p1 Ubuntu 3ubuntu0.10 Ubuntu Linux; protocol 2.0', cpe: ['cpe:/a:openbsd:openssh:8.9p1'] },
        { type: 'service', host: '203.0.113.9', port: 80, protocol: 'tcp', state: 'open', source: 'nmap', service: 'http', product: null, version: null, cpe: null },
        { type: 'service', host: '203.0.113.9', port: 443, protocol: 'tcp', state: 'open', source: 'nmap', service: 'https', product: null, version: null, cpe: null },
        { type: 'service', host: '203.0.113.9', port: 8080, protocol: 'tcp', state: 'closed', source: 'nmap', service: 'http-proxy', product: null, version: null, cpe: null },
    ];
    const r = await worker(`/jobs/${id}/results`, { worker_id: 'w1', observations: batch });
    assert.deepEqual([r.data.accepted, r.data.rejected_invalid, r.data.invalid_reasons], [5, 0, undefined]);
    assert.deepEqual(db.tables.vms_services.filter((s) => s.port !== 22 || s.cpe).map((s) => [s.port, s.state, s.cpe]).sort(), [[22, 'open', ['cpe:/a:openbsd:openssh:8.9p1']], [443, 'open', null], [80, 'open', null]].sort(), 'open services stored (closed ones are not inventory)');
    // A genuinely malformed observation is still rejected, and the reason names the field, not the value.
    const bad = await worker(`/jobs/${id}/results`, { worker_id: 'w1', observations: [{ type: 'service', host: '203.0.113.9', port: 70000, protocol: 'tcp', source: 'nmap', product: 'secret-banner-value' }] });
    assert.equal(bad.data.rejected_invalid, 1);
    assert.match(bad.data.invalid_reasons[0], /^service port: /);
    assert.ok(!JSON.stringify(bad.data).includes('secret-banner-value'));
});

test('revoking scope cancels queued scans and tells running ones to stop', async () => {
    const dom = (await newScope({ kind: 'domain', value: 'example.test' })).data.scope;
    await http('POST', '/api/vms/scans', AN, { scope_id: dom.id, kind: 'discovery' });
    const id = (await worker('/claim', { worker_id: 'w1', kinds: ['discovery'] })).data.job.id;
    await http('POST', '/api/vms/scans', AN, { scope_id: dom.id, kind: 'discovery', targets: ['www.example.test'] });
    assert.equal((await http('POST', `/api/vms/scopes/${dom.id}/revoke`, AN)).status, 403);
    assert.equal((await http('POST', `/api/vms/scopes/${dom.id}/revoke`, MGR)).status, 200);
    assert.deepEqual(db.tables.vms_scan_jobs.map((j) => j.status).sort(), ['cancelled', 'running']);
    assert.equal((await worker(`/jobs/${id}/heartbeat`, { worker_id: 'w1' })).data.cancel, true);
    const late = await worker(`/jobs/${id}/results`, { worker_id: 'w1', observations: [{ type: 'host', host: 'api.example.test', source: 'subfinder' }] });
    assert.equal(late.data.rejected_out_of_scope, 1, 'nothing is accepted under a revoked scope');
});

test('queue upkeep: a silent worker\'s job is requeued once, then failed; expired-scope jobs are cancelled', async () => {
    const dom = (await newScope({ kind: 'domain', value: 'example.test' })).data.scope;
    await http('POST', '/api/vms/scans', AN, { scope_id: dom.id, kind: 'discovery' });
    await worker('/claim', { worker_id: 'w1', kinds: ['discovery'] });
    const job = db.tables.vms_scan_jobs[0];
    job.heartbeat_at = '2000-01-01T00:00:00Z';
    assert.equal((await runVmsMaintenance()).requeued, 1);
    assert.equal(job.status, 'queued');
    await worker('/claim', { worker_id: 'w1', kinds: ['discovery'] });
    job.heartbeat_at = '2000-01-01T00:00:00Z';
    assert.equal((await runVmsMaintenance()).failed, 1);
    assert.match(String(job.error), /No heartbeat or completion from the scanner worker/);
    await http('POST', '/api/vms/scans', AN, { scope_id: dom.id, kind: 'discovery', targets: ['www.example.test'] });
    db.tables.vms_scopes[0].expires_at = '2000-01-01T00:00:00Z';
    assert.equal((await runVmsMaintenance()).cancelled, 1);
});

test('tenant isolation: another org sees none of the inventory, scope or scans', async () => {
    const dom = (await newScope({ kind: 'domain', value: 'example.test' })).data.scope;
    await http('POST', '/api/vms/scans', AN, { scope_id: dom.id, kind: 'discovery' });
    const id = (await worker('/claim', { worker_id: 'w1', kinds: ['discovery'] })).data.job.id;
    await worker(`/jobs/${id}/results`, { worker_id: 'w1', observations: [{ type: 'host', host: 'api.example.test', source: 'subfinder' }] });
    const BT = tok('analyst', B);
    assert.equal((await http('GET', '/api/vms/assets', BT)).data.assets.length, 0);
    assert.equal((await http('GET', '/api/vms/scopes', BT)).data.scopes.length, 0);
    assert.equal((await http('GET', '/api/vms/scans', BT)).data.scans.length, 0);
    assert.equal((await http('GET', `/api/vms/assets/${db.tables.vms_assets[0].id}`, BT)).status, 404);
    assert.equal((await http('PATCH', `/api/vms/assets/${db.tables.vms_assets[0].id}`, BT, { criticality: 'critical' })).status, 404, 'another org\'s asset looks like a missing one');
});
