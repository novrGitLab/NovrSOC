// P14: attack-surface relationships from stored records only (confirmed / observed / inferred, Wazuh
// endpoints never merged with scan assets), linked records on the asset detail, automatic
// assessment policies (disabled by default, manager-only, cooldown, cap, blocked reasons, same
// planning as manual), the admin status (no secrets), coverage metrics and worker tool versions.
// Fake PostgREST; nothing is scanned.
process.env.JWT_SECRET = 'vms-platform-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'VMS_WORKER_TOKEN', 'ANTHROPIC_API_KEY']) delete process.env[k];

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
import vmsAdminRouter from '../vmsAdmin';
import vmsAssessmentsRouter from '../vmsAssessments';
import vmsWorkerRouter from '../vmsWorker';
import { runEnabledPolicies, runPolicy, type Policy } from '../../services/vmsPolicies';

const WT = 'w'.repeat(40);
const ORG = 'org-a';
const SCOPE_PRIV = '5c0e5c0e-0000-4000-8000-0000000000b1';
const SCOPE_PUB = '5c0e5c0e-0000-4000-8000-0000000000b2';
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = ORG) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const MGR = tok('soc_manager');
const AN = tok('analyst');
async function http(method: string, path: string, bearer: string, body?: unknown) {
    const r = await fetch(`${base}${path}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: (await r.json().catch(() => null)) as Row };
}
const now = () => new Date().toISOString();
const future = new Date(Date.now() + 30 * 86_400_000).toISOString();
const ids = { endpoint: randomUUID(), ip: randomUUID(), domain: randomUUID(), sub: randomUUID(), other: randomUUID() };

before(async () => {
    db = await startFakePostgrest(
        { vms_workers: [], vms_scopes: [], vms_scan_jobs: [], vms_assets: [], vms_services: [], vms_technologies: [], vms_asset_events: [], vms_assessments: [], vms_assessment_policies: [], vms_findings: [], vms_finding_evidence: [], vms_observations: [], vms_job_evidence: [], vms_wazuh_sync: [], cve_intel: [], audit_log: [] },
        {},
        {
            vms_scan_jobs: { status: 'queued', attempts: 0, cancel_requested: false, progress: {}, purpose: 'assessment', get requested_at() { return new Date().toISOString(); } } as Row,
            vms_assessments: { profile: 'full', trigger: 'manual', steps: [], retried_at: null, cancelled_at: null, get requested_at() { return new Date().toISOString(); } } as Row,
            vms_assessment_policies: { enabled: false, profile: 'full', cooldown_hours: 168, max_per_run: 5, get created_at() { return new Date().toISOString(); } } as Row,
            vms_workers: { kinds: [], tools: {}, networks: [], features: [], tool_versions: {} },
        },
        { vms_claim_job: () => [] },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    process.env.VMS_WORKER_TOKEN = WT;
    const app = express();
    app.use('/api/vms/worker', express.json(), vmsWorkerRouter);
    app.use(express.json());
    app.use('/api/vms', requireAuth, vmsRouter);
    app.use('/api/vms', requireAuth, vmsAssessmentsRouter);
    app.use('/api/vms', requireAuth, vmsAdminRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => {
    for (const t of Object.keys(db.tables)) db.tables[t] = [];
    const a = (id: string, asset_type: string, value: string, b: Row = {}) => ({ id, org_id: ORG, asset_type, value, ips: [], hostnames: [], dns: {}, exposure: 'internal', criticality: 'medium', discovery_sources: [], status: 'active', last_seen: now(), first_seen: now(), wazuh_agent_id: null, ...b });
    db.tables.vms_assets.push(
        a(ids.endpoint, 'endpoint', 'rayneops', { ips: ['10.88.1.139'], wazuh_agent_id: '003', discovery_sources: ['wazuh'], criticality: 'high' }),
        a(ids.ip, 'ip', '10.88.1.139', { ips: ['10.88.1.139'], discovery_sources: ['nmap'] }),
        a(ids.domain, 'host', 'example.test', { ips: ['203.0.113.9'], dns: { a: ['203.0.113.9'] }, exposure: 'internet', discovery_sources: ['dnsx'] }),
        a(ids.sub, 'host', 'api.example.test', { discovery_sources: ['subfinder'] }),
        { ...a(ids.other, 'ip', '10.88.1.139'), org_id: 'org-b' },
    );
    db.tables.vms_services.push({ id: 's1', asset_id: ids.ip, port: 22, protocol: 'tcp', service: 'ssh', product: 'OpenSSH', version: '9.6', source: 'nmap', status: 'active', last_seen: now() });
    db.tables.vms_findings.push(
        { id: 'f1', org_id: ORG, asset_id: ids.ip, title: 'Weak SSH ciphers', priority: 'P3', evidence_class: 'scanner_check', source_class: 'active_scan', status: 'open', last_seen: now() },
        { id: 'f2', org_id: ORG, asset_id: ids.endpoint, title: 'CVE-2024-6387 in openssh', priority: 'P2', evidence_class: 'package_inventory', source_class: 'wazuh', status: 'open', last_seen: now() },
        { id: 'f3', org_id: ORG, asset_id: ids.domain, title: 'CVE-2023-44487 version match', priority: 'P3', evidence_class: 'version_match', source_class: 'passive_intel', status: 'open', last_seen: now() },
    );
    db.tables.vms_scopes.push(
        { id: SCOPE_PRIV, org_id: ORG, kind: 'ip', value: '10.88.1.139', include_subdomains: false, allow_discovery: true, allow_port_scan: true, allow_vuln_scan: false, exclusions: [], status: 'active', expires_at: future, approved_at: now(), approved_by: 'm', authorization_reference: 'LOA-1' },
        { id: SCOPE_PUB, org_id: ORG, kind: 'domain', value: 'example.test', include_subdomains: true, allow_discovery: true, allow_port_scan: true, allow_vuln_scan: false, exclusions: [], status: 'active', expires_at: future, approved_at: now(), approved_by: 'm', authorization_reference: 'LOA-2' },
    );
    db.tables.vms_workers.push({ worker_id: 'vps3-demo-worker', kinds: ['discovery', 'ports'], version: '1.5.0', tools: { httpx: true, nmap: true, nuclei: true, openvas: false }, tool_versions: { nmap: '7.94SVN' }, networks: [], features: ['exclusions'], first_seen_at: now(), last_seen_at: now() });
});

test('graph: stored relationships only, each labelled; Wazuh endpoint and scan asset linked, not merged', async () => {
    const g = (await http('GET', `/api/vms/assets/${ids.endpoint}/graph`, AN)).data;
    const edges = g.edges as Row[];
    const find = (type: string, from: string, to: string) => edges.find((e) => e.type === type && e.from === from && e.to === to);
    assert.equal(find('reported_address', `asset:${ids.endpoint}`, 'ip:10.88.1.139')?.basis, 'confirmed');
    assert.equal(find('same_address', `asset:${ids.endpoint}`, `asset:${ids.ip}`)?.basis, 'inferred');
    assert.equal(find('exposes', `asset:${ids.ip}`, 'service:s1')?.basis, 'observed');
    assert.equal(find('affected_by', `asset:${ids.ip}`, 'finding:f1')?.basis, 'confirmed');
    assert.equal(find('affected_by', `asset:${ids.endpoint}`, 'finding:f2')?.basis, 'confirmed', 'Wazuh package inventory');
    const nodeIds = (g.nodes as Row[]).map((n) => n.id);
    assert.ok(nodeIds.includes(`asset:${ids.endpoint}`) && nodeIds.includes(`asset:${ids.ip}`), 'two separate nodes');
    assert.ok(!nodeIds.includes(`asset:${ids.other}`), 'never another organisation');
    assert.ok(edges.every((e) => ['confirmed', 'observed', 'inferred'].includes(String(e.basis))));
    const d = (await http('GET', `/api/vms/assets/${ids.domain}/graph`, AN)).data;
    const de = d.edges as Row[];
    assert.equal(de.find((e) => e.type === 'subdomain')?.basis, 'inferred');
    assert.equal(de.find((e) => e.type === 'resolves_to')?.basis, 'observed');
    assert.equal(de.find((e) => e.to === 'finding:f3')?.basis, 'inferred', 'a version match is not confirmed');
    assert.equal((await http('GET', `/api/vms/assets/${ids.endpoint}/graph`, tok('analyst', 'org-b'))).status, 404);
});

test('asset detail: a Wazuh endpoint shows the scanned services at its address, and vice versa', async () => {
    const e = (await http('GET', `/api/vms/assets/${ids.endpoint}`, AN)).data;
    const linked = e.linked as Row[];
    assert.deepEqual(linked.map((l) => l.id), [ids.ip]);
    assert.equal(((linked[0].services as Row[])[0]).port, 22);
    assert.match(String(linked[0].relation), /inferred/);
    const i = (await http('GET', `/api/vms/assets/${ids.ip}`, AN)).data;
    assert.deepEqual((i.linked as Row[]).map((l) => l.id), [ids.endpoint]);
});

test('policies: managers only, created disabled, changes audited', async () => {
    assert.equal((await http('POST', '/api/vms/admin/policies', AN, { name: 'Wazuh endpoints weekly', asset_source: 'wazuh' })).status, 403);
    assert.equal((await http('GET', '/api/vms/admin/status', AN)).status, 403);
    assert.equal((await http('POST', '/api/vms/admin/policies', MGR, { name: 'x', asset_source: 'everything' })).status, 400);
    const c = await http('POST', '/api/vms/admin/policies', MGR, { name: 'Wazuh endpoints weekly', asset_source: 'wazuh' });
    assert.equal(c.status, 201);
    assert.equal((c.data.policy as Row).enabled, false);
    const p = await http('PATCH', `/api/vms/admin/policies/${(c.data.policy as Row).id}`, MGR, { enabled: true });
    assert.equal((p.data.policy as Row).enabled, true);
    assert.equal((await http('PATCH', `/api/vms/admin/policies/${(c.data.policy as Row).id}`, tok('soc_manager', 'org-b'), { enabled: false })).status, 404);
});

test('policy runs: same planning as manual, private endpoint not attempted, cooldown, cap, blocked reasons', async () => {
    const policy = (b: Partial<Policy>): Policy => {
        const p = { id: randomUUID(), org_id: ORG, name: 'p', enabled: true, asset_source: 'wazuh', profile: 'full', cooldown_hours: 168, max_per_run: 5, last_run_at: null, last_result: null, ...b } as Policy;
        db.tables.vms_assessment_policies.push(p as unknown as Row);
        return p;
    };
    const wz = policy({ asset_source: 'wazuh' });
    const r1 = await runPolicy(wz);
    assert.deepEqual([r1.queued, r1.blocked.length], [1, 0]);
    const a = db.tables.vms_assessments[0];
    assert.deepEqual([a.target, a.trigger, a.policy_id, a.asset_id], ['10.88.1.139', 'policy', wz.id, ids.endpoint]);
    assert.ok((a.steps as Row[]).every((s) => s.decision !== 'queued'), 'public worker has no route: nothing queued');
    assert.equal(db.tables.vms_scan_jobs.length, 0);
    const r2 = await runPolicy(wz);
    assert.deepEqual([r2.queued, r2.skipped_cooldown], [0, 1], 'not re-queued within the cooldown');
    // External assets: in scope -> assessed; out of scope -> blocked with the reason; capped.
    db.tables.vms_assets.push({ id: randomUUID(), org_id: ORG, asset_type: 'ip', value: '198.51.100.20', ips: [], status: 'active', criticality: 'low' });
    const ext = policy({ asset_source: 'external', max_per_run: 2 });
    const r3 = await runPolicy(ext);
    assert.equal(r3.queued + r3.existing, 2, 'capped at max_per_run');
    db.tables.vms_assessments = [];
    const ext2 = policy({ asset_source: 'external', max_per_run: 10 });
    const r4 = await runPolicy(ext2);
    assert.ok(r4.blocked.some((b) => b.asset === '198.51.100.20' && /not inside an active authorised scope/.test(b.reason)));
    // Only enabled policies run from the scheduler.
    db.tables.vms_assessment_policies.forEach((p) => { p.enabled = false; });
    assert.deepEqual(await runEnabledPolicies(), []);
});

test('admin status: workers with tool versions, integrations as configured/not, never a secret', async () => {
    process.env.ANTHROPIC_API_KEY = 'sk-ant-test-secret-value';
    try {
        const s = (await http('GET', '/api/vms/admin/status', MGR)).data;
        const w = ((s.workers as Row).list as Row[])[0];
        assert.deepEqual([w.worker_id, (w.tool_versions as Row).nmap, (w.features as string[])[0]], ['vps3-demo-worker', '7.94SVN', 'exclusions']);
        assert.equal((s.ai as Row).configured, true);
        assert.ok(!JSON.stringify(s).includes('sk-ant-test-secret-value'));
        assert.ok(!JSON.stringify(s).includes(WT));
        assert.equal((s.scopes as Row).active, 2);
        assert.equal((s.policies as Row).available, true);
    } finally { delete process.env.ANTHROPIC_API_KEY; }
});

test('overview coverage counts Wazuh and external assets separately and never counts unrun checks as assessed', async () => {
    const [jOk, jUnreach] = [randomUUID(), randomUUID()];
    db.tables.vms_scan_jobs.push(
        { id: jOk, org_id: ORG, kind: 'discovery', status: 'succeeded', started_at: now(), finished_at: now(), summary: { outcome: 'assessed' } },
        { id: jUnreach, org_id: ORG, kind: 'ports', status: 'succeeded', started_at: now(), finished_at: now(), summary: { outcome: 'unreachable' } },
    );
    db.tables.vms_assessments.push({ id: randomUUID(), org_id: ORG, target: '10.88.1.139', requested_at: now(), steps: [
        { kind: 'discovery', decision: 'queued', job_id: jOk, previous_job_ids: [] },
        { kind: 'ports', decision: 'queued', job_id: jUnreach, previous_job_ids: [] },   // ran, target did not answer: inconclusive
        { kind: 'vuln_nuclei', decision: 'not_attempted', reason: 'scope', job_id: null, previous_job_ids: [] },
    ] });
    // last_assessed_at is stamped for every outcome: only a reached target counts as assessed (P15 fix).
    Object.assign(db.tables.vms_assets.find((a) => a.id === ids.ip)!, { last_assessed_at: now(), last_assessment: { outcome: 'no_route' } });
    let c = (await http('GET', '/api/vms/overview', AN)).data.coverage as Row;
    assert.deepEqual([c.wazuh_endpoints, c.external_assets, c.assessments_last_30_days, c.checks_not_run_last_30_days], [1, 3, 1, 2]);
    assert.equal(c.assessed_last_30_days, 0, 'a no-route result is not an assessment');
    Object.assign(db.tables.vms_assets.find((a) => a.id === ids.domain)!, { last_assessed_at: now(), last_assessment: { outcome: 'reachable_no_open' } });
    c = (await http('GET', '/api/vms/overview', AN)).data.coverage as Row;
    assert.equal(c.assessed_last_30_days, 1);
});

test('worker heartbeat carries tool versions; before the P14 SQL it still lands', async () => {
    const hb = (body: Row) => fetch(`${base}/api/vms/worker/heartbeat`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${WT}` }, body: JSON.stringify(body) });
    const body = { worker_id: 'vps3-demo-worker', kinds: ['discovery', 'ports'], version: '1.5.0', tools: { nmap: true }, networks: [], features: ['exclusions'], tool_versions: { nmap: '7.94SVN', httpx: '1.6.8' } };
    assert.equal((await hb(body)).status, 200);
    assert.deepEqual(db.tables.vms_workers[0].tool_versions, { nmap: '7.94SVN', httpx: '1.6.8' });
    assert.equal((await hb({ ...body, tool_versions: { metasploit: '6' } })).status, 400, 'only known tools');
    db.missingColumns.vms_workers = ['tool_versions'];
    assert.equal((await hb(body)).status, 200);
    delete db.missingColumns.vms_workers;

    // P15: a rollback to an older worker (no features/tool_versions in its heartbeat) must not keep
    // the newer worker's announced features — the claim gate trusts them.
    const old = { worker_id: 'vps3-demo-worker', kinds: ['discovery', 'ports'], version: '1.3.0', tools: { nmap: true } };
    assert.equal((await hb(old)).status, 200);
    const w = db.tables.vms_workers.find((x) => x.worker_id === 'vps3-demo-worker')!;
    assert.deepEqual([w.version, w.features, w.tool_versions, w.networks], ['1.3.0', [], {}, []]);

    // Before P13/P14 SQL both columns are missing: whichever the database names first, the heartbeat lands.
    for (const order of [['tool_versions', 'features'], ['features', 'tool_versions']]) {
        db.missingColumns.vms_workers = order;
        assert.equal((await hb(body)).status, 200, `missing ${order.join(', ')}`);
    }
    delete db.missingColumns.vms_workers;
});
