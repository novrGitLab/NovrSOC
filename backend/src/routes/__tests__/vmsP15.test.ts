// P15 review fixes: a scan that ran but could not assess the target is "inconclusive", never
// "completed"; concurrent or overlapping requests do not create duplicate assessments; cancelling
// leaves finished assessments and scans shared with other requests alone; a policy run's blocked
// assets are budgeted; VMS Admin shows only the caller's organisation's policy results; the Wazuh
// integration check reports what the installation answers (or why it cannot), never a secret.
// Fake PostgREST and injected Wazuh replies; nothing is scanned and nothing external is contacted.
process.env.JWT_SECRET = 'vms-p15-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'VMS_WORKER_TOKEN', 'ANTHROPIC_API_KEY', 'WAZUH_HOST', 'WAZUH_INDEXER_HOST']) delete process.env[k];

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
import vmsAssessmentsRouter from '../vmsAssessments';
import vmsAdminRouter, { ownPolicyRuns } from '../vmsAdmin';
import { stepStatus, assessmentStatus, managementReport, type Step } from '../../services/vmsAssessments';
import { runPolicy, type Policy } from '../../services/vmsPolicies';
import { lastVmsContinuousRun } from '../../jobs/vmsContinuousJob';
import { unusableReply, wazuhFreshness } from '../../services/wazuhVulnSync';
import { checkWazuhIntegration } from '../../services/wazuhCheck';

const ORG = 'org-a';
const PUB = '5c0e5c0e-0000-4000-8000-0000000000c1';   // ip 8.8.8.8, everything allowed
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = ORG) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const AN = tok('analyst');
const MGR = tok('soc_manager');
async function http(method: string, path: string, bearer: string, body?: unknown) {
    const r = await fetch(`${base}${path}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: (await r.json().catch(() => null)) as Row };
}
const assess = (body: Row) => http('POST', '/api/vms/assessments', AN, body);
const now = () => new Date().toISOString();
const future = new Date(Date.now() + 30 * 86_400_000).toISOString();
const steps = (a: Row) => Object.fromEntries((a.steps as Row[]).map((s) => [s.kind, s]));

before(async () => {
    db = await startFakePostgrest(
        { vms_workers: [], vms_scopes: [], vms_scan_jobs: [], vms_assets: [], vms_services: [], vms_technologies: [], vms_asset_events: [], vms_assessments: [], vms_assessment_policies: [], vms_findings: [], vms_finding_evidence: [], vms_job_evidence: [], vms_wazuh_sync: [], wazuh_group_org_map: [], cve_intel: [], audit_log: [] },
        {},
        {
            vms_scan_jobs: { status: 'queued', attempts: 0, cancel_requested: false, progress: {}, purpose: 'assessment', get requested_at() { return new Date().toISOString(); } } as Row,
            vms_assessments: { profile: 'full', trigger: 'manual', steps: [], retried_at: null, cancelled_at: null, get requested_at() { return new Date().toISOString(); } } as Row,
        },
        { vms_claim_job: () => [] },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
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
    db.tables.vms_scopes.push({ id: PUB, org_id: ORG, kind: 'ip', value: '8.8.8.8', include_subdomains: false, allow_discovery: true, allow_port_scan: true, allow_vuln_scan: true, exclusions: [], status: 'active', expires_at: future, approved_by: 'mgr@org-a.test', authorization_reference: 'LOA-1' });
    db.tables.vms_workers.push({ worker_id: 'vps3-demo-worker', kinds: ['discovery', 'ports'], version: '1.5.0', tools: { httpx: true, nmap: true, nuclei: true, openvas: false }, networks: [], features: ['exclusions'], first_seen_at: now(), last_seen_at: now() });
});

// ── Inconclusive is not completed ────────────────────────────────────────────────────────────
test('a scan that ran but could not reach the target is inconclusive: not completed, retried, reported', async () => {
    const q: Step = { kind: 'ports', decision: 'queued', reason: 'Queued', job_id: 'j', previous_job_ids: [] };
    const j = (b: Row) => ({ id: 'j', kind: 'ports', status: 'succeeded', started_at: now(), finished_at: now(), error: null, summary: null, progress: null, ...b }) as never;
    assert.equal(stepStatus(q, j({ summary: { outcome: 'unreachable' } }), 0).status, 'inconclusive');
    assert.equal(stepStatus(q, j({ summary: { outcome: 'insufficient_evidence' } }), 0).status, 'inconclusive');
    assert.equal(stepStatus(q, j({ summary: { outcome: 'assessed' } }), 0).status, 'completed', 'zero findings from a scan that reached the target');
    assert.equal(stepStatus(q, j({ summary: {} }), 0).status, 'completed');
    assert.equal(assessmentStatus(['inconclusive', 'unsupported'], false), 'inconclusive', 'ran, but not the same as never attempted');
    assert.equal(assessmentStatus(['completed', 'inconclusive'], false), 'partial');

    const a = (await assess({ target: '8.8.8.8' })).data.assessment as Row;
    const job = (k: string) => db.tables.vms_scan_jobs.find((x) => x.kind === k && x.assessment_id === a.id)!;
    const ports = job('ports');
    Object.assign(job('discovery'), { status: 'succeeded', started_at: now(), finished_at: now(), summary: { outcome: 'assessed' } });
    Object.assign(ports, { status: 'succeeded', started_at: now(), finished_at: now(), summary: { outcome: 'unreachable' } });
    const d = (await http('GET', `/api/vms/assessments/${a.id}`, AN)).data.assessment as Row;
    assert.deepEqual([steps(d).ports.status, d.status], ['inconclusive', 'partial']);
    assert.match(String(steps(d).ports.detail), /no assurance/);
    const r = await http('POST', `/api/vms/assessments/${a.id}/retry`, AN);
    assert.deepEqual(steps(r.data.assessment as Row).ports.previous_job_ids, [ports.id], 'the inconclusive step is re-planned');
    const md = managementReport(d as never, {}, [], []);
    assert.match(md, /Checks completed: 1 of 4; not completed: Ports & services/);
});

// ── Duplicates ───────────────────────────────────────────────────────────────────────────────
test('concurrent submissions for one target create one assessment', async () => {
    const rs = await Promise.all([assess({ target: '8.8.8.8' }), assess({ target: '8.8.8.8' }), assess({ target: '8.8.8.8' })]);
    assert.equal(db.tables.vms_assessments.length, 1);
    assert.equal(new Set(rs.map((r) => (r.data.assessment as Row).id)).size, 1);
    assert.deepEqual(rs.map((r) => r.status).sort(), [200, 200, 201]);
    assert.equal(db.tables.vms_scan_jobs.length, 2, 'discovery and ports queued once');
});

test('an assessment saved but not yet planned counts as in progress for a while, then not', async () => {
    const pending = { id: randomUUID(), org_id: ORG, scope_id: PUB, target: '8.8.8.8', profile: 'full', steps: [], requested_by: 'x', requested_at: now(), retried_at: null, cancelled_at: null };
    db.tables.vms_assessments.push(pending);
    const r = await assess({ target: '8.8.8.8' });
    assert.deepEqual([r.status, (r.data.assessment as Row).id], [200, pending.id]);
    pending.requested_at = new Date(Date.now() - 20 * 60_000).toISOString();
    const r2 = await assess({ target: '8.8.8.8' });
    assert.equal(r2.status, 201, 'an abandoned empty row does not block new assessments forever');
});

// ── Cancel ───────────────────────────────────────────────────────────────────────────────────
test('cancel: refused once finished; a scan shared with an earlier request is not cancelled', async () => {
    const own = await http('POST', '/api/vms/scans', AN, { scope_id: PUB, kind: 'discovery', targets: ['8.8.8.8'] });
    assert.equal(own.status, 201);
    const a = (await assess({ target: '8.8.8.8' })).data.assessment as Row;
    assert.equal(steps(a).discovery.job_id, (own.data.scan as Row).id, 'deduplicated onto the scan already queued');
    assert.equal((await http('POST', `/api/vms/assessments/${a.id}/cancel`, AN)).status, 200);
    const byId = (id: unknown) => db.tables.vms_scan_jobs.find((j) => j.id === id)!;
    assert.equal(byId((own.data.scan as Row).id).status, 'queued', 'the other request\'s scan keeps running');
    assert.equal(byId(steps(a).ports.job_id).status, 'cancelled');
    assert.equal((await http('POST', `/api/vms/assessments/${a.id}/cancel`, AN)).status, 409, 'already cancelled');

    db.tables.vms_scan_jobs.length = 0;
    db.tables.vms_assessments.length = 0;
    const b = (await assess({ target: '8.8.8.8' })).data.assessment as Row;
    for (const j of db.tables.vms_scan_jobs) Object.assign(j, { status: 'succeeded', started_at: now(), finished_at: now(), summary: { outcome: 'assessed' } });
    const c = await http('POST', `/api/vms/assessments/${b.id}/cancel`, AN);
    assert.equal(c.status, 409, 'a finished assessment keeps its result');
    assert.equal(db.tables.vms_assessments[0].cancelled_at, null);
});

// ── Policies ─────────────────────────────────────────────────────────────────────────────────
test('a policy run tries a bounded number of blocked assets and says how many it left', async () => {
    for (let i = 1; i <= 30; i++) db.tables.vms_assets.push({ id: randomUUID(), org_id: ORG, asset_type: 'ip', value: `9.9.9.${i}`, status: 'active', criticality: 'medium', ips: [], hostnames: [] });
    const p: Policy = { id: randomUUID(), org_id: ORG, name: 'weekly', enabled: true, asset_source: 'external', profile: 'full', cooldown_hours: 168, max_per_run: 2, last_run_at: null, last_result: null };
    db.tables.vms_assessment_policies.push({ ...p });
    const r = await runPolicy(p);
    assert.deepEqual([r.queued, r.blocked_total, r.not_evaluated], [0, 8, 22]);
    assert.match(r.blocked[0].reason, /not inside an active authorised scope/);
    assert.equal(db.tables.vms_assessments.length, 0);
});

test('VMS Admin shows only this organisation\'s policy results', async () => {
    lastVmsContinuousRun.policies = { at: now(), result: [
        { policy: 'p1', org: ORG, queued: 1, existing: 0, skipped_cooldown: 0, blocked: [] },
        { policy: 'p2', org: 'org-b', queued: 0, existing: 0, skipped_cooldown: 0, blocked: [{ asset: 'secret-host.org-b.test', reason: 'x' }] },
    ] };
    const s = await http('GET', '/api/vms/admin/status', MGR);
    assert.equal(s.status, 200);
    assert.ok(!JSON.stringify(s.data).includes('secret-host.org-b.test'));
    assert.equal(((s.data.scheduler as Row).policies as Row).result instanceof Array, true);
    assert.deepEqual(ownPolicyRuns({ at: now(), result: { error: 'Assessment policies are not set up yet' } }, ORG)?.result, { error: 'The last policy run failed; see the backend log' });
    assert.equal(ownPolicyRuns(null, ORG), null);
    lastVmsContinuousRun.policies = null;
});

// ── Wazuh ────────────────────────────────────────────────────────────────────────────────────
test('indexer replies: errors and a missing index are not "no vulnerabilities"', () => {
    assert.equal(unusableReply({ hits: { total: { value: 0 }, hits: [] }, _shards: { total: 3, failed: 0 } }), null);
    assert.match(String(unusableReply({ _shards: { total: 0, failed: 0 }, hits: { hits: [] } })), /no index matches wazuh-states-vulnerabilities-\*: Wazuh before 4\.8/);
    assert.match(String(unusableReply({ error: { type: 'security_exception' }, status: 403 })), /refused the query \(security_exception, HTTP 403\)/);
    assert.match(String(unusableReply({ error: { type: 'search_phase_execution_exception' }, status: 400 })), /search_phase_execution_exception \(HTTP 400\)/);
    assert.match(String(unusableReply({ _shards: { total: 4, failed: 1 } })), /1 of 4 indexer shard/);
    assert.match(String(unusableReply(null)), /no readable answer/);
});

test('Wazuh freshness is judged on the last complete sync', () => {
    assert.deepEqual(wazuhFreshness(null), { last_attempt_at: null, last_complete_at: null, complete: null, problem: null });
    assert.equal(wazuhFreshness({ last_synced_at: 't1', last_result: { complete: true } }).last_complete_at, 't1', 'rows from before P15');
    const f = wazuhFreshness({ last_synced_at: 't2', last_result: { complete: false, last_complete_at: 't1', errors: ['indexer: connection refused'] } });
    assert.deepEqual([f.last_complete_at, f.complete, f.problem], ['t1', false, 'indexer: connection refused']);
    assert.equal(wazuhFreshness({ last_synced_at: 't2', last_result: { complete: false, errors: [] } }).last_complete_at, null);
});

test('Wazuh check: managers only; reports version, agents and vulnerability counts; never a secret', async () => {
    assert.equal((await http('POST', '/api/vms/admin/wazuh/check', AN)).status, 403);
    assert.equal((await http('POST', '/api/vms/admin/wazuh/check', tok('executive'))).status, 403);
    const nc = await http('POST', '/api/vms/admin/wazuh/check', MGR);
    assert.equal(nc.status, 200);
    assert.equal(nc.data.verdict, 'not_configured', 'no Wazuh variables in the test environment');

    db.tables.wazuh_group_org_map.push({ wazuh_group: 'acme', org_id: ORG }, { wazuh_group: 'other', org_id: 'org-b' });
    const env = { WAZUH_HOST: 'manager.test', WAZUH_API_PASSWORD: 'api-pass-SECRET', WAZUH_INDEXER_HOST: 'indexer.test', WAZUH_INDEXER_PASSWORD: 'idx-pass-SECRET' };
    const agents = async (g: string) => (g === 'acme' ? [{ id: '001', name: 'web-01', status: 'active', os: null, ip: '10.0.0.5', lastKeepAlive: null, group: ['acme'] }, { id: '002', name: 'db-01', status: 'disconnected', os: null, ip: null, lastKeepAlive: null, group: ['acme'] }] : []);
    const seen: { index: string; body: Row }[] = [];
    const search = async (index: string, body: unknown) => {
        seen.push({ index, body: body as Row });
        return index.startsWith('wazuh-monitoring') ? { _shards: { total: 1, failed: 0 }, hits: { total: { value: 2 }, hits: [] } }
            : { _shards: { total: 2, failed: 0 }, hits: { total: { value: 5 }, hits: [] }, aggregations: { severity: { buckets: [{ key: 'High', doc_count: 3 }, { key: 'Low', doc_count: 2 }] } } } as never;
    };
    const managerGet = async () => ({ status: 200, json: { data: { api_version: '4.9.2' } } });
    let r = await checkWazuhIntegration(ORG, { env, search, agentsForGroup: agents as never, managerGet });
    assert.equal(r.verdict, 'reachable_not_synced', 'answers, but no complete sync recorded yet');
    assert.deepEqual([r.manager.ok && r.manager.api_version, r.agents.ok && r.agents.count, r.agents.ok && r.agents.active], ['4.9.2', 2, 1]);
    assert.deepEqual(r.vulnerabilities.ok && [r.vulnerabilities.records_for_org, r.vulnerabilities.by_severity], [5, { High: 3, Low: 2 }]);
    const vq = seen.find((s) => s.index === 'wazuh-states-vulnerabilities-*')!.body;
    assert.equal(vq.size, 0, 'counts only, no documents');
    assert.deepEqual(((vq.query as Row).bool as Row).filter, [{ terms: { 'agent.name': ['web-01', 'db-01'] } }], 'only this organisation\'s agents');
    assert.ok(!/SECRET/.test(JSON.stringify(r)));

    db.tables.vms_wazuh_sync.push({ org_id: ORG, last_synced_at: now(), last_result: { complete: true } });
    r = await checkWazuhIntegration(ORG, { env, search, agentsForGroup: agents as never, managerGet });
    assert.equal(r.verdict, 'working');

    // No vulnerability index, a refused monitoring query, a manager that never answers.
    r = await checkWazuhIntegration(ORG, { env, agentsForGroup: agents as never, managerGet: () => new Promise(() => undefined), timeoutMs: 50,
        search: async (index: string) => (index.startsWith('wazuh-monitoring') ? { error: { type: 'security_exception' }, status: 403 } : { _shards: { total: 0 }, hits: { hits: [] } }) as never });
    assert.equal(r.verdict, 'not_working');
    assert.match(String(!r.manager.ok && r.manager.error), /did not answer within/);
    assert.match(String(!r.agents.ok && r.agents.error), /refused the query .*wazuh-monitoring-\*/);
    assert.match(String(!r.vulnerabilities.ok && r.vulnerabilities.error), /Wazuh before 4\.8/);
    assert.ok(!/SECRET/.test(JSON.stringify(r)));

    // An organisation with no mapped group is told so.
    r = await checkWazuhIntegration('org-c', { env, search, agentsForGroup: agents as never, managerGet });
    assert.match(String(!r.agents.ok && r.agents.error), /no Wazuh group is mapped/);
});
