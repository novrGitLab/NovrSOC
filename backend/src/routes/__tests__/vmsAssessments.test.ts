// P13 Full Assessment: authorisation and tenant isolation, planning before dispatch (scope
// permissions, exclusions, worker kinds, tools, features, private routes), never reporting an
// unattempted scan as done, idempotent submission, derived step/assessment status (completed,
// findings detected, failed, not attempted, unsupported, partial), safe retry that keeps completed
// steps and earlier evidence, cancel, the management report, exclusions enforced at queue, claim
// and ingest, and the pre-migration answer. Fake PostgREST; nothing is scanned.
process.env.JWT_SECRET = 'vms-assessments-test-secret';
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
import vmsAssessmentsRouter from '../vmsAssessments';
import vmsWorkerRouter from '../vmsWorker';
import { stepStatus, assessmentStatus, type Step } from '../../services/vmsAssessments';
import { coveringScope, isExcluded, normalizeExclusion, type ScopeEntry } from '../../lib/vmsScope';

const WT = 'w'.repeat(40);
const ORG = 'org-a';
const PUB = '5c0e5c0e-0000-4000-8000-0000000000a1';   // ip 8.8.8.8, everything allowed
const PRIV = '5c0e5c0e-0000-4000-8000-0000000000a2';  // ip 10.88.1.139, everything allowed
const NOPORTS = '5c0e5c0e-0000-4000-8000-0000000000a3'; // ip 1.1.1.1, discovery only
const RANGE = '5c0e5c0e-0000-4000-8000-0000000000a4';  // cidr 203.0.113.0/28, excluding .5
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = ORG) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const AN = tok('analyst');
async function http(method: string, path: string, bearer: string | null, body?: unknown) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const r = await fetch(`${base}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await r.text();
    let data: Row | null = null;
    try { data = JSON.parse(text); } catch { /* markdown */ }
    return { status: r.status, data: data as Row, text, headers: r.headers };
}
const assess = (body: Row, bearer = AN) => http('POST', '/api/vms/assessments', bearer, body);
const future = new Date(Date.now() + 30 * 86_400_000).toISOString();
const now = () => new Date().toISOString();
const worker = (b: Row = {}) => ({ worker_id: 'vps3-demo-worker', kinds: ['discovery', 'ports'], version: '1.4.0', tools: { subfinder: true, dnsx: true, httpx: true, nmap: true, nuclei: true, openvas: false }, networks: [], features: [], first_seen_at: now(), last_seen_at: now(), ...b });
const steps = (a: Row) => Object.fromEntries((a.steps as Row[]).map((s) => [s.kind, s]));

before(async () => {
    db = await startFakePostgrest(
        { vms_workers: [], vms_scopes: [], vms_scan_jobs: [], vms_assets: [], vms_services: [], vms_asset_events: [], vms_assessments: [], vms_findings: [], vms_finding_evidence: [], vms_job_evidence: [], vms_technologies: [] },
        {},
        {
            vms_scan_jobs: { status: 'queued', attempts: 0, cancel_requested: false, progress: {}, purpose: 'assessment', get requested_at() { return new Date().toISOString(); } } as Row,
            vms_assessments: { profile: 'full', steps: [], retried_at: null, cancelled_at: null, get requested_at() { return new Date().toISOString(); } } as Row,
            vms_assets: { status: 'active', exposure: 'unknown', criticality: 'medium', hostnames: [], ips: [], dns: {}, discovery_sources: [] },
        },
        {
            vms_claim_job: (args, tables) => {
                const j = tables.vms_scan_jobs.find((x) => x.status === 'queued' && (args.p_kinds as string[]).includes(String(x.kind)) && !x.cancel_requested);
                if (!j) return [];
                Object.assign(j, { status: 'running', worker_id: args.p_worker, claimed_at: now(), heartbeat_at: now(), started_at: now(), attempts: Number(j.attempts ?? 0) + 1 });
                return [j];
            },
        },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    process.env.VMS_WORKER_TOKEN = WT;
    const app = express();
    app.use('/api/vms/worker', express.json(), vmsWorkerRouter);
    app.use(express.json());
    app.use('/api/vms', requireAuth, vmsRouter);
    app.use('/api/vms', requireAuth, vmsAssessmentsRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => {
    for (const t of Object.keys(db.tables)) db.tables[t] = [];
    const s = (id: string, kind: string, value: string, b: Row = {}) => ({ id, org_id: ORG, kind, value, include_subdomains: false, allow_discovery: true, allow_port_scan: true, allow_vuln_scan: true, exclusions: [], status: 'active', expires_at: future, approved_at: now(), approved_by: 'mgr@org-a.test', authorization_reference: 'LOA-2026-042', ...b });
    db.tables.vms_scopes.push(s(PUB, 'ip', '8.8.8.8'), s(PRIV, 'ip', '10.88.1.139'), s(NOPORTS, 'ip', '1.1.1.1', { allow_port_scan: false, allow_vuln_scan: false }), s(RANGE, 'cidr', '203.0.113.0/28', { exclusions: ['203.0.113.5'] }));
    db.tables.vms_workers.push(worker());
});

test('authorisation: signed-in users only; executives read but cannot start; other organisations see nothing', async () => {
    assert.equal((await http('GET', '/api/vms/assessments', null)).status, 401);
    assert.equal((await assess({ target: '8.8.8.8' }, tok('executive'))).status, 403);
    const a = await assess({ target: '8.8.8.8' });
    assert.equal(a.status, 201);
    assert.equal((await http('GET', `/api/vms/assessments/${(a.data.assessment as Row).id}`, tok('executive'))).status, 200);
    assert.equal((await http('GET', `/api/vms/assessments/${(a.data.assessment as Row).id}`, tok('analyst', 'org-b'))).status, 404);
    assert.equal(((await http('GET', '/api/vms/assessments', tok('analyst', 'org-b'))).data.assessments as Row[]).length, 0);
    assert.equal((await assess({ target: '9.9.9.9' })).status, 403, 'outside every scope entry');
});

test('planning matches the deployed worker: discovery and ports queued; Nuclei and OpenVAS unsupported, never queued', async () => {
    const r = await assess({ target: '8.8.8.8' });
    const a = r.data.assessment as Row;
    const s = steps(a);
    assert.deepEqual([s.discovery.status, s.ports.status, s.vuln_nuclei.status, s.vuln_openvas.status], ['pending', 'pending', 'unsupported', 'unsupported']);
    assert.match(String(s.vuln_nuclei.reason), /No connected scanner worker runs Vulnerabilities \(Nuclei\)/);
    assert.equal(db.tables.vms_scan_jobs.length, 2);
    assert.ok(db.tables.vms_scan_jobs.every((j) => j.assessment_id === a.id && (j.targets as string[])[0] === '8.8.8.8'));
    assert.equal(a.status, 'in_progress');
    // A worker that runs nuclei but lacks OpenVAS: Nuclei queued, OpenVAS unsupported for the tool.
    db.tables.vms_workers[0].kinds = ['discovery', 'ports', 'vuln_nuclei', 'vuln_openvas'];
    const b = steps((await assess({ target: '1.1.1.1' })).data.assessment as Row);
    assert.deepEqual([b.ports.status, b.vuln_nuclei.status], ['not_attempted', 'not_attempted'], 'scope allows discovery only');
    assert.match(String(b.ports.reason), /does not allow port scanning/);
});

test('a private target with no worker route is not attempted, with the reason; nothing is queued', async () => {
    const a = (await assess({ target: '10.88.1.139' })).data.assessment as Row;
    const s = steps(a);
    assert.deepEqual([s.discovery.status, s.ports.status], ['not_attempted', 'not_attempted']);
    assert.match(String(s.ports.reason), /private address and no connected worker declares a route/);
    assert.equal(db.tables.vms_scan_jobs.length, 0);
    assert.equal(a.status, 'not_attempted');
    db.tables.vms_workers[0].networks = ['10.88.0.0/16'];
    db.tables.vms_assessments = [];
    assert.equal(steps((await assess({ target: '10.88.1.139' })).data.assessment as Row).ports.status, 'pending', 'declared route: queued');
});

test('an asset-centric assessment of a Wazuh endpoint uses its recorded address', async () => {
    const id = randomUUID();
    db.tables.vms_assets.push({ id, org_id: ORG, asset_type: 'endpoint', value: 'rayneops', ips: ['10.88.1.139'] });
    const r = await assess({ asset_id: id });
    assert.equal(r.status, 201);
    assert.deepEqual([(r.data.assessment as Row).target, (r.data.assessment as Row).asset_id], ['10.88.1.139', id]);
    assert.equal((await assess({ asset_id: randomUUID() })).status, 404);
});

test('duplicate submissions return the assessment in progress', async () => {
    const one = await assess({ target: '8.8.8.8' });
    const two = await assess({ target: '8.8.8.8' });
    assert.deepEqual([two.status, two.data.existing, (two.data.assessment as Row).id], [200, true, (one.data.assessment as Row).id]);
    assert.equal(db.tables.vms_assessments.length, 1);
    assert.equal(db.tables.vms_scan_jobs.length, 2);
});

test('status is derived from jobs: completed, findings detected, failed, not attempted, partial', async () => {
    const a = (await assess({ target: '8.8.8.8' })).data.assessment as Row;
    const job = (k: string) => db.tables.vms_scan_jobs.find((j) => j.kind === k)!;
    Object.assign(job('discovery'), { status: 'succeeded', started_at: now(), finished_at: now(), summary: { outcome: 'assessed' } });
    Object.assign(job('ports'), { status: 'failed', started_at: now(), finished_at: now(), error: 'nmap exited 1: bad flag' });
    let d = (await http('GET', `/api/vms/assessments/${a.id}`, AN)).data.assessment as Row;
    let s = steps(d);
    assert.deepEqual([s.discovery.status, s.ports.status, d.status], ['completed', 'failed', 'partial']);
    assert.match(String(s.ports.detail), /bad flag/);
    db.tables.vms_finding_evidence.push({ id: randomUUID(), finding_id: 'f1', job_id: job('discovery').id });
    db.tables.vms_findings.push({ id: 'f1', org_id: ORG, title: 'Exposed admin panel', priority: 'P2', status: 'open', evidence_class: 'scanner_check', risk_score: 70 });
    const det = (await http('GET', `/api/vms/assessments/${a.id}`, AN)).data;
    assert.equal(steps(det.assessment as Row).discovery.status, 'findings_detected');
    assert.equal((det.findings as Row[])[0].title, 'Exposed admin panel');
    // Pure rules for the remaining cases.
    const q: Step = { kind: 'ports', decision: 'queued', reason: 'Queued', job_id: 'j', previous_job_ids: [] };
    const j = (b: Row) => ({ id: 'j', kind: 'ports', status: 'failed', started_at: now(), finished_at: now(), error: null, summary: null, progress: null, ...b }) as never;
    assert.equal(stepStatus(q, j({ summary: { outcome: 'no_route' }, error: 'no route' }), 0).status, 'not_attempted', 'worker could not attempt it');
    assert.equal(stepStatus(q, j({ status: 'cancelled', started_at: null }), 0).status, 'not_attempted');
    assert.equal(stepStatus(q, undefined, 0).status, 'failed');
    assert.equal(assessmentStatus(['unsupported', 'not_attempted'], false), 'not_attempted');
    assert.equal(assessmentStatus(['completed', 'findings_detected'], false), 'completed');
    assert.equal(assessmentStatus(['failed', 'unsupported'], false), 'failed');
    d = (await http('GET', '/api/vms/assessments', AN)).data.assessments as unknown as Row;
    s = steps((d as unknown as Row[])[0]);
    assert.equal(s.vuln_openvas.status, 'unsupported');
});

test('retry re-plans only incomplete steps; completed steps and earlier evidence stay', async () => {
    const a = (await assess({ target: '8.8.8.8' })).data.assessment as Row;
    const job = (k: string) => db.tables.vms_scan_jobs.find((x) => x.kind === k && x.assessment_id === a.id)!;
    const disc = job('discovery'); const ports = job('ports');
    Object.assign(disc, { status: 'succeeded', started_at: now(), finished_at: now(), summary: {} });
    Object.assign(ports, { status: 'failed', started_at: now(), finished_at: now(), error: 'worker restarted' });
    db.tables.vms_job_evidence.push({ id: randomUUID(), org_id: ORG, job_id: ports.id, target: '8.8.8.8', tool: 'nmap', truncated: false, bytes: 10, sha256: 'a'.repeat(64), created_at: now(), expires_at: future });
    const r = await http('POST', `/api/vms/assessments/${a.id}/retry`, AN);
    assert.equal(r.status, 200);
    const s = steps(r.data.assessment as Row);
    assert.equal(s.discovery.job_id, disc.id, 'completed step untouched');
    assert.notEqual(s.ports.job_id, ports.id);
    assert.deepEqual(s.ports.previous_job_ids, [ports.id]);
    assert.equal(s.ports.status, 'pending');
    const det = (await http('GET', `/api/vms/assessments/${a.id}`, AN)).data;
    assert.equal((det.evidence as Row[]).length, 1, 'evidence from the earlier attempt is still listed');
    // Retrying again only re-plans the still-unsupported vulnerability steps: they stay unsupported
    // and nothing new is queued; completed steps keep their jobs.
    Object.assign(db.tables.vms_scan_jobs.find((x) => x.id === s.ports.job_id)!, { status: 'succeeded', started_at: now(), finished_at: now(), summary: {} });
    const before = db.tables.vms_scan_jobs.length;
    const again = steps((await http('POST', `/api/vms/assessments/${a.id}/retry`, AN)).data.assessment as Row);
    assert.equal(db.tables.vms_scan_jobs.length, before, 'no job queued for an unsupported step');
    assert.deepEqual([again.discovery.status, again.ports.status, again.vuln_nuclei.status], ['completed', 'completed', 'unsupported']);
});

test('cancel stops queued scans; the report is a Markdown download stating authorisation and what did not run', async () => {
    const a = (await assess({ target: '8.8.8.8' })).data.assessment as Row;
    const rep = await http('GET', `/api/vms/assessments/${a.id}/report`, tok('executive'));
    assert.equal(rep.status, 200);
    assert.match(String(rep.headers.get('content-type')), /text\/markdown/);
    assert.match(String(rep.headers.get('content-disposition')), /attachment; filename="assessment-8\.8\.8\.8-/);
    assert.match(rep.text, /reference "LOA-2026-042"/);
    assert.match(rep.text, /\| Vulnerabilities \(OpenVAS\) \| unsupported \|/);
    assert.match(rep.text, /give no assurance/);
    assert.equal((await http('POST', `/api/vms/assessments/${a.id}/cancel`, AN)).status, 200);
    assert.ok(db.tables.vms_scan_jobs.every((j) => j.status === 'cancelled'));
    assert.equal(((await http('GET', `/api/vms/assessments/${a.id}`, AN)).data.assessment as Row).status, 'cancelled');
    assert.equal((await http('POST', `/api/vms/assessments/${a.id}/retry`, AN)).status, 409);
});

test('exclusions: never planned, never queued, never claimed by a worker that does not enforce them, dropped at ingest', async () => {
    const e = (b: Partial<ScopeEntry>): ScopeEntry => ({ id: 'x', org_id: ORG, kind: 'domain', value: 'example.test', include_subdomains: true, allow_port_scan: true, allow_vuln_scan: true, status: 'active', expires_at: future, exclusions: ['.legacy.example.test', 'pay.example.test'], ...b });
    assert.equal(coveringScope({ type: 'host', value: 'www.example.test' }, [e({})], 'ports') !== null, true);
    for (const h of ['pay.example.test', 'legacy.example.test', 'a.legacy.example.test']) assert.equal(coveringScope({ type: 'host', value: h }, [e({})], 'passive'), null, h);
    assert.equal(isExcluded({ type: 'ip', value: '203.0.113.5' }, ['203.0.113.0/29']), true);
    assert.equal(isExcluded({ type: 'ip', value: '203.0.113.5' }, ['203.0.113.0/30']), false, '/30 stops at .3');
    assert.deepEqual([normalizeExclusion('.Legacy.Example.test'), normalizeExclusion('203.0.113.0/30'), normalizeExclusion('*.x')], ['.legacy.example.test', '203.0.113.0/30', null]);

    assert.equal((await assess({ target: '203.0.113.5' })).status, 403, 'excluded target');
    // Not excluded, but the scope has exclusions and the worker does not enforce them: unsupported.
    db.tables.vms_workers[0].networks = ['203.0.113.0/24'];
    let s = steps((await assess({ target: '203.0.113.6' })).data.assessment as Row);
    assert.equal(s.ports.status, 'unsupported');
    assert.match(String(s.ports.reason), /enforces them \(worker 1\.4\.0 or later\)/);
    db.tables.vms_workers[0].features = ['exclusions'];
    db.tables.vms_assessments = [];
    s = steps((await assess({ target: '203.0.113.6' })).data.assessment as Row);
    assert.equal(s.ports.status, 'pending');
    assert.equal((await http('POST', '/api/vms/scans', tok('soc_manager'), { scope_id: RANGE, kind: 'ports', targets: ['203.0.113.0/28'] })).status, 400, 'no whole-range sweep over exclusions');

    // Claim gating: the old worker (no features) gets nothing and the job goes back unchanged.
    db.tables.vms_workers[0].features = [];
    const portsJob = db.tables.vms_scan_jobs.find((j) => j.kind === 'ports')!;
    const before = portsJob.attempts;
    const c = await http('POST', '/api/vms/worker/claim', WT, { worker_id: 'vps3-demo-worker', kinds: ['ports'] });
    assert.equal(c.data.job, null);
    assert.match(String(c.data.notice), /enforces scope exclusions/);
    assert.deepEqual([portsJob.status, portsJob.worker_id, portsJob.attempts], ['queued', null, before]);
    db.tables.vms_workers[0].features = ['exclusions'];
    const ok = await http('POST', '/api/vms/worker/claim', WT, { worker_id: 'vps3-demo-worker', kinds: ['ports'] });
    assert.equal((ok.data.job as Row).id, portsJob.id);
    assert.deepEqual(((ok.data.scopes as Row[]).find((x) => x.value === '203.0.113.0/28') as Row).exclusions, ['203.0.113.5']);
    // A result for the excluded address is dropped at ingest.
    const r = await http('POST', `/api/vms/worker/jobs/${portsJob.id}/results`, WT, { worker_id: 'vps3-demo-worker', observations: [{ type: 'service', host: '203.0.113.5', port: 22, protocol: 'tcp', state: 'open', source: 'nmap' }] });
    assert.deepEqual([r.data.accepted, r.data.rejected_out_of_scope], [0, 1]);
});

test('before the P13 SQL: a clear 503; the rest of VMS keeps working', async () => {
    (db.tables as Record<string, Row[] | null>).vms_assessments = null;
    const r = await assess({ target: '8.8.8.8' });
    assert.equal(r.status, 503);
    assert.match(String(r.data.error), /2026-10-20_p13_vms_assessments\.sql/);
    assert.equal((await http('GET', '/api/vms/assessments', AN)).status, 503);
    assert.equal((await http('POST', '/api/vms/scans', tok('soc_manager'), { scope_id: PUB, kind: 'discovery' })).status, 201);
    db.tables.vms_assessments = [];
});
