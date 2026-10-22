// Phase P22: OpenVAS / Greenbone results through the worker API into VMS findings. The observations
// are exactly what the worker's parser produces from a representative GMP report
// (fixtures/openvas-observations.json, kept in step by infra/vms-worker/test_openvas_report.py).
// Covers the execution policy (switch + approved scopes, at queue and at claim), ingestion of every
// reported field, deduplication and history across scans, filling what a first detection lacked,
// EPSS/KEV/criticality enrichment kept apart from the CVSS severity, empty reports, failed jobs,
// invalid and out-of-scope results, and tenant isolation. Fake PostgREST; nothing is scanned.
process.env.JWT_SECRET = 'openvas-ingest-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'VMS_WORKER_TOKEN', 'VMS_OPENVAS_ENABLED', 'VMS_OPENVAS_SCOPE_IDS', 'NVIDIA_API_KEY', 'WAZUH_HOST']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { join } from 'path';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import vmsRouter from '../vms';
import vmsFindingsRouter from '../vmsFindings';
import vmsWorkerRouter from '../vmsWorker';
import vmsOperationsRouter, { engineStatus } from '../vmsOperations';
import { getAuditLog } from '../../lib/audit';

const A = 'org-a';
const B = 'org-b';
const WT = 'w'.repeat(40);
const OBS: Row[] = JSON.parse(readFileSync(join(__dirname, 'fixtures', 'openvas-observations.json'), 'utf8'));
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = A) => jwt.sign({ sub: `${role}-${org}`, email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
async function http(method: string, path: string, bearer?: string, body?: unknown) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const r = await fetch(`${base}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const worker = (path: string, body: unknown) => http('POST', `/api/vms/worker${path}`, WT, body);
const future = new Date(Date.now() + 30 * 86_400_000).toISOString();
let seq = 0;
const ts = () => new Date(Date.now() + ++seq).toISOString();
let hostScope: { id: string }, netScope: { id: string }, betaScope: { id: string };

before(async () => {
    db = await startFakePostgrest(
        { organisations: [{ id: 'oa', slug: A }, { id: 'ob', slug: B }], vms_scopes: [], vms_scan_jobs: [], vms_assets: [], vms_services: [], vms_findings: [], vms_finding_evidence: [], vms_finding_events: [], vms_remediation_tasks: [], cve_intel: [], vms_asset_events: [], vms_workers: [], vms_job_evidence: [], audit_log: [], org_access_audit: [], staff_org_assignments: [], vms_wazuh_sync: [], cnii_org_profiles: [], vms_risk_snapshots: [] },
        {},
        {
            vms_scopes: { status: 'active', approved_at: new Date().toISOString(), exclusions: [] },
            vms_scan_jobs: { status: 'queued', attempts: 0, cancel_requested: false, progress: {}, purpose: 'assessment', get requested_at() { return ts(); } } as Row,
            vms_assets: { status: 'active', exposure: 'internet', criticality: 'medium', hostnames: [], ips: [], dns: {}, discovery_sources: [] },
            vms_findings: { status: 'open', detected_by: [], cve_ids: [], references_urls: [], risk_factors: {}, due_manual: false },
            cve_intel: { kev: false },
        },
        {
            vms_claim_job: (args, tables) => {
                const j = tables.vms_scan_jobs.filter((x) => x.status === 'queued' && (args.p_kinds as string[]).includes(String(x.kind))).sort((a, b) => String(a.requested_at).localeCompare(String(b.requested_at)))[0];
                if (!j) return [];
                Object.assign(j, { status: 'running', worker_id: args.p_worker, started_at: new Date().toISOString(), heartbeat_at: new Date().toISOString(), attempts: 1 });
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
    app.use('/api/vms', requireAuth, vmsFindingsRouter);
    app.use('/api/vms', requireAuth, vmsOperationsRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(async () => {
    for (const t of Object.keys(db.tables)) if (t !== 'organisations') db.tables[t].length = 0;
    const mk = async (org: string, kind: string, value: string) => (await http('POST', '/api/vms/scopes', tok('soc_manager', org), { kind, value, allow_port_scan: true, allow_vuln_scan: true, authorization_reference: 'LOA-2026-07 signed by asset owner', expires_at: future })).data.scope;
    hostScope = await mk(A, 'domain', 'app.qa-alpha.test');
    netScope = await mk(A, 'cidr', '192.0.2.0/24');
    betaScope = await mk(B, 'cidr', '198.51.100.0/24');
    process.env.VMS_OPENVAS_ENABLED = 'true';
    process.env.VMS_OPENVAS_SCOPE_IDS = [hostScope.id, netScope.id].join(',');
});

async function queue(scopeId: string, targets: string[], org = A) {
    return http('POST', '/api/vms/scans', tok('analyst', org), { scope_id: scopeId, kind: 'vuln_openvas', targets });
}
/** One OpenVAS job: queued under the policy, claimed, results posted, completed. */
async function runOpenvas(obs: Row[], opts: { status?: 'succeeded' | 'failed'; error?: string; scopeId?: string; targets?: string[] } = {}) {
    const q = await queue(opts.scopeId ?? netScope.id, opts.targets ?? ['192.0.2.10', '192.0.2.20']);
    assert.equal(q.status, 201, JSON.stringify(q.data));
    const c = await worker('/claim', { worker_id: 'vps-worker', kinds: ['vuln_openvas'] });
    const id = c.data.job.id;
    const r = obs.length ? await worker(`/jobs/${id}/results`, { worker_id: 'vps-worker', observations: obs }) : { data: null };
    await worker(`/jobs/${id}/complete`, { worker_id: 'vps-worker', status: opts.status ?? 'succeeded', ...(opts.error ? { error: opts.error } : {}), summary: { outcome: 'assessed', openvas: { findings: obs.length } } });
    return { id, results: r.data };
}
const findingsOf = (org = A) => db.tables.vms_findings.filter((f) => f.org_id === org);

// ── Execution policy ──────────────────────────────────────────────────────────────────────────
test('policy: OpenVAS is refused (and audited) unless switched on and the scope is approved', async () => {
    delete process.env.VMS_OPENVAS_ENABLED;
    let r = await queue(netScope.id, ['192.0.2.10']);
    assert.equal(r.status, 409);
    assert.match(r.data.error, /switched off on this server/);
    process.env.VMS_OPENVAS_ENABLED = 'true';
    process.env.VMS_OPENVAS_SCOPE_IDS = hostScope.id;
    r = await queue(netScope.id, ['192.0.2.10']);
    assert.equal(r.status, 409);
    assert.match(r.data.error, /not approved for OpenVAS/);
    assert.equal(db.tables.vms_scan_jobs.length, 0, 'nothing was queued');
    assert.ok(getAuditLog(500).filter((a) => a.action === 'VMS_SCAN_REFUSED' && a.resource_id === netScope.id).length >= 2, 'each refusal is audited');
    // Nuclei on the same scope is unaffected: the policy is specific to OpenVAS.
    assert.equal((await http('POST', '/api/vms/scans', tok('analyst'), { scope_id: netScope.id, kind: 'vuln_nuclei', targets: ['192.0.2.10'] })).status, 201);
});

test('policy: a job queued while allowed is not handed out after the policy is tightened', async () => {
    assert.equal((await queue(netScope.id, ['192.0.2.10'])).status, 201);
    process.env.VMS_OPENVAS_ENABLED = 'false';
    const c = await worker('/claim', { worker_id: 'vps-worker', kinds: ['vuln_openvas'] });
    assert.equal(c.data.job, null);
    assert.match(c.data.notice, /switched off/);
    const job = db.tables.vms_scan_jobs[0];
    assert.equal(job.status, 'failed');
    assert.match(String(job.error), /^Not run: OpenVAS scanning is switched off/);
});

test('policy: the engine never shows as available while OpenVAS is switched off', () => {
    const w = [{ worker_id: 'w', online: true, kinds: ['vuln_openvas'], tools: { openvas: true }, tool_versions: {}, last_seen_at: new Date().toISOString() }] as never;
    process.env.VMS_OPENVAS_ENABLED = 'false';
    const off = engineStatus(w).find((e) => e.id === 'openvas')!;
    assert.equal(off.state, 'not_enabled');
    assert.match(off.note, /Switched off on this server/);
    process.env.VMS_OPENVAS_ENABLED = 'true';
    assert.equal(engineStatus(w).find((e) => e.id === 'openvas')!.state, 'available');
});

test('policy: a scope that does not allow vulnerability scans is refused even when approved for OpenVAS', async () => {
    const passive: { id: string } = (await http('POST', '/api/vms/scopes', tok('soc_manager'), { kind: 'ip', value: '192.0.2.50', allow_port_scan: true, allow_vuln_scan: false, authorization_reference: 'LOA ports only', expires_at: future })).data.scope;
    process.env.VMS_OPENVAS_SCOPE_IDS = passive.id;
    assert.ok((await queue(passive.id, ['192.0.2.50'])).status >= 400);
});

// ── Ingestion ─────────────────────────────────────────────────────────────────────────────────
test('ingestion: every reported field reaches the finding and its evidence', async () => {
    const { results } = await runOpenvas(OBS);
    assert.equal(results.accepted, 4, JSON.stringify(results));
    assert.equal(results.new_findings, 4);
    const fs = findingsOf();
    const tls = fs.find((f) => f.rule_id === '1.3.6.1.4.1.25623.1.0.108031')!;
    assert.deepEqual(tls.cve_ids, ['CVE-2016-2183', 'CVE-2016-6329']);
    assert.equal(tls.scanner_cvss, 7.5);
    assert.equal(tls.scanner_severity, 'high');
    assert.equal(tls.asset_value, 'app.qa-alpha.test');
    assert.equal(tls.port, 443);
    assert.equal(tls.protocol, 'tcp');
    assert.equal(tls.title, 'SSL/TLS: Report Vulnerable Cipher Suites for HTTPS');
    assert.match(String(tls.description), /TLS_RSA_WITH_3DES_EDE_CBC_SHA/);
    assert.match(String(tls.remediation), /Disable the reported vulnerable cipher suites/);
    assert.deepEqual(tls.detected_by, ['openvas']);
    assert.equal(tls.source_class, 'active_scan');
    assert.deepEqual(tls.references_urls, ['https://sweet32.info/']);
    const ev = db.tables.vms_finding_evidence.find((e) => e.finding_id === tls.id)!;
    assert.equal(ev.source, 'openvas');
    const e = ev.evidence as Row;
    assert.equal(e.cvss_version, '3.1');
    assert.equal(e.cvss_vector, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N');
    assert.equal(e.oid, '1.3.6.1.4.1.25623.1.0.108031');
    assert.equal(e.qod, '98');
    assert.equal(e.scan_started_at, '2026-10-21T09:00:04Z');
    assert.equal(e.scan_ended_at, '2026-10-21T09:41:37Z');
    assert.equal(e.report_id, 'rep-fixture-0001');
    assert.equal(ev.matched_at, 'app.qa-alpha.test:443/tcp');
    // An ICMP check has no port; the CVSS v2 score of an older NVT is kept as reported.
    const icmp = fs.find((f) => f.rule_id === '1.3.6.1.4.1.25623.1.0.103190')!;
    assert.equal(icmp.port, null);
    assert.equal(icmp.scanner_cvss, 2.1);
    assert.equal(((db.tables.vms_finding_evidence.find((x) => x.finding_id === icmp.id)!.evidence) as Row).cvss_version, '2.0');
    // Assets were created for the scanned hosts and linked.
    assert.deepEqual(db.tables.vms_assets.filter((a) => a.org_id === A).map((a) => a.value).sort(), ['192.0.2.20', 'app.qa-alpha.test']);
    assert.equal(db.tables.vms_finding_events.filter((x) => x.action === 'detected' && x.actor === 'scanner:openvas').length, 4);
});

test('ingestion: the same report again deduplicates, keeps history and does not re-detect', async () => {
    await runOpenvas(OBS);
    const first = Object.fromEntries(findingsOf().map((f) => [f.id, f.first_seen]));
    const { results } = await runOpenvas(OBS);
    assert.equal(results.new_findings, 0);
    assert.equal(findingsOf().length, 4);
    for (const f of findingsOf()) assert.equal(f.first_seen, first[f.id as string], 'first seen never moves');
    assert.equal(db.tables.vms_finding_evidence.length, 8, 'one evidence row per detection: the history across scans');
    assert.equal(db.tables.vms_finding_events.filter((x) => x.action === 'detected').length, 4);
});

test('ingestion: a finding verified fixed and found again is reopened', async () => {
    await runOpenvas(OBS);
    const ssh = findingsOf().find((f) => f.rule_id === '1.3.6.1.4.1.25623.1.0.104879')!;
    Object.assign(ssh, { status: 'verified', verified_at: new Date().toISOString() });
    const { results } = await runOpenvas(OBS);
    assert.equal(results.reopened, 1);
    assert.equal(findingsOf().find((f) => f.id === ssh.id)!.status, 'reopened');
});

test('ingestion: what a first detection lacked is filled from a later one, and the risk is recomputed', async () => {
    const bare = { ...OBS[1], cvss: null, cvss_version: null, cvss_vector: null, description: null, remediation: null, severity: 'medium' };
    await runOpenvas([bare]);
    const f0 = findingsOf()[0];
    assert.equal(f0.scanner_cvss, null);
    const before = f0.risk_score;
    await runOpenvas([OBS[1]]);
    const f1 = findingsOf()[0];
    assert.equal(f1.scanner_cvss, 9.8);
    assert.equal(f1.scanner_severity, 'critical');
    assert.match(String(f1.remediation), /9\.3p2/);
    assert.ok(Number(f1.risk_score) > Number(before), `risk ${before} → ${f1.risk_score}`);
});

test('enrichment: EPSS, KEV and asset criticality raise the contextual risk; the CVSS severity stays as reported', async () => {
    db.tables.cve_intel.push({ cve_id: 'CVE-2023-38408', kev: true, kev_checked_at: new Date().toISOString(), epss_score: 0.71, cvss_score: 9.8 });
    await runOpenvas(OBS);
    const ssh = findingsOf().find((f) => f.rule_id === '1.3.6.1.4.1.25623.1.0.104879')!;
    assert.equal(ssh.scanner_cvss, 9.8, 'the scanner CVSS is kept');
    assert.equal(ssh.scanner_severity, 'critical');
    assert.equal(ssh.priority, 'P1', 'KEV on an internet-facing asset');
    const rf = ssh.risk_factors as Row;
    assert.match(String((rf.exploitation as Row).basis), /KEV/);
    // No intelligence for a CVE: exploitation is unknown and scores 0 — never invented.
    const jq = findingsOf().find((f) => f.rule_id === '1.3.6.1.4.1.25623.1.0.143812')!;
    assert.equal(((jq.risk_factors as Row).exploitation as Row).points, 0);
    assert.notEqual(jq.risk_score, jq.scanner_cvss);
    // Asset criticality is part of the score: raising it raises the risk.
    const asset = db.tables.vms_assets.find((a) => a.value === '192.0.2.20')!;
    const low = Number(jq.risk_score);
    await http('PATCH', `/api/vms/assets/${asset.id}`, tok('analyst'), { criticality: 'critical' });
    const { recomputeRisk } = await import('../../services/vmsFindings');
    await recomputeRisk({ assetId: String(asset.id) });
    assert.ok(Number(findingsOf().find((f) => f.id === jq.id)!.risk_score) > low);
});

test('empty report and failed scan: no finding is invented', async () => {
    const empty = await runOpenvas([]);
    assert.equal(findingsOf().length, 0);
    assert.equal(db.tables.vms_scan_jobs.find((j) => j.id === empty.id)!.status, 'succeeded');
    const failed = await runOpenvas([], { status: 'failed', error: 'Greenbone rejected GVM_USER / GVM_PASSWORD (authentication failed)' });
    const job = db.tables.vms_scan_jobs.find((j) => j.id === failed.id)!;
    assert.equal(job.status, 'failed');
    assert.match(String(job.error), /authentication failed/);
    assert.equal(findingsOf().length, 0);
});

test('invalid and out-of-scope results are refused and counted, never stored', async () => {
    const outside = { ...OBS[0], host: '203.0.113.99', matched_at: '203.0.113.99:23/tcp' };
    const broken = { ...OBS[0], cvss: 11 };
    const { results } = await runOpenvas([outside, broken, OBS[0]]);
    assert.equal(results.accepted, 1);
    assert.equal(results.rejected_out_of_scope, 1);
    assert.equal(results.rejected_invalid, 1);
    assert.ok(!db.tables.vms_assets.some((a) => a.value === '203.0.113.99'));
});

test('tenant isolation: findings land in the job\'s organisation only and other tenants never see them', async () => {
    await runOpenvas(OBS);
    process.env.VMS_OPENVAS_SCOPE_IDS += `,${betaScope.id}`;
    // A job of organisation B reporting organisation A's hosts: outside B's scope, nothing stored.
    const q = await queue(betaScope.id, ['198.51.100.7'], B);
    assert.equal(q.status, 201);
    const c = await worker('/claim', { worker_id: 'vps-worker', kinds: ['vuln_openvas'] });
    const r = await worker(`/jobs/${c.data.job.id}/results`, { worker_id: 'vps-worker', observations: OBS });
    assert.equal(r.data.accepted, 0);
    assert.equal(findingsOf(B).length, 0);
    assert.equal((await http('GET', '/api/vms/findings?status=all', tok('analyst', B))).data.findings.length, 0);
    const own = (await http('GET', '/api/vms/findings?status=all', tok('executive'))).data.findings;
    assert.equal(own.length, 4);
    assert.equal((await http('GET', `/api/vms/findings/${own[0].id}`, tok('analyst', B))).status, 404);
});

test('the finding detail serves the scanner CVSS (with version) next to, not instead of, the NovrSOC risk score', async () => {
    await runOpenvas(OBS);
    const tls = findingsOf().find((f) => f.rule_id === '1.3.6.1.4.1.25623.1.0.108031')!;
    const d = await http('GET', `/api/vms/findings/${tls.id}`, tok('analyst'));
    assert.equal(d.status, 200);
    assert.equal(d.data.finding.scanner_cvss, 7.5);
    assert.equal(typeof d.data.finding.risk_score, 'number');
    assert.equal(d.data.scanner_cvss.version, '3.1');
    assert.equal(d.data.scanner_cvss.vector, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N');
    assert.equal(d.data.scanner_cvss.source, 'openvas');
});

// The end-to-end CNII National data-path test (P23) is not part of this deployment: CNII National
// (routes/cniiNational.ts) is not in the deployed backend. It runs on main.

test('verification: an OpenVAS finding is rescanned only under the OpenVAS policy, and verified only when the rescan reached the host', async () => {
    await runOpenvas(OBS);
    const ssh = findingsOf().find((f) => f.rule_id === '1.3.6.1.4.1.25623.1.0.104879')!;
    assert.equal((await http('PATCH', `/api/vms/findings/${ssh.id}`, tok('analyst'), { status: 'fixed_pending_verification', note: 'patched to 9.3p2' })).status, 200);
    delete process.env.VMS_OPENVAS_ENABLED;
    const refused = await http('POST', `/api/vms/findings/${ssh.id}/verify`, tok('analyst'), {});
    assert.equal(refused.status, 409);
    assert.match(refused.data.error, /switched off/);
    process.env.VMS_OPENVAS_ENABLED = 'true';
    const ok = await http('POST', `/api/vms/findings/${ssh.id}/verify`, tok('analyst'), {});
    assert.equal(ok.status, 201, JSON.stringify(ok.data));
    assert.equal(ok.data.scan.kind, 'vuln_openvas');
    assert.equal(ok.data.scan.purpose, 'verification');
    const c = await worker('/claim', { worker_id: 'vps-worker', kinds: ['vuln_openvas'] });
    assert.deepEqual(c.data.job.options.finding_ids, [ssh.id]);
    // A rescan that did not show it reached the host verifies nothing.
    await worker(`/jobs/${c.data.job.id}/complete`, { worker_id: 'vps-worker', status: 'succeeded', summary: { outcome: 'unreachable', target_outcomes: { 'app.qa-alpha.test': { outcome: 'unreachable', reason: 'no answer' } } } });
    assert.equal(findingsOf().find((f) => f.id === ssh.id)!.status, 'fixed_pending_verification');
    // One that reached it and no longer detects the issue verifies it.
    await http('POST', `/api/vms/findings/${ssh.id}/verify`, tok('analyst'), {});
    const c2 = await worker('/claim', { worker_id: 'vps-worker', kinds: ['vuln_openvas'] });
    await worker(`/jobs/${c2.data.job.id}/complete`, { worker_id: 'vps-worker', status: 'succeeded', summary: { outcome: 'assessed', target_outcomes: { 'app.qa-alpha.test': { outcome: 'reachable_open', reason: '22/tcp open' } } } });
    const done = findingsOf().find((f) => f.id === ssh.id)!;
    assert.equal(done.status, 'verified');
    assert.ok(db.tables.vms_finding_events.some((e) => e.finding_id === ssh.id && e.action === 'verified'));
});
