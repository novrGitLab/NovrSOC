// Phase P5 VMS Release 2: risk engine, CVE-intel parsers, findings ingest (dedupe across scanners,
// reopen, scope), verification (evidence only), manual transitions, Wazuh sync (guarded absence),
// the findings API, case promotion and tenant isolation. Fake PostgREST, fake indexer, no network.
process.env.JWT_SECRET = 'vms-findings-test-secret';
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
import vmsFindingsRouter from '../vmsFindings';
import vmsWorkerRouter from '../vmsWorker';
import { riskScore } from '../../lib/riskScore';
import { parseKev, parseEpss, parseNvd } from '../../services/cveIntel';
import { recomputeRisk } from '../../services/vmsFindings';
import { syncWazuhVulnerabilities } from '../../services/wazuhVulnSync';

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
const worker = (path: string, body: unknown) => http('POST', `/api/vms/worker${path}`, WT, body);
const future = new Date(Date.now() + 30 * 86_400_000).toISOString();
let seq = 0;
const ts = () => new Date(Date.now() + ++seq).toISOString();

before(async () => {
    let caseNo = 0;
    db = await startFakePostgrest(
        { vms_scopes: [], vms_scan_jobs: [], vms_assets: [], vms_services: [], vms_findings: [], vms_finding_evidence: [], vms_finding_events: [], vms_remediation_tasks: [], cve_intel: [], cases: [], case_timeline: [], wazuh_group_org_map: [], vms_wazuh_sync: [], vms_asset_events: [] },
        {},
        {
            vms_scopes: { status: 'active', approved_at: new Date().toISOString() },
            vms_scan_jobs: { status: 'queued', attempts: 0, cancel_requested: false, progress: {}, purpose: 'assessment', get requested_at() { return ts(); } } as Row,
            vms_assets: { status: 'active', exposure: 'internet', criticality: 'medium', hostnames: [], ips: [], dns: {}, discovery_sources: [] },
            vms_findings: { status: 'open', detected_by: [], cve_ids: [], references_urls: [], risk_factors: {}, due_manual: false },
            cve_intel: { kev: false },
            vms_remediation_tasks: { status: 'todo' },
            cases: { status: 'open', get case_number() { return `CASE-${++caseNo}`; } } as Row,
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
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => { for (const t of Object.keys(db.tables)) db.tables[t].length = 0; });

async function scope(over: Row = {}) {
    return (await http('POST', '/api/vms/scopes', MGR, { kind: 'domain', value: 'example.test', allow_port_scan: true, allow_vuln_scan: true, authorization_reference: 'LOA-1', expires_at: future, ...over })).data.scope;
}
async function runJob(kind: string, obs: Row[], status: 'succeeded' | 'failed' = 'succeeded', summary: Row | null = null) {
    const c = await worker('/claim', { worker_id: 'w1', kinds: [kind] });
    const id = c.data.job.id;
    const r = await worker(`/jobs/${id}/results`, { worker_id: 'w1', observations: obs });
    await worker(`/jobs/${id}/complete`, { worker_id: 'w1', status, summary });
    return { id, results: r.data };
}
const nuclei = (over: Row = {}) => ({ type: 'finding', host: 'api.example.test', port: 443, protocol: 'tcp', scanner: 'nuclei', rule_id: 'CVE-2023-12345', title: 'Example RCE', severity: 'critical', cve_ids: ['CVE-2023-12345'], cvss: 9.8, matched_at: 'https://api.example.test/', evidence: { extracted: ['1.2.3'], note: 'password=hunter2' }, ...over });

// ── Units ────────────────────────────────────────────────────────────────────────────────────
test('risk engine: documented weights, KEV on the internet is P1, unknown exploitation scores 0, info stays P4', () => {
    const kev = riskScore({ scanner_severity: 'medium', cvss: 6.5, kev: true, epss: null, exposure: 'internet', criticality: 'low' });
    assert.equal(kev.priority, 'P1');
    assert.match(String(kev.factors.rule), /KEV on an internet-facing/);
    const crit = riskScore({ scanner_severity: 'critical', cvss: 9.8, kev: false, epss: 0.9, exposure: 'internet', criticality: 'critical' });
    assert.equal(crit.score, Math.round(98 * 0.45 + 90 * 0.3 + 100 * 0.15 + 100 * 0.1));
    assert.equal(crit.priority, 'P1');
    const unk = riskScore({ scanner_severity: 'high', cvss: null, kev: null, epss: null, exposure: 'internal', criticality: 'medium' });
    assert.equal((unk.factors.exploitation as Row).points, 0);
    assert.match(String((unk.factors.exploitation as Row).basis), /unknown/);
    assert.equal(riskScore({ scanner_severity: 'info', cvss: null, kev: null, epss: null, exposure: 'internet', criticality: 'critical' }).priority, 'P4');
    assert.equal(crit.due_days, 2);
});

test('intel parsers: KEV, EPSS and NVD take only well-formed values', () => {
    const kev = parseKev({ vulnerabilities: [{ cveID: 'CVE-2021-44228', dateAdded: '2021-12-10', dueDate: '2021-12-24', requiredAction: 'Apply updates', knownRansomwareCampaignUse: 'Known' }, { cveID: 'nope' }] });
    assert.deepEqual([...kev.keys()], ['CVE-2021-44228']);
    assert.equal(kev.get('CVE-2021-44228')!.ransomware, 'Known');
    assert.throws(() => parseKev({}));
    const epss = parseEpss({ data: [{ cve: 'CVE-2021-44228', epss: '0.97565', percentile: '0.99995', date: '2026-10-13' }, { cve: 'CVE-2020-1', epss: '7' }] });
    assert.deepEqual(epss.get('CVE-2021-44228'), { epss: 0.97565, percentile: 0.99995, date: '2026-10-13' });
    assert.equal(epss.size, 1);
    const nvd = parseNvd({ vulnerabilities: [{ cve: { id: 'CVE-2021-44228', published: '2021-12-10T10:15:09.143', lastModified: '2025-01-01T00:00:00.000',
        descriptions: [{ lang: 'es', value: 'x' }, { lang: 'en', value: 'Log4j JNDI' }],
        metrics: { cvssMetricV31: [{ type: 'Secondary', cvssData: { baseScore: 9.0, version: '3.1' } }, { type: 'Primary', cvssData: { baseScore: 10.0, vectorString: 'CVSS:3.1/AV:N', version: '3.1' } }], cvssMetricV2: [{ cvssData: { baseScore: 9.3 } }] },
        weaknesses: [{ description: [{ value: 'CWE-502' }, { value: 'NVD-CWE-noinfo' }] }], references: [{ url: 'https://logging.apache.org' }, { url: 'javascript:x' }] } }] }, 'CVE-2021-44228');
    assert.deepEqual([nvd!.description, nvd!.cvss_score, nvd!.cvss_version, nvd!.cwe_ids, nvd!.references_urls], ['Log4j JNDI', 10, '3.1', ['CWE-502'], ['https://logging.apache.org']]);
    assert.equal(parseNvd({ vulnerabilities: [] }, 'CVE-2021-44228'), null);
});

// ── Ingest and lifecycle ────────────────────────────────────────────────────────────────────
test('vuln scans need vuln authorisation; findings dedupe across scanners and keep each sighting', async () => {
    const noVuln = await scope({ value: 'other.test', allow_vuln_scan: false });
    assert.equal((await http('POST', '/api/vms/scans', AN, { scope_id: noVuln.id, kind: 'vuln_nuclei' })).status, 403);
    const s = await scope();
    assert.equal((await http('POST', '/api/vms/scans', AN, { scope_id: s.id, kind: 'vuln_nuclei' })).status, 201);
    const r1 = await runJob('vuln_nuclei', [nuclei(), nuclei({ host: 'evil.test' }), { type: 'host', host: 'api.example.test', source: 'httpx' }]);
    assert.deepEqual([r1.results.accepted, r1.results.new_findings, r1.results.rejected_out_of_scope, r1.results.rejected_invalid], [1, 1, 1, 1]);
    await http('POST', '/api/vms/scans', AN, { scope_id: s.id, kind: 'vuln_openvas' });
    await runJob('vuln_openvas', [{ ...nuclei(), scanner: 'openvas', rule_id: '1.3.6.1.4.1.25623.1.0.9', title: 'Same issue (OpenVAS)', severity: 'high' }]);
    assert.equal(db.tables.vms_findings.length, 1, 'same asset + port + CVE = one finding');
    const f = db.tables.vms_findings[0];
    assert.deepEqual([...(f.detected_by as string[])].sort(), ['nuclei', 'openvas']);
    assert.equal(f.scanner_severity, 'critical', 'highest severity kept');
    assert.equal(db.tables.vms_finding_evidence.length, 2);
    assert.ok(!JSON.stringify(db.tables.vms_finding_evidence).includes('hunter2'), 'evidence redacted');
    assert.equal(f.source_class, 'active_scan');
    assert.ok(f.priority && f.due_at && f.risk_factors);
    assert.deepEqual(db.tables.cve_intel.map((c) => c.cve_id), ['CVE-2023-12345']);
});

test('people cannot verify by hand; verification needs a rescan, and only a successful one counts', async () => {
    const s = await scope();
    await http('POST', '/api/vms/scans', AN, { scope_id: s.id, kind: 'vuln_nuclei' });
    await runJob('vuln_nuclei', [nuclei()]);
    const id = db.tables.vms_findings[0].id;
    assert.equal((await http('PATCH', `/api/vms/findings/${id}`, AN, { status: 'verified' })).status, 409);
    assert.equal((await http('POST', `/api/vms/findings/${id}/verify`, AN)).status, 409, 'mark fixed first');
    assert.equal((await http('PATCH', `/api/vms/findings/${id}`, AN, { status: 'risk_accepted' })).status, 400, 'a reason is required');
    assert.equal((await http('PATCH', `/api/vms/findings/${id}`, AN, { status: 'fixed_pending_verification', note: 'patched to 1.2.4' })).status, 200);

    // A failed verification scan verifies nothing.
    const q1 = await http('POST', `/api/vms/findings/${id}/verify`, AN);
    assert.equal(q1.status, 201);
    assert.deepEqual(q1.data.scan.options.templates, ['CVE-2023-12345'], 'the same check is rerun');
    assert.equal(q1.data.scan.purpose, 'verification');
    await runJob('vuln_nuclei', [], 'failed');
    assert.equal(db.tables.vms_findings[0].status, 'fixed_pending_verification');

    // Still present → reopened.
    await http('POST', `/api/vms/findings/${id}/verify`, AN);
    await runJob('vuln_nuclei', [nuclei()]);
    assert.equal(db.tables.vms_findings[0].status, 'reopened');

    // Fixed again; a clean rescan that does not show it reached the host proves nothing (P16).
    await http('PATCH', `/api/vms/findings/${id}`, AN, { status: 'fixed_pending_verification' });
    await http('POST', `/api/vms/findings/${id}/verify`, AN);
    await runJob('vuln_nuclei', []);
    assert.equal(db.tables.vms_findings[0].status, 'fixed_pending_verification', 'no reachability evidence: not verified');
    await http('POST', `/api/vms/findings/${id}/verify`, AN);
    await runJob('vuln_nuclei', [], 'succeeded', { outcome: 'unreachable', target_outcomes: { 'api.example.test': { outcome: 'unreachable', reason: 'no answer on 443' } } });
    assert.equal(db.tables.vms_findings[0].status, 'fixed_pending_verification', 'host did not answer: not verified');
    assert.ok(db.tables.vms_finding_events.some((e) => e.action === 'verification' && /did not show it reached api\.example\.test \(unreachable\)/.test(String(e.details))));

    // A clean rescan that reached the host → verified.
    await http('POST', `/api/vms/findings/${id}/verify`, AN);
    await runJob('vuln_nuclei', [], 'succeeded', { outcome: 'assessed', target_outcomes: { 'api.example.test': { outcome: 'reachable_open', reason: '443 open' } } });
    const f = db.tables.vms_findings[0];
    assert.equal(f.status, 'verified');
    assert.ok(f.verified_at && f.verification_job_id);
    const actions = db.tables.vms_finding_events.map((e) => e.action);
    for (const a of ['detected', 'status', 'verification_queued', 'reopened', 'verified']) assert.ok(actions.includes(a), a);
    // Seen again after verification → reopened.
    await http('POST', '/api/vms/scans', AN, { scope_id: s.id, kind: 'vuln_nuclei' });
    await runJob('vuln_nuclei', [nuclei()]);
    assert.equal(db.tables.vms_findings[0].status, 'reopened');
});

test('risk follows intelligence: a CVE added to KEV raises priority (policy deadline moves; a manual one stays)', async () => {
    const s = await scope();
    await http('POST', '/api/vms/scans', AN, { scope_id: s.id, kind: 'vuln_nuclei' });
    await runJob('vuln_nuclei', [nuclei({ severity: 'medium', cvss: 5.0, rule_id: 'CVE-2024-0001', cve_ids: ['CVE-2024-0001'] })]);
    const f = db.tables.vms_findings[0];
    assert.notEqual(f.priority, 'P1');
    Object.assign(db.tables.cve_intel[0], { kev: true, kev_checked_at: new Date().toISOString() });
    assert.equal(await recomputeRisk({ org: A }), 1);
    assert.equal(f.priority, 'P1', 'KEV on an internet-facing asset');
    assert.ok(db.tables.vms_finding_events.some((e) => e.action === 'risk' && e.to_value === 'P1'));
    await http('PATCH', `/api/vms/findings/${f.id}`, MGR, { due_at: '2030-01-01T00:00:00Z' });
    Object.assign(db.tables.cve_intel[0], { kev: false });
    await recomputeRisk({ org: A });
    assert.equal(f.due_at, '2030-01-01T00:00:00.000Z', 'a person\'s deadline is kept');
});

// ── Wazuh ───────────────────────────────────────────────────────────────────────────────────
test('Wazuh sync: endpoints and findings per org; ambiguous agents skipped; absence closes only with data', async () => {
    db.tables.wazuh_group_org_map.push({ wazuh_group: 'acme', org_id: A }, { wazuh_group: 'beta', org_id: B });
    const agents: Record<string, Row[]> = {
        acme: [{ id: '001', name: 'web-01', status: 'active', ip: '10.0.0.5', group: ['acme'] }, { id: '002', name: 'db-01', status: 'active', ip: '10.0.0.6', group: ['acme'] }, { id: '009', name: 'shared', status: 'active', ip: '10.0.0.9', group: ['acme', 'beta'] }],
        beta: [{ id: '009', name: 'shared', status: 'active', ip: '10.0.0.9', group: ['acme', 'beta'] }],
    };
    let docs: Row[] = [
        { agent: { id: '001', name: 'web-01' }, package: { name: 'openssl', version: '3.0.2' }, vulnerability: { id: 'CVE-2024-1111', severity: 'High', score: { base: 7.5 }, description: 'x' } },
        { agent: { id: '002', name: 'db-01' }, package: { name: 'postgres', version: '14.1' }, vulnerability: { id: 'CVE-2024-2222', severity: 'Critical', score: { base: 9.1 } } },
    ];
    const deps = {
        agentsForGroup: async (g: string) => agents[g] as never,
        search: async (_i: string, body: unknown) => {
            const names = ((body as { query: { bool: { filter: { terms: { 'agent.name': string[] } }[] } } }).query.bool.filter[0].terms['agent.name']);
            const hits = docs.filter((d) => names.includes((d.agent as Row).name as string)).map((d) => ({ _source: d }));
            return { hits: { total: { value: hits.length }, hits } };
        },
    };
    let r = await syncWazuhVulnerabilities(deps);
    const ra = r.find((x) => x.org === A)!;
    assert.deepEqual([ra.agents, ra.ambiguous_agents, ra.new_findings, ra.complete], [2, 1, 2, true]);
    assert.deepEqual(db.tables.vms_assets.filter((a) => a.org_id === A).map((a) => a.value).sort(), ['db-01', 'web-01']);
    assert.ok(db.tables.vms_findings.every((f) => f.source_class === 'wazuh' && f.org_id === A));

    // web-01 patched (still reports another vuln); db-01 returns nothing at all.
    docs = [{ agent: { id: '001', name: 'web-01' }, package: { name: 'curl', version: '7.1' }, vulnerability: { id: 'CVE-2024-3333', severity: 'Low', score: { base: 3.1 } } }];
    r = await syncWazuhVulnerabilities(deps);
    const byCve = (c: string) => db.tables.vms_findings.find((f) => (f.cve_ids as string[]).includes(c))!;
    assert.equal(byCve('CVE-2024-1111').status, 'verified', 'Wazuh returned data for web-01 and no longer lists it');
    assert.equal(byCve('CVE-2024-2222').status, 'open', 'db-01 returned no data: nothing concluded from silence');

    // An incomplete sync (indexer error) closes nothing.
    docs = [];
    const failing = { ...deps, search: async () => { throw new Error('connect ECONNREFUSED'); } };
    r = await syncWazuhVulnerabilities(failing);
    assert.equal(r.find((x) => x.org === A)!.complete, false);
    assert.equal(byCve('CVE-2024-3333').status, 'open');
    const lastComplete = (db.tables.vms_wazuh_sync.find((x) => x.org_id === A)!.last_result as Row).last_complete_at;
    assert.ok(lastComplete, 'the last complete sync time is kept across an incomplete run');

    // P15: error replies and a missing index are incomplete syncs, not "no vulnerabilities".
    for (const reply of [{ error: { type: 'security_exception' }, status: 403 }, { _shards: { total: 0, failed: 0 }, hits: { total: { value: 0 }, hits: [] } }]) {
        r = await syncWazuhVulnerabilities({ ...deps, search: async () => reply as never });
        const x = r.find((y) => y.org === A)!;
        assert.equal(x.complete, false);
        assert.match(x.errors[0], /refused the query|no index matches/);
        assert.equal(x.last_complete_at, lastComplete);
        assert.equal(byCve('CVE-2024-3333').status, 'open', 'nothing concluded');
    }
});

// ── API ──────────────────────────────────────────────────────────────────────────────────────
test('findings API: summary, filters, case promotion without duplicates, tasks, tenant isolation', async () => {
    const s = await scope();
    await http('POST', '/api/vms/scans', AN, { scope_id: s.id, kind: 'vuln_nuclei' });
    await runJob('vuln_nuclei', [nuclei(), nuclei({ port: 22, rule_id: 'ssh-weak-kex', cve_ids: [], cvss: null, severity: 'low', title: 'Weak SSH KEX' })]);
    db.tables.cve_intel.push({ cve_id: 'CVE-2023-12345', kev: true, kev_checked_at: new Date().toISOString() });
    const sum = await http('GET', '/api/vms/findings/summary', tok('executive'));
    assert.deepEqual([sum.data.open, sum.data.known_exploited_open], [2, 1]);
    assert.equal((await http('GET', '/api/vms/findings?kev=true', AN)).data.findings.length, 1);
    assert.equal((await http('GET', '/api/vms/findings?q=CVE-2023-12345', AN)).data.findings.length, 1);
    assert.equal((await http('GET', '/api/vms/findings?q=a%22)%2Cor(', AN)).status, 400);
    const id = db.tables.vms_findings.find((f) => (f.cve_ids as string[]).length)!.id;
    const c1 = await http('POST', `/api/vms/findings/${id}/case`, AN);
    const c2 = await http('POST', `/api/vms/findings/${id}/case`, AN);
    assert.deepEqual([c1.status, c2.status, c1.data.case.id === c2.data.case.id], [201, 200, true]);
    assert.equal(db.tables.cases.length, 1);
    const t = await http('POST', `/api/vms/findings/${id}/tasks`, AN, { title: 'Upgrade to 1.2.4', owner: 'Platform team' });
    assert.equal(t.status, 201);
    await http('PATCH', `/api/vms/tasks/${t.data.task.id}`, AN, { status: 'done' });
    assert.notEqual(db.tables.vms_findings.find((f) => f.id === id)!.status, 'verified', 'finishing tasks never closes a finding');
    assert.equal((await http('PATCH', `/api/vms/findings/${id}`, tok('executive'), { owner: 'x' })).status, 403);
    const BT = tok('analyst', B);
    assert.equal((await http('GET', '/api/vms/findings', BT)).data.findings.length, 0);
    assert.equal((await http('GET', `/api/vms/findings/${id}`, BT)).status, 404);
    assert.equal((await http('POST', `/api/vms/findings/${id}/case`, BT)).status, 404);
    const rem = await http('GET', '/api/vms/remediation', AN);
    assert.equal(rem.data.items.length, 2);
});
