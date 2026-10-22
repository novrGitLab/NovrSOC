// Phase P19 — VMS automation: Wazuh endpoint eligibility (coverage, routes, offline, duplicate and
// NAT addresses), the endpoint sync (agent identity and detail, address changes), event-triggered
// policy assessments, scan profiles, queue priority, and the operations / services / endpoints /
// retry APIs with tenant isolation. Fake PostgREST and injected Wazuh replies; nothing is scanned.
process.env.JWT_SECRET = 'vms-p19-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'VMS_WORKER_TOKEN', 'NVIDIA_API_KEY', 'WAZUH_HOST', 'WAZUH_INDEXER_HOST']) delete process.env[k];

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
import vmsRouter, { JOB_PRIORITY } from '../vms';
import vmsAssessmentsRouter from '../vmsAssessments';
import vmsOperationsRouter, { engineStatus } from '../vmsOperations';
import { endpointEligibility, duplicateAddresses } from '../../services/vmsEligibility';
import { runPolicy, type Policy } from '../../services/vmsPolicies';
import { syncWazuhVulnerabilities } from '../../services/wazuhVulnSync';
import { PROFILES } from '../../services/vmsProfiles';
import type { ScopeEntry } from '../../lib/vmsScope';
import type { WorkerView } from '../../services/vmsWorkers';

const A = 'org-a';
const B = 'org-b';
const S_PUB = '5c0e5c0e-0000-4000-8000-0000000019a1';  // cidr 8.8.8.0/24, all activities
const S_LAN = '5c0e5c0e-0000-4000-8000-0000000019a2';  // cidr 10.20.0.0/16, all activities
const S_B = '5c0e5c0e-0000-4000-8000-0000000019b1';    // org-b: cidr 8.8.8.0/24
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = A) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const AN = tok('analyst');
const EXEC = tok('executive');
const AN_B = tok('analyst', B);
async function http(method: string, path: string, bearer: string, body?: unknown) {
    const r = await fetch(`${base}${path}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: (await r.json().catch(() => null)) as Row };
}
const future = new Date(Date.now() + 30 * 86_400_000).toISOString();
const now = () => new Date().toISOString();
const ago = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString();
const scope = (id: string, org: string, kind: string, value: string, b: Row = {}): Row => ({ id, org_id: org, kind, value, include_subdomains: false, allow_discovery: true, allow_port_scan: true, allow_vuln_scan: true, exclusions: [], status: 'active', expires_at: future, approved_at: now(), approved_by: 'mgr', authorization_reference: 'MSA-2026-001 schedule B', ...b });
const endpoint = (id: string, name: string, ips: string[], b: Row = {}): Row => ({ id, org_id: A, asset_type: 'endpoint', value: name, ips, status: 'active', agent_status: 'active', criticality: 'medium', discovery_sources: ['wazuh'], wazuh_agent_id: name, hostnames: [], ...b });
const worker = (b: Row = {}): Row => ({ worker_id: 'vps-worker', kinds: ['discovery', 'ports', 'vuln_nuclei', 'vuln_openvas'], version: '1.8.0', tools: { subfinder: true, dnsx: true, httpx: true, nmap: true, nuclei: true, openvas: true }, tool_versions: { nmap: '7.94SVN', nuclei: '3.3.0' }, networks: [], features: ['exclusions', 'pinned_addresses'], first_seen_at: now(), last_seen_at: now(), ...b });

before(async () => {
    db = await startFakePostgrest(
        { vms_workers: [], vms_scopes: [], vms_scan_jobs: [], vms_assets: [], vms_services: [], vms_technologies: [], vms_asset_events: [], vms_assessments: [], vms_assessment_policies: [], vms_findings: [], vms_finding_evidence: [], vms_job_evidence: [], vms_wazuh_sync: [], wazuh_group_org_map: [], cve_intel: [], audit_log: [] },
        {},
        {
            vms_scan_jobs: { status: 'queued', attempts: 0, cancel_requested: false, progress: {}, purpose: 'assessment', get requested_at() { return new Date().toISOString(); } } as Row,
            vms_assessments: { steps: [], retried_at: null, cancelled_at: null, trigger: 'manual', get requested_at() { return new Date().toISOString(); } } as Row,
            vms_assets: { status: 'active', exposure: 'unknown', criticality: 'medium', hostnames: [], ips: [], dns: {}, discovery_sources: [] },
        },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use(express.json());
    app.use('/api/vms', requireAuth, vmsRouter);
    app.use('/api/vms', requireAuth, vmsAssessmentsRouter);
    app.use('/api/vms', requireAuth, vmsOperationsRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => {
    for (const t of Object.keys(db.tables)) db.tables[t] = [];
    for (const k of Object.keys(db.missingColumns)) delete db.missingColumns[k];
    db.tables.vms_scopes.push(scope(S_PUB, A, 'cidr', '8.8.8.0/24'), scope(S_LAN, A, 'cidr', '10.20.0.0/16'), scope(S_B, B, 'cidr', '8.8.8.0/24'));
    db.tables.vms_workers.push(worker());
});

// ── Eligibility (pure) ─────────────────────────────────────────────────────────────────────────
const scopes = (): ScopeEntry[] => [scope(S_PUB, A, 'cidr', '8.8.8.0/24'), scope(S_LAN, A, 'cidr', '10.20.0.0/16')] as unknown as ScopeEntry[];
test('eligibility: telemetry alone never authorises; coverage, route, agent state and duplicates decide', () => {
    const el = (ips: string[], b: Row = {}, nets: string[] = [], dups: string[] = [], activity: 'vuln' | 'ports' = 'vuln') =>
        endpointEligibility({ id: 'e', ips, agent_status: 'active', ...b } as never, scopes(), nets, new Set(dups), Date.now(), activity);
    assert.deepEqual([el(['8.8.8.10']).status, el(['8.8.8.10']).target, el(['8.8.8.10']).scope_id], ['eligible', '8.8.8.10', S_PUB]);
    assert.equal(el(['9.9.9.9']).status, 'not_covered', 'an address Wazuh reports but nobody authorised');
    assert.match(el(['9.9.9.9']).reason, /never authorises a scan/);
    assert.equal(el(['10.20.1.5']).status, 'private_no_route');
    assert.deepEqual([el(['10.20.1.5'], {}, ['10.20.0.0/16']).status, el(['10.20.1.5'], {}, ['10.20.0.0/16']).target], ['eligible', '10.20.1.5']);
    assert.equal(el(['10.20.1.5', '8.8.8.10'], {}, ['10.20.0.0/16']).target, '8.8.8.10', 'a public address first');
    assert.equal(el(['8.8.8.10'], { agent_status: 'disconnected' }).status, 'offline');
    assert.equal(el(['8.8.8.10'], { agent_status: undefined, alive: false }).status, 'offline');
    assert.equal(el([]).status, 'no_address');
    assert.equal(el(['not-an-ip']).status, 'no_address');
    assert.equal(el(['8.8.8.10'], {}, [], ['8.8.8.10']).status, 'duplicate_address');
    assert.equal(el(['8.8.8.10', '8.8.8.11'], {}, [], ['8.8.8.10']).target, '8.8.8.11', 'a unique address is still usable');
    // Scope permissions per activity: a Discovery profile needs port-scan permission only.
    const portsOnly = [scope(S_PUB, A, 'cidr', '8.8.8.0/24', { allow_vuln_scan: false })] as unknown as ScopeEntry[];
    assert.equal(endpointEligibility({ id: 'e', ips: ['8.8.8.10'], agent_status: 'active' }, portsOnly, [], new Set()).status, 'not_covered');
    assert.equal(endpointEligibility({ id: 'e', ips: ['8.8.8.10'], agent_status: 'active' }, portsOnly, [], new Set(), Date.now(), 'ports').status, 'eligible');
    // Expired or revoked agreement coverage is no coverage.
    const expired = [scope(S_PUB, A, 'cidr', '8.8.8.0/24', { expires_at: ago(1) })] as unknown as ScopeEntry[];
    assert.equal(endpointEligibility({ id: 'e', ips: ['8.8.8.10'], agent_status: 'active' }, expired, [], new Set()).status, 'not_covered');
});

test('duplicate addresses: DHCP reuse within an organisation, NAT across endpoints; private ranges repeat across clients by design', () => {
    const e = (id: string, org: string, ips: string[]) => ({ id, org_id: org, ips, status: 'active' });
    const all = [e('1', A, ['10.20.0.5', '8.8.8.1']), e('2', A, ['10.20.0.5']), e('3', B, ['10.20.0.9']), e('4', B, ['8.8.8.1', '10.20.0.1']), e('5', A, ['10.20.0.1']), e('6', A, ['8.8.8.2'])];
    const d = duplicateAddresses(A, all);
    assert.ok(d.has('10.20.0.5'), 'two endpoints of the organisation');
    assert.ok(d.has('8.8.8.1'), 'a public address shared with another organisation (NAT)');
    assert.ok(!d.has('10.20.0.1'), 'the same private address in another client network is not a conflict');
    assert.ok(!d.has('8.8.8.2'));
    assert.ok(!duplicateAddresses(A, [...all, { id: '7', org_id: A, ips: ['8.8.8.2'], status: 'gone' }]).has('8.8.8.2'), 'gone endpoints do not count');
});

// ── Wazuh endpoint sync ─────────────────────────────────────────────────────────────────────────
const EMPTY = { hits: { total: { value: 0 }, hits: [] }, _shards: { total: 1, failed: 0 } };
const agent = (id: string, name: string, ip: string | null, b: Row = {}) => ({ id, name, status: 'active', os: 'Ubuntu 24.04', ip, lastKeepAlive: ago(1), group: ['acme'], ...b });
test('sync: agents matched by id (a rename keeps the asset), agent detail stored, address changes recorded, eligibility evaluated', async () => {
    db.tables.wazuh_group_org_map.push({ wazuh_group: 'acme', org_id: A });
    let agents = [agent('003', 'web-01', '8.8.8.10'), agent('000', 'novrsoc-wazuh', null, { lastKeepAlive: now(), os: 'Ubuntu 22.04 LTS' })];
    const deps = { agentsForGroup: async () => agents as never, search: async () => EMPTY as never };
    const r = await syncWazuhVulnerabilities(deps);
    const mine = r.find((x) => x.org === A)!;
    assert.deepEqual(mine.eligibility, { eligible: 1, not_covered: 0, private_no_route: 0, offline: 0, no_address: 1, duplicate_address: 0 });
    const web = db.tables.vms_assets.find((a) => a.wazuh_agent_id === '003')!;
    assert.deepEqual([web.value, web.os, web.agent_status, (web.agent_groups as string[])[0], web.ips], ['web-01', 'Ubuntu 24.04', 'active', 'acme', ['8.8.8.10']]);
    assert.ok(Math.abs(Date.parse(String(web.agent_last_keepalive)) - Date.parse(ago(1))) < 60_000, 'the agent\'s own keep-alive, not the sync time');
    assert.deepEqual([(web.scan_eligibility as Row).status, (web.scan_eligibility as Row).target], ['eligible', '8.8.8.10']);
    const mgr = db.tables.vms_assets.find((a) => a.wazuh_agent_id === '000')!;
    assert.deepEqual([mgr.agent_last_keepalive, mgr.os], [null, null], 'placeholder values for the manager are not stored as facts');
    // Renamed and re-addressed agent: same asset, both changes recorded.
    agents = [agent('003', 'web-01-renamed', '8.8.8.11', { status: 'disconnected' })];
    await syncWazuhVulnerabilities(deps);
    const endpoints = db.tables.vms_assets.filter((a) => a.asset_type === 'endpoint' && a.wazuh_agent_id === '003');
    assert.equal(endpoints.length, 1, 'no duplicate asset for a renamed agent');
    assert.deepEqual([endpoints[0].value, endpoints[0].ips, endpoints[0].agent_status, (endpoints[0].scan_eligibility as Row).status], ['web-01-renamed', ['8.8.8.11'], 'disconnected', 'offline']);
    const changed = db.tables.vms_asset_events.find((e) => e.event === 'asset_changed')!;
    assert.deepEqual([(changed.details as Row).ips, (changed.details as Row).name], [{ from: ['8.8.8.10'], to: ['8.8.8.11'] }, { from: 'web-01', to: 'web-01-renamed' }]);
});

// ── Policies: event trigger, profile, next scan ─────────────────────────────────────────────────
test('policy: an endpoint whose eligible address changed is assessed inside the cooldown (event); otherwise cooldown holds', async () => {
    const id = randomUUID();
    db.tables.vms_assets.push(endpoint(id, 'web-01', ['8.8.8.10']));
    const p = { id: randomUUID(), org_id: A, name: 'managed endpoints', enabled: true, asset_source: 'wazuh', profile: 'standard', cooldown_hours: 168, max_per_run: 5, last_run_at: null, last_result: null } as Policy;
    db.tables.vms_assessment_policies.push(p as unknown as Row);
    const r1 = await runPolicy(p);
    assert.deepEqual([r1.queued, r1.event_triggered, r1.profile], [1, 0, 'standard']);
    const first = db.tables.vms_assessments[0];
    assert.deepEqual([first.profile, first.trigger, first.target, (first.steps as Row[]).length], ['standard', 'policy', '8.8.8.10', 3]);
    const jobs = db.tables.vms_scan_jobs;
    assert.deepEqual(jobs.map((j) => j.kind).sort(), ['discovery', 'ports', 'vuln_nuclei']);
    assert.ok(jobs.every((j) => j.priority === JOB_PRIORITY.policy));
    assert.equal(jobs.find((j) => j.kind === 'ports')!.options && (jobs.find((j) => j.kind === 'ports')!.options as Row).ports, 'top-1000');
    // The running checks finish; within the cooldown nothing new is queued.
    for (const j of jobs) Object.assign(j, { status: 'succeeded', started_at: now(), finished_at: now(), summary: { outcome: 'assessed' } });
    const r2 = await runPolicy(p);
    assert.deepEqual([r2.queued, r2.skipped_cooldown], [0, 1]);
    // DHCP moved the endpoint: assessed now at the new address, as an event.
    db.tables.vms_assets.find((a) => a.id === id)!.ips = ['8.8.8.20'];
    const r3 = await runPolicy(p);
    assert.deepEqual([r3.queued, r3.event_triggered], [1, 1]);
    const latest = db.tables.vms_assessments.at(-1)!;
    assert.deepEqual([latest.trigger, latest.target], ['event', '8.8.8.20']);
    assert.ok(db.tables.vms_scan_jobs.filter((j) => j.status === 'queued').every((j) => j.priority === JOB_PRIORITY.event));
});

// ── Profiles and priority ────────────────────────────────────────────────────────────────────────
test('profiles: discovery / standard / full plan their steps and port coverage; unknown profiles refused; manual jobs outrank policy jobs', async () => {
    const one = async (target: string, profile?: string) => http('POST', '/api/vms/assessments', AN, { target, ...(profile ? { profile } : {}) });
    const d = await one('8.8.8.1', 'discovery');
    assert.deepEqual([d.status, (d.data.assessment as Row).profile, ((d.data.assessment as Row).steps as Row[]).map((s) => s.kind)], [201, 'discovery', ['discovery', 'ports']]);
    const f = await one('8.8.8.2');
    assert.deepEqual([(f.data.assessment as Row).profile, ((f.data.assessment as Row).steps as Row[]).length], ['full', 4], 'full is the default');
    const ports = db.tables.vms_scan_jobs.filter((j) => j.kind === 'ports').map((j) => [j.targets, (j.options as Row).ports]);
    assert.deepEqual(ports, [[['8.8.8.1'], 'top-1000'], [['8.8.8.2'], '1-65535']], 'Full covers every TCP port');
    assert.ok(db.tables.vms_scan_jobs.every((j) => j.priority === JOB_PRIORITY.manual));
    assert.ok(JOB_PRIORITY.verification > JOB_PRIORITY.manual && JOB_PRIORITY.manual > JOB_PRIORITY.event && JOB_PRIORITY.event > JOB_PRIORITY.schedule && JOB_PRIORITY.schedule > JOB_PRIORITY.policy);
    assert.equal((await one('8.8.8.3', 'everything')).status, 400);
    // One target is never assessed twice at once, whatever the profile.
    const again = await one('8.8.8.1', 'full');
    assert.deepEqual([again.status, again.data.existing], [200, true]);
    // The claim function orders by priority, then arrival (the SQL that production runs).
    const sql = readFileSync(join(__dirname, '../../../sql/2026-10-25_p19_vms_automation.sql'), 'utf8');
    assert.match(sql, /ORDER BY priority DESC, requested_at\s+FOR UPDATE SKIP LOCKED/);
    const prof = await http('GET', '/api/vms/profiles', AN);
    const ids = (prof.data.profiles as Row[]).map((p) => [p.id, p.runnable]);
    assert.deepEqual(ids, [['discovery', true], ['standard', true], ['full', true], ['authenticated', false], ['verification', false]]);
    const auth = (prof.data.profiles as Row[]).find((p) => p.id === 'authenticated')!;
    assert.equal(auth.available, false, 'no complete Wazuh sync: not claimed');
    assert.ok((auth.not_covered as string[]).some((x) => /credentialed checks: not available/.test(x)));
    assert.deepEqual(PROFILES.full.steps, ['discovery', 'ports', 'vuln_nuclei', 'vuln_openvas']);
});

// ── Operations ───────────────────────────────────────────────────────────────────────────────────
test('engines: available only from a connected worker running the kind with its tool', () => {
    const w = (b: Partial<WorkerView>): WorkerView => ({ worker_id: 'w', kinds: [], version: '1.8.0', tools: {}, first_seen_at: now(), last_seen_at: now(), last_heartbeat_at: null, last_claim_at: null, last_job_id: null, last_job_at: null, online: true, ...b });
    const state = (ws: WorkerView[]) => Object.fromEntries(engineStatus(ws).map((e) => [e.id, e.state]));
    assert.deepEqual(state([]), { discovery: 'no_worker', nmap: 'no_worker', nuclei: 'no_worker', openvas: 'no_worker' });
    assert.deepEqual(state([w({ kinds: ['ports', 'vuln_nuclei'], tools: { nmap: true, nuclei: true, openvas: true } })]),
        { discovery: 'not_installed', nmap: 'available', nuclei: 'available', openvas: 'not_enabled' });
    assert.equal(state([w({ kinds: ['vuln_openvas'], tools: { openvas: false } })]).openvas, 'not_installed');
    assert.equal(state([w({ kinds: ['ports'], tools: { nmap: true }, online: false })]).nmap, 'offline');
});

test('operations: queue and 7-day outcomes per kind (ran-but-unreachable is inconclusive, not success); tenant-scoped; workers for staff only', async () => {
    // The OpenVAS engine is "available" only with the server switch on (lib/openvasPolicy.ts, P22).
    process.env.VMS_OPENVAS_ENABLED = 'true';
    after(() => { delete process.env.VMS_OPENVAS_ENABLED; });
    const job = (org: string, kind: string, status: string, b: Row = {}) => ({ id: randomUUID(), org_id: org, scope_id: S_PUB, kind, status, targets: ['8.8.8.1'], options: {}, requested_at: ago(2), requested_by: 'x', attempts: 1, progress: {}, cancel_requested: false, ...b });
    db.tables.vms_scan_jobs.push(
        job(A, 'ports', 'succeeded', { started_at: ago(2), finished_at: ago(1.9), summary: { outcome: 'assessed' } }),
        job(A, 'ports', 'succeeded', { started_at: ago(2), finished_at: ago(1.95), summary: { outcome: 'unreachable' } }),
        job(A, 'vuln_openvas', 'failed', { error: 'Greenbone rejected GVM_USER / GVM_PASSWORD (authentication failed)', finished_at: ago(1) }),
        job(A, 'vuln_nuclei', 'queued'),
        job(B, 'ports', 'failed', { error: 'other org' }),
    );
    const o = await http('GET', '/api/vms/operations', AN);
    assert.equal(o.status, 200);
    const queue = o.data.queue as Row;
    const ports = (o.data.last_7_days as Record<string, Row>).ports;
    assert.deepEqual([queue.queued, queue.running], [1, 0]);
    assert.deepEqual([ports.succeeded, ports.inconclusive], [1, 1]);
    assert.notEqual(ports.median_duration_s, null);
    assert.deepEqual((o.data.recent_failures as Row[]).map((j) => j.kind), ['vuln_openvas'], 'another organisation\'s failure is not shown');
    assert.equal((o.data.engines as Row[]).find((e) => e.id === 'openvas')!.state, 'available');
    assert.ok(Array.isArray(o.data.workers), 'staff see the workers');
    const ex = await http('GET', '/api/vms/operations', EXEC);
    assert.equal(ex.data.workers, undefined, 'executives get engine states only');
});

test('services: open services and technologies with open findings per asset/port, own organisation only', async () => {
    const a1 = randomUUID();
    const b1 = randomUUID();
    db.tables.vms_assets.push({ id: a1, org_id: A, asset_type: 'ip', value: '8.8.8.1', exposure: 'internet', criticality: 'high', status: 'active' }, { id: b1, org_id: B, asset_type: 'ip', value: '8.8.8.1', status: 'active' });
    db.tables.vms_services.push(
        { id: 's1', org_id: A, asset_id: a1, port: 443, protocol: 'tcp', service: 'https', product: 'nginx', version: '1.25.3', status: 'active', source: 'nmap' },
        { id: 's2', org_id: A, asset_id: a1, port: 22, protocol: 'tcp', service: 'ssh', status: 'gone', source: 'nmap' },
        { id: 's3', org_id: B, asset_id: b1, port: 3389, protocol: 'tcp', service: 'ms-wbt-server', status: 'active', source: 'nmap' },
    );
    db.tables.vms_technologies.push({ id: 't1', org_id: A, asset_id: a1, name: 'nginx', version: '1.25.3', source: 'httpx' });
    db.tables.vms_findings.push({ id: 'f1', org_id: A, asset_id: a1, port: 443, priority: 'P2', scanner_severity: 'high', status: 'open' }, { id: 'f2', org_id: A, asset_id: a1, port: 443, priority: 'P4', scanner_severity: 'low', status: 'verified' });
    const s = await http('GET', '/api/vms/services', AN);
    assert.deepEqual((s.data.services as Row[]).map((x) => [x.port, (x.asset as Row).value, (x.open_findings as Row).count]), [[443, '8.8.8.1', 1]], 'active services only; closed findings not counted');
    assert.deepEqual(((s.data.services as Row[])[0].open_findings as Row).severities, { high: 1 });
    assert.deepEqual((s.data.technologies as Row[]).map((t) => [t.name, t.asset_open_findings]), [['nginx', 1]]);
    assert.deepEqual(((await http('GET', '/api/vms/services', AN_B)).data.services as Row[]).map((x) => x.port), [3389]);
});

test('endpoints: eligibility evaluated on read, coverage counts, last and next scan, open findings', async () => {
    const e1 = randomUUID(); const e2 = randomUUID(); const e3 = randomUUID();
    db.tables.vms_assets.push(
        endpoint(e1, 'web-01', ['8.8.8.10'], { last_assessed_at: ago(5), last_assessment: { outcome: 'reachable_open' }, next_scan_at: future }),
        endpoint(e2, 'laptop-07', ['10.20.3.4']),
        endpoint(e3, 'kiosk', ['8.8.8.12'], { agent_status: 'disconnected' }),
    );
    db.tables.vms_findings.push({ id: 'f1', org_id: A, asset_id: e1, scanner_severity: 'critical', source_class: 'wazuh', status: 'open' });
    const r = await http('GET', '/api/vms/endpoints', AN);
    assert.equal(r.status, 200);
    const by = Object.fromEntries((r.data.endpoints as Row[]).map((x) => [x.name, x]));
    assert.deepEqual([(by['web-01'].eligibility as Row).status, by['web-01'].assessed_recently, by['web-01'].next_scan_at, by['web-01'].open_findings], ['eligible', true, future, { critical: 1 }]);
    assert.equal((by['laptop-07'].eligibility as Row).status, 'private_no_route');
    assert.equal((by.kiosk.eligibility as Row).status, 'offline');
    assert.deepEqual(r.data.coverage, { active: 3, eligible: 1, assessed_last_30_days: 1, awaiting_assessment: 0, not_eligible: { not_covered: 0, private_no_route: 1, offline: 1, no_address: 0, duplicate_address: 0 } });
    assert.equal(((await http('GET', '/api/vms/endpoints', AN_B)).data.endpoints as Row[]).length, 0, 'another organisation sees none');
});

test('retry: a failed scan is queued again through the scope checks; running, assessment and other-org scans are not', async () => {
    const failed = { id: randomUUID(), org_id: A, scope_id: S_PUB, kind: 'ports', status: 'failed', targets: ['8.8.8.1'], options: { ports: '22,443' }, requested_at: ago(1), requested_by: 'x', attempts: 1, progress: {}, cancel_requested: false, error: 'nmap exited 1' };
    db.tables.vms_scan_jobs.push(failed, { ...failed, id: randomUUID(), status: 'running', targets: ['8.8.8.2'] }, { ...failed, id: randomUUID(), assessment_id: randomUUID() }, { ...failed, id: randomUUID(), org_id: B, scope_id: S_B });
    const r = await http('POST', `/api/vms/scans/${failed.id}/retry`, AN);
    assert.equal(r.status, 201);
    // Retrying again while the retry is queued returns it instead of a duplicate.
    assert.deepEqual([(await http('POST', `/api/vms/scans/${failed.id}/retry`, AN)).data.existing], [true]);
    assert.deepEqual([(r.data.scan as Row).kind, (r.data.scan as Row).targets, ((r.data.scan as Row).options as Row).ports, r.data.retry_of], ['ports', ['8.8.8.1'], '22,443', failed.id]);
    assert.equal((await http('POST', `/api/vms/scans/${db.tables.vms_scan_jobs[1].id}/retry`, AN)).status, 409);
    const asm = await http('POST', `/api/vms/scans/${db.tables.vms_scan_jobs[2].id}/retry`, AN);
    assert.deepEqual([asm.status, /retry the assessment/.test(String(asm.data.error))], [409, true]);
    assert.equal((await http('POST', `/api/vms/scans/${db.tables.vms_scan_jobs[3].id}/retry`, AN)).status, 404, 'another organisation\'s scan');
    assert.equal((await http('POST', `/api/vms/scans/${failed.id}/retry`, EXEC)).status, 403, 'executives cannot queue scans');
    // Coverage withdrawn: the retry is refused like a new scan.
    db.tables.vms_scopes.find((s) => s.id === S_PUB)!.status = 'revoked';
    db.tables.vms_scan_jobs = db.tables.vms_scan_jobs.filter((j) => j.status !== 'queued');
    assert.equal((await http('POST', `/api/vms/scans/${failed.id}/retry`, AN)).status, 400);
});

test('overview: most vulnerable assets ranked by open severity, then risk; closed findings and other organisations excluded', async () => {
    const f = (asset_id: string, value: string, sev: string, b: Row = {}) => ({ id: randomUUID(), org_id: A, asset_id, asset_value: value, scanner_severity: sev, risk_score: 50, status: 'open', ...b });
    db.tables.vms_findings.push(
        f('a1', 'db-01', 'critical'), f('a1', 'db-01', 'low'),
        f('a2', 'web-01', 'high'), f('a2', 'web-01', 'high'), f('a2', 'web-01', 'high'),
        f('a3', 'old-01', 'critical', { status: 'verified' }),
        f('a4', 'mail-01', 'high', { risk_score: 90 }),
        { ...f('b1', 'other-org', 'critical'), org_id: B },
    );
    const o = await http('GET', '/api/vms/overview', AN);
    const mv = o.data.most_vulnerable_assets as Row[];
    assert.deepEqual(mv.map((x) => [x.value, x.open]), [['db-01', 2], ['web-01', 3], ['mail-01', 1]]);
    assert.deepEqual(mv[0].by_severity, { critical: 1, low: 1 });
});

test('production before the P19 SQL: sync, eligibility, manual and policy assessments and the new pages all work; nothing P19-only is written', async () => {
    db.missingColumns.vms_assets = ['os', 'agent_status', 'agent_last_keepalive', 'agent_groups', 'scan_eligibility', 'next_scan_at'];
    db.missingColumns.vms_scan_jobs = ['priority'];
    db.tables.wazuh_group_org_map.push({ wazuh_group: 'acme', org_id: A });
    const r = await syncWazuhVulnerabilities({ agentsForGroup: async () => [agent('003', 'web-01', '8.8.8.10')] as never, search: async () => EMPTY as never });
    const mine = r.find((x) => x.org === A)!;
    assert.deepEqual([mine.errors, mine.eligibility], [[], null], 'stored without the new columns; eligibility evaluated but not stored');
    const ep = db.tables.vms_assets.find((x) => x.wazuh_agent_id === '003')!;
    assert.deepEqual([ep.value, ep.ips, ep.alive, ep.os, ep.scan_eligibility], ['web-01', ['8.8.8.10'], true, undefined, undefined]);
    // Manual assessment of the endpoint: eligibility computed live, jobs queued without a priority.
    const m = await http('POST', '/api/vms/assessments', AN, { asset_id: ep.id, profile: 'full' });
    assert.equal(m.status, 201);
    assert.equal((m.data.assessment as Row).target, '8.8.8.10');
    assert.ok(db.tables.vms_scan_jobs.length >= 1 && db.tables.vms_scan_jobs.every((j) => j.priority === undefined));
    // A policy run (next_scan_at cannot be stored) still assesses and records its result.
    db.tables.vms_assessments = []; db.tables.vms_scan_jobs = [];
    const p = { id: randomUUID(), org_id: A, name: 'p', enabled: true, asset_source: 'wazuh', profile: 'full', cooldown_hours: 168, max_per_run: 5, last_run_at: null, last_result: null } as Policy;
    db.tables.vms_assessment_policies.push(p as unknown as Row);
    const run = await runPolicy(p);
    assert.equal(run.queued, 1);
    assert.equal(ep.next_scan_at, undefined);
    const en = await http('GET', '/api/vms/endpoints', AN);
    assert.deepEqual([en.status, en.data.eligibility_stored, ((en.data.endpoints as Row[])[0].eligibility as Row).status], [200, false, 'eligible']);
    for (const path of ['/api/vms/operations', '/api/vms/services', '/api/vms/profiles', '/api/vms/overview']) assert.equal((await http('GET', path, AN)).status, 200, path);
});
