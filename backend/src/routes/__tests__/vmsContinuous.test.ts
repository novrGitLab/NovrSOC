// Phase P7 VMS Release 3: schedules (scope checks on create and on every run, no pile-up,
// disabled when scope ends, tenant isolation, manager-only), daily snapshots, trends and
// recurring problems, the period report's limitations, change digests (honest "not sent"), and
// the VMS health checks. Fake PostgREST, no network, no email.
process.env.JWT_SECRET = 'vms-continuous-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'EMAIL_ENABLED', 'VMS_NOTIFY_ENABLED']) delete process.env[k];

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
import vmsContinuousRouter from '../vmsContinuous';
import { nextRunAfter, runDueSchedules, snapshotOrg, riskTrends, periodReport, notifyChanges } from '../../services/vmsContinuous';
import { vmsChecks } from '../../services/pipelineHealth';

const A = 'org-a';
const B = 'org-b';
const H = 3_600_000;
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = A) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const MGR = tok('soc_manager');
const MGR_B = tok('soc_manager', B);
const AN = tok('analyst');
async function http(method: string, path: string, bearer?: string, body?: unknown) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const r = await fetch(`${base}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const future = (days = 30) => new Date(Date.now() + days * 86_400_000).toISOString();

before(async () => {
    db = await startFakePostgrest(
        { vms_scopes: [], vms_scan_jobs: [], vms_scan_schedules: [], vms_assets: [], vms_findings: [], vms_finding_events: [], vms_asset_events: [], vms_risk_snapshots: [], vms_notify_state: [], vms_wazuh_sync: [], cve_intel: [], audit_log: [] },
        { 'vms_scan_schedules.vms_scopes': 'scope_id', 'vms_asset_events.vms_assets': 'asset_id' },
        {
            vms_scan_jobs: { status: 'queued', attempts: 0, cancel_requested: false, progress: {}, purpose: 'assessment', get requested_at() { return new Date().toISOString(); } } as Row,
            vms_scan_schedules: { enabled: true, targets: [] },
        },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use(express.json());
    app.use('/api/vms', requireAuth, vmsRouter);
    app.use('/api/vms', requireAuth, vmsContinuousRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => { for (const t of Object.keys(db.tables)) db.tables[t].length = 0; });

function scope(org = A, over: Row = {}): Row {
    const s = { id: randomUUID(), org_id: org, kind: 'domain', value: 'example.test', include_subdomains: true, allow_port_scan: true, allow_vuln_scan: false, status: 'active', expires_at: future(), authorization_reference: 'LOA-1', approved_by: 'm', approved_at: new Date().toISOString(), ...over };
    db.tables.vms_scopes.push(s);
    return s;
}

// ── Schedules ─────────────────────────────────────────────────────────────────────────────────
test('nextRunAfter keeps the cadence and skips missed runs instead of catching up', () => {
    const now = Date.parse('2026-10-16T12:00:00Z');
    assert.equal(nextRunAfter('2026-10-16T10:00:00Z', 24, now), '2026-10-17T10:00:00.000Z');
    assert.equal(nextRunAfter('2026-10-10T10:00:00Z', 24, now), '2026-10-17T10:00:00.000Z', 'six missed days queue one run, not six');
    assert.equal(nextRunAfter('2026-10-18T10:00:00Z', 24, now), '2026-10-18T10:00:00.000Z');
});

test('schedule API: managers only, scope checked, other organisations cannot touch it', async () => {
    const s = scope();
    assert.equal((await http('POST', '/api/vms/schedules', AN, { scope_id: s.id, kind: 'discovery', interval_hours: 24 })).status, 403);
    assert.equal((await http('POST', '/api/vms/schedules', MGR, { scope_id: s.id, kind: 'discovery', interval_hours: 1 })).status, 400, 'at most daily');
    assert.equal((await http('POST', '/api/vms/schedules', MGR, { scope_id: s.id, kind: 'vuln_nuclei', interval_hours: 24 })).status, 403, 'scope does not allow vuln scans');
    assert.equal((await http('POST', '/api/vms/schedules', MGR, { scope_id: s.id, kind: 'ports', targets: ['other.test'], interval_hours: 24 })).status, 400, 'target outside scope');
    assert.equal((await http('POST', '/api/vms/schedules', MGR, { scope_id: s.id, kind: 'discovery', interval_hours: 24, first_run_at: future(60) })).status, 400, 'first run after scope expiry');
    const r = await http('POST', '/api/vms/schedules', MGR, { scope_id: s.id, kind: 'ports', targets: ['www.example.test'], ports: 'top-100', interval_hours: 168 });
    assert.equal(r.status, 201);
    assert.deepEqual(r.data.schedule.targets, ['www.example.test']);
    assert.equal((await http('POST', '/api/vms/schedules', MGR_B, { scope_id: s.id, kind: 'discovery', interval_hours: 24 })).status, 400, "another org's scope");
    assert.equal((await http('PATCH', `/api/vms/schedules/${r.data.schedule.id}`, MGR_B, { enabled: false })).status, 404);
    assert.equal((await http('DELETE', `/api/vms/schedules/${r.data.schedule.id}`, MGR_B)).status, 404);
    const list = await http('GET', '/api/vms/schedules', AN);
    assert.equal(list.data.schedules.length, 1);
    assert.equal((await http('GET', '/api/vms/schedules', MGR_B)).data.schedules.length, 0);
    assert.equal((await http('DELETE', `/api/vms/schedules/${r.data.schedule.id}`, MGR)).status, 200);
});

test('runDueSchedules queues through scope checks, waits for an unfinished run, and disables when scope ends', async () => {
    const s = scope();
    const id = randomUUID();
    db.tables.vms_scan_schedules.push({ id, org_id: A, scope_id: s.id, kind: 'discovery', targets: [], ports: null, interval_hours: 24, next_run_at: new Date(Date.now() - 60_000).toISOString(), enabled: true, created_by: 'm' });
    let r = await runDueSchedules();
    assert.equal(r[0].outcome, 'queued');
    assert.equal(db.tables.vms_scan_jobs.length, 1);
    assert.equal(db.tables.vms_scan_jobs[0].schedule_id, id);
    assert.equal(db.tables.vms_scan_jobs[0].requested_by, `schedule:${id}`);
    const sched = db.tables.vms_scan_schedules[0];
    assert.ok(Date.parse(sched.next_run_at as string) > Date.now() + 23 * H);

    sched.next_run_at = new Date(Date.now() - 1000).toISOString();
    r = await runDueSchedules();
    assert.equal(r[0].outcome, 'skipped_in_progress');
    assert.equal(db.tables.vms_scan_jobs.length, 1, 'no pile-up');

    db.tables.vms_scan_jobs[0].status = 'succeeded';
    s.status = 'revoked';
    sched.next_run_at = new Date(Date.now() - 1000).toISOString();
    r = await runDueSchedules();
    assert.equal(r[0].outcome, 'disabled');
    assert.equal(sched.enabled, false);
    assert.match(String(sched.last_result), /^Disabled: That scope is not active/);
    assert.equal(db.tables.vms_scan_jobs.length, 1);
    assert.equal((await http('PATCH', `/api/vms/schedules/${id}`, MGR, { enabled: true })).status, 400, 'cannot re-enable on a revoked scope');
});

// ── Snapshots, trends, report ─────────────────────────────────────────────────────────────────
function finding(over: Row): Row {
    const f = { id: randomUUID(), org_id: A, status: 'open', priority: 'P3', cve_ids: [], asset_id: null, asset_value: 'h1', rule_id: 'r1', title: 'T', first_seen: new Date(Date.now() - 10 * 86_400_000).toISOString(), due_at: null, verified_at: null, source_class: 'active_scan', ...over };
    db.tables.vms_findings.push(f);
    return f;
}

test('snapshotOrg counts open findings by priority, overdue, KEV and internet-facing; same day replaces', async () => {
    const asset = { id: randomUUID(), org_id: A, status: 'active', exposure: 'internet' };
    db.tables.vms_assets.push(asset, { id: randomUUID(), org_id: A, status: 'active', exposure: 'internal' });
    db.tables.cve_intel.push({ cve_id: 'CVE-2024-3400', kev: true });
    finding({ priority: 'P1', cve_ids: ['CVE-2024-3400'], asset_id: asset.id, due_at: new Date(Date.now() - H).toISOString() });
    finding({ priority: 'P2' });
    finding({ priority: 'P2', status: 'verified', verified_at: new Date().toISOString() });
    finding({ priority: 'P4', org_id: B });
    const row = await snapshotOrg(A);
    assert.equal(row.open_total, 2);
    assert.deepEqual(row.open_by_priority, { P1: 1, P2: 1, P3: 0, P4: 0 });
    assert.equal(row.overdue, 1);
    assert.equal(row.kev_open, 1);
    assert.equal(row.internet_open, 1);
    assert.equal(row.assets_internet, 1);
    assert.equal(row.verified, 1);
    await snapshotOrg(A);
    assert.equal(db.tables.vms_risk_snapshots.length, 1);
});

test('snapshotOrg records P20 risk and exposure (info excluded), and still writes the P7 row before the P20 SQL', async () => {
    const asset = { id: randomUUID(), org_id: A, status: 'active', exposure: 'internet' };
    db.tables.vms_assets.push(asset);
    finding({ scanner_severity: 'critical', risk_score: 90, asset_id: asset.id });
    finding({ scanner_severity: 'medium', risk_score: 40 });
    finding({ scanner_severity: 'info', risk_score: 5, asset_id: asset.id });
    const row = await snapshotOrg(A);
    assert.equal(row.risk_mean, 65);
    assert.equal(row.risk_max, 90);
    assert.equal(row.critical_exposures, 1);
    assert.deepEqual(row.open_by_severity, { critical: 1, medium: 1, info: 1 });
    db.tables.vms_risk_snapshots.length = 0;
    db.missingColumns.vms_risk_snapshots = ['risk_mean'];
    const p7 = await snapshotOrg(A);
    assert.equal(p7.risk_mean, undefined);
    assert.equal(db.tables.vms_risk_snapshots.length, 1);
    assert.equal(db.tables.vms_risk_snapshots[0].open_total, 3);
    delete db.missingColumns.vms_risk_snapshots;
});

test('trends say when there is not enough history; time to remediate and widespread rules are measured', async () => {
    const t0 = Date.now() - 5 * 86_400_000;
    finding({ priority: 'P1', status: 'verified', first_seen: new Date(t0).toISOString(), verified_at: new Date(t0 + 48 * H).toISOString(), due_at: new Date(t0 + 72 * H).toISOString() });
    for (const h of ['a', 'b', 'c']) finding({ rule_id: 'tls-weak', title: 'Weak TLS', asset_value: h });
    const r = await riskTrends(A, 30);
    assert.match(String(r.note), /at least two daily snapshots/);
    assert.deepEqual(r.time_to_remediate.P1, { verified: 1, mean_hours: 48, within_deadline: 1 });
    assert.deepEqual(r.recurring.widespread, [{ rule_id: 'tls-weak', title: 'Weak TLS', open_on_assets: 3 }]);
});

test('period report states its limitations instead of implying coverage', async () => {
    finding({ priority: 'P1' });
    const r = await periodReport(A, 30);
    assert.equal(r.open_now.by_priority.P1, 1);
    assert.ok(r.limitations.some((l) => /No active authorised scope/.test(l)));
    assert.ok(r.limitations.some((l) => /No scan succeeded/.test(l)));
    assert.ok(r.limitations.some((l) => /Wazuh vulnerability sync has not run/.test(l)));
    const api = await http('GET', '/api/vms/report?days=7', AN);
    assert.equal(api.status, 200);
    assert.equal(api.data.period.days, 7);
});

// ── Notifications ─────────────────────────────────────────────────────────────────────────────
test('notifyChanges starts from now, reports internet-facing changes and new P1/P2, and says when email is off', async () => {
    let r = await notifyChanges(A);
    assert.match(r.detail, /Started tracking/);
    const st = db.tables.vms_notify_state[0];
    st.last_event_at = st.last_finding_at = new Date(Date.now() - 60_000).toISOString();
    const pub = { id: randomUUID(), org_id: A, value: 'new.example.test', exposure: 'internet', status: 'active' };
    const internal = { id: randomUUID(), org_id: A, value: 'intra.example.test', exposure: 'internal', status: 'active' };
    db.tables.vms_assets.push(pub, internal);
    const now = new Date().toISOString();
    db.tables.vms_asset_events.push(
        { id: randomUUID(), org_id: A, asset_id: pub.id, event: 'asset_new', at: now, details: {} },
        { id: randomUUID(), org_id: A, asset_id: pub.id, event: 'service_new', at: now, details: { port: 8443, protocol: 'tcp', service: 'https' } },
        { id: randomUUID(), org_id: A, asset_id: internal.id, event: 'asset_new', at: now, details: {} },
        { id: randomUUID(), org_id: B, asset_id: pub.id, event: 'asset_new', at: now, details: {} },
    );
    finding({ priority: 'P1', title: 'RCE', asset_value: 'new.example.test', first_seen: now });
    finding({ priority: 'P4', title: 'Banner', first_seen: now });
    r = await notifyChanges(A);
    assert.deepEqual(r.lines, ['New internet-facing asset: new.example.test', 'New service on new.example.test: 8443/tcp https', 'New P1 finding on new.example.test: RCE']);
    assert.equal(r.sent, false);
    assert.equal(r.detail, 'Not sent: email is not configured');
    r = await notifyChanges(A);
    assert.equal(r.lines.length, 0, 'the same changes are not reported twice');
});

// ── Health ────────────────────────────────────────────────────────────────────────────────────
test('VMS health: waiting scans with no worker is down; schedules stopped by scope are flagged', async () => {
    db.tables.vms_scan_jobs.push({ id: randomUUID(), org_id: A, status: 'queued', requested_at: new Date(Date.now() - 7 * H).toISOString() });
    db.tables.vms_scan_schedules.push({ id: randomUUID(), org_id: A, enabled: false, next_run_at: new Date().toISOString(), last_result: 'Disabled: That scope is not active' });
    const checks = await vmsChecks();
    const by = Object.fromEntries(checks.map((c) => [c.name, c]));
    assert.equal(by['VMS scanner'].status, 'down');
    assert.equal(by['VMS scan queue'].status, 'degraded');
    assert.equal(by['VMS schedules'].status, 'degraded');
    assert.match(by['VMS schedules'].detail, /1 stopped because their scope ended/);
});
