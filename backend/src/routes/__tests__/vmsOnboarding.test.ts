// Phase P27 VMS onboarding and automation: scan authorisation (request → the organisation's
// approval with a declaration → immutable record), who may approve, rejection and renewal; pending
// scopes authorise nothing (queue, claim, the worker's scope list); scan windows and job limits at
// queue time, at claim and in the scheduler; verification schedules; asset imports (manual, CSV,
// Wazuh by group) that never change scope; the inventory's authorisation column; tenant isolation
// and the unchanged CNII passive registration. Fake PostgREST only; no scanner runs and nothing on
// the network is touched. All targets are reserved documentation names and addresses.
process.env.JWT_SECRET = 'vms-onboarding-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'VMS_WORKER_TOKEN', 'VMS_MAX_ACTIVE_JOBS_PER_ORG', 'VMS_MAX_ACTIVE_JOBS_PER_SCOPE']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest } from './fakePostgrest';
import vmsRouter from '../vms';
import vmsWorkerRouter from '../vmsWorker';
import vmsImportRouter from '../vmsImport';
import vmsContinuousRouter from '../vmsContinuous';
import { runDueSchedules, LIMIT_RETRY_MS } from '../../services/vmsContinuous';
import { parseCsv, previewGroup, importGroup, authorisationFor } from '../../services/vmsImport';
import { parseScanWindows, inScanWindow, nextScanWindow, type ScanWindows } from '../../lib/scanWindows';
import { DECLARATION_VERSION, sha256 } from '../../services/vmsAuthorisation';
import { hasPermission } from '../../lib/permissions';
import type { WazuhAgent } from '../../lib/wazuh-group';
import type { ScopeEntry } from '../../lib/vmsScope';

const A = 'org-a';
const B = 'org-b';
const WT = 'w'.repeat(40);
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = A, email = `${role}@${org}.test`) => jwt.sign({ sub: randomUUID(), email, role, org_id: org }, process.env.JWT_SECRET!);
const MGR = tok('soc_manager');
const EXEC = tok('executive');
async function http(method: string, path: string, bearer?: string, body?: unknown, headers: Record<string, string> = {}) {
    const h: Record<string, string> = { 'Content-Type': 'application/json', ...headers };
    if (bearer) h.Authorization = `Bearer ${bearer}`;
    const r = await fetch(`${base}${path}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const future = (d = 30) => new Date(Date.now() + d * 86_400_000).toISOString();
const worker = (path: string, body: unknown) => http('POST', `/api/vms/worker${path}`, WT, body);
const request = (body: Record<string, unknown>, bearer = MGR, headers: Record<string, string> = {}) =>
    http('POST', '/api/vms/scopes', bearer, { authorization_reference: 'LOA-2026-031 signed by the asset owner', expires_at: future(), ...body }, headers);
const approval = (over: Record<string, unknown> = {}) => ({ authority_name: 'Ada Obi', authority_title: 'Chief Information Security Officer', organisation_name: 'Acme Water Ltd', declaration_version: DECLARATION_VERSION, declaration_accepted: true, ...over });
const approve = (group: string, bearer = EXEC, over: Record<string, unknown> = {}, headers: Record<string, string> = {}) =>
    http('POST', `/api/vms/scope-requests/${group}/approve`, bearer, approval(over), headers);
/** A requested and approved active scope entry. */
async function activeScope(body: Record<string, unknown>, org = A): Promise<Record<string, any>> { // eslint-disable-line @typescript-eslint/no-explicit-any
    const r = await request(body, tok('soc_manager', org));
    assert.equal(r.status, 201, JSON.stringify(r.data));
    const a = await approve(r.data.request_group_id, tok('executive', org), org === B ? { organisation_name: 'Beta Grid' } : {});
    assert.equal(a.status, 200, JSON.stringify(a.data));
    return a.data.scopes[0];
}
const hhmm = (t: number) => new Date(t).toISOString().slice(11, 16);
/** Windows (UTC, every day) that open `from` ms from now and close `to` ms from now. */
const windowsFrom = (from: number, to: number): ScanWindows => ({ tz: 'UTC', windows: [{ days: [1, 2, 3, 4, 5, 6, 7], start: hhmm(Date.now() + from), end: hhmm(Date.now() + to) }] });

before(async () => {
    db = await startFakePostgrest(
        {
            organisations: [{ id: 'oa', slug: A, name: 'Acme Water Ltd' }, { id: 'ob', slug: B, name: 'Beta Grid' }],
            vms_scopes: [], vms_scan_jobs: [], vms_assets: [], vms_services: [], vms_technologies: [], vms_asset_events: [], vms_scope_approvals: [], vms_scan_schedules: [],
            vms_findings: [], vms_finding_events: [], wazuh_group_org_map: [], vms_workers: [], org_access_audit: [], staff_org_assignments: [],
        },
        { 'vms_asset_events.vms_assets': 'asset_id', 'vms_scan_jobs.vms_scopes': 'scope_id' },
        {
            vms_scopes: { status: 'active', approved_at: new Date().toISOString() },
            vms_scan_jobs: { status: 'queued', attempts: 0, cancel_requested: false, progress: {}, requested_at: new Date().toISOString() },
            vms_assets: { status: 'active', exposure: 'unknown', criticality: 'medium', hostnames: [], ips: [], dns: {}, discovery_sources: [], first_seen: new Date().toISOString(), last_seen: new Date().toISOString() },
            vms_asset_events: { at: new Date().toISOString() },
            vms_scan_schedules: { enabled: true },
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
    app.use('/api/vms/import', requireAuth, express.json({ limit: '1mb' }), vmsImportRouter);
    app.use(express.json());
    app.use('/api/vms', requireAuth, vmsRouter);
    app.use('/api/vms', requireAuth, vmsContinuousRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => {
    for (const t of ['vms_scopes', 'vms_scan_jobs', 'vms_assets', 'vms_asset_events', 'vms_scope_approvals', 'vms_scan_schedules', 'vms_findings', 'vms_finding_events', 'wazuh_group_org_map', 'vms_workers']) db.tables[t].length = 0;
    process.env.VMS_WORKER_TOKEN = WT;
    delete process.env.VMS_MAX_ACTIVE_JOBS_PER_ORG;
});

// ── Permissions ──────────────────────────────────────────────────────────────────────────────
test('vms:authorize: the organisation administrator (executive) and super_admin, never the soc_manager who requests', () => {
    assert.equal(hasPermission('executive', 'vms:authorize'), true);
    assert.equal(hasPermission('super_admin', 'vms:authorize'), true);
    for (const r of ['soc_manager', 'analyst', 'portal_user']) assert.equal(hasPermission(r, 'vms:authorize'), false, r);
    assert.equal(hasPermission('executive', 'vms:scope'), false, 'the approver does not also request');
});

// ── Authorisation workflow ───────────────────────────────────────────────────────────────────
test('an active request is pending; only the organisation approves it, with the full declaration, and the record is kept', async () => {
    const r = await request({ kind: 'ip', value: '192.0.2.10', allow_port_scan: true });
    assert.equal(r.status, 201);
    assert.equal(r.data.scope.status, 'pending');
    const g = r.data.request_group_id as string;
    assert.equal((await request({ kind: 'ip', value: '192.0.2.10', allow_port_scan: true })).status, 409, 'one open request per target');

    // The approver reads exactly what they would accept.
    const view = await http('GET', `/api/vms/scope-requests/${g}`, EXEC);
    assert.equal(view.status, 200);
    assert.equal(view.data.organisation_name, 'Acme Water Ltd');
    assert.match(view.data.declaration, /192\.0\.2\.10: discovery, port scanning/);
    assert.equal(view.data.declaration_sha256, sha256(view.data.declaration));

    // Not the requester, not an analyst, not another organisation.
    assert.equal((await approve(g, MGR)).status, 403);
    assert.equal((await approve(g, tok('analyst'))).status, 403);
    assert.equal((await approve(g, tok('executive', B), { organisation_name: 'Beta Grid' })).status, 404, 'org B cannot see org A\'s request');
    assert.equal((await http('GET', `/api/vms/scope-requests/${g}`, tok('executive', B))).status, 404);
    // A disclaimer alone is not enough: every element of the declaration is checked.
    assert.equal((await approve(g, EXEC, { declaration_accepted: false })).status, 400);
    assert.equal((await approve(g, EXEC, { declaration_version: 'vms-scan-authority-v0' })).status, 400);
    assert.equal((await approve(g, EXEC, { organisation_name: 'Acme' })).status, 400, 'the organisation name must be typed exactly');
    assert.equal((await approve(g, EXEC, { authority_name: 'A' })).status, 400);
    assert.equal((await approve(g, EXEC, { method: 'offline_document', signed_document_ref: 'DOC-1' })).status, 400, 'executives approve in the platform');
    assert.equal(db.tables.vms_scope_approvals.length, 0, 'refused attempts store no approval');
    assert.equal(db.tables.vms_scopes.find((s) => s.id === r.data.scope.id)!.status, 'pending');

    const ok = await approve(g, EXEC, { organisation_name: 'acme water ltd' });
    assert.equal(ok.status, 200, JSON.stringify(ok.data));
    const s = ok.data.scopes[0];
    assert.deepEqual([s.status, s.approved_by, s.approval_method, s.approval_id, s.requested_by], ['active', 'executive@org-a.test', 'in_platform', ok.data.approval_id, 'soc_manager@org-a.test']);
    const rec = db.tables.vms_scope_approvals[0];
    assert.deepEqual([rec.org_id, rec.decision, rec.method, rec.decided_by_email, rec.decided_by_role, rec.authority_name, rec.declaration_version], [A, 'approved', 'in_platform', 'executive@org-a.test', 'executive', 'Ada Obi', DECLARATION_VERSION]);
    assert.equal(rec.declaration_text, view.data.declaration);
    assert.equal(rec.declaration_sha256, sha256(String(rec.declaration_text)));
    assert.deepEqual(rec.scope_ids, [s.id]);
    assert.equal((rec.snapshot as { entries: { value: string }[] }).entries[0].value, '192.0.2.10');
    assert.equal((await approve(g)).status, 409, 'a decided request cannot be decided again');

    const list = await http('GET', '/api/vms/scope-approvals', MGR);
    assert.equal(list.data.approvals.length, 1);
    assert.equal((await http('GET', '/api/vms/scope-approvals', tok('soc_manager', B))).data.approvals.length, 0, 'tenant isolation');
    // Approved once, scanned repeatedly: no further approval per scan.
    for (const kind of ['discovery', 'ports']) assert.equal((await http('POST', '/api/vms/scans', MGR, { scope_id: s.id, kind })).status, 201, kind);
});

test('a super_admin approves in the platform only for their own organisation; for a client, only a signed document', async () => {
    const r = await request({ kind: 'ip', value: '198.51.100.7' }, tok('soc_manager', B));
    const g = r.data.request_group_id as string;
    const SA = tok('super_admin');
    const asB = { 'X-Org-Id': B };
    assert.equal((await approve(g, SA, { organisation_name: 'Beta Grid' }, asB)).status, 403, 'in-platform approval is the client\'s');
    assert.equal((await approve(g, SA, { organisation_name: 'Beta Grid', method: 'offline_document' }, asB)).status, 400, 'the signed document reference is required');
    const ok = await approve(g, SA, { organisation_name: 'Beta Grid', method: 'offline_document', signed_document_ref: 'Signed LOA BG-2026-11, filed DMS-4471' }, asB);
    assert.equal(ok.status, 200, JSON.stringify(ok.data));
    assert.equal(ok.data.scopes[0].approval_method, 'offline_document');
    assert.equal(db.tables.vms_scope_approvals[0].signed_document_ref, 'Signed LOA BG-2026-11, filed DMS-4471');
    assert.equal(db.tables.vms_scope_approvals[0].org_id, B);

    // A super_admin who requested for their own organisation cannot also approve it.
    const own = await request({ kind: 'ip', value: '198.51.100.8' }, SA);
    assert.equal((await approve(own.data.request_group_id, SA)).status, 403);
    assert.equal((await approve(own.data.request_group_id, EXEC)).status, 200);
});

test('rejection: a reason is required; a rejected request authorises nothing and cannot be approved later', async () => {
    const r = await request({ kind: 'domain', value: 'shop.example.test', allow_vuln_scan: true });
    const g = r.data.request_group_id as string;
    assert.equal((await http('POST', `/api/vms/scope-requests/${g}/reject`, EXEC, { reason: '' })).status, 400);
    assert.equal((await http('POST', `/api/vms/scope-requests/${g}/reject`, MGR, { reason: 'not ours' })).status, 403);
    const rej = await http('POST', `/api/vms/scope-requests/${g}/reject`, EXEC, { reason: 'That shop is run by a supplier, not by us' });
    assert.equal(rej.status, 200);
    const s = db.tables.vms_scopes.find((x) => x.id === r.data.scope.id)!;
    assert.deepEqual([s.status, s.rejected_by, s.rejection_reason], ['rejected', 'executive@org-a.test', 'That shop is run by a supplier, not by us']);
    assert.equal(db.tables.vms_scope_approvals[0].decision, 'rejected');
    assert.equal((await approve(g)).status, 409);
    assert.equal((await http('POST', '/api/vms/scans', MGR, { scope_id: s.id, kind: 'discovery' })).status, 400);
});

test('a multi-entry request is approved under one declaration; passive and active entries are requested separately', async () => {
    const entries = [{ kind: 'cidr', value: '203.0.113.0/28', allow_port_scan: true }, { kind: 'domain', value: 'example.test' }].map((e) => ({ authorization_reference: 'LOA-9', expires_at: future(), ...e }));
    const r = await http('POST', '/api/vms/scope-requests', MGR, { entries });
    assert.equal(r.status, 201);
    assert.equal(r.data.scopes.length, 2);
    assert.ok(r.data.scopes.every((s: { request_group_id: string; status: string }) => s.status === 'pending' && s.request_group_id === r.data.request_group_id));
    const ok = await approve(r.data.request_group_id);
    assert.equal(ok.data.scopes.length, 2);
    assert.equal(db.tables.vms_scope_approvals.length, 1);
    const mixed = await http('POST', '/api/vms/scope-requests', MGR, { entries: [{ kind: 'asn', value: 'AS64500', authorization_reference: 'x-1', expires_at: future() }, { ...entries[0], value: '203.0.113.16/28' }] });
    assert.equal(mixed.status, 400);
});

test('renewal: the approved entry supersedes the active one; schedules move if still permitted, otherwise stop with the reason', async () => {
    const old = await activeScope({ kind: 'ip', value: '192.0.2.20', allow_port_scan: true });
    const sDisc = { id: randomUUID(), org_id: A, scope_id: old.id, kind: 'discovery', targets: [], interval_hours: 24, next_run_at: future(1), enabled: true };
    const sPorts = { id: randomUUID(), org_id: A, scope_id: old.id, kind: 'ports', targets: [], interval_hours: 24, next_run_at: future(1), enabled: true };
    db.tables.vms_scan_schedules.push(sDisc, sPorts);
    // The renewal is pending and does not disturb the active entry until approved.
    const r = await request({ kind: 'ip', value: '192.0.2.20', allow_port_scan: false });
    assert.equal(r.status, 201);
    assert.equal(db.tables.vms_scopes.find((s) => s.id === old.id)!.status, 'active');
    const ok = await approve(r.data.request_group_id);
    assert.deepEqual(ok.data.superseded, [old.id]);
    const was = db.tables.vms_scopes.find((s) => s.id === old.id)!;
    assert.equal(was.status, 'revoked');
    assert.match(String(was.revoked_by), /^superseded by approval /);
    assert.equal(sDisc.scope_id, r.data.scope.id, 'discovery is still permitted: the schedule moves');
    assert.equal(sPorts.enabled, false, 'ports are no longer permitted: the schedule stops');
    assert.match(String((sPorts as Record<string, unknown>).last_result), /no longer permits ports/);
});

test('revocation is open to the organisation that granted the authorisation', async () => {
    const s = await activeScope({ kind: 'ip', value: '192.0.2.30' });
    assert.equal((await http('POST', `/api/vms/scopes/${s.id}/revoke`, tok('analyst'))).status, 403);
    assert.equal((await http('POST', `/api/vms/scopes/${s.id}/revoke`, tok('executive', B))).status, 404);
    assert.equal((await http('POST', `/api/vms/scopes/${s.id}/revoke`, EXEC)).status, 200);
});

// ── Pending scope authorises nothing, anywhere ───────────────────────────────────────────────
test('a pending entry authorises nothing: not at queue time, not at claim, not in the worker\'s scope list', async () => {
    const r = await request({ kind: 'ip', value: '192.0.2.40', allow_port_scan: true });
    const pendingId = r.data.scope.id as string;
    assert.equal((await http('POST', '/api/vms/scans', MGR, { scope_id: pendingId, kind: 'discovery' })).status, 400);
    // A job that somehow names it (written straight to the queue) is cancelled when a worker asks.
    db.tables.vms_scan_jobs.push({ id: randomUUID(), org_id: A, scope_id: pendingId, kind: 'discovery', status: 'queued', targets: ['192.0.2.40'], cancel_requested: false, requested_at: new Date().toISOString() });
    const c = await worker('/claim', { worker_id: 'vps-1', kinds: ['discovery'] });
    assert.equal(c.status, 200);
    assert.equal(c.data.job, null);
    assert.match(c.data.notice, /no longer active/);
    assert.equal(db.tables.vms_scan_jobs[0].status, 'cancelled');
    // With an active entry alongside, the worker receives only active entries to check against.
    const s = await activeScope({ kind: 'ip', value: '192.0.2.41' });
    assert.equal((await http('POST', '/api/vms/scans', MGR, { scope_id: s.id, kind: 'discovery' })).status, 201);
    const got = await worker('/claim', { worker_id: 'vps-1', kinds: ['discovery'] });
    assert.ok(got.data.job);
    assert.deepEqual(got.data.scopes.map((x: { value: string }) => x.value), ['192.0.2.41']);
});

test('passive-only registrations (CNII Watch) are still registered at once, without the approval step', async () => {
    const r = await request({ kind: 'domain', value: 'grid.example.test', allow_discovery: false });
    assert.equal(r.status, 201);
    assert.equal(r.data.approval_required, undefined);
    assert.deepEqual([r.data.scope.status, r.data.scope.approved_by], ['active', 'soc_manager@org-a.test']);
    const asn = await request({ kind: 'asn', value: 'AS64501' });
    assert.equal(asn.data.scope.status, 'active');
    assert.equal(db.tables.vms_scope_approvals.length, 0);
});

// ── Scan windows ─────────────────────────────────────────────────────────────────────────────
test('scan windows: validated; across midnight; the next opening', () => {
    assert.equal(parseScanWindows({ tz: 'Mars/Olympus', windows: [{ days: [1], start: '01:00', end: '02:00' }] }).ok, false);
    assert.equal(parseScanWindows({ windows: [{ days: [8], start: '01:00', end: '02:00' }] }).ok, false);
    assert.equal(parseScanWindows({ windows: [{ days: [1], start: '1:00', end: '02:00' }] }).ok, false);
    assert.equal(parseScanWindows({ windows: [{ days: [1], start: '02:00', end: '02:00' }] }).ok, false);
    assert.equal(parseScanWindows({ windows: [] }).ok, false);
    const p = parseScanWindows({ windows: [{ days: [5], start: '22:00', end: '05:00' }] });
    assert.ok(p.ok && p.value);
    const w = (p as { value: ScanWindows }).value;
    assert.equal(w.tz, 'Africa/Lagos', 'default time zone');
    // 2026-10-23 is a Friday. Lagos is UTC+1.
    assert.equal(inScanWindow(w, Date.parse('2026-10-23T21:30:00Z')), true, 'Friday 22:30 Lagos');
    assert.equal(inScanWindow(w, Date.parse('2026-10-24T03:59:00Z')), true, 'Saturday 04:59 Lagos — the same window');
    assert.equal(inScanWindow(w, Date.parse('2026-10-24T04:00:00Z')), false, 'Saturday 05:00 Lagos — closed');
    assert.equal(inScanWindow(w, Date.parse('2026-10-22T21:30:00Z')), false, 'Thursday evening is not listed');
    assert.equal(nextScanWindow(w, Date.parse('2026-10-23T12:00:00Z')), Date.parse('2026-10-23T21:00:00Z'));
    assert.equal(inScanWindow(null), true, 'no windows: any time');
});

test('scan windows are enforced at queue time (with when to retry), at claim, and the scheduler waits for them', async () => {
    const s = await activeScope({ kind: 'ip', value: '192.0.2.50', allow_port_scan: true, scan_windows: windowsFrom(2 * 3_600_000, 3 * 3_600_000) });
    assert.equal(s.scan_windows.tz, 'UTC');
    const q = await http('POST', '/api/vms/scans', MGR, { scope_id: s.id, kind: 'ports' });
    assert.equal(q.status, 409);
    assert.match(q.data.error, /Outside the approved scan windows/);
    const retry = Date.parse(q.data.retry_at);
    assert.ok(Math.abs(retry - (Date.now() + 2 * 3_600_000)) < 2 * 60_000, 'retry when the window opens');
    // Passive collection is not scanning and is not held to the window.
    assert.notEqual((await http('POST', '/api/vms/scans', MGR, { scope_id: s.id, kind: 'passive_osint' })).status, 409);

    // A job queued earlier (before the windows were in force) is not handed out.
    db.tables.vms_scan_jobs.length = 0;
    db.tables.vms_scan_jobs.push({ id: randomUUID(), org_id: A, scope_id: s.id, kind: 'ports', status: 'queued', targets: ['192.0.2.50'], cancel_requested: false, requested_at: new Date().toISOString() });
    const c = await worker('/claim', { worker_id: 'vps-1', kinds: ['ports'] });
    assert.equal(c.data.job, null);
    assert.match(c.data.notice, /outside the approved scan windows/);
    assert.equal(db.tables.vms_scan_jobs[0].status, 'cancelled');

    const sched = { id: randomUUID(), org_id: A, scope_id: s.id, kind: 'ports', targets: [], interval_hours: 24, next_run_at: new Date(Date.now() - 60_000).toISOString(), enabled: true };
    db.tables.vms_scan_schedules.push(sched);
    const runs = await runDueSchedules();
    assert.equal(runs[0].outcome, 'waiting');
    assert.equal(sched.enabled, true, 'not disabled');
    assert.ok(Math.abs(Date.parse(sched.next_run_at) - retry) < 2 * 60_000, 'next run is the window opening');
});

test('job limits: per scope entry and per organisation; the scheduler retries shortly instead of failing', async () => {
    const s = await activeScope({ kind: 'ip', value: '192.0.2.60', allow_port_scan: true, max_active_jobs: 1 });
    assert.equal((await http('POST', '/api/vms/scans', MGR, { scope_id: s.id, kind: 'discovery' })).status, 201);
    const q = await http('POST', '/api/vms/scans', MGR, { scope_id: s.id, kind: 'ports' });
    assert.equal(q.status, 429);
    assert.match(q.data.error, /under this scope entry \(limit 1\)/);
    assert.equal((await http('POST', '/api/vms/scans', MGR, { scope_id: s.id, kind: 'discovery' })).status, 200, 'the same scan returns the open job, not a limit');

    const sched = { id: randomUUID(), org_id: A, scope_id: s.id, kind: 'ports', targets: [], interval_hours: 24, next_run_at: new Date(Date.now() - 60_000).toISOString(), enabled: true };
    db.tables.vms_scan_schedules.push(sched);
    const now = Date.now();
    const runs = await runDueSchedules(now);
    assert.equal(runs[0].outcome, 'waiting');
    assert.equal(Date.parse(sched.next_run_at), now + LIMIT_RETRY_MS);

    process.env.VMS_MAX_ACTIVE_JOBS_PER_ORG = '1';
    const other = await activeScope({ kind: 'ip', value: '192.0.2.61' });
    const o = await http('POST', '/api/vms/scans', MGR, { scope_id: other.id, kind: 'discovery' });
    assert.equal(o.status, 429);
    assert.match(o.data.error, /for this organisation \(limit 1\)/);
    assert.equal((await http('POST', '/api/vms/scans', tok('soc_manager', B), { scope_id: (await activeScope({ kind: 'ip', value: '198.51.100.61' }, B)).id, kind: 'discovery' })).status, 201, 'one organisation\'s queue does not hold back another\'s');
});

// ── Verification schedules ───────────────────────────────────────────────────────────────────
test('verification schedules: need a scope that permits vulnerability tests; rescan fixed findings inside it, once', async () => {
    const noVuln = await activeScope({ kind: 'ip', value: '192.0.2.70', allow_port_scan: true });
    const bad = await http('POST', '/api/vms/schedules', MGR, { scope_id: noVuln.id, kind: 'verification', interval_hours: 24 });
    assert.equal(bad.status, 403, JSON.stringify(bad.data));
    const s = await activeScope({ kind: 'ip', value: '192.0.2.71', allow_port_scan: true, allow_vuln_scan: true });
    const created = await http('POST', '/api/vms/schedules', MGR, { scope_id: s.id, kind: 'verification', interval_hours: 24 });
    assert.equal(created.status, 201, JSON.stringify(created.data));
    const sched = db.tables.vms_scan_schedules.find((x) => x.id === created.data.schedule.id)!;
    assert.equal(sched.kind, 'verification');

    const fixed = (id: string, asset_value: string, extra: Record<string, unknown> = {}) => ({ id, org_id: A, status: 'fixed_pending_verification', asset_value, source_class: 'active_scan', detected_by: ['nuclei'], rule_id: 'tls-weak', title: 'Weak TLS', port: 443, protocol: 'tcp', service: 'https', ...extra });
    db.tables.vms_findings.push(fixed(randomUUID(), '192.0.2.71'), fixed(randomUUID(), '192.0.2.99'), fixed(randomUUID(), '192.0.2.71', { source_class: 'wazuh', detected_by: ['wazuh'] }), fixed(randomUUID(), '192.0.2.71', { source_class: 'passive_intel', detected_by: [] }));
    sched.next_run_at = new Date(Date.now() - 60_000).toISOString();
    const runs = await runDueSchedules();
    assert.equal(runs[0].outcome, 'queued', runs[0].detail);
    const jobs = db.tables.vms_scan_jobs.filter((j) => j.purpose === 'verification');
    assert.equal(jobs.length, 1, 'only the finding inside the scope, and not the Wazuh one');
    assert.deepEqual(jobs[0].targets, ['192.0.2.71']);
    sched.next_run_at = new Date(Date.now() - 60_000).toISOString();
    await runDueSchedules();
    assert.equal(db.tables.vms_scan_jobs.filter((j) => j.purpose === 'verification').length, 1, 'a waiting verification is not queued twice');
});

// ── Imports ──────────────────────────────────────────────────────────────────────────────────
test('CSV: header optional, values checked, limits enforced', () => {
    const p = parseCsv('value,type,owner,criticality\n192.0.2.5,ip,Ops,high\n"www.example.test",,Web team,\n\n');
    assert.ok(p.ok);
    assert.deepEqual((p as { rows: unknown[] }).rows, [{ value: '192.0.2.5', type: 'ip', owner: 'Ops', criticality: 'high' }, { value: 'www.example.test', type: undefined, owner: 'Web team', criticality: undefined }].map((r) => Object.fromEntries(Object.entries(r).filter(([, v]) => v !== undefined))));
    assert.equal(parseCsv('x'.repeat(600 * 1024)).ok, false);
});

test('manual and CSV imports: dry run stores nothing; duplicates collapse; existing assets are labelled; scope never changes', async () => {
    const s = await activeScope({ kind: 'cidr', value: '192.0.2.0/28', allow_port_scan: true });
    await request({ kind: 'domain', value: 'pending.example.test' });
    const scopesBefore = JSON.stringify(db.tables.vms_scopes);
    const entries = [{ value: '192.0.2.5', owner: 'Ops' }, { value: '192.0.2.5' }, { value: 'www.pending.example.test' }, { value: '198.51.100.9' }, { value: 'not a host!' }, { value: '10.0.0.0/8' }];
    const dry = await http('POST', '/api/vms/import/assets', MGR, { entries, dry_run: true });
    assert.equal(dry.status, 200, JSON.stringify(dry.data));
    assert.equal(db.tables.vms_assets.length, 0, 'a dry run stores nothing');
    const byValue = Object.fromEntries(dry.data.results.filter((r: { status: string }) => r.status !== 'duplicate').map((r: { value: string }) => [r.value, r]));
    assert.equal(byValue['192.0.2.5'].authorisation.status, 'authorised');
    assert.equal(byValue['192.0.2.5'].authorisation.scope_id, s.id);
    assert.equal(byValue['www.pending.example.test'].authorisation.status, 'pending_approval');
    assert.equal(byValue['198.51.100.9'].authorisation.status, 'not_authorised');
    assert.equal(dry.data.counts.duplicate, 1);
    assert.ok(dry.data.counts.invalid >= 1);

    const real = await http('POST', '/api/vms/import/assets', MGR, { entries, dry_run: false });
    assert.equal(real.status, 200);
    const created = db.tables.vms_assets.length;
    assert.equal(created, real.data.counts.new);
    assert.ok(db.tables.vms_assets.every((a) => a.org_id === A && (a.discovery_sources as string[]).includes('manual')));
    const csv = await http('POST', '/api/vms/import/csv', MGR, { csv: 'value,owner\n192.0.2.5,Network team\n192.0.2.6,\n' });
    assert.equal(csv.status, 200, JSON.stringify(csv.data));
    assert.equal(csv.data.counts.existing, 1);
    assert.equal(csv.data.counts.new, 1);
    const five = db.tables.vms_assets.find((a) => a.value === '192.0.2.5')!;
    assert.deepEqual(five.discovery_sources, ['manual', 'csv']);
    assert.equal(JSON.stringify(db.tables.vms_scopes), scopesBefore, 'an import never creates or widens scope');
    assert.equal((await http('POST', '/api/vms/import/assets', EXEC, { entries })).status, 403, 'executives read the inventory; they do not change it');

    // The same value in another organisation is that organisation's own asset.
    await http('POST', '/api/vms/import/assets', tok('soc_manager', B), { entries: [{ value: '192.0.2.5' }] });
    assert.equal(db.tables.vms_assets.filter((a) => a.value === '192.0.2.5').length, 2);

    // The inventory shows where each came from and whether it may be scanned.
    const inv = await http('GET', '/api/vms/assets', MGR);
    assert.equal(inv.status, 200);
    const a5 = inv.data.assets.find((a: { value: string }) => a.value === '192.0.2.5');
    assert.deepEqual(a5.sources, ['Manual', 'CSV import']);
    assert.equal(a5.authorization.status, 'authorised');
    assert.equal(inv.data.assets.find((a: { value: string }) => a.value === '198.51.100.9').authorization.status, 'not_authorised');
    assert.equal(inv.data.assets.length, created + 1, 'org A sees only its own assets');
});

const agent = (id: string, name: string, ip: string | null, group: string[]): WazuhAgent => ({ id, name, ip, os: 'Ubuntu 24.04', status: 'active', lastKeepAlive: null, group });

test('Wazuh import by group: only the organisation\'s own groups; ambiguous agents and the manager are left out; scope unchanged', async () => {
    db.tables.wazuh_group_org_map.push({ wazuh_group: 'acme-servers', org_id: A }, { wazuh_group: 'shared-dmz', org_id: B }, { wazuh_group: 'beta', org_id: B });
    const agents = [agent('000', 'manager', '127.0.0.1', ['acme-servers']), agent('001', 'Web-01', '192.0.2.11', ['acme-servers']), agent('002', 'gw-01', '192.0.2.12', ['acme-servers', 'shared-dmz']), agent('003', 'db-01', '192.0.2.13', ['acme-servers'])];
    const deps = { agentsForGroup: async (g: string) => (g === 'acme-servers' ? agents : []), addresses: async (id: string) => (id === '001' ? [{ address: '10.20.0.11' }] : []) };
    await activeScope({ kind: 'ip', value: '192.0.2.11', allow_port_scan: true });
    const scopesBefore = JSON.stringify(db.tables.vms_scopes);

    assert.deepEqual((await http('GET', '/api/vms/import/wazuh/groups', MGR)).data.groups, ['acme-servers']);
    assert.deepEqual((await http('GET', '/api/vms/import/wazuh/groups', tok('soc_manager', B))).data.groups, ['beta', 'shared-dmz']);
    const foreign = await previewGroup(B, 'acme-servers', false, deps);
    assert.equal(foreign.ok, false, 'org B cannot preview org A\'s group');
    assert.equal((foreign as { status: number }).status, 404);

    const p = await previewGroup(A, 'acme-servers', true, deps);
    assert.ok(p.ok);
    const by = Object.fromEntries((p as { agents: { agent_id: string }[] }).agents.map((a) => [a.agent_id, a])) as unknown as Record<string, { importable: boolean; reason: string | null; addresses: string[]; authorisation: { status: string } }>;
    assert.equal(by['000'].importable, false);
    assert.equal(by['002'].importable, false);
    assert.match(String(by['002'].reason), /more than one organisation/);
    assert.deepEqual(by['001'].addresses, ['192.0.2.11', '10.20.0.11'], 'IP discovery adds interface addresses');
    assert.equal(by['001'].authorisation.status, 'authorised');
    assert.equal(by['003'].authorisation.status, 'not_authorised');

    const r = await importGroup(A, 'soc_manager@org-a.test', 'acme-servers', ['000', '001', '002', '003', '777'], true, deps);
    assert.ok(r.ok);
    const ok = r as { imported: number; updated: number; skipped: { agent_id: string }[] };
    assert.equal(ok.imported, 2);
    assert.deepEqual(ok.skipped.map((x) => x.agent_id).sort(), ['000', '002', '777']);
    const web = db.tables.vms_assets.find((a) => a.wazuh_agent_id === '001')!;
    assert.deepEqual([web.org_id, web.asset_type, web.value, web.ips], [A, 'endpoint', 'web-01', ['192.0.2.11']], 'ips stay the registered address, as the sync keeps them');
    assert.deepEqual((db.tables.vms_asset_events.find((e) => e.asset_id === web.id)!.details as { addresses_seen: string[] }).addresses_seen, ['192.0.2.11', '10.20.0.11']);
    // Importing again updates rather than duplicates.
    const again = await importGroup(A, 'soc_manager@org-a.test', 'acme-servers', ['001'], false, deps);
    assert.deepEqual([(again as { imported: number }).imported, (again as { updated: number }).updated], [0, 1]);
    assert.equal(db.tables.vms_assets.filter((a) => a.wazuh_agent_id === '001').length, 1);
    assert.equal(JSON.stringify(db.tables.vms_scopes), scopesBefore, 'an import never creates or widens scope');
    assert.equal((await http('POST', '/api/vms/import/wazuh', MGR, { group: 'beta', agent_ids: ['001'] })).status, 404, 'org A cannot import org B\'s group');
});

test('authorisation per target follows the activities, the expiry and pending status', () => {
    const e = (over: Partial<ScopeEntry>) => ({ id: randomUUID(), org_id: A, kind: 'ip', value: '192.0.2.80', include_subdomains: false, allow_port_scan: false, allow_vuln_scan: false, status: 'active', expires_at: future(), ...over }) as ScopeEntry;
    assert.deepEqual(authorisationFor('192.0.2.80', [e({ allow_port_scan: true })], []).activities, ['discovery', 'ports']);
    assert.equal(authorisationFor('192.0.2.80', [e({ expires_at: new Date(Date.now() - 1000).toISOString() })], []).status, 'not_authorised');
    assert.equal(authorisationFor('192.0.2.80', [], [e({ status: 'pending' })]).status, 'pending_approval');
    assert.equal(authorisationFor(null, [], []).status, 'not_applicable');
});
