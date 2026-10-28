// R3.3E — the Reporting Center API and its supporting services (phase P30): schedule and
// recipient CRUD with tenant isolation and permission gating, generate-now (view-only vs.
// deliver), history/download with org ownership, delivery retry, scheduler claim idempotency,
// and the honest "failed delivery is never recorded as sent" rule. Fake PostgREST only; no
// network call ever leaves this process (no EMAIL_ENABLED/provider key is set, so email delivery
// always takes the documented "not configured" failure path — see services/reportDelivery.ts).
process.env.JWT_SECRET = 'reports-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'EMAIL_ENABLED', 'BREVO_API_KEY', 'RESEND_API_KEY', 'SENDGRID_API_KEY', 'SMTP_HOST']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import reportsRouter from '../reports';
import { nextRunAt, claimDueSchedules } from '../../lib/reportScheduling';

const A = 'org-a';
const B = 'org-b';
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org: string, sub = randomUUID()) => jwt.sign({ sub, email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const SUPER = tok('super_admin', A);
const MGR = tok('soc_manager', A);
const AN = tok('analyst', A);
const EXEC = tok('executive', A);
const EXEC_B = tok('executive', B);

async function http(method: string, path: string, bearer?: string, body?: unknown) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const r = await fetch(`${base}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const ct = r.headers.get('content-type') ?? '';
    return { status: r.status, data: ct.includes('json') ? await r.json().catch(() => null) : await r.text(), headers: r.headers };
}

before(async () => {
    db = await startFakePostgrest(
        {
            organisations: [{ id: randomUUID(), slug: A, name: 'Org A', is_active: true }, { id: randomUUID(), slug: B, name: 'Org B', is_active: true }],
            platform_users: [],
            report_schedules: [], report_recipients: [], report_jobs: [], report_artifacts: [], report_deliveries: [],
            org_service_grants: [], org_onboarding: [], audit_log: [],
            // Enough for periodReport() (services/vmsContinuous.ts) to run end to end against an
            // empty but existing set of tables — same table list vmsContinuous.test.ts uses.
            vms_scopes: [], vms_scan_jobs: [], vms_scan_schedules: [], vms_assets: [], vms_findings: [],
            vms_finding_events: [], vms_asset_events: [], vms_risk_snapshots: [], vms_notify_state: [], vms_wazuh_sync: [], cve_intel: [],
        },
        {},
        {
            report_schedules: { created_by: null, last_success_at: null, last_failure_at: null, last_error: null },
            report_recipients: { report_types: [], enabled: true, display_name: null, external_authorised_by: null, external_authorised_at: null, updated_by: null, get added_at() { return new Date().toISOString(); } },
            report_jobs: { schedule_id: null, requested_by: null, worker_id: null, attempts: 0, last_error: null, claimed_at: null, started_at: null, finished_at: null, get requested_at() { return new Date().toISOString(); } },
            report_deliveries: { recipient_id: null, provider: null, provider_message_id: null, error: null, attempts: 0, last_attempt_at: null, delivered_at: null },
        },
        {
            report_claim_job: (args, tables) => {
                const j = tables.report_jobs.filter((x) => x.status === 'queued').sort((a, b) => String(a.requested_at).localeCompare(String(b.requested_at)))[0];
                if (!j) return [];
                Object.assign(j, { status: 'running', worker_id: args.p_worker, claimed_at: new Date().toISOString(), started_at: new Date().toISOString(), attempts: Number(j.attempts ?? 0) + 1 });
                return [j];
            },
        },
        { report_recipients: [['org_id', 'kind', 'email']] },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use(express.json());
    app.use('/api/reports', requireAuth, reportsRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => { for (const t of Object.keys(db.tables)) if (t !== 'organisations') db.tables[t].length = 0; });

// ── Schedules ────────────────────────────────────────────────────────────────────────────────
test('schedules: create needs reports:manage, validates cadence fields, and computes a future next_run_at', async () => {
    assert.equal((await http('POST', '/api/reports/schedules', EXEC, { report_type: 'vms', cadence: 'weekly', day_of_week: 2 })).status, 403, 'executive has reports:read only');
    const bad = await http('POST', '/api/reports/schedules', MGR, { report_type: 'vms', cadence: 'weekly' });
    assert.equal(bad.status, 400, 'weekly without day_of_week');
    const r = await http('POST', '/api/reports/schedules', MGR, { report_type: 'vms', cadence: 'weekly', day_of_week: 2, hour_local: 9, enabled: true });
    assert.equal(r.status, 201, JSON.stringify(r.data));
    assert.ok(Date.parse(r.data.schedule.next_run_at) > Date.now());
    assert.equal(r.data.schedule.org_id, A);
});

test('schedules: tenant isolation — another organisation cannot see, patch or delete this one', async () => {
    const created = await http('POST', '/api/reports/schedules', MGR, { report_type: 'vms', cadence: 'weekly', day_of_week: 2 });
    const id = created.data.schedule.id;
    assert.deepEqual((await http('GET', '/api/reports/schedules', EXEC_B)).data.schedules, []);
    assert.equal((await http('PATCH', `/api/reports/schedules/${id}`, tok('soc_manager', B), { enabled: true })).status, 404);
    assert.equal((await http('DELETE', `/api/reports/schedules/${id}`, tok('soc_manager', B))).status, 404);
    // Own tenant can still act on it.
    assert.equal((await http('PATCH', `/api/reports/schedules/${id}`, MGR, { enabled: true })).status, 200);
});

test('schedules: a report type whose module is disabled for this org cannot be scheduled', async () => {
    db.tables.org_onboarding.push({ org_id: A, status: 'active', current_step: 6, completed_steps: [1, 2, 3, 4, 5, 6], steps: {} });
    db.tables.org_service_grants.push({ org_id: A, service: 'vms', status: 'disabled' });
    const r = await http('POST', '/api/reports/schedules', MGR, { report_type: 'vms', cadence: 'weekly', day_of_week: 2 });
    assert.equal(r.status, 403);
    assert.match(r.data.error, /not enabled/);
});

// ── Recipients ───────────────────────────────────────────────────────────────────────────────
test('recipients: portal_user must be an active account in this organisation; external_email just needs to be well-formed', async () => {
    const noAccount = await http('POST', '/api/reports/recipients', MGR, { kind: 'portal_user', email: 'nobody@org-a.test' });
    assert.equal(noAccount.status, 400);
    db.tables.platform_users.push({ id: randomUUID(), org_id: db.tables.organisations.find((o) => o.slug === A)!.id, email: 'ciso@org-a.test', role: 'executive', status: 'active' });
    const ok = await http('POST', '/api/reports/recipients', MGR, { kind: 'portal_user', email: 'ciso@org-a.test' });
    assert.equal(ok.status, 201, JSON.stringify(ok.data));
    const ext = await http('POST', '/api/reports/recipients', MGR, { kind: 'external_email', email: 'partner@elsewhere.test' });
    assert.equal(ext.status, 201);
    assert.equal(ext.data.recipient.external_authorised_by, null, 'external recipients start unauthorised');
    assert.equal((await http('POST', '/api/reports/recipients', MGR, { kind: 'external_email', email: 'not-an-email' })).status, 400);
    const dup = await http('POST', '/api/reports/recipients', MGR, { kind: 'external_email', email: 'partner@elsewhere.test' });
    assert.equal(dup.status, 409);
    assert.equal((await http('POST', '/api/reports/recipients', EXEC, { kind: 'external_email', email: 'x@y.test' })).status, 403, 'read-only role cannot add recipients');
});

test('recipients: an unauthorised external address is excluded from delivery until explicitly authorised, and stays out if disabled', async () => {
    const ext = (await http('POST', '/api/reports/recipients', MGR, { kind: 'external_email', email: 'partner@elsewhere.test' })).data.recipient;
    const { recipientsFor } = await import('../../services/reportRecipients');
    assert.deepEqual(await recipientsFor(A, 'vms'), [], 'unauthorised external recipient is not eligible yet');
    assert.equal((await http('POST', `/api/reports/recipients/${ext.id}/authorise`, AN)).status, 200);
    assert.equal((await recipientsFor(A, 'vms')).length, 1);
    await http('PATCH', `/api/reports/recipients/${ext.id}`, MGR, { enabled: false });
    assert.deepEqual(await recipientsFor(A, 'vms'), [], 'disabled recipient excluded even once authorised');
});

test('recipients: cross-tenant delete/patch is a 404, not a silent no-op that could leak existence', async () => {
    const r = await http('POST', '/api/reports/recipients', MGR, { kind: 'external_email', email: 'x@elsewhere.test' });
    assert.equal((await http('DELETE', `/api/reports/recipients/${r.data.recipient.id}`, tok('soc_manager', B))).status, 404);
    assert.equal((await http('DELETE', `/api/reports/recipients/${r.data.recipient.id}`, MGR)).status, 200);
});

// ── Generate / history / download ────────────────────────────────────────────────────────────
test('generate: view-only (reports:read) works without delivering; reports:manage is required to also deliver', async () => {
    const viewOnly = await http('POST', '/api/reports/generate', EXEC, { report_type: 'vms', period_days: 7, deliver: false });
    assert.equal(viewOnly.status, 201, JSON.stringify(viewOnly.data));
    assert.deepEqual(viewOnly.data.deliveries, [], 'no delivery attempted when deliver is false');
    const noManage = await http('POST', '/api/reports/generate', EXEC, { report_type: 'vms', deliver: true });
    assert.equal(noManage.status, 403, 'executive holds reports:read only, not reports:manage');
});

test('generate: an email recipient but no configured provider never becomes a false "sent" — it is honestly recorded failed', async () => {
    await http('POST', '/api/reports/recipients', MGR, { kind: 'external_email', email: 'ext@elsewhere.test' });
    const extId = (await http('GET', '/api/reports/recipients', MGR)).data.recipients[0].id;
    await http('POST', `/api/reports/recipients/${extId}/authorise`, MGR);
    const r = await http('POST', '/api/reports/generate', MGR, { report_type: 'vms', period_days: 7, deliver: true });
    assert.equal(r.status, 201, JSON.stringify(r.data));
    assert.equal(r.data.deliveries.length, 1);
    assert.equal(r.data.deliveries[0].status, 'failed', 'email is not configured in this test environment');
    assert.equal(db.tables.report_deliveries[0].status, 'failed');
    assert.notEqual(db.tables.report_deliveries[0].status, 'sent');
});

test('generate: a module disabled for this org is refused before any report is built', async () => {
    db.tables.org_onboarding.push({ org_id: A, status: 'active', current_step: 6, completed_steps: [1, 2, 3, 4, 5, 6], steps: {} });
    db.tables.org_service_grants.push({ org_id: A, service: 'cnii_watch', status: 'disabled' });
    const r = await http('POST', '/api/reports/generate', MGR, { report_type: 'cnii' });
    assert.equal(r.status, 403);
    assert.equal(db.tables.report_jobs.length, 0, 'no job row for a report that was never allowed to start');
});

test('history and download: scoped to the caller\'s organisation, with real PDF and CSV bytes', async () => {
    const gen = await http('POST', '/api/reports/generate', MGR, { report_type: 'vms', period_days: 7, deliver: false });
    const jobId = gen.data.job_id;
    const hist = await http('GET', '/api/reports/history', MGR);
    assert.equal(hist.data.jobs[0].id, jobId);
    assert.equal((await http('GET', '/api/reports/history', tok('soc_manager', B))).data.jobs.length, 0, 'another org sees none of this history');
    const pdf = await http('GET', `/api/reports/${jobId}/download?format=pdf`, MGR);
    assert.equal(pdf.status, 200);
    assert.equal(pdf.headers.get('content-type'), 'application/pdf');
    const csv = await http('GET', `/api/reports/${jobId}/download?format=csv`, MGR);
    assert.equal(csv.status, 200);
    assert.match(String(csv.headers.get('content-type')), /text\/csv/);
    assert.equal((await http('GET', `/api/reports/${jobId}/download?format=pdf`, tok('soc_manager', B))).status, 404, 'another org cannot download this artifact');
});

test('delivery retry: a recipient removed since the original attempt is never silently retried', async () => {
    await http('POST', '/api/reports/recipients', MGR, { kind: 'external_email', email: 'ext2@elsewhere.test' });
    const extId = (await http('GET', '/api/reports/recipients', MGR)).data.recipients[0].id;
    await http('POST', `/api/reports/recipients/${extId}/authorise`, MGR);
    const gen = await http('POST', '/api/reports/generate', MGR, { report_type: 'vms', deliver: true });
    const deliveryId = db.tables.report_deliveries[0].id;
    assert.equal(db.tables.report_deliveries[0].status, 'failed');
    await http('DELETE', `/api/reports/recipients/${extId}`, MGR);
    const retry = await http('POST', `/api/reports/deliveries/${deliveryId}/retry`, MGR);
    assert.equal(retry.status, 400);
    assert.match(retry.data.error, /no longer eligible/);
    void gen;
});

// ── Operations (staff only, platform-wide) ──────────────────────────────────────────────────
test('ops health: staff only, never executive, and reports real queue/stuck-job state', async () => {
    assert.equal((await http('GET', '/api/reports/ops/health', EXEC)).status, 403);
    assert.equal((await http('GET', '/api/reports/ops/health', AN)).status, 403, 'analyst is not a manager/admin');
    const stale = randomUUID();
    db.tables.report_jobs.push({ id: stale, org_id: A, report_type: 'vms', status: 'running', claimed_at: new Date(Date.now() - 60 * 60_000).toISOString(), worker_id: 'w1', requested_at: new Date().toISOString() });
    const r = await http('GET', '/api/reports/ops/health', SUPER);
    assert.equal(r.status, 200);
    assert.equal(r.data.stuck_jobs.length, 1);
    assert.equal(r.data.stuck_jobs[0].id, stale);
});

// ── Scheduling: pure next-run computation and claim idempotency ────────────────────────────
test('nextRunAt: weekly and monthly cadences land in the future, in Africa/Lagos local time', () => {
    const weekly = nextRunAt({ cadence: 'weekly', day_of_week: 3, day_of_month: null, hour_local: 8, timezone: 'Africa/Lagos' });
    assert.ok(weekly.getTime() > Date.now());
    const monthly = nextRunAt({ cadence: 'monthly', day_of_week: null, day_of_month: 15, hour_local: 8, timezone: 'Africa/Lagos' });
    assert.ok(monthly.getTime() > Date.now());
});

test('claimDueSchedules: a due schedule is claimed by only one caller — no duplicate scheduled delivery across replicas', async () => {
    const dueId = randomUUID();
    db.tables.report_schedules.push({ id: dueId, org_id: A, report_type: 'vms', format: 'executive', cadence: 'weekly', day_of_week: 1, day_of_month: null, hour_local: 8, timezone: 'Africa/Lagos', enabled: true, next_run_at: new Date(Date.now() - 1000).toISOString(), last_success_at: null, last_failure_at: null, last_error: null });
    const [first, second] = await Promise.all([claimDueSchedules(), claimDueSchedules()]);
    const claimedIds = [...first, ...second].map((s) => s.id);
    assert.equal(claimedIds.filter((id) => id === dueId).length, 1, 'exactly one of the two concurrent callers claims it');
});
