// Phase P3: response approvals (request → approve/reject/cancel, no self-approval, honest result)
// and alert triage (assignment to real accounts, acknowledgement, notes, history, promote to case
// without duplicates, tenant isolation). Fake PostgREST only; OPNsense and Wazuh are not
// configured here, so an approved action honestly comes back "skipped". All data synthetic.
process.env.JWT_SECRET = 'secops-p3-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'OPNSENSE_URL', 'OPNSENSE_KEY', 'OPNSENSE_SECRET', 'WAZUH_HOST', 'WAZUH_PASSWORD', 'RESPONSE_ALLOW_SELF_APPROVAL']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import casesRouter from '../cases';
import secopsRouter from '../secops';
import alertStoreRouter from '../alertStore';
import responseApprovalsRouter from '../responseApprovals';

const A = 'org-a';
const B = 'org-b';
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, email: string, org = A) => jwt.sign({ sub: randomUUID(), email, role, org_id: org }, process.env.JWT_SECRET!);
const ANALYST = tok('analyst', 'ana@a.test');
const MANAGER = tok('soc_manager', 'mo@a.test');
const MANAGER2 = tok('soc_manager', 'max@a.test');
const B_MANAGER = tok('soc_manager', 'bea@b.test', B);
async function http(method: string, path: string, bearer: string, body?: unknown) {
    const r = await fetch(`${base}${path}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
let caseRow: Row;
let alertRow: Row;

before(async () => {
    let n = 0;
    db = await startFakePostgrest({
        organisations: [{ id: 'oa', slug: A, name: 'Org A' }, { id: 'ob', slug: B, name: 'Org B' }],
        cases: [], case_tasks: [], case_timeline: [], soar_log: [], response_approvals: [], alerts: [], alert_events: [], platform_users: [],
    }, { 'platform_users.organisations': 'org_id' }, {
        response_approvals: { status: 'pending', requested_at: new Date().toISOString() },
        cases: { status: 'open', get case_number() { return `CASE-${++n}`; } } as Row,
    });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use(express.json());
    app.use('/api/cases', requireAuth, casesRouter);
    app.use('/api/secops', requireAuth, secopsRouter);
    app.use('/api/alerts', alertStoreRouter);
    app.use('/api/response-approvals', requireAuth, responseApprovalsRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => {
    for (const t of ['cases', 'case_tasks', 'case_timeline', 'soar_log', 'response_approvals', 'alerts', 'alert_events', 'platform_users']) db.tables[t].length = 0;
    caseRow = { id: randomUUID(), org_id: A, case_number: 'CASE-A1', title: 'Brute force on web-01', severity: 'high', status: 'open', source: 'manual', source_ip: '203.0.113.9', agent_id: '003', agent_name: 'web-01', tier: 2 };
    db.tables.cases.push(caseRow);
    db.tables.case_tasks.push({ id: randomUUID(), case_id: caseRow.id, step_id: 'isolate_agent', title: 'Isolate host', status: 'pending' });
    alertRow = { id: randomUUID(), org_id: A, wazuh_alert_id: 'w-1', rule_id: '5710', rule_level: 10, rule_description: 'sshd: authentication failed', agent_id: '003', agent_name: 'web-01', severity: 'high', mitre_ids: ['T1110'], status: 'new', case_id: null, event_time: '2026-10-14T08:00:00Z', received_at: '2026-10-14T08:00:05Z', raw: { data: { srcip: '203.0.113.9' } }, raw_truncated: false, assigned_to: null, acknowledged_at: null, triage_note: null };
    db.tables.alerts.push(alertRow);
    db.tables.platform_users.push(
        { id: randomUUID(), org_id: 'oa', email: 'ana@a.test', role: 'analyst', status: 'active' },
        { id: randomUUID(), org_id: 'ob', email: 'bob@b.test', role: 'portal_user', status: 'active' },
        { id: randomUUID(), org_id: 'oa', email: 'gone@a.test', role: 'analyst', status: 'disabled' },
    );
    delete process.env.RESPONSE_ALLOW_SELF_APPROVAL;
});

// ── Response approvals ───────────────────────────────────────────────────────────────────────

test('isolating from a case only creates a pending request; nothing runs', async () => {
    const r = await http('POST', `/api/cases/${caseRow.id}/execute-step`, ANALYST, { step_id: 'isolate_agent' });
    assert.equal(r.status, 202);
    assert.equal(r.data.outcome, 'pending_approval');
    assert.equal(db.tables.soar_log.length, 0, 'no action was attempted');
    const a = db.tables.response_approvals[0];
    assert.deepEqual([a.action, a.target, a.target_label, a.status, a.case_id, a.requested_by], ['isolate_agent', '003', 'web-01', 'pending', caseRow.id, 'ana@a.test']);
    assert.match(String(db.tables.case_tasks[0].result), /PENDING APPROVAL/);
    assert.equal(db.tables.case_tasks[0].status, 'pending');
    const again = await http('POST', `/api/cases/${caseRow.id}/execute-step`, ANALYST, { step_id: 'isolate_agent' });
    assert.equal(again.data.message, 'Already waiting for approval');
    assert.equal(db.tables.response_approvals.length, 1, 'one open request per action and target');
});

test('playbook block and isolate also wait for approval', async () => {
    assert.equal((await http('POST', '/api/secops/actions/block-ip', ANALYST, { ip: '198.51.100.7', reason: 'C2 beacon' })).status, 202);
    assert.equal((await http('POST', '/api/secops/actions/isolate', ANALYST, { endpoint_id: '009' })).status, 202);
    assert.equal(db.tables.response_approvals.length, 2);
    assert.equal(db.tables.soar_log.length, 0);
});

test('an analyst cannot approve; a manager cannot approve their own request; another manager can', async () => {
    await http('POST', '/api/secops/actions/block-ip', MANAGER, { ip: '198.51.100.7', reason: 'C2 beacon' });
    const id = db.tables.response_approvals[0].id;
    assert.equal((await http('POST', `/api/response-approvals/${id}/approve`, ANALYST)).status, 403);
    const self = await http('POST', `/api/response-approvals/${id}/approve`, MANAGER);
    assert.equal(self.status, 409);
    const ok = await http('POST', `/api/response-approvals/${id}/approve`, MANAGER2, { note: 'confirmed C2' });
    assert.equal(ok.status, 200);
    // OPNsense isn't configured: the honest result is "skipped", never "executed".
    assert.equal(ok.data.approval.status, 'skipped');
    assert.match(ok.data.approval.result, /^SKIPPED/);
    assert.equal(ok.data.approval.decided_by, 'max@a.test');
    assert.equal((await http('POST', `/api/response-approvals/${id}/approve`, MANAGER2)).status, 409, 'decided once');
});

test('self-approval is possible only when explicitly allowed (a team of one)', async () => {
    process.env.RESPONSE_ALLOW_SELF_APPROVAL = 'true';
    await http('POST', `/api/cases/${caseRow.id}/execute-step`, MANAGER, { step_id: 'isolate_agent' });
    const id = db.tables.response_approvals[0].id;
    const r = await http('POST', `/api/response-approvals/${id}/approve`, MANAGER);
    assert.equal(r.status, 200);
    assert.notEqual(r.data.approval.status, 'executed', 'Wazuh not configured here');
    assert.equal(db.tables.case_tasks[0].status, 'pending', 'task stays pending unless the action succeeded');
    assert.ok(db.tables.case_timeline.some((t) => /Approved and ran: isolate agent web-01/.test(String(t.action))));
});

test('reject runs nothing; the requester can cancel; other orgs see and decide nothing', async () => {
    await http('POST', '/api/secops/actions/block-ip', ANALYST, { ip: '198.51.100.7', reason: 'x' });
    await http('POST', '/api/secops/actions/isolate', ANALYST, { endpoint_id: '009' });
    const [blk, iso] = db.tables.response_approvals;
    assert.equal((await http('GET', '/api/response-approvals', B_MANAGER)).data.approvals.length, 0);
    assert.equal((await http('POST', `/api/response-approvals/${blk.id}/approve`, B_MANAGER)).status, 404);
    const rej = await http('POST', `/api/response-approvals/${blk.id}/reject`, MANAGER, { note: 'false positive' });
    assert.equal(rej.data.approval.status, 'rejected');
    assert.equal(db.tables.soar_log.length, 0);
    assert.equal((await http('POST', `/api/response-approvals/${iso.id}/cancel`, ANALYST)).data.approval.status, 'cancelled');
    const list = await http('GET', '/api/response-approvals?status=pending', MANAGER);
    assert.equal(list.data.approvals.length, 0);
});

// ── Alert triage ─────────────────────────────────────────────────────────────────────────────

test('assign to a real active account, acknowledge, note — each recorded in the history', async () => {
    let r = await http('PATCH', `/api/alerts/${alertRow.id}`, ANALYST, { assigned_to: 'Ana@A.test', acknowledged: true, triage_note: 'checking auth logs' });
    assert.equal(r.status, 200);
    assert.deepEqual([alertRow.assigned_to, alertRow.acknowledged_by, alertRow.triage_note], ['ana@a.test', 'ana@a.test', 'checking auth logs']);
    for (const bad of ['bob@b.test', 'gone@a.test', 'nobody@a.test']) {
        r = await http('PATCH', `/api/alerts/${alertRow.id}`, ANALYST, { assigned_to: bad });
        assert.equal(r.status, 400, bad);
    }
    assert.equal((await http('PATCH', `/api/alerts/${alertRow.id}`, ANALYST, { status: 'closed' })).status, 400, 'status has its own route');
    await http('PATCH', `/api/alerts/${alertRow.id}/status`, ANALYST, { status: 'false_positive' });
    const ev = await http('GET', `/api/alerts/${alertRow.id}/events`, ANALYST);
    assert.deepEqual(ev.data.events.map((e: Row) => e.action), ['assign', 'acknowledge', 'note', 'status']);
    assert.equal(ev.data.events[3].to_value, 'false_positive');
});

test('search and filters: text, unassigned, mine, in a case or not', async () => {
    db.tables.alerts.push({ ...alertRow, id: randomUUID(), wazuh_alert_id: 'w-2', rule_description: 'Possible ransomware', assigned_to: 'ana@a.test', case_id: randomUUID() });
    const get = async (qs: string) => (await http('GET', `/api/alerts?${qs}`, ANALYST)).data.alerts.map((a: Row) => a.wazuh_alert_id).sort();
    assert.deepEqual(await get('q=ransomware'), ['w-2']);
    assert.deepEqual(await get('assigned=unassigned'), ['w-1']);
    assert.deepEqual(await get('assigned=me'), ['w-2']);
    assert.deepEqual(await get('case=unlinked'), ['w-1']);
    assert.equal((await http('GET', '/api/alerts?q=a%22)%2Cor(', ANALYST)).status, 400, 'filter injection refused');
});

test('promote to case: one case, linked, repeat calls return it; other orgs get 404', async () => {
    const r = await http('POST', `/api/alerts/${alertRow.id}/case`, ANALYST);
    assert.equal(r.status, 201);
    assert.equal(alertRow.case_id, r.data.case.id);
    const c = db.tables.cases.find((x) => x.id === r.data.case.id)!;
    assert.deepEqual([c.source, c.source_id, c.org_id, c.source_ip], ['alert', alertRow.id, A, '203.0.113.9']);
    const again = await http('POST', `/api/alerts/${alertRow.id}/case`, ANALYST);
    assert.equal(again.status, 200);
    assert.equal(again.data.case.id, r.data.case.id);
    assert.equal(db.tables.cases.filter((x) => x.source === 'alert').length, 1);
    assert.equal((await http('POST', `/api/alerts/${alertRow.id}/case`, B_MANAGER)).status, 404);
    assert.equal((await http('PATCH', `/api/alerts/${alertRow.id}`, B_MANAGER, { triage_note: 'x' })).status, 404);
});
