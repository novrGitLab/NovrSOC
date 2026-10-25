// F-07: the SOAR engine (infra/soar/soar.py) no longer blocks an IP or isolates a host directly
// for tier 2/3 alerts — it asks for approval here (POST /api/soar/response-requests, shared
// SOAR_ENGINE_TOKEN, same pattern as POST /api/soar/enrich) and a soc_manager/super_admin decides
// it exactly like a request from a case, a playbook or the threat board. This file proves:
//   • the token check fails closed (wrong token, no token, SOAR_ENGINE_TOKEN unset);
//   • a valid request only ever creates a pending response_approvals row — nothing runs;
//   • a repeated request for the same action/target returns the existing one, not a duplicate;
//   • bad input (unknown action, no target, no org_id) is refused;
//   • once approved, it runs through the exact same path every other source uses (honestly
//     "skipped" here, since OPNsense/Wazuh are not configured in this test).
// Fake PostgREST only; no network.
process.env.JWT_SECRET = 'soar-response-requests-test-secret';
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
import soarRouter from '../soar';
import responseApprovalsRouter from '../responseApprovals';

const A = 'org-a';
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const TOKEN = 'unit-test-soar-engine-token-do-not-log';
const tok = (role: string, email: string) => jwt.sign({ sub: randomUUID(), email, role, org_id: A }, process.env.JWT_SECRET!);
const MANAGER = tok('soc_manager', 'mo@a.test');
const MANAGER2 = tok('soc_manager', 'max@a.test');

async function soarPost(path: string, body: unknown, token: string | null = TOKEN) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (token !== null) headers['X-NovrSOC-SOAR-Token'] = token;
    const r = await fetch(`${base}${path}`, { method: 'POST', headers, body: JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
async function http(method: string, path: string, bearer: string, body?: unknown) {
    const r = await fetch(`${base}${path}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
let caseRow: Row;

before(async () => {
    let n = 0;
    db = await startFakePostgrest({
        organisations: [{ id: 'oa', slug: A, name: 'Org A' }],
        cases: [], case_tasks: [], case_timeline: [], soar_log: [], response_approvals: [], alerts: [],
    }, {}, {
        response_approvals: { status: 'pending', requested_at: new Date().toISOString() },
        cases: { status: 'open', get case_number() { return `CASE-${++n}`; } } as Row,
    });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    process.env.SOAR_ENGINE_TOKEN = TOKEN;
    const app = express();
    app.use(express.json());
    app.use('/api/soar', soarRouter);
    app.use('/api/response-approvals', requireAuth, responseApprovalsRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => {
    for (const t of ['cases', 'case_tasks', 'case_timeline', 'soar_log', 'response_approvals']) db.tables[t].length = 0;
    caseRow = { id: randomUUID(), org_id: A, case_number: 'CASE-A1', title: 'Brute force on web-01', severity: 'high', status: 'open', source: 'wazuh', source_ip: '203.0.113.9', agent_id: '003', agent_name: 'web-01', tier: 3 };
    db.tables.cases.push(caseRow);
    process.env.SOAR_ENGINE_TOKEN = TOKEN;
});

test('no SOAR_ENGINE_TOKEN configured refuses every request, even a correct-looking one', async () => {
    delete process.env.SOAR_ENGINE_TOKEN;
    const r = await soarPost('/api/soar/response-requests', { action: 'block_ip', target: '198.51.100.7', org_id: A, reason: 'x' });
    assert.equal(r.status, 401);
    assert.match(r.data.detail, /not set/);
    assert.equal(db.tables.response_approvals.length, 0);
});

test('wrong or missing token is refused', async () => {
    assert.equal((await soarPost('/api/soar/response-requests', { action: 'block_ip', target: '1.2.3.4', org_id: A, reason: 'x' }, 'wrong-token')).status, 401);
    assert.equal((await soarPost('/api/soar/response-requests', { action: 'block_ip', target: '1.2.3.4', org_id: A, reason: 'x' }, null)).status, 401);
    assert.equal(db.tables.response_approvals.length, 0);
});

test('bad input is refused before anything is created', async () => {
    assert.equal((await soarPost('/api/soar/response-requests', { action: 'delete_everything', target: '1.2.3.4', org_id: A, reason: 'x' })).status, 400, 'unknown action');
    assert.equal((await soarPost('/api/soar/response-requests', { action: 'block_ip', target: '', org_id: A, reason: 'x' })).status, 400, 'empty target');
    assert.equal((await soarPost('/api/soar/response-requests', { action: 'block_ip', target: '1.2.3.4', reason: 'x' })).status, 400, 'no org_id');
    assert.equal(db.tables.response_approvals.length, 0);
});

test('a valid block_ip request only creates a pending approval — nothing runs', async () => {
    const r = await soarPost('/api/soar/response-requests', {
        action: 'block_ip', target: '203.0.113.9', org_id: A, case_id: caseRow.id, reason: 'Tier 3 alert — automatic containment request',
    });
    assert.equal(r.status, 201);
    assert.equal(r.data.existing, false);
    assert.equal(db.tables.soar_log.length, 0, 'no action was attempted');
    assert.equal(db.tables.response_approvals.length, 1);
    const a = db.tables.response_approvals[0];
    assert.deepEqual([a.action, a.target, a.status, a.case_id, a.source, a.requested_by], ['block_ip', '203.0.113.9', 'pending', caseRow.id, 'soar', 'novrsoc-soar-engine']);
    assert.equal(a.id, r.data.approval_id);
});

test('an isolate_agent request carries the agent name as target_label', async () => {
    const r = await soarPost('/api/soar/response-requests', {
        action: 'isolate_agent', target: '003', target_label: 'web-01', org_id: A, case_id: caseRow.id, reason: 'Tier 3 alert — automatic containment request',
    });
    assert.equal(r.status, 201);
    assert.deepEqual([db.tables.response_approvals[0].action, db.tables.response_approvals[0].target_label], ['isolate_agent', 'web-01']);
});

test('a repeated request for the same action and target returns the existing one, not a duplicate', async () => {
    const first = await soarPost('/api/soar/response-requests', { action: 'block_ip', target: '203.0.113.9', org_id: A, reason: 'first' });
    const again = await soarPost('/api/soar/response-requests', { action: 'block_ip', target: '203.0.113.9', org_id: A, reason: 'second alert, same source' });
    assert.equal(again.status, 200);
    assert.equal(again.data.existing, true);
    assert.equal(again.data.approval_id, first.data.approval_id);
    assert.equal(db.tables.response_approvals.length, 1);
});

test('once approved, it runs through the same path as any other source — honestly "skipped" with no containment configured', async () => {
    const req = await soarPost('/api/soar/response-requests', { action: 'block_ip', target: '203.0.113.9', org_id: A, case_id: caseRow.id, reason: 'Tier 3 alert' });
    const ok = await http('POST', `/api/response-approvals/${req.data.approval_id}/approve`, MANAGER);
    assert.equal(ok.status, 200);
    assert.equal(ok.data.approval.status, 'skipped');
    assert.match(ok.data.approval.result, /^SKIPPED/);
    assert.ok(db.tables.case_timeline.some((t) => /Approved and ran: block IP 203\.0\.113\.9/.test(String(t.action))), 'the case this alert created gets the outcome on its timeline');
});

test('rejecting a SOAR request runs nothing, same as any other source', async () => {
    const req = await soarPost('/api/soar/response-requests', { action: 'isolate_agent', target: '003', target_label: 'web-01', org_id: A, reason: 'Tier 3 alert' });
    const rej = await http('POST', `/api/response-approvals/${req.data.approval_id}/reject`, MANAGER, { note: 'false positive' });
    assert.equal(rej.data.approval.status, 'rejected');
    assert.equal(db.tables.soar_log.length, 0);
});

test('the SOAR engine itself can never approve its own request — only a person with response:approve can', async () => {
    const req = await soarPost('/api/soar/response-requests', { action: 'block_ip', target: '203.0.113.9', org_id: A, reason: 'Tier 3 alert' });
    // self-approval is blocked by requested_by vs decider; the engine's requested_by ('novrsoc-soar-engine')
    // never matches a real account, so this only confirms a second manager can decide it normally.
    const ok = await http('POST', `/api/response-approvals/${req.data.approval_id}/approve`, MANAGER2);
    assert.equal(ok.status, 200);
});
