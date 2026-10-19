// Phase P8 weekly insights: counts for the period and the one before, tenant isolation, top
// rules, limitations from unhealthy pipelines, the route's permission, and that the AI context is
// exactly the counted facts (every record cited by ref). Fake PostgREST, no network, no model call.
process.env.JWT_SECRET = 'insights-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'NVIDIA_API_KEY']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest } from './fakePostgrest';
import insightsRouter from '../insights';
import { weeklyFacts } from '../../services/weeklyInsights';
import { aiPurpose } from '../../services/aiPurposes';
import '../../services/aiPurposesTi';

const A = 'org-a';
const B = 'org-b';
const DAY = 86_400_000;
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = A) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const ago = (days: number) => new Date(Date.now() - days * DAY).toISOString();

before(async () => {
    db = await startFakePostgrest({ alerts: [], cases: [], response_approvals: [], vms_findings: [], vms_finding_events: [], ti_matches: [], alert_quarantine: [], audit_log: [] });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use(express.json());
    app.use('/api/insights', requireAuth, insightsRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => { for (const t of Object.keys(db.tables)) db.tables[t].length = 0; });

function seed() {
    const alert = (org: string, days: number, severity: string, rule: string) => db.tables.alerts.push({ id: randomUUID(), org_id: org, received_at: ago(days), event_time: ago(days), severity, rule_id: rule, rule_description: `Rule ${rule}`, agent_name: 'web-01' });
    alert(A, 1, 'high', '5710'); alert(A, 2, 'high', '5710'); alert(A, 3, 'critical', '100200');
    alert(A, 9, 'low', '5710');                       // previous period
    alert(B, 1, 'critical', '999');                   // another organisation
    db.tables.cases.push(
        { id: randomUUID(), org_id: A, status: 'open', severity: 'high', created_at: ago(1), due_at: ago(0.5), resolved_at: null },
        { id: randomUUID(), org_id: A, status: 'resolved', severity: 'medium', created_at: ago(10), resolved_at: ago(2) },
        { id: randomUUID(), org_id: B, status: 'open', severity: 'critical', created_at: ago(1) },
    );
    db.tables.response_approvals.push({ id: randomUUID(), org_id: A, status: 'approved', requested_at: ago(1) }, { id: randomUUID(), org_id: A, status: 'pending', requested_at: ago(2) });
    db.tables.vms_findings.push(
        { id: randomUUID(), org_id: A, status: 'open', priority: 'P1', first_seen: ago(1), due_at: ago(0.1) },
        { id: randomUUID(), org_id: A, status: 'verified', priority: 'P2', first_seen: ago(20), verified_at: ago(2) },
    );
    db.tables.ti_matches.push({ id: randomUUID(), org_id: A, status: 'promoted', first_matched_at: ago(1) }, { id: randomUUID(), org_id: B, status: 'new', first_matched_at: ago(1) });
}

test('weeklyFacts counts this period against the previous one, for this organisation only', async () => {
    seed();
    const f = await weeklyFacts(A, 7);
    assert.equal(f.alerts.total, 3);
    assert.equal(f.alerts.previous_total, 1);
    assert.deepEqual(f.alerts.by_severity, { high: 2, critical: 1 });
    assert.deepEqual(f.alerts.top_rules[0], { rule_id: '5710', description: 'Rule 5710', count: 2 });
    assert.equal(f.alerts.sampled, false);
    assert.deepEqual([f.cases.opened, f.cases.resolved, f.cases.open_now, f.cases.overdue_now], [1, 1, 1, 1]);
    assert.deepEqual(f.approvals, { approved: 1, pending: 1 });
    assert.deepEqual(f.vulnerabilities, { open_now: 1, open_by_priority: { P1: 1 }, new_p1_p2: 1, verified: 1, reopened: 0, overdue_now: 1 });
    assert.deepEqual(f.threat_intel, { new_matches: 1, promoted: 1 });
});

test('unhealthy pipelines become stated limitations', async () => {
    // No alert has ever been stored: alert ingestion is down, so the numbers may be missing data.
    const f = await weeklyFacts(A, 7);
    assert.ok(f.limitations.some((l) => /Alert ingestion is down/.test(l)), f.limitations.join(' | '));
    assert.equal(f.alerts.total, 0);
});

test('GET /api/insights/weekly: staff only, 7 or 30 days', async () => {
    seed();
    const get = async (t: string, q = '') => { const r = await fetch(`${base}/api/insights/weekly${q}`, { headers: { Authorization: `Bearer ${t}` } }); return { status: r.status, data: await r.json() }; };
    assert.equal((await get(tok('executive'))).status, 403);
    assert.equal((await get(tok('portal_user'))).status, 403);
    const r = await get(tok('analyst'), '?days=30');
    assert.equal(r.status, 200);
    assert.equal(r.data.period.days, 30);
    assert.equal(r.data.org, A);
});

test('weekly_insights AI context is exactly the counted facts, each with a citable ref', async () => {
    seed();
    const p = aiPurpose('weekly_insights')!;
    assert.equal(p.permission, 'alerts:read');
    assert.equal(await p.build(A, 'yesterday'), null, 'only 7d or 30d');
    const ctx = (await p.build(A, '7d'))!;
    const refs = ctx.refs.map((r) => r.ref);
    for (const r of ['period:7d', 'metric:alerts', 'metric:cases', 'metric:approvals', 'metric:vulnerabilities', 'metric:threat_intel', 'limitations:all']) assert.ok(refs.includes(r), r);
    const alerts = ctx.records.find((r) => r.ref === 'metric:alerts')!;
    assert.equal(alerts.total, 3);
    assert.ok(!JSON.stringify(ctx.records).includes(B), 'nothing from another organisation');
});
