// Phase P20 — read-only VMS insights: dashboard KPIs and series, risk model and matrix, audit trail,
// remediation tasks and AI plans. Fake PostgREST; asserts tenant isolation, that inconclusive scans
// are never counted as assessed, that missing history stays empty, and that nothing is written.
process.env.JWT_SECRET = 'vms-insights-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'VMS_WORKER_TOKEN', 'NVIDIA_API_KEY', 'WAZUH_HOST', 'WAZUH_INDEXER_HOST']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import vmsInsightsRouter, { likelihoodOf } from '../vmsInsights';

const A = 'org-a';
const B = 'org-b';
const DAY = 86_400_000;
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = A) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const AN = tok('analyst');
const EXEC = tok('executive');
const PORTAL = tok('portal_user');
async function get(path: string, bearer: string) {
    const r = await fetch(`${base}${path}`, { headers: { Authorization: `Bearer ${bearer}` } });
    return { status: r.status, data: (await r.json().catch(() => null)) as Row };
}
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();
const asset = (org: string, exposure: string, b: Row = {}): Row => { const a = { id: randomUUID(), org_id: org, value: `${exposure}-${randomUUID().slice(0, 4)}`, asset_type: 'host', exposure, criticality: 'high', status: 'active', ...b }; db.tables.vms_assets.push(a); return a; };
const finding = (org: string, b: Row = {}): Row => { const f = { id: randomUUID(), org_id: org, title: 'Finding', asset_id: null, asset_value: 'h', scanner_severity: 'medium', scanner_cvss: null, priority: 'P3', risk_score: 40, status: 'open', first_seen: iso(2 * DAY), last_seen: iso(0), due_at: null, verified_at: null, cve_ids: [], owner: null, risk_factors: null, ...b }; db.tables.vms_findings.push(f); return f; };

before(async () => {
    db = await startFakePostgrest(
        { vms_assets: [], vms_findings: [], vms_remediation_tasks: [], vms_scan_jobs: [], vms_risk_snapshots: [], vms_asset_events: [], vms_finding_events: [], vms_workers: [], cve_intel: [], audit_log: [], ai_artifacts: [] },
        { 'vms_asset_events.vms_assets': 'asset_id' },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use(express.json());
    app.use('/api/vms', requireAuth, vmsInsightsRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => { for (const t of Object.keys(db.tables)) db.tables[t].length = 0; db.log.length = 0; });

test('dashboard KPIs count only this organisation, exclude info from vulnerabilities, and define critical exposure', async () => {
    const pub = asset(A, 'internet');
    const lan = asset(A, 'internal');
    asset(B, 'internet');
    finding(A, { scanner_severity: 'critical', priority: 'P1', risk_score: 90, asset_id: pub.id, asset_value: String(pub.value) });
    finding(A, { scanner_severity: 'high', priority: 'P2', risk_score: 70, asset_id: lan.id });
    finding(A, { scanner_severity: 'info', priority: 'P4', risk_score: 2, asset_id: pub.id });
    finding(A, { status: 'verified', verified_at: iso(DAY) });
    finding(B, { scanner_severity: 'critical', priority: 'P1', risk_score: 99 });
    db.tables.vms_remediation_tasks.push(
        { id: randomUUID(), org_id: A, finding_id: randomUUID(), title: 'Patch', status: 'todo', due_at: iso(DAY), created_at: iso(3 * DAY) },
        { id: randomUUID(), org_id: A, finding_id: randomUUID(), title: 'Done', status: 'done', due_at: iso(DAY), created_at: iso(3 * DAY) },
        { id: randomUUID(), org_id: B, finding_id: randomUUID(), title: 'B', status: 'todo', due_at: iso(DAY), created_at: iso(3 * DAY) },
    );
    const r = await get('/api/vms/dashboard?days=30', AN);
    assert.equal(r.status, 200);
    const k = r.data.kpis as Row;
    assert.equal(k.total_assets, 2);
    assert.equal(k.open_findings, 3);
    assert.equal(k.open_vulnerabilities, 2);
    assert.equal(k.critical_open, 1);
    assert.equal(k.critical_exposures, 1);
    assert.equal(k.overdue_tasks, 1);
    assert.equal(k.verified_in_period, 1);
    assert.equal(k.remediation_rate, 33);
    assert.equal(k.risk_mean, 80);
    assert.equal(k.risk_max, 90);
    assert.equal(k.engines_available, 0);
    const lists = r.data.lists as Row;
    assert.equal((lists.recent_critical as Row[]).length, 2);
    assert.equal(((lists.highest_risk_assets as Row[])[0]).asset_id, pub.id);
    assert.ok(db.log.every((l) => !/^(POST|PATCH|DELETE)/.test(l)), 'the dashboard never writes');
});

test('scan activity never counts a scan that reached no host as assessed', async () => {
    const job = (status: string, outcome?: string): Row => ({ id: randomUUID(), org_id: A, kind: 'ports', status, summary: outcome ? { outcome } : {}, requested_at: iso(DAY), finished_at: iso(DAY) });
    db.tables.vms_scan_jobs.push(job('succeeded', 'assessed'), job('succeeded', 'unreachable'), job('succeeded', 'insufficient_evidence'), job('failed'), { ...job('succeeded', 'assessed'), org_id: B });
    const r = await get('/api/vms/dashboard?days=7', AN);
    const series = (r.data.charts as Row).scan_activity as Row[];
    const total = (k: string) => series.reduce((s, d) => s + Number(d[k]), 0);
    assert.equal(series.length >= 7, true);
    assert.equal(total('assessed'), 1);
    assert.equal(total('inconclusive'), 2);
    assert.equal(total('failed'), 1);
});

test('risk history is empty until snapshots record it — never estimated', async () => {
    const today = new Date().toISOString().slice(0, 10);
    db.tables.vms_risk_snapshots.push({ org_id: A, day: today, open_total: 1, open_by_priority: {}, kev_open: 0, internet_open: 0 });
    let r = await get('/api/vms/dashboard', AN);
    assert.deepEqual((r.data.charts as Row).risk, []);
    db.tables.vms_risk_snapshots[0].risk_mean = 42.5;
    db.tables.vms_risk_snapshots[0].risk_max = 70;
    r = await get('/api/vms/dashboard', AN);
    assert.deepEqual((r.data.charts as Row).risk, [{ day: today, risk_mean: 42.5, risk_max: 70 }]);
});

test('risk: model is published, matrix places KEV and EPSS likelihood, queue is ordered by priority then score', async () => {
    const pub = asset(A, 'internet');
    db.tables.cve_intel.push({ cve_id: 'CVE-1', kev: true, epss_score: 0.9, cvss_score: 9.8 }, { cve_id: 'CVE-2', kev: false, epss_score: 0.02, cvss_score: 5 });
    finding(A, { scanner_severity: 'critical', priority: 'P1', risk_score: 95, cve_ids: ['CVE-1'], asset_id: pub.id });
    finding(A, { scanner_severity: 'medium', priority: 'P3', risk_score: 41, cve_ids: ['CVE-2'] });
    finding(A, { scanner_severity: 'high', priority: 'P2', risk_score: 66 });
    finding(B, { scanner_severity: 'critical', priority: 'P1', risk_score: 99, cve_ids: ['CVE-1'] });
    const r = await get('/api/vms/risk', EXEC);
    assert.equal(r.status, 200);
    const model = r.data.model as Row;
    assert.equal((model.weights as Row).technical, 0.45);
    assert.equal((model.due_days as Row).P1, 2);
    const m = r.data.matrix as Record<string, Row>;
    assert.equal(m.kev.critical, 1);
    assert.equal(m.epss_low.medium, 1);
    assert.equal(m.unknown.high, 1);
    assert.deepEqual((r.data.queue as Row[]).map((q) => q.priority), ['P1', 'P2', 'P3']);
    assert.equal((r.data.totals as Row).kev, 1);
    assert.equal((r.data.epss as Row).no_cve, 1);
    assert.equal(likelihoodOf(false, null), 'unknown');
    assert.equal(likelihoodOf(false, 0.1), 'epss_high');
});

test('audit trail merges platform and finding history for this organisation only', async () => {
    const f = finding(A);
    db.tables.audit_log.push(
        { id: 1, at: iso(DAY), actor: 'a@x', action: 'VMS_SCAN_REQUESTED', resource: 'vms_scan', resource_id: 'j1', org_id: A, result: 'success', severity: 'info', details: '' },
        { id: 2, at: iso(DAY), actor: 'a@x', action: 'CASE_CREATED', resource: 'case', resource_id: 'c1', org_id: A, result: 'success', severity: 'info', details: '' },
        { id: 3, at: iso(DAY), actor: 'b@x', action: 'VMS_SCAN_REQUESTED', resource: 'vms_scan', resource_id: 'j2', org_id: B, result: 'success', severity: 'info', details: '' },
        { id: 4, at: iso(2 * DAY), actor: 'admin@x', action: 'CROSS_ORG_ACCESS', resource: 'GET /api/vms/findings', resource_id: A, org_id: null, result: 'success', severity: 'warning', details: '' },
        { id: 5, at: iso(2 * DAY), actor: 'admin@x', action: 'CROSS_ORG_ACCESS', resource: 'GET /api/alerts', resource_id: A, org_id: null, result: 'success', severity: 'warning', details: '' },
    );
    db.tables.vms_finding_events.push({ id: randomUUID(), org_id: A, finding_id: f.id, at: iso(0), actor: 'a@x', action: 'status', from_value: 'open', to_value: 'acknowledged', details: null });
    const r = await get('/api/vms/audit', AN);
    const entries = r.data.entries as Row[];
    assert.deepEqual(entries.map((e) => e.action), ['FINDING_STATUS', 'VMS_SCAN_REQUESTED', 'CROSS_ORG_ACCESS']);
    assert.equal(entries[0].details, 'open → acknowledged');
});

test('tasks carry their finding and an overdue flag; AI plans list only this organisation', async () => {
    const f = finding(A, { title: 'OpenSSH' });
    const fb = finding(B);
    db.tables.vms_remediation_tasks.push(
        { id: randomUUID(), org_id: A, finding_id: f.id, title: 'Upgrade', status: 'doing', due_at: iso(DAY), created_at: iso(2 * DAY) },
        { id: randomUUID(), org_id: B, finding_id: fb.id, title: 'B', status: 'todo', due_at: null, created_at: iso(DAY) },
    );
    db.tables.ai_artifacts.push(
        { id: randomUUID(), org_id: A, purpose: 'remediation_plan', subject_type: 'finding', subject_id: f.id, content: { summary: 's' }, model: 'm', created_by: 'a', created_at: iso(0), status: 'draft' },
        { id: randomUUID(), org_id: B, purpose: 'remediation_plan', subject_type: 'finding', subject_id: fb.id, content: {}, model: 'm', created_by: 'b', created_at: iso(0), status: 'draft' },
    );
    const t = await get('/api/vms/tasks', AN);
    const tasks = t.data.tasks as Row[];
    assert.equal(tasks.length, 1);
    assert.equal(tasks[0].overdue, true);
    assert.equal((tasks[0].finding as Row).title, 'OpenSSH');
    const p = await get('/api/vms/ai-plans', AN);
    assert.equal((p.data.plans as Row[]).length, 1);
    assert.equal(((p.data.plans as Row[])[0].finding as Row).title, 'OpenSSH');
});

test('every insights route requires vms:read', async () => {
    for (const path of ['dashboard', 'risk', 'audit', 'tasks', 'ai-plans']) {
        assert.equal((await get(`/api/vms/${path}`, PORTAL)).status, 403, path);
        assert.equal((await fetch(`${base}/api/vms/${path}`)).status, 401, path);
    }
});
