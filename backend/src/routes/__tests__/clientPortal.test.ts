// Phase P21: the client VMS portal on NovrSOC's own accounts (portal_user), and analyst
// organisation assignments. Sign-in and invitations, token confinement to /api/client/, tenant
// isolation, what client responses leave out, and the assignment API end to end — against the local
// fake PostgREST with synthetic organisations and accounts.
process.env.JWT_SECRET = 'client-portal-test-secret';
for (const k of ['DEV_ADMIN_EMAIL', 'DEV_ADMIN_PASSWORD', 'DEV_ADMIN_LOGIN_ENABLED', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'FRONTEND_URL', 'DEV_TOKEN_SECRET', 'WAZUH_HOST', 'WAZUH_INDEXER_HOST', 'NVIDIA_API_KEY']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { randomUUID, createHash, randomBytes } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import { requireAuth, requireRole } from '../../middleware/auth';
import authRouter from '../auth';
import portalRouter from '../portal';
import vmsRouter from '../vms';
import vmsInsightsRouter from '../vmsInsights';
import vmsFindingsRouter from '../vmsFindings';
import vmsOperationsRouter from '../vmsOperations';
import vmsClientRouter from '../vmsClient';
import { adminRouter as orgAssignmentsRouter, mineRouter as orgAccessRouter } from '../orgAccess';

const A = { id: randomUUID(), slug: 'client-a', name: 'Client A' };
const B = { id: randomUUID(), slug: 'client-b', name: 'Client B' };
const HOME = { id: randomUUID(), slug: 'soc-home', name: 'SOC' };
const PW = 'correct horse battery staple';
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
let portalA: Row, portalB: Row, analyst: Row;
let fA: Row, fB: Row;

async function http(method: string, path: string, opts: { body?: unknown; bearer?: string; asOrg?: string } = {}) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (opts.bearer) headers.Authorization = `Bearer ${opts.bearer}`;
    if (opts.asOrg) headers['X-Org-Id'] = opts.asOrg;
    const r = await fetch(`${base}${path}`, { method, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const staff = (role: string, org = HOME.slug, sub: unknown = randomUUID()) => jwt.sign({ sub, email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const portalSignin = (email: string, password = PW) => http('POST', '/api/portal/auth/signin', { body: { email, password } });

before(async () => {
    db = await startFakePostgrest({
        organisations: [A, B, HOME], platform_users: [], auth_links: [], audit_log: [], staff_org_assignments: [], org_access_audit: [],
        vms_assets: [], vms_findings: [], vms_remediation_tasks: [], vms_finding_events: [], vms_finding_evidence: [], cve_intel: [], vms_scan_jobs: [], vms_workers: [],
        vms_scopes: [], vms_risk_snapshots: [], vms_asset_events: [], vms_assessments: [], vms_wazuh_sync: [], vms_services: [], vms_technologies: [], vms_job_evidence: [],
    }, {}, { auth_links: { used_at: null }, staff_org_assignments: { get assigned_at() { return new Date().toISOString(); } } });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use(express.json());
    app.use('/api/auth', authRouter);
    app.use('/api/portal', portalRouter);
    app.use('/api/vms', requireAuth, vmsRouter);
    app.use('/api/vms', requireAuth, vmsFindingsRouter);
    app.use('/api/vms', requireAuth, vmsInsightsRouter);
    app.use('/api/vms', requireAuth, vmsOperationsRouter);
    app.use('/api/client/vms', requireAuth, vmsClientRouter);
    app.use('/api/admin/org-assignments', requireAuth, requireRole('super_admin'), orgAssignmentsRouter);
    app.use('/api/org-access', requireAuth, orgAccessRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(async () => {
    for (const t of Object.keys(db.tables)) if (t !== 'organisations') db.tables[t].length = 0;
    const hash = await bcrypt.hash(PW, 4);
    portalA = { id: randomUUID(), org_id: A.id, email: 'ciso@client-a.test', name: 'Client A CISO', role: 'portal_user', status: 'active', password_hash: hash, failed_logins: 0, locked_until: null };
    portalB = { id: randomUUID(), org_id: B.id, email: 'ciso@client-b.test', name: 'Client B CISO', role: 'portal_user', status: 'active', password_hash: hash, failed_logins: 0, locked_until: null };
    analyst = { id: randomUUID(), org_id: HOME.id, email: 'ana@soc.test', name: 'Ana', role: 'analyst', status: 'active', password_hash: hash, failed_logins: 0, locked_until: null };
    db.tables.platform_users.push(portalA, portalB, analyst);
    const asset = (org: string, value: string) => ({ id: randomUUID(), org_id: org, value, asset_type: 'ip', exposure: 'internet', criticality: 'high', status: 'active', hostnames: [], ips: [value], owner: null, first_seen: new Date().toISOString(), last_seen: new Date().toISOString() });
    const aA = asset(A.slug, '192.0.2.1'), aB = asset(B.slug, '198.51.100.1');
    db.tables.vms_assets.push(aA, aB);
    const finding = (org: string, assetRow: Row, title: string) => ({ id: randomUUID(), org_id: org, asset_id: assetRow.id, asset_value: assetRow.value, port: 443, protocol: 'tcp', title, cve_ids: ['CVE-2024-3400'], scanner_severity: 'critical', scanner_cvss: 10, risk_score: 96, priority: 'P1', status: 'open', due_at: null, first_seen: new Date().toISOString(), last_seen: new Date().toISOString(), verified_at: null, source_class: 'active_scan', description: 'desc', remediation: 'patch', references_urls: [], owner: 'net-team' });
    fA = finding(A.slug, aA, 'A: GlobalProtect'); fB = finding(B.slug, aB, 'B: secret finding');
    db.tables.vms_findings.push(fA, fB);
    db.tables.vms_finding_events.push(
        { id: randomUUID(), org_id: A.slug, finding_id: fA.id, at: new Date().toISOString(), actor: 'ana@soc.test', action: 'status', from_value: 'open', to_value: 'acknowledged', details: null },
        { id: randomUUID(), org_id: A.slug, finding_id: fA.id, at: new Date().toISOString(), actor: 'ana@soc.test', action: 'note', from_value: null, to_value: null, details: 'INTERNAL: customer contact is slow' },
    );
    db.tables.vms_finding_evidence.push({ id: randomUUID(), org_id: A.slug, finding_id: fA.id, source: 'nuclei', job_id: null, observed_at: new Date().toISOString(), matched_at: 'https://192.0.2.1', evidence: { raw: 'scanner output' } });
    db.tables.vms_remediation_tasks.push({ id: randomUUID(), org_id: A.slug, finding_id: fA.id, title: 'Apply hotfix', details: null, owner: 'net-team', due_at: null, status: 'todo', ai_artifact_id: null, created_by: 'ana@soc.test', created_at: new Date().toISOString(), completed_at: null });
    db.tables.cve_intel.push({ cve_id: 'CVE-2024-3400', kev: true, epss_score: 0.9, cvss_score: 10, description: 'public', kev_date_added: '2024-04-12', kev_required_action: 'patch' });
    db.tables.vms_workers.push({ worker_id: 'vps-worker', kinds: ['ports'], tools: { nmap: true }, last_seen_at: new Date().toISOString() });
    process.env.JWT_SECRET = 'client-portal-test-secret';
});

// ── Sign-in and invitations ───────────────────────────────────────────────────────────────────
test('a portal_user signs in at the client portal with a token for its own organisation', async () => {
    const r = await portalSignin('CISO@client-a.test');
    assert.equal(r.status, 200, JSON.stringify(r.data));
    const claims = jwt.verify(r.data.token, process.env.JWT_SECRET!) as Row;
    assert.equal(claims.role, 'portal_user');
    assert.equal(claims.org_id, A.slug);
    assert.equal(claims.sub, portalA.id);
    assert.equal(r.data.user.orgId, A.slug);
    assert.equal(r.data.user.email, portalA.email);
});

test('the client portal refuses staff accounts (same answer as a wrong password), wrong passwords and disabled accounts', async () => {
    const st = await portalSignin('ana@soc.test');
    assert.equal(st.status, 401);
    assert.equal(st.data.error, 'Invalid email or password');
    const wrong = await portalSignin('ciso@client-a.test', 'nope nope nope');
    assert.equal(wrong.status, 401);
    assert.equal(db.tables.platform_users.find((u) => u.id === portalA.id)!.failed_logins, 1, 'the lockout counter applies');
    portalB.status = 'disabled';
    assert.equal((await portalSignin('ciso@client-b.test')).status, 403);
    assert.equal((await portalSignin('nobody@client-a.test')).status, 401);
});

test('a portal_user cannot sign in to the staff portal', async () => {
    const r = await http('POST', '/api/auth/signin', { body: { email: 'ciso@client-a.test', password: PW } });
    assert.equal(r.status, 403);
    assert.match(r.data.error, /client portal account/);
});

test('portal status reports sign-in available', async () => {
    assert.equal((await http('GET', '/api/portal/status')).data.configured, true);
});

test('invitation: the one-time link sets the password and points a client account to the client portal', async () => {
    const invited = { id: randomUUID(), org_id: A.id, email: 'it@client-a.test', name: 'IT', role: 'portal_user', status: 'invited', password_hash: null, failed_logins: 0, locked_until: null };
    db.tables.platform_users.push(invited);
    const token = randomBytes(32).toString('base64url');
    db.tables.auth_links.push({ id: randomUUID(), user_id: invited.id, token_hash: createHash('sha256').update(token).digest('hex'), purpose: 'invite', created_by: 'root', expires_at: new Date(Date.now() + 3_600_000).toISOString(), used_at: null });
    const set = await http('POST', '/api/auth/set-password', { body: { token, password: 'a long client password 42' } });
    assert.equal(set.status, 200, JSON.stringify(set.data));
    assert.equal(set.data.portal, true);
    assert.equal((await portalSignin('it@client-a.test', 'a long client password 42')).status, 200);
    assert.equal((await http('POST', '/api/auth/set-password', { body: { token, password: 'a long client password 43' } })).status, 400, 'the link works once');
});

// ── Confinement and isolation ─────────────────────────────────────────────────────────────────
test('a portal token reaches only /api/client/: staff VMS, Scanner Operations and admin APIs are refused', async () => {
    const t = (await portalSignin('ciso@client-a.test')).data.token;
    for (const p of ['/api/vms/dashboard', '/api/vms/findings', '/api/vms/operations', '/api/vms/admin/status', '/api/vms/scans', '/api/vms/audit', '/api/org-access/mine', '/api/admin/org-assignments']) {
        const r = await http('GET', p, { bearer: t });
        assert.equal(r.status, 403, p);
    }
    assert.equal((await http('POST', '/api/vms/scans', { bearer: t, body: { scope_id: randomUUID(), kind: 'discovery' } })).status, 403);
    assert.equal((await http('GET', '/api/client/vms/summary', { bearer: t })).status, 200);
});

test('a client sees only its own organisation, whatever X-Org-Id says', async () => {
    const t = (await portalSignin('ciso@client-a.test')).data.token;
    const f = await http('GET', '/api/client/vms/findings?status=all', { bearer: t, asOrg: B.slug });
    assert.equal(f.status, 200);
    assert.deepEqual(f.data.findings.map((x: Row) => x.title), ['A: GlobalProtect']);
    assert.equal((await http('GET', `/api/client/vms/findings/${fB.id}`, { bearer: t })).status, 404);
    const assets = await http('GET', '/api/client/vms/assets', { bearer: t, asOrg: B.slug });
    assert.deepEqual(assets.data.assets.map((x: Row) => x.value), ['192.0.2.1']);
    const s = await http('GET', '/api/client/vms/summary', { bearer: t });
    assert.equal(s.data.kpis.assets, 1);
    assert.equal(s.data.kpis.critical, 1);
    assert.equal(s.data.kpis.known_exploited, 1);
    const tb = (await portalSignin('ciso@client-b.test')).data.token;
    assert.deepEqual((await http('GET', '/api/client/vms/findings', { bearer: tb })).data.findings.map((x: Row) => x.title), ['B: secret finding']);
    assert.equal((await http('GET', '/api/client/vms/tasks', { bearer: tb })).data.tasks.length, 0);
    assert.equal(db.tables.org_access_audit.length, 0, 'X-Org-Id from a client is not even a cross-org attempt');
});

test('client responses leave out scanner operations, raw evidence, staff identities and internal notes', async () => {
    const t = (await portalSignin('ciso@client-a.test')).data.token;
    const d = await http('GET', `/api/client/vms/findings/${fA.id}`, { bearer: t });
    assert.equal(d.status, 200);
    const body = JSON.stringify(d.data);
    assert.ok(!body.includes('scanner output'), 'no raw evidence');
    assert.ok(!body.includes('ana@soc.test'), 'no staff identities');
    assert.ok(!body.includes('INTERNAL'), 'no internal notes');
    assert.deepEqual(d.data.history.map((h: Row) => h.to), ['Confirmed']);
    assert.equal(d.data.tasks[0].title, 'Apply hotfix');
    assert.equal(d.data.cve_intel[0].kev, true);
    const s = JSON.stringify((await http('GET', '/api/client/vms/summary', { bearer: t })).data);
    for (const word of ['worker', 'engine', 'vps-worker', 'scope']) assert.ok(!s.includes(word), word);
});

test('only vms:client holders use the client API: analysts and executives are refused, super_admin may preview', async () => {
    assert.equal((await http('GET', '/api/client/vms/summary', { bearer: staff('analyst', A.slug) })).status, 403);
    assert.equal((await http('GET', '/api/client/vms/summary', { bearer: staff('executive', A.slug) })).status, 403);
    const preview = await http('GET', '/api/client/vms/findings', { bearer: staff('super_admin'), asOrg: A.slug });
    assert.equal(preview.status, 200);
    assert.deepEqual(preview.data.findings.map((x: Row) => x.title), ['A: GlobalProtect']);
});

// ── Analyst organisation assignments ─────────────────────────────────────────────────────────
test('assignments: super_admin assigns an analyst; the analyst can then act on that organisation only, until removed', async () => {
    const root = staff('super_admin');
    const an = staff('analyst', HOME.slug, analyst.id);
    assert.equal((await http('GET', '/api/vms/findings', { bearer: an, asOrg: A.slug })).status, 403, 'not assigned yet');
    assert.equal((await http('POST', '/api/admin/org-assignments', { bearer: staff('soc_manager'), body: { user_id: analyst.id, org_slug: A.slug } })).status, 403, 'managers cannot assign');
    assert.equal((await http('POST', '/api/admin/org-assignments', { bearer: root, body: { user_id: portalA.id, org_slug: B.slug } })).status, 400, 'only analysts are assigned');
    const add = await http('POST', '/api/admin/org-assignments', { bearer: root, body: { user_id: analyst.id, org_slug: A.slug } });
    assert.equal(add.status, 201, JSON.stringify(add.data));
    assert.equal((await http('POST', '/api/admin/org-assignments', { bearer: root, body: { user_id: analyst.id, org_slug: A.slug } })).status, 409);
    const ok = await http('GET', '/api/vms/findings?status=all', { bearer: an, asOrg: A.slug });
    assert.equal(ok.status, 200);
    assert.deepEqual(ok.data.findings.map((x: Row) => x.title), ['A: GlobalProtect']);
    assert.equal((await http('GET', '/api/vms/findings', { bearer: an, asOrg: B.slug })).status, 403, 'still not client-b');
    assert.equal(db.tables.org_access_audit.length, 1, 'the access is audited');
    const mine = await http('GET', '/api/org-access/mine', { bearer: an });
    assert.equal(mine.data.mode, 'assigned');
    assert.deepEqual(mine.data.organisations.map((o: Row) => o.slug).sort(), [A.slug, HOME.slug].sort());
    const del = await http('DELETE', `/api/admin/org-assignments/${add.data.assignment.id}`, { bearer: root });
    assert.equal(del.status, 200);
    assert.equal((await http('GET', '/api/vms/findings', { bearer: an, asOrg: A.slug })).status, 403, 'removal takes effect at once');
    assert.equal((await http('GET', '/api/org-access/mine', { bearer: staff('super_admin') })).data.mode, 'all');
});
