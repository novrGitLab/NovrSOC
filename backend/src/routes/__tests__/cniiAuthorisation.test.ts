// P18: bulk intake (per-entry results, partial failure, deduplication), manual registration
// (unverified, authorises nothing, permissions), and CNII scan authorisation as exact, pinned VMS
// scope entries enforced by the existing checks — queueing, assessment planning, ingest, worker claim
// and the scheduler — including DNS drift and revocation. Fake PostgREST; DNS and RIPE Stat injected;
// no network and no scan.
process.env.JWT_SECRET = 'cnii-auth-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'NVIDIA_API_KEY', 'SPIDERFOOT_URL', 'OPENCTI_URL', 'OPENCTI_TOKEN', 'VMS_WORKER_TOKEN']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import cniiRouter from '../cnii';
import vmsWorkerRouter from '../vmsWorker';
import { setIntakeDepsForTests } from '../../services/cniiIntake';
import { ingestObservations } from '../../services/vmsIngest';
import { runDueSchedules } from '../../services/vmsContinuous';
import { flushAuditForTests } from '../../lib/audit';
import type { ScopeEntry } from '../../lib/vmsScope';

const A = 'org-a';      // ict, candidate
const B = 'org-b';      // power, designated
const C = 'org-c';      // unclassified
const WT = 'w'.repeat(40);
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = A) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const AN = tok('analyst');
const MGR = tok('soc_manager');
async function call(method: string, p: string, bearer: string, body?: unknown) {
    const r = await fetch(`${base}/api/cnii${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: (await r.json().catch(() => null)) as Row };
}
const worker = (p: string, body: unknown) => fetch(`${base}/api/vms/worker${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${WT}` }, body: JSON.stringify(body) }).then(async (r) => ({ status: r.status, data: (await r.json().catch(() => null)) as Row }));
const audited = async (action: string) => { await flushAuditForTests(); return db.tables.audit_log.some((x) => x.action === action); };
const future = (d = 30) => new Date(Date.now() + d * 86_400_000).toISOString();
const now = () => new Date().toISOString();
const TABLES = ['organisations', 'audit_log', 'cnii_org_profiles', 'cnii_profile_events', 'cnii_submissions', 'vms_scopes', 'vms_scan_jobs', 'vms_scan_schedules', 'vms_assets', 'vms_asset_events', 'vms_observations', 'vms_findings', 'vms_finding_evidence', 'vms_assessments', 'vms_workers', 'cve_intel', 'ti_indicators', 'ti_matches', 'vms_job_evidence', 'vms_services'];

let DNS: Record<string, string[]> = {};
const nx = () => Object.assign(new Error('not found'), { code: 'ENOTFOUND' });

before(async () => {
    db = await startFakePostgrest(Object.fromEntries(TABLES.map((t) => [t, []])), { 'ti_matches.ti_indicators': 'indicator_id' }, {
        vms_scan_jobs: { status: 'queued', attempts: 0, cancel_requested: false, progress: {}, purpose: 'assessment', get requested_at() { return new Date().toISOString(); } } as Row,
        vms_assessments: { profile: 'full', trigger: 'manual', steps: [], retried_at: null, cancelled_at: null, get requested_at() { return new Date().toISOString(); } } as Row,
        vms_assets: { status: 'active', exposure: 'internet', criticality: 'medium', confidence: 'confirmed', hostnames: [], ips: [], dns: {}, discovery_sources: [], get last_seen() { return new Date().toISOString(); } } as Row,
        cnii_submissions: { status: 'candidate', ips: [], evidence: [], asset_ids: [], authorisation: null, get updated_at() { return new Date().toISOString(); } } as Row,
        vms_scan_schedules: { enabled: true } as Row,
        vms_scopes: { origin: 'vms', pinned_addresses: [], exclusions: [], cnii_submission_id: null } as Row,
    }, {
        vms_claim_job: (args, tables) => {
            const j = tables.vms_scan_jobs.find((x) => x.status === 'queued' && (args.p_kinds as string[]).includes(String(x.kind)));
            if (!j) return [];
            Object.assign(j, { status: 'running', worker_id: args.p_worker, claimed_at: now(), started_at: now(), attempts: Number(j.attempts ?? 0) + 1 });
            return [j];
        },
    });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    process.env.VMS_WORKER_TOKEN = WT;
    setIntakeDepsForTests({
        resolve4: async (h) => { if (h === 'boom.test') return null as never; const r = DNS[h]?.filter((x) => !x.includes(':')); if (!r?.length) throw nx(); return r; },
        resolve6: async (h) => { const r = DNS[h]?.filter((x) => x.includes(':')); if (!r?.length) throw Object.assign(new Error('no data'), { code: 'ENODATA' }); return r; },
        reverse: async () => [],
        networkInfo: async () => ({ asns: ['37282'], prefix: '196.0.0.0/8' }),
        holder: async () => 'EXAMPLE-AS Example Networks',
    });
    const app = express();
    app.use('/api/vms/worker', express.json(), vmsWorkerRouter);
    app.use(express.json());
    app.use('/api/cnii', requireAuth, cniiRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { setIntakeDepsForTests(null); Object.assign(console, realLog); server.close(); await db.close(); });

const scope = (org: string, kind: string, value: string, b: Row = {}) => {
    const s = { id: randomUUID(), org_id: org, kind, value, include_subdomains: true, allow_discovery: true, allow_port_scan: true, allow_vuln_scan: true, exclusions: [], pinned_addresses: [], origin: 'vms', cnii_submission_id: null, status: 'active', expires_at: future(), approved_at: now(), approved_by: 'mgr@x.test', authorization_reference: `LOA-${org}`, ...b };
    db.tables.vms_scopes.push(s);
    return s;
};
beforeEach(() => {
    for (const t of TABLES) db.tables[t].length = 0;
    DNS = { 'portal.grid.test': ['196.1.2.3', '196.1.2.4'], 'cdn-site.test': ['196.8.8.8'], 'app.telco.test': ['196.9.9.9'] };
    db.tables.organisations.push({ slug: A, name: 'Telco A' }, { slug: B, name: 'Grid B' }, { slug: C, name: 'Shop C' });
    db.tables.cnii_org_profiles.push({ org_id: A, sector_id: 'ict', subfield: null, designation: 'candidate' }, { org_id: B, sector_id: 'power', subfield: null, designation: 'designated' });
    scope(B, 'domain', 'grid.test');
    scope(A, 'domain', 'telco.test');
    db.tables.vms_workers.push({ worker_id: 'w1', kinds: ['discovery', 'ports'], version: '1.7.0', tools: { httpx: true, nmap: true, nuclei: true, openvas: false }, networks: [], features: ['exclusions', 'pinned_addresses'], first_seen_at: now(), last_seen_at: now() });
});

/** A confirmed submission outside any scope: confirmed by a manager, not yet authorised to scan. */
async function confirmedOutsideScope(value = 'cdn-site.test') {
    const s = (await call('POST', '/intake', AN, { value })).data.submission as Row;
    await call('POST', `/intake/${s.id}/decision`, MGR, { decision: 'confirm', org_id: B, note: 'operator confirmed in writing, ref GB-17' });
    return s.id as string;
}
const authBody = { reference: 'NERC/LOA/2026/9', evidence: 'Signed testing authorisation from Grid B CISO, 2026-10-10', expires_days: 30, allow_port_scan: true, allow_vuln_scan: false };

// ── Bulk ─────────────────────────────────────────────────────────────────────────────────────
test('bulk intake: each entry on its own — invalid, duplicate and failed entries never block the rest', async () => {
    const r = await call('POST', '/intake', AN, { values: 'portal.grid.test, https://bad.test/x  196.1.2.9;portal.grid.test,boom.test\n2001:DB8::5, app.telco.test' });
    assert.equal(r.status, 200);
    const out = (r.data.results as Row[]).map((x) => [x.value ?? x.input, x.outcome]);
    assert.deepEqual(out, [
        ['portal.grid.test', 'confirmed'], ['https://bad.test/x', 'invalid'], ['196.1.2.9', 'candidate'], ['portal.grid.test', 'duplicate'],
        ['boom.test', 'failed'], ['2001:db8::5', 'candidate'], ['app.telco.test', 'candidate'],
    ]);
    assert.deepEqual(r.data.counts, { confirmed: 1, invalid: 1, candidate: 3, duplicate: 1, failed: 1 });
    assert.equal(db.tables.cnii_submissions.length, 4, 'one record per valid, processed value');
    const again = await call('POST', '/intake', AN, { values: ['portal.grid.test', '196.1.2.9'] });
    assert.deepEqual((again.data.results as Row[]).map((x) => x.created), [false, false]);
    assert.equal(db.tables.cnii_submissions.length, 4);
    assert.equal(db.tables.vms_assets.filter((a) => a.value === 'portal.grid.test').length, 1, 'no duplicate inventory record');
    assert.ok(await audited('CNII_INTAKE_SUBMITTED'));
    const many = await call('POST', '/intake', AN, { values: Array.from({ length: 30 }, (_, i) => `h${i}.example.test`).join(',') });
    assert.equal((many.data.results as Row[]).length, 25);
    assert.match(String(many.data.note), /first 25/);
    assert.equal((await call('POST', '/intake', tok('executive'), { values: 'a.test' })).status, 403);
    assert.equal((await call('POST', '/intake', AN, { values: ' , ' })).status, 400);
});

// ── Manual registration ──────────────────────────────────────────────────────────────────────
test('manual registration: unverified, never on the watch list, authorises nothing; checked server-side', async () => {
    const body = { org_id: B, sector_id: 'power', ip: '196.5.5.5', justification: 'Listed in Grid B asset register v3 (email 2026-10-12)' };
    assert.equal((await call('POST', '/intake/manual', tok('executive'), body)).status, 403);
    assert.equal((await call('POST', '/intake/manual', AN, { ...body, ip: 'grid.test' })).status, 400, 'an IP address');
    assert.equal((await call('POST', '/intake/manual', AN, { ...body, justification: 'short' })).status, 400);
    assert.equal((await call('POST', '/intake/manual', AN, { ...body, org_id: 'nope' })).status, 404);
    assert.equal((await call('POST', '/intake/manual', AN, { ...body, sector_id: 'ict' })).status, 409, 'Grid B is classified in power');
    const r = await call('POST', '/intake/manual', AN, body);
    assert.equal(r.status, 201);
    const s = r.data.submission as Row;
    assert.deepEqual([s.status, s.basis, s.org_id, s.sector_id], ['candidate', 'manual_registration', B, 'power']);
    assert.ok((s.evidence as Row[]).some((e) => e.kind === 'manual_registration'));
    const sector = (await call('GET', '/sectors/power', AN)).data;
    assert.deepEqual([(sector.watchlist as Row[]).length, (sector.registered as Row[]).map((x) => x.value)], [0, ['196.5.5.5']]);
    assert.equal(db.tables.vms_assets.length, 0, 'no inventory record, no scope');
    assert.equal(db.tables.vms_scopes.filter((x) => x.value === '196.5.5.5').length, 0);
    await call('POST', '/intake', AN, { value: '196.5.5.5' });
    assert.equal(db.tables.cnii_submissions[0].basis, 'manual_registration', 'a re-check keeps the registration');
    assert.equal((await call('POST', `/intake/${s.id}/assess`, AN)).status, 409, 'not confirmed: not assessable');
    // Verification is separate (managers), and still not permission to scan.
    const c = await call('POST', `/intake/${s.id}/decision`, MGR, { decision: 'confirm', note: 'Confirmed with Grid B CISO by phone, ticket 4411' });
    assert.deepEqual([(c.data.submission as Row).status, (c.data.submission as Row).org_id], ['confirmed', B]);
    assert.equal((await call('POST', `/intake/${s.id}/assess`, AN)).status, 409, 'confirmed but not authorised to scan');
    assert.ok(await audited('CNII_ASSET_REGISTERED'));
});

// ── CNII scan authorisation ──────────────────────────────────────────────────────────────────
test('authorisation: managers only, confirmed only, evidence required; written as exact pinned scope entries', async () => {
    const cand = (await call('POST', '/intake', AN, { value: 'app.telco.test' })).data.submission as Row;
    assert.equal((await call('POST', `/intake/${cand.id}/authorise`, MGR, authBody)).status, 409, 'a candidate cannot be authorised');
    const id = await confirmedOutsideScope();
    assert.equal((await call('POST', `/intake/${id}/assess`, AN)).status, 409, 'confirmed is not permission to scan');
    assert.equal((await call('POST', `/intake/${id}/authorise`, AN, authBody)).status, 403);
    assert.equal((await call('POST', `/intake/${id}/authorise`, MGR, { ...authBody, evidence: 'ok' })).status, 400);
    assert.equal((await call('POST', `/intake/${id}/authorise`, MGR, { ...authBody, expires_days: 91 })).status, 400);
    assert.equal((await call('POST', `/intake/${id}/authorise`, MGR, { ...authBody, addresses: ['203.0.113.9'] })).status, 400, 'only its own addresses');
    const r = await call('POST', `/intake/${id}/authorise`, MGR, authBody);
    assert.equal(r.status, 200);
    const mine = db.tables.vms_scopes.filter((x) => x.origin === 'cnii');
    assert.deepEqual(mine.map((x) => [x.kind, x.value, x.include_subdomains, x.pinned_addresses, x.org_id, x.cnii_submission_id, x.allow_vuln_scan]).sort(), [
        ['domain', 'cdn-site.test', false, ['196.8.8.8'], B, id, false],
        ['ip', '196.8.8.8', false, [], B, id, false],
    ]);
    assert.ok(mine.every((x) => /^CNII NERC\/LOA\/2026\/9/.test(String(x.authorization_reference)) && Date.parse(String(x.expires_at)) <= Date.now() + 30.01 * 86_400_000));
    assert.equal(db.tables.vms_assets.filter((a) => a.org_id === B).length, 2, 'now in scope: added to the operator\'s inventory');
    assert.ok(await audited('CNII_SCAN_AUTHORISED'));
    // Re-approving updates the same entries; never a duplicate.
    await call('POST', `/intake/${id}/authorise`, MGR, { ...authBody, allow_vuln_scan: true });
    assert.equal(db.tables.vms_scopes.filter((x) => x.origin === 'cnii').length, 2);
    assert.ok(db.tables.vms_scopes.filter((x) => x.origin === 'cnii').every((x) => x.allow_vuln_scan === true));
    // A name that resolves to a reserved address is never authorised.
    DNS['loop.test'] = ['127.0.0.1'];
    const loop = await confirmedOutsideScope('loop.test');
    assert.equal((await call('POST', `/intake/${loop}/authorise`, MGR, authBody)).status, 409);
});

test('an existing general VMS scope entry is left unchanged and reported', async () => {
    scope(B, 'ip', '196.8.8.8');
    const id = await confirmedOutsideScope();
    const r = await call('POST', `/intake/${id}/authorise`, MGR, authBody);
    const ip = (r.data.results as Row[]).find((x) => x.target === '196.8.8.8')!;
    assert.equal(ip.outcome, 'existing_vms_scope');
    assert.equal(db.tables.vms_scopes.filter((x) => x.value === '196.8.8.8').length, 1);
    assert.equal(db.tables.vms_scopes.find((x) => x.value === '196.8.8.8')!.origin, 'vms');
});

test('assessment through the authorisation; a DNS change stops it at queueing; revoking stops everything', async () => {
    const id = await confirmedOutsideScope();
    await call('POST', `/intake/${id}/authorise`, MGR, authBody);
    let r = await call('POST', `/intake/${id}/assess`, AN, { targets: ['cdn-site.test'] });
    assert.equal(r.status, 200);
    assert.equal((r.data.results as Row[])[0].ok, true);
    assert.deepEqual(db.tables.vms_scan_jobs.map((j) => j.kind).sort(), ['discovery', 'ports']);
    // The name moves to a new address: nothing is queued on the old approval.
    db.tables.vms_scan_jobs.length = 0; db.tables.vms_assessments.length = 0;
    DNS['cdn-site.test'] = ['196.8.8.8', '203.0.113.50'];
    r = await call('POST', `/intake/${id}/assess`, AN, { targets: ['cdn-site.test'] });
    assert.equal(db.tables.vms_scan_jobs.length, 0, 'not queued');
    const a = db.tables.vms_assessments[0];
    assert.ok((a.steps as Row[]).filter((s) => s.kind === 'discovery' || s.kind === 'ports').every((s) => s.decision === 'not_attempted' && /pinned to its approved addresses.*203\.0\.113\.50/.test(String(s.reason))));
    // The address entry is unaffected by the name's DNS.
    r = await call('POST', `/intake/${id}/assess`, AN, { targets: ['196.8.8.8'] });
    assert.equal((r.data.results as Row[])[0].ok, true);
    // Revoke: entries revoked, schedules stopped, nothing assessable.
    DNS['cdn-site.test'] = ['196.8.8.8'];
    db.tables.vms_scan_schedules.push({ id: randomUUID(), org_id: B, scope_id: db.tables.vms_scopes.find((x) => x.origin === 'cnii' && x.kind === 'domain')!.id, kind: 'full_assessment', targets: ['cdn-site.test'], interval_hours: 48, next_run_at: now(), ends_at: future(60), enabled: true });
    assert.equal((await call('POST', `/intake/${id}/authorise/revoke`, AN, { reason: 'contract ended' })).status, 403);
    const rv = await call('POST', `/intake/${id}/authorise/revoke`, MGR, { reason: 'contract ended' });
    assert.deepEqual((rv.data.revoked as string[]).sort(), ['196.8.8.8', 'cdn-site.test']);
    assert.ok(db.tables.vms_scopes.filter((x) => x.origin === 'cnii').every((x) => x.status === 'revoked'));
    assert.equal(db.tables.vms_scan_schedules[0].enabled, false);
    assert.equal((await call('POST', `/intake/${id}/assess`, AN)).status, 409);
    assert.ok(await audited('CNII_SCAN_AUTHORISATION_REVOKED'));
});

test('ingest drops a pinned name seen at an unapproved address', async () => {
    const pinned = { ...scope(B, 'domain', 'cdn-site.test', { include_subdomains: false, origin: 'cnii', pinned_addresses: ['196.8.8.8'] }) } as unknown as ScopeEntry;
    const job = { id: randomUUID(), org_id: B, kind: 'discovery', started_at: now() };
    const r = await ingestObservations(job, [
        { type: 'host', host: 'cdn-site.test', ips: ['203.0.113.50'], source: 'httpx' },
        { type: 'host', host: 'cdn-site.test', ips: ['196.8.8.8'], source: 'httpx' },
    ], [pinned]);
    assert.deepEqual([r.rejected_out_of_scope, r.accepted], [1, 1]);
});

test('worker claim: a job under a pinned entry goes only to a worker that enforces pins', async () => {
    const pin = scope(B, 'domain', 'cdn-site.test', { include_subdomains: false, origin: 'cnii', pinned_addresses: ['196.8.8.8'] });
    db.tables.vms_scan_jobs.push({ id: randomUUID(), org_id: B, scope_id: pin.id, kind: 'ports', targets: ['cdn-site.test'], options: {}, status: 'queued', attempts: 0, requested_at: now() });
    db.tables.vms_workers.push({ worker_id: 'old', kinds: ['ports'], version: '1.6.0', features: ['exclusions'], tools: {}, networks: [], last_seen_at: now() });
    const old = await worker('/claim', { worker_id: 'old', kinds: ['ports'] });
    assert.equal(old.data.job, null);
    assert.match(String(old.data.notice), /CNII pinned addresses/);
    assert.equal(db.tables.vms_scan_jobs[0].status, 'queued', 'put back as it was');
    const ok = await worker('/claim', { worker_id: 'w1', kinds: ['ports'] });
    assert.equal((ok.data.job as Row).id, db.tables.vms_scan_jobs[0].id);
    assert.deepEqual(((ok.data.scopes as Row[]).find((s) => s.value === 'cdn-site.test')!).pinned_addresses, ['196.8.8.8'], 'the worker receives the pins');
    const hb = await worker('/heartbeat', { worker_id: 'w1', kinds: ['ports'], version: '1.7.0', features: ['exclusions', 'pinned_addresses'] });
    assert.equal(hb.status, 200, 'the backend accepts the 1.7.0 feature');
});

test('scheduler: a Full Assessment schedule under a revoked CNII entry is disabled, not run', async () => {
    const pin = scope(B, 'domain', 'cdn-site.test', { include_subdomains: false, origin: 'cnii', pinned_addresses: ['196.8.8.8'], status: 'revoked' });
    db.tables.vms_scan_schedules.push({ id: randomUUID(), org_id: B, scope_id: pin.id, kind: 'full_assessment', targets: ['cdn-site.test'], interval_hours: 48, next_run_at: new Date(Date.now() - 1000).toISOString(), ends_at: future(60), enabled: true });
    const runs = await runDueSchedules();
    assert.equal(runs[0].outcome, 'disabled');
    assert.equal(db.tables.vms_assessments.length, 0);
});
