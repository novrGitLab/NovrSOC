// P17: CNII Watch intake — domain/IP validation, DNS resolution with several addresses, linking to a
// designated CNII organisation only from authorised scope (candidates kept with the reason, never on
// the watch list), duplicate submissions, manager decisions, Full Assessment through the existing
// planner and queue, results per asset, sector watch list, AI optional, and the 48 h / 60-day
// schedule. Fake PostgREST; DNS and RIPE Stat injected; no network and no scan.
process.env.JWT_SECRET = 'cnii-intake-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'ANTHROPIC_API_KEY', 'SPIDERFOOT_URL', 'OPENCTI_URL', 'OPENCTI_TOKEN']) delete process.env[k];

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
import { setIntakeDepsForTests, parseIntake, reservedAddress } from '../../services/cniiIntake';
import { runDueSchedules } from '../../services/vmsContinuous';
import { aiPurpose } from '../../services/aiPurposes';
import { buildIntakeClassification } from '../../services/aiPurposesCnii';
import { flushAuditForTests } from '../../lib/audit';
const audited = async (action: string) => { await flushAuditForTests(); return db.tables.audit_log.some((x) => x.action === action); };

const A = 'org-a';      // ICT, candidate designation
const B = 'org-b';      // power, designated
const C = 'org-c';      // no CNII profile
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = A) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const AN = tok('analyst');
const MGR = tok('soc_manager');
async function call(method: string, p: string, bearer: string | null, body?: unknown) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const r = await fetch(`${base}/api/cnii${p}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: (await r.json().catch(() => null)) as Row };
}
const submit = (value: string, t = AN) => call('POST', '/intake', t, { value });
const future = (d = 30) => new Date(Date.now() + d * 86_400_000).toISOString();
const now = () => new Date().toISOString();
const TABLES = ['organisations', 'audit_log', 'cnii_org_profiles', 'cnii_profile_events', 'cnii_submissions', 'vms_scopes', 'vms_scan_jobs', 'vms_scan_schedules', 'vms_assets', 'vms_asset_events', 'vms_observations', 'vms_findings', 'vms_finding_evidence', 'vms_assessments', 'vms_workers', 'cve_intel', 'ti_indicators', 'ti_matches', 'vms_job_evidence'];

// DNS and registry, as the injected resolver answers them.
const DNS: Record<string, { a?: string[]; aaaa?: string[] }> = {
    'portal.grid.test': { a: ['196.1.2.4', '196.1.2.3'], aaaa: ['2001:db8::1'] },
    'shared.cdn.test': { a: ['196.1.2.3'] },
    'app.telco.test': { a: ['196.9.9.9'] },
    'twoorgs.test': { a: ['196.7.7.7'] },
    'loop.test': { a: ['127.0.0.1'] },
};
const nx = () => Object.assign(new Error('not found'), { code: 'ENOTFOUND' });

before(async () => {
    db = await startFakePostgrest(Object.fromEntries(TABLES.map((t) => [t, []])), { 'ti_matches.ti_indicators': 'indicator_id' }, {
        vms_scan_jobs: { status: 'queued', attempts: 0, cancel_requested: false, progress: {}, purpose: 'assessment', get requested_at() { return new Date().toISOString(); } } as Row,
        vms_assessments: { profile: 'full', trigger: 'manual', steps: [], retried_at: null, cancelled_at: null, get requested_at() { return new Date().toISOString(); } } as Row,
        vms_assets: { status: 'active', exposure: 'internet', criticality: 'medium', confidence: 'confirmed', hostnames: [], ips: [], dns: {}, discovery_sources: [], get last_seen() { return new Date().toISOString(); } } as Row,
        cnii_submissions: { status: 'candidate', ips: [], evidence: [], asset_ids: [], get updated_at() { return new Date().toISOString(); } } as Row,
        vms_scan_schedules: { enabled: true, get created_at() { return new Date().toISOString(); } } as Row,
    });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    setIntakeDepsForTests({
        resolve4: async (h) => { const r = DNS[h]?.a; if (!r) throw nx(); return r; },
        resolve6: async (h) => { const r = DNS[h]?.aaaa; if (!r) throw Object.assign(new Error('no data'), { code: 'ENODATA' }); return r; },
        reverse: async (ip) => (ip === '196.1.2.9' ? ['mail.grid.test'] : []),
        networkInfo: async () => ({ asns: ['37282'], prefix: '196.1.0.0/16' }),
        holder: async () => 'NERC-AS Nigerian Electricity Regulatory Commission',
    });
    const app = express();
    app.use(express.json());
    app.use('/api/cnii', requireAuth, cniiRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { setIntakeDepsForTests(null); Object.assign(console, realLog); server.close(); await db.close(); });

const scope = (org: string, kind: string, value: string, b: Row = {}) => {
    const s = { id: randomUUID(), org_id: org, kind, value, include_subdomains: true, allow_discovery: true, allow_port_scan: true, allow_vuln_scan: true, exclusions: [], status: 'active', expires_at: future(), approved_at: now(), approved_by: 'mgr@x.test', authorization_reference: `LOA-${org}`, ...b };
    db.tables.vms_scopes.push(s);
    return s;
};
beforeEach(() => {
    for (const t of TABLES) db.tables[t].length = 0;
    db.tables.organisations.push({ slug: A, name: 'Telco A' }, { slug: B, name: 'Grid B' }, { slug: C, name: 'Shop C' });
    db.tables.cnii_org_profiles.push(
        { org_id: A, sector_id: 'ict', subfield: 'Communications Companies', designation: 'candidate' },
        { org_id: B, sector_id: 'power', subfield: 'Power Generation & Distribution', designation: 'designated' },
    );
    scope(B, 'domain', 'grid.test');
    scope(B, 'ip', '196.1.2.9');
    scope(A, 'domain', 'telco.test');
    scope(C, 'ip', '196.1.2.3');                       // an address shared with B's domain (CDN-like)
    scope(A, 'domain', 'twoorgs.test'); scope(B, 'domain', 'twoorgs.test');
    db.tables.vms_workers.push({ worker_id: 'w1', kinds: ['discovery', 'ports'], version: '1.6.0', tools: { httpx: true, nmap: true, nuclei: true, openvas: false }, networks: [], features: ['exclusions'], first_seen_at: now(), last_seen_at: now() });
});

test('input: a domain or an IP only; access needs cnii:sector', async () => {
    assert.deepEqual(parseIntake(' Portal.Grid.TEST. '), { kind: 'domain', value: 'portal.grid.test' });
    assert.deepEqual(parseIntake('196.1.2.9'), { kind: 'ip', value: '196.1.2.9' });
    for (const bad of ['https://grid.test', 'grid.test/login', '*.grid.test', '196.1.2.0/24', 'grid.test:443', 'localhost', '']) assert.equal(parseIntake(bad), null, bad);
    assert.equal((await submit('https://grid.test')).status, 400);
    assert.equal((await submit('portal.grid.test', null as never)).status, 401);
    assert.equal((await call('POST', '/intake', null, { value: 'portal.grid.test' })).status, 401);
    assert.equal((await submit('portal.grid.test', tok('executive'))).status, 403);
    assert.equal((await submit('portal.grid.test', tok('portal_user'))).status, 403);
    assert.equal((await call('GET', '/intake', tok('executive'))).status, 403);
    assert.equal(db.tables.cnii_submissions.length, 0);
});

test('a domain resolving to several addresses, inside a designated operator\'s scope, is confirmed in its sector and joins its inventory', async () => {
    const r = await submit('portal.grid.test');
    assert.equal(r.status, 201);
    const s = r.data.submission as Row;
    assert.deepEqual([s.status, s.basis, s.org_id, s.sector_id], ['confirmed', 'authorised_scope', B, 'power']);
    assert.deepEqual(s.ips, ['196.1.2.3', '196.1.2.4', '2001:db8::1'], 'every address kept, associated with the domain');
    const addrs = (s.resolution as Row).addresses as Row[];
    assert.equal(addrs.find((a) => a.ip === '196.1.2.3')!.holder, 'Nigerian Electricity Regulatory Commission', 'the AS handle is stripped (cleanAsHolder)');
    assert.deepEqual((addrs.find((a) => a.ip === '196.1.2.3')!.covered_by as Row[]).map((c) => c.org_id), [C], 'the shared address is in another organisation\'s scope — recorded, not used');
    assert.ok((s.evidence as Row[]).some((e) => e.kind === 'authorised_scope' && e.strength === 'trusted'));
    assert.ok((s.evidence as Row[]).some((e) => e.kind === 'address_in_scope' && /does not show who operates/.test(String(e.detail))));
    // Only the domain is inside B's scope: its addresses are not added or assessed.
    const assets = db.tables.vms_assets.filter((a) => a.org_id === B);
    assert.deepEqual(assets.map((a) => [a.asset_type, a.value]), [['host', 'portal.grid.test']]);
    assert.deepEqual(assets[0].ips, ['196.1.2.3', '196.1.2.4', '2001:db8::1']);
    assert.deepEqual((r.data.link as Row).not_in_scope, ['196.1.2.3', '196.1.2.4', '2001:db8::1']);
    assert.ok(!db.tables.vms_assets.some((a) => a.org_id === C), 'nothing added to the organisation whose scope merely holds a shared address');
    const sector = await call('GET', '/sectors/power', AN);
    assert.deepEqual((sector.data.watchlist as Row[]).map((w) => w.value), ['portal.grid.test']);
    assert.equal(((await call('GET', '/sectors/ict', AN)).data.watchlist as Row[]).length, 0);
    assert.ok(await audited('CNII_INTAKE_SUBMITTED'));
});

test('unverified candidates are kept with the reason and never put on the watch list', async () => {
    const cases: [string, RegExp][] = [
        ['shared.cdn.test', /not inside any organisation's active authorised scope/],           // only its address is in C's scope
        ['app.telco.test', /only a CNII candidate \(not designated\)/],
        ['twoorgs.test', /more than one organisation/],
        ['196.1.2.3', /has no CNII sector profile/],                                            // C's scope, C unclassified
        ['unknown.example.test', /not inside any organisation's active authorised scope/],
    ];
    for (const [v, why] of cases) {
        const s = (await submit(v)).data.submission as Row;
        assert.equal(s.status, 'candidate', v);
        assert.match(String(s.reason), why, v);
    }
    const unknown = db.tables.cnii_submissions.find((x) => x.value === 'unknown.example.test')!;
    assert.match(((unknown.resolution as Row).errors as string[]).join(), /no A or AAAA records/, 'DNS failure recorded, not a crash');
    assert.equal(db.tables.vms_assets.length, 0, 'candidates add nothing to any inventory');
    for (const sec of ['power', 'ict']) assert.equal(((await call('GET', `/sectors/${sec}`, AN)).data.watchlist as Row[]).length, 0);
    const loop = (await submit('loop.test')).data.submission as Row;
    assert.equal(((loop.resolution as Row).addresses as Row[])[0].reserved, true);
    assert.ok(reservedAddress('169.254.169.254') && reservedAddress('::1') && !reservedAddress('196.1.2.3'));
});

test('an IP: reverse DNS and registry recorded; re-submitting updates the same record without duplicates', async () => {
    const one = await submit('196.1.2.9');
    assert.equal(one.status, 201);
    const s = one.data.submission as Row;
    assert.deepEqual([s.status, s.org_id, (((s.resolution as Row).addresses as Row[])[0].ptr as string[])[0]], ['confirmed', B, 'mail.grid.test']);
    const again = await submit('196.1.2.9');
    assert.deepEqual([again.status, again.data.created], [200, false]);
    assert.equal(db.tables.cnii_submissions.length, 1);
    assert.equal(db.tables.vms_assets.filter((a) => a.value === '196.1.2.9').length, 1, 'one inventory record');
    assert.equal((db.tables.cnii_submissions[0].asset_ids as string[]).length, 1);
    assert.ok(await audited('CNII_INTAKE_RECHECKED'));
});

test('manager decisions: confirm needs a classified organisation; a person\'s decision survives re-checks', async () => {
    const s = (await submit('shared.cdn.test')).data.submission as Row;
    assert.equal((await call('POST', `/intake/${s.id}/decision`, AN, { decision: 'confirm', org_id: B, note: 'letter NERC/2026/1' })).status, 403, 'analysts cannot confirm');
    assert.equal((await call('POST', `/intake/${s.id}/decision`, MGR, { decision: 'confirm', org_id: C, note: 'letter NERC/2026/1' })).status, 409, 'unclassified organisation');
    assert.equal((await call('POST', `/intake/${s.id}/decision`, MGR, { decision: 'confirm', org_id: B, note: 'ok' })).status, 400, 'a note with the evidence is required');
    const c = await call('POST', `/intake/${s.id}/decision`, MGR, { decision: 'confirm', org_id: B, note: 'registrant confirmed by Grid B, ref GB-17' });
    assert.equal(c.status, 200);
    assert.deepEqual([(c.data.submission as Row).status, (c.data.submission as Row).basis, (c.data.submission as Row).sector_id], ['confirmed', 'analyst_confirmed', 'power']);
    assert.equal(db.tables.vms_assets.length, 0, 'confirmed, but outside B\'s scope: nothing added until a scope covers it');
    assert.deepEqual(((c.data.link as Row).not_in_scope as string[]).sort(), ['196.1.2.3', 'shared.cdn.test']);
    await submit('shared.cdn.test');
    assert.equal(db.tables.cnii_submissions[0].basis, 'analyst_confirmed', 'a re-check keeps the manager\'s decision');
    const r = await call('POST', `/intake/${s.id}/decision`, MGR, { decision: 'reject', note: 'CDN edge, not operated by Grid B' });
    assert.equal((r.data.submission as Row).status, 'rejected');
    assert.ok(await audited('CNII_INTAKE_CONFIRMED') && await audited('CNII_INTAKE_REJECTED'));
});

test('assessment: only confirmed, in-scope values; through the existing Full Assessment planner and queue', async () => {
    const cand = (await submit('app.telco.test')).data.submission as Row;
    assert.equal((await call('POST', `/intake/${cand.id}/assess`, AN)).status, 409);
    const s = (await submit('portal.grid.test')).data.submission as Row;
    assert.equal((await call('POST', `/intake/${s.id}/assess`, tok('executive'))).status, 403);
    const r = await call('POST', `/intake/${s.id}/assess`, AN, { targets: ['portal.grid.test', '196.1.2.4'] });
    assert.equal(r.status, 200);
    const res = r.data.results as Row[];
    assert.deepEqual(res.map((x) => [x.target, x.ok]), [['portal.grid.test', true], ['196.1.2.4', false]], 'an address outside scope is refused');
    assert.equal(db.tables.vms_assessments.length, 1);
    assert.deepEqual([db.tables.vms_assessments[0].org_id, db.tables.vms_assessments[0].target], [B, 'portal.grid.test']);
    const jobs = db.tables.vms_scan_jobs;
    assert.deepEqual(jobs.map((j) => j.kind).sort(), ['discovery', 'ports'], 'only what the connected worker runs; Nuclei and OpenVAS not queued');
    assert.ok(jobs.every((j) => j.assessment_id === db.tables.vms_assessments[0].id && j.org_id === B && (j.targets as string[])[0] === 'portal.grid.test'));
    assert.equal(((await call('POST', `/intake/${s.id}/assess`, AN)).data.results as Row[])[0].existing, true, 'no duplicate assessment');
    assert.ok(await audited('CNII_INTAKE_ASSESSMENT'));
});

test('results: findings of the scanned asset and its assessment, from stored records only', async () => {
    const s = (await submit('portal.grid.test')).data.submission as Row;
    let d = await call('GET', `/intake/${s.id}`, AN);
    assert.deepEqual([d.data.findings, d.data.assessments, d.data.severity], [[], [], {}], 'nothing yet: empty, not invented');
    await call('POST', `/intake/${s.id}/assess`, AN);
    for (const j of db.tables.vms_scan_jobs) Object.assign(j, { status: 'succeeded', started_at: now(), finished_at: now(), summary: { outcome: 'assessed' } });
    const fid = randomUUID();
    db.tables.vms_findings.push(
        { id: fid, org_id: B, asset_value: 'portal.grid.test', title: 'Exposed admin panel', rule_id: 'exposed-panel', cve_ids: [], scanner_severity: 'high', priority: 'P2', risk_score: 70, status: 'open', port: 443, evidence_class: 'scanner_check', source_class: 'active_scan', detected_by: ['nuclei'], remediation: 'Restrict access', first_seen: now(), last_seen: now() },
        { id: randomUUID(), org_id: A, asset_value: 'portal.grid.test', title: 'Other org', rule_id: 'x', cve_ids: [], scanner_severity: 'critical', status: 'open', evidence_class: 'scanner_check', first_seen: now(), last_seen: now() },
    );
    db.tables.vms_finding_evidence.push({ id: randomUUID(), org_id: B, finding_id: fid, source: 'nuclei', job_id: db.tables.vms_scan_jobs[0].id, observed_at: now(), matched_at: 'https://portal.grid.test/admin', evidence: {} });
    d = await call('GET', `/intake/${s.id}`, AN);
    assert.deepEqual((d.data.findings as Row[]).map((f) => [f.title, f.asset_value, f.port]), [['Exposed admin panel', 'portal.grid.test', 443]], 'only the linked organisation\'s finding');
    assert.equal(((d.data.findings as Row[])[0].latest_evidence as Row).matched_at, 'https://portal.grid.test/admin');
    assert.deepEqual(d.data.severity, { high: 1 });
    assert.equal((d.data.assessments as Row[])[0].status, 'partial', 'discovery and ports completed; Nuclei and OpenVAS unsupported, so not "completed"');
    const list = (await call('GET', '/intake', AN)).data.submissions as Row[];
    assert.deepEqual(list[0].open_by_severity, { high: 1 });
    assert.ok(list[0].last_assessment_at);
});

test('AI is optional: the workflow runs without credentials; the AI purpose only suggests', async () => {
    assert.equal(process.env.ANTHROPIC_API_KEY, undefined);
    const s = (await submit('shared.cdn.test')).data.submission as Row;
    assert.equal(s.status, 'candidate');
    const p = aiPurpose('cnii_intake_classification')!;
    assert.equal(p.permission, 'cnii:sector');
    const ctx = await buildIntakeClassification(A, String(s.id));
    assert.deepEqual([...new Set(ctx!.records.map((r) => r.kind))].sort(), ['address', 'evidence', 'organisation', 'submission'], 'record kinds are not overwritten by row fields');
    assert.ok(ctx!.records.some((r) => r.kind === 'submission') && ctx!.records.filter((r) => r.kind === 'organisation').length === 2);
    assert.ok(p.schema.safeParse({ suggested_org_id: B, suggested_sector_id: 'power', summary: 'x', statements: [], verify_before_confirming: [], data_gaps: [], confidence: 'low' }).success);
    assert.ok(!p.schema.safeParse({ suggested_org_id: B, suggested_sector_id: 'banking-made-up', summary: 'x', statements: [], verify_before_confirming: [], data_gaps: [], confidence: 'low' }).success, 'model output is validated');
    assert.equal(db.tables.cnii_submissions[0].status, 'candidate', 'nothing the AI could say changes the status');
});

test('schedule: managers only; every 48 h; at most 60 days; no duplicates; no overlap; stops at the end date', async () => {
    const s = (await submit('portal.grid.test')).data.submission as Row;
    assert.equal((await call('POST', `/intake/${s.id}/schedule`, AN, { days: 60 })).status, 403);
    assert.equal((await call('POST', `/intake/${s.id}/schedule`, MGR, { days: 61 })).status, 400);
    const r = await call('POST', `/intake/${s.id}/schedule`, MGR, { days: 60 });
    assert.equal(r.status, 200);
    const sch = db.tables.vms_scan_schedules;
    assert.equal(sch.length, 1);
    assert.deepEqual([sch[0].kind, sch[0].interval_hours, sch[0].targets, sch[0].org_id], ['full_assessment', 48, ['portal.grid.test'], B]);
    const days = (Date.parse(String(sch[0].ends_at)) - Date.now()) / 86_400_000;
    assert.ok(days > 59.9 && days <= 60.01, `ends after 60 days (${days})`);
    assert.equal(((await call('POST', `/intake/${s.id}/schedule`, MGR, { days: 60 })).data.schedules as Row[])[0].existing, true);
    assert.equal(db.tables.vms_scan_schedules.length, 1);

    const t0 = Date.parse(String(sch[0].next_run_at));
    let runs = await runDueSchedules(t0 + 1000);
    assert.equal(runs[0].outcome, 'queued');
    assert.equal(db.tables.vms_assessments.length, 1);
    assert.equal(db.tables.vms_assessments[0].trigger, 'schedule');
    assert.equal(Date.parse(String(sch[0].next_run_at)), t0 + 48 * 3_600_000, 'next run two days later');
    runs = await runDueSchedules(t0 + 48 * 3_600_000 + 1000);
    assert.equal(runs[0].outcome, 'skipped_in_progress', 'the previous assessment is still running: not duplicated');
    assert.equal(db.tables.vms_assessments.length, 1);
    runs = await runDueSchedules(Date.parse(String(sch[0].ends_at)) + 1000);
    assert.equal(runs[0].outcome, 'disabled');
    assert.match(runs[0].detail, /Ended/);
    assert.equal(sch[0].enabled, false);
    assert.equal((await runDueSchedules(Date.parse(String(sch[0].ends_at)) + 10 * 86_400_000)).length, 0, 'never runs after the end date');
});
