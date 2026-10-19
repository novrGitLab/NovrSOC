// P16: cross-source CVE correlation (derived, explainable, never merging, never crossing
// organisations, stable under re-ingestion), the Wazuh Vulnerabilities view on shared findings
// (freshness and incomplete states are never shown as zero), verified closure (evidence only;
// a rescan must show it reached the target), assessment coverage in the period report, and OSV
// enrichment (bounded, isolated, never storing a failed lookup as "none").
// Fake PostgREST and injected fetch; nothing external is contacted and nothing is scanned.
process.env.JWT_SECRET = 'vms-p16-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'VMS_WORKER_TOKEN', 'NVIDIA_API_KEY', 'WAZUH_HOST', 'WAZUH_INDEXER_HOST', 'WAZUH_INDEXER_PASSWORD', 'WAZUH_INDEXER_PASS']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import vmsFindingsRouter from '../vmsFindings';
import wazuhRouter from '../wazuh';
import { correlatePure, assetRelation, type CorrFinding, type CorrAsset } from '../../services/vmsCorrelation';
import { verificationReach } from '../../services/vmsFindings';
import { closureInPeriod, coverageInPeriod } from '../../services/vmsContinuous';
import { syncWazuhVulnerabilities } from '../../services/wazuhVulnSync';
import { parseOsv, refreshOsv } from '../../services/cveIntel';

const A = 'org-a';
const B = 'org-b';
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = A) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const AN = tok('analyst');
async function http(method: string, path: string, bearer: string) {
    const r = await fetch(`${base}${path}`, { method, headers: { Authorization: `Bearer ${bearer}` } });
    return { status: r.status, data: (await r.json().catch(() => null)) as Row };
}
const now = () => new Date().toISOString();
const ago = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString();
const CVE = 'CVE-2024-1111';
const ids = { endpoint: randomUUID(), ip: randomUUID(), host: randomUUID(), other: randomUUID(), bEndpoint: randomUUID(), bIp: randomUUID() };
const fids = { wazuh: randomUUID(), nuclei: randomUUID(), intelSameIp: randomUUID(), hostF: randomUUID(), otherF: randomUUID(), bWazuh: randomUUID(), bNuclei: randomUUID() };

before(async () => {
    db = await startFakePostgrest(
        { vms_assets: [], vms_findings: [], vms_finding_evidence: [], vms_finding_events: [], vms_remediation_tasks: [], vms_wazuh_sync: [], vms_assessments: [], vms_scan_jobs: [], wazuh_group_org_map: [], cve_intel: [], vms_asset_events: [], audit_log: [] },
        {}, {}, {},
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use(express.json());
    app.use('/api/vms', requireAuth, vmsFindingsRouter);
    app.use('/api/wazuh', requireAuth, wazuhRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });

const finding = (id: string, org: string, asset_id: string, asset_value: string, b: Row = {}) => ({
    id, org_id: org, asset_id, asset_value, dedupe_key: `${asset_value}|${id}`, source_class: 'active_scan', detected_by: ['nuclei'], rule_id: CVE, title: `${CVE} on ${asset_value}`,
    finding_type: 'vulnerability', cve_ids: [CVE], scanner_severity: 'high', scanner_cvss: 7.5, risk_score: 60, priority: 'P2', status: 'open', evidence_class: 'scanner_check',
    first_seen: ago(48), last_seen: now(), due_at: null, owner: null, verified_at: null, case_id: null, port: 443, protocol: 'tcp', ...b,
});
beforeEach(() => {
    for (const t of Object.keys(db.tables)) db.tables[t] = [];
    const asset = (id: string, org: string, asset_type: string, value: string, b: Row = {}) => ({ id, org_id: org, asset_type, value, ips: [], hostnames: [], dns: {}, status: 'active', exposure: 'internal', criticality: 'medium', last_seen: now(), wazuh_agent_id: null, ...b });
    db.tables.vms_assets.push(
        asset(ids.endpoint, A, 'endpoint', 'rayneops', { ips: ['10.88.1.139'], wazuh_agent_id: '003' }),
        asset(ids.ip, A, 'ip', '10.88.1.139', { ips: ['10.88.1.139'] }),
        asset(ids.host, A, 'host', 'app.example.test', { ips: ['10.88.1.139'], dns: { a: ['10.88.1.139'] } }),   // resolves there: NOT a correlation basis
        asset(ids.other, A, 'ip', '10.88.1.200', { ips: ['10.88.1.200'] }),
        asset(ids.bEndpoint, B, 'endpoint', 'rayneops', { ips: ['10.88.1.139'] }),
        asset(ids.bIp, B, 'ip', '10.88.1.139'),
    );
    db.tables.vms_findings.push(
        finding(fids.wazuh, A, ids.endpoint, 'RayneOps', { source_class: 'wazuh', detected_by: ['wazuh'], evidence_class: 'package_inventory', port: null, dedupe_key: `endpoint:rayneops|-|${CVE}|openssl` }),
        finding(fids.nuclei, A, ids.ip, '10.88.1.139'),
        finding(fids.intelSameIp, A, ids.ip, '10.88.1.139', { detected_by: ['passive'], evidence_class: 'version_match', rule_id: 'passive', port: null }),
        finding(fids.hostF, A, ids.host, 'app.example.test'),
        finding(fids.otherF, A, ids.other, '10.88.1.200'),
        finding(fids.bWazuh, B, ids.bEndpoint, 'rayneops', { source_class: 'wazuh', detected_by: ['wazuh'] }),
        finding(fids.bNuclei, B, ids.bIp, '10.88.1.139'),
    );
});

// ── Correlation ──────────────────────────────────────────────────────────────────────────────
test('correlation rules: same asset is confirmed, Wazuh endpoint ↔ its reported address is inferred, nothing else links', () => {
    const asA = (id: string, asset_type: string, value: string, ips: string[] = []): CorrAsset => ({ id, asset_type, value, ips });
    const ep = asA('e', 'endpoint', 'rayneops', ['10.88.1.139']);
    assert.equal(assetRelation(ep, asA('i', 'ip', '10.88.1.139'))?.basis, 'inferred');
    assert.equal(assetRelation(asA('i', 'ip', '10.88.1.139'), ep)?.relation, 'same_address', 'either direction');
    assert.equal(assetRelation(ep, asA('h', 'host', 'app.example.test', ['10.88.1.139'])), null, 'a hostname resolving there is not a recorded relationship');
    assert.equal(assetRelation(ep, asA('i2', 'ip', '10.88.1.200')), null);
    assert.equal(assetRelation(asA('i', 'ip', '1.2.3.4'), asA('j', 'ip', '1.2.3.4')), null, 'two scan assets are never linked by value alone');
    assert.equal(assetRelation(ep, ep)?.basis, 'confirmed');

    const f = (id: string, asset_id: string, cves: string[]): CorrFinding => ({ id, asset_id, asset_value: id, source_class: 'active_scan', detected_by: [], cve_ids: cves, status: 'open' });
    const m = correlatePure([f('w', 'e', ['CVE-1-1', 'CVE-2-2'])], [f('w', 'e', ['CVE-1-1']), f('n', 'i', ['CVE-1-1', 'CVE-2-2']), f('n2', 'i', ['CVE-9-9'])], [ep, asA('i', 'ip', '10.88.1.139')]);
    const list = m.get('w')!;
    assert.equal(list.length, 1, 'itself excluded; no shared CVE, no link');
    assert.deepEqual(list[0].cves, ['CVE-1-1', 'CVE-2-2'], 'one entry per pair, every shared CVE named');
    assert.match(list[0].explanation, /reports the address 10\.88\.1\.139.*Inferred/);
});

test('findings API: correlations explained, within the organisation only, sources and states untouched', async () => {
    const before = JSON.stringify(db.tables.vms_findings);
    const d = await http('GET', `/api/vms/findings/${fids.wazuh}`, AN);
    assert.equal(d.status, 200);
    const corr = d.data.correlated as Row[];
    assert.deepEqual(corr.map((c) => (c.other as Row).id).sort(), [fids.intelSameIp, fids.nuclei].sort(), 'the scanned address only; not the host that resolves there, not org-b');
    assert.ok(corr.every((c) => c.basis === 'inferred' && c.relation === 'same_address' && (c.basis_record as Row).reported_address === '10.88.1.139'));
    const n = (await http('GET', `/api/vms/findings/${fids.nuclei}`, AN)).data.correlated as Row[];
    assert.deepEqual(n.map((c) => [(c.other as Row).id, c.basis]), [[fids.intelSameIp, 'confirmed'], [fids.wazuh, 'inferred']], 'confirmed first');
    assert.equal(((n[1].other as Row).source_class), 'wazuh', 'each side keeps its source');
    const list = (await http('GET', '/api/vms/findings', AN)).data.findings as Row[];
    assert.equal(list.find((r) => r.id === fids.wazuh)!.correlated, 2);
    assert.equal(list.find((r) => r.id === fids.otherF)!.correlated, 0);
    assert.ok(!list.some((r) => r.id === fids.bWazuh || r.id === fids.bNuclei));
    assert.equal((await http('GET', `/api/vms/findings/${fids.bWazuh}`, AN)).status, 404);
    const bCorr = (await http('GET', `/api/vms/findings/${fids.bWazuh}`, tok('analyst', B))).data.correlated as Row[];
    assert.deepEqual(bCorr.map((c) => (c.other as Row).id), [fids.bNuclei], 'org-b sees only its own');
    assert.equal(JSON.stringify(db.tables.vms_findings), before, 'reading correlations changes no finding');
});

test('re-ingesting Wazuh data creates no duplicate findings and no duplicate correlations', async () => {
    db.tables.vms_findings = db.tables.vms_findings.filter((f) => f.source_class !== 'wazuh');
    db.tables.wazuh_group_org_map.push({ wazuh_group: 'acme', org_id: A });
    const deps = {
        agentsForGroup: async () => [{ id: '003', name: 'rayneops', status: 'active', ip: '10.88.1.139', group: ['acme'] }] as never,
        search: async () => ({ hits: { total: { value: 1 }, hits: [{ _source: { agent: { id: '003', name: 'rayneops' }, package: { name: 'openssl', version: '3.0.2' }, vulnerability: { id: CVE, severity: 'High', score: { base: 7.5 } } } }] } }),
    };
    await syncWazuhVulnerabilities(deps);
    await syncWazuhVulnerabilities(deps);
    const wz = db.tables.vms_findings.filter((f) => f.source_class === 'wazuh' && f.org_id === A);
    assert.equal(wz.length, 1);
    const corr = (await http('GET', `/api/vms/findings/${wz[0].id}`, AN)).data.correlated as Row[];
    assert.equal(corr.filter((c) => (c.other as Row).id === fids.nuclei).length, 1);
    // A new package version that still has the CVE: same finding, new evidence, title updated.
    const evBefore = db.tables.vms_finding_evidence.filter((e) => e.finding_id === wz[0].id).length;
    await syncWazuhVulnerabilities({ ...deps, search: async () => ({ hits: { total: { value: 1 }, hits: [{ _source: { agent: { id: '003', name: 'rayneops' }, package: { name: 'openssl', version: '3.0.3' }, vulnerability: { id: CVE, severity: 'High', score: { base: 7.5 } } } }] } }) });
    assert.equal(db.tables.vms_findings.filter((f) => f.source_class === 'wazuh' && f.org_id === A).length, 1);
    assert.match(String(wz[0].title), /openssl 3\.0\.3/);
    assert.equal(db.tables.vms_finding_evidence.filter((e) => e.finding_id === wz[0].id).length, evBefore + 1, 'the earlier sighting is kept');
});

// ── Wazuh Vulnerabilities view ──────────────────────────────────────────────────────────────
test('Wazuh view: no sync or no complete sync is "not available", never zero; fresh, stale and incomplete are named', async () => {
    const get = (q = '', t = AN) => http('GET', `/api/vms/wazuh/vulnerabilities${q}`, t);
    let r = await get();
    assert.deepEqual([r.status, r.data.state, r.data.summary], [200, 'not_synced', null]);
    db.tables.vms_wazuh_sync.push({ org_id: A, last_synced_at: now(), last_result: { complete: false, last_complete_at: null, errors: ['indexer: no index matches wazuh-states-vulnerabilities-*'] } });
    r = await get();
    assert.deepEqual([r.data.state, r.data.summary], ['never_complete', null]);
    assert.match(String((r.data.freshness as Row).problem), /no index matches/);

    Object.assign(db.tables.vms_wazuh_sync[0], { last_result: { complete: true, last_complete_at: now() } });
    db.tables.vms_finding_evidence.push(
        { id: randomUUID(), org_id: A, finding_id: fids.wazuh, source: 'wazuh', observed_at: ago(5), evidence: { package: { name: 'openssl', version: '3.0.1' } } },
        { id: randomUUID(), org_id: A, finding_id: fids.wazuh, source: 'wazuh', observed_at: ago(1), evidence: { package: { name: 'openssl', version: '3.0.2' } } },
    );
    r = await get();
    assert.equal(r.data.state, 'fresh');
    assert.deepEqual([(r.data.summary as Row).total, (r.data.summary as Row).high], [1, 1], 'Wazuh findings of this organisation only');
    const v = (r.data.vulnerabilities as Row[])[0];
    assert.deepEqual([v.id, v.package, v.package_version, v.correlated], [fids.wazuh, 'openssl', '3.0.2', 2], 'newest Wazuh evidence; correlations counted');
    assert.deepEqual((r.data.endpoints as Row[]).map((e) => e.name), ['rayneops']);

    Object.assign(db.tables.vms_wazuh_sync[0], { last_result: { complete: true, last_complete_at: ago(5) } });
    assert.equal((await get()).data.state, 'stale');
    Object.assign(db.tables.vms_wazuh_sync[0], { last_result: { complete: false, last_complete_at: ago(2), errors: ['indexer: connection refused'] } });
    r = await get();
    assert.equal(r.data.state, 'incomplete');
    assert.equal((r.data.summary as Row).total, 1, 'data as of the last complete sync, labelled');

    assert.equal(((await get(`?asset_id=${ids.ip}`)).data.vulnerabilities as Row[]).length, 0);
    assert.equal(((await get(`?asset_id=${ids.endpoint}&severity=critical`)).data.vulnerabilities as Row[]).length, 0);
    assert.equal((await get('?asset_id=rayneops')).status, 400);
    const rb = await get('', tok('analyst', B));
    assert.equal(rb.data.state, 'not_synced', 'org-b has its own (absent) sync');
    assert.equal((await http('GET', '/api/vms/wazuh/vulnerabilities', tok('portal_user'))).status, 403, 'portal users hold no VMS permission');
    assert.equal((await http('GET', '/api/vms/wazuh/vulnerabilities', tok('executive'))).status, 200, 'executives read their own organisation');
});

test('the live indexer endpoint reports "could not read" instead of zeros when the indexer does not answer', async () => {
    const r = await http('GET', '/api/wazuh/vulnerabilities', tok('soc_manager'));
    assert.equal(r.status, 502);
    assert.deepEqual([r.data.index_available, r.data.summary], [false, null]);
    assert.ok(r.data.problem);
});

// ── Verified closure ─────────────────────────────────────────────────────────────────────────
test('verification needs evidence that the scan reached the target', () => {
    assert.deepEqual(verificationReach({ target_outcomes: { 'a.test': { outcome: 'reachable_open' } } }, 'a.test'), { reached: true, detail: 'reachable open' });
    assert.equal(verificationReach({ outcome: 'unreachable', target_outcomes: { 'a.test': { outcome: 'unreachable' } } }, 'a.test').reached, false);
    assert.equal(verificationReach({ outcome: 'assessed' }, 'a.test').reached, true);
    assert.match(verificationReach({}, 'a.test').detail, /did not report whether it reached/);
    assert.equal(verificationReach(null, 'a.test').reached, false);
});

test('period closure: evidence-verified fixes are counted apart from claims, tasks and risk acceptance; per organisation', async () => {
    const ev = (finding_id: string, actor: string, action: string, from: string | null, to: string | null, org = A, details = 'x') => ({ id: randomUUID(), org_id: org, finding_id, actor, action, from_value: from, to_value: to, details, at: ago(24) });
    db.tables.vms_finding_events.push(
        ev(fids.nuclei, 'analyst@org-a.test', 'status', 'open', 'fixed_pending_verification'),
        ev(fids.nuclei, 'NovrSOC verification', 'verification', null, null),
        ev(fids.nuclei, 'NovrSOC verification', 'verified', 'fixed_pending_verification', 'verified', A, 'Not detected by verification scan j1, which reached 10.88.1.139 (reachable open)'),
        ev(fids.wazuh, 'wazuh', 'verified', 'open', 'verified'),
        ev(fids.otherF, 'analyst@org-a.test', 'status', 'open', 'risk_accepted'),
        ev(fids.hostF, 'analyst@org-a.test', 'status', 'open', 'fixed_pending_verification'),
        ev(fids.bNuclei, 'NovrSOC verification', 'verified', 'fixed_pending_verification', 'verified', B),
    );
    Object.assign(db.tables.vms_findings.find((f) => f.id === fids.nuclei)!, { status: 'verified' });
    Object.assign(db.tables.vms_findings.find((f) => f.id === fids.hostF)!, { status: 'fixed_pending_verification' });
    db.tables.vms_remediation_tasks.push(
        { id: randomUUID(), org_id: A, finding_id: fids.hostF, status: 'done', completed_at: ago(20) },
        { id: randomUUID(), org_id: A, finding_id: fids.nuclei, status: 'done', completed_at: ago(20) },
    );
    const c = await closureInPeriod(A, ago(24 * 7), now());
    assert.ok(c.available);
    if (!c.available) return;
    assert.deepEqual([c.verified_by_rescan, c.verified_by_wazuh, c.marked_fixed_by_people, c.awaiting_verification_now, c.verification_inconclusive], [1, 1, 2, 1, 1]);
    assert.deepEqual(c.closed_without_fix, { risk_accepted: 1, false_positive: 0 });
    assert.deepEqual(c.tasks_completed, { total: 2, findings: 2, findings_verified: 1, findings_not_verified: 1 }, 'a task marked done is not a verified fix');
    assert.match(String(c.verified_examples.find((e) => e.how === 'rescan')!.evidence), /which reached 10\.88\.1\.139/);
});

test('period coverage: assessments by derived status, latest checks by outcome; missing P13 table is "not set up"', async () => {
    const j = randomUUID();
    db.tables.vms_scan_jobs.push({ id: j, org_id: A, kind: 'ports', status: 'succeeded', started_at: ago(3), finished_at: ago(3), summary: { outcome: 'unreachable' } });
    db.tables.vms_assessments.push({ id: randomUUID(), org_id: A, target: '10.88.1.139', requested_at: ago(4), cancelled_at: null, trigger: 'policy', steps: [{ kind: 'ports', decision: 'queued', job_id: j, previous_job_ids: [] }, { kind: 'vuln_openvas', decision: 'unsupported', reason: 'x', job_id: null, previous_job_ids: [] }] });
    Object.assign(db.tables.vms_assets.find((a) => a.id === ids.ip)!, { last_assessed_at: ago(3), last_assessment: { outcome: 'no_route' } });
    Object.assign(db.tables.vms_assets.find((a) => a.id === ids.host)!, { last_assessed_at: ago(3), last_assessment: { outcome: 'reachable_open' } });
    const c = await coverageInPeriod(A, ago(24), now());
    assert.deepEqual(c.inventory, { wazuh_endpoints: 1, external_assets: 3 });
    assert.deepEqual([c.latest_checks.total, c.latest_checks.reached], [2, 1]);
    assert.ok(c.full_assessments.available);
    assert.deepEqual((c.full_assessments as Row).by_status, { inconclusive: 1 });
    assert.deepEqual((c.full_assessments as Row).checks_by_status, { inconclusive: 1, unsupported: 1 });
    assert.deepEqual((c.full_assessments as Row).by_trigger, { policy: 1 });
    const saved = db.tables.vms_assessments;
    (db.tables as Record<string, Row[] | null>).vms_assessments = null;
    assert.equal((await coverageInPeriod(A, ago(24), now())).full_assessments.available, false);
    db.tables.vms_assessments = saved;
});

// ── OSV ──────────────────────────────────────────────────────────────────────────────────────
test('OSV record parsing keeps ids, summary and fixed versions only', () => {
    const p = parseOsv({ id: CVE, aliases: ['GHSA-xxxx-yyyy-zzzz'], related: ['DSA-1'], summary: 'Overflow', affected: [
        { package: { ecosystem: 'Debian:12', name: 'openssl' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '3.0.11-1' }] }] },
        { ranges: [{ type: 'GIT', repo: 'https://github.com/openssl/openssl', events: [{ introduced: 'a' }, { fixed: 'b' }] }] },
        { package: {} },
    ] })!;
    assert.deepEqual(p.ids, [CVE, 'GHSA-xxxx-yyyy-zzzz', 'DSA-1']);
    assert.deepEqual(p.affected.map((a) => [a.ecosystem, a.name, a.repo, a.fixed]), [['Debian:12', 'openssl', null, ['3.0.11-1']], [null, null, 'https://github.com/openssl/openssl', ['b']]]);
    assert.equal(parseOsv({ code: 5, message: 'Bug not found.' }), null);
});

test('OSV refresh: found and not-found stored; errors, timeouts and rate limits store nothing and stop safely', async () => {
    const cves = ['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003', 'CVE-2024-0004', 'CVE-2024-0005'];
    db.tables.cve_intel.push(...cves.map((cve_id) => ({ cve_id, osv_fetched_at: null, kev: false })), { cve_id: 'CVE-2024-0009', osv_fetched_at: now(), osv_status: 'found' });
    const urls: string[] = [];
    const fake = (async (url: string | URL) => {
        const u = String(url); urls.push(u);
        const id = u.split('/').pop()!;
        if (id === 'CVE-2024-0001') return new Response(JSON.stringify({ id, aliases: ['GHSA-a'], affected: [] }), { status: 200 });
        if (id === 'CVE-2024-0002') return new Response(JSON.stringify({ code: 5 }), { status: 404 });
        if (id === 'CVE-2024-0003') return new Response('oops', { status: 500 });
        if (id === 'CVE-2024-0004') { const e = new Error('timed out'); e.name = 'TimeoutError'; throw e; }
        return new Response('slow down', { status: 429 });
    }) as typeof fetch;
    const r = await refreshOsv({ fetchImpl: fake, sleep: async () => undefined });
    assert.deepEqual([r.state, r.looked_up, r.found, r.not_found], ['rate_limited', 5, 1, 1]);
    assert.ok(!urls.some((u) => u.endsWith('CVE-2024-0009')), 'fresh records are not refetched');
    assert.ok(urls.every((u) => u.startsWith('https://api.osv.dev/v1/vulns/')));
    const row = (id: string) => db.tables.cve_intel.find((c) => c.cve_id === id)!;
    assert.deepEqual([row('CVE-2024-0001').osv_status, row('CVE-2024-0001').osv_ids], ['found', ['CVE-2024-0001', 'GHSA-a']]);
    assert.equal(row('CVE-2024-0002').osv_status, 'not_found');
    for (const id of ['CVE-2024-0003', 'CVE-2024-0004', 'CVE-2024-0005']) assert.equal(row(id).osv_fetched_at, null, `${id}: retried next run, not stored as "none"`);
    assert.ok(r.errors.some((e) => /no answer within 15 s/.test(e)));
    assert.equal(row('CVE-2024-0001').kev, false, 'other intelligence untouched');

    // Before the P16 SQL the update is refused: reported, nothing claimed.
    db.tables.cve_intel = [{ cve_id: 'CVE-2024-0007', osv_fetched_at: null }];
    db.missingColumns.cve_intel = ['osv_ids'];
    const r2 = await refreshOsv({ fetchImpl: (async () => new Response(JSON.stringify({ id: 'CVE-2024-0007' }), { status: 200 })) as typeof fetch, sleep: async () => undefined });
    delete db.missingColumns.cve_intel;
    assert.deepEqual([r2.found, r2.state], [0, 'failed']);
    assert.match(r2.errors[0], /not stored/);
});
