// Phase P23: CNII national intelligence. Only organisations with a CNII profile are counted; an
// analyst sees only its own and assigned organisations (others are absent and 404); figures come
// from each organisation's VMS records; the risk is the mean contextual score, defined; client roles
// are refused. Fake PostgREST with synthetic organisations.
process.env.JWT_SECRET = 'cnii-national-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY']) delete process.env[k];

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import cniiNationalRouter from '../cniiNational';

let db: FakePostgrest;
let server: Server;
let base = '';
const tok = (role: string, org: string, sub = `${role}-${org}`) => jwt.sign({ sub, email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const get = async (path: string, t: string) => { const r = await fetch(`${base}/api/cnii/national${path}`, { headers: { Authorization: `Bearer ${t}` } }); return { status: r.status, data: (await r.json().catch(() => null)) as any }; }; // eslint-disable-line @typescript-eslint/no-explicit-any
const now = new Date().toISOString();
const asset = (org: string, value: string, b: Row = {}) => ({ id: randomUUID(), org_id: org, value, asset_type: 'ip', exposure: 'internet', criticality: 'high', status: 'active', first_seen: now, last_seen: now, ...b });
const finding = (org: string, a: Row, sev: string, risk: number, b: Row = {}) => ({ id: randomUUID(), org_id: org, asset_id: a.id, asset_value: a.value, port: 443, title: `${sev} issue`, rule_id: 'r', cve_ids: [], scanner_severity: sev, scanner_cvss: 7, risk_score: risk, priority: risk >= 80 ? 'P1' : risk >= 60 ? 'P2' : 'P3', status: 'open', detected_by: ['nuclei'], source_class: 'active_scan', first_seen: now, last_seen: now, due_at: null, verified_at: null, ...b });
let grid: Row, bank: Row, unprofiled: Row;

before(async () => {
    grid = asset('grid-co', '192.0.2.1'); bank = asset('bank-co', '198.51.100.1'); unprofiled = asset('other-co', '203.0.113.1');
    db = await startFakePostgrest({
        organisations: [{ slug: 'grid-co', name: 'Grid Co' }, { slug: 'bank-co', name: 'Bank Co' }, { slug: 'other-co', name: 'Other Co' }, { slug: 'soc', name: 'SOC' }],
        cnii_org_profiles: [{ org_id: 'grid-co', sector_id: 'power', subfield: 'Power Generation & Distribution', designation: 'designated' }, { org_id: 'bank-co', sector_id: 'finance', subfield: null, designation: 'candidate' }],
        vms_assets: [grid, bank, unprofiled],
        vms_findings: [finding('grid-co', grid, 'critical', 90, { cve_ids: ['CVE-2024-3400'] }), finding('grid-co', grid, 'medium', 40), finding('grid-co', grid, 'info', 2), finding('bank-co', bank, 'high', 60), finding('other-co', unprofiled, 'critical', 99), finding('grid-co', grid, 'high', 70, { status: 'verified' })],
        vms_scopes: [{ org_id: 'grid-co', status: 'active', expires_at: new Date(Date.now() + 9e8).toISOString() }],
        cve_intel: [{ cve_id: 'CVE-2024-3400', kev: true }],
        // grid-co is scoped AND has actually collected (connected_fresh); bank-co has neither a
        // scope nor a collection (not_connected) — R3.3B Stage 2 requires real telemetry evidence,
        // not just an authorised scope, before a monitoring coverage figure counts an org as covered.
        vms_risk_snapshots: [], vms_remediation_tasks: [], vms_scan_jobs: [{ id: randomUUID(), org_id: 'grid-co', kind: 'passive_osint', status: 'succeeded', finished_at: now }], vms_finding_evidence: [], vms_finding_events: [], audit_log: [],
        staff_org_assignments: [{ id: randomUUID(), user_id: 'analyst-soc', user_email: 'a@soc.test', org_slug: 'grid-co', assigned_by: 'root', assigned_at: now }],
        ti_matches: [], ti_indicators: [], ti_indicator_sources: [],
    }, { 'ti_matches.ti_indicators': 'indicator_id' });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use('/api/cnii/national', requireAuth, cniiNationalRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(async () => { server.close(); await db.close(); });

test('national: only profiled organisations are counted; risk is the defined contextual mean', async () => {
    const r = await get('/', tok('super_admin', 'soc'));
    assert.equal(r.status, 200);
    const k = r.data.kpis as Row;
    assert.equal(k.organisations, 2);
    assert.equal(k.sectors_configured, 13);
    assert.equal(k.sectors_monitored, 2);
    assert.equal(k.assets, 2, 'the unprofiled organisation\'s asset is not CNII');
    assert.equal(k.open_vulnerabilities, 3, 'open, informational excluded; the verified finding is closed');
    assert.equal(k.critical, 1);
    assert.equal(k.kev_open, 1);
    assert.deepEqual(k.risk, { mean: Math.round(((90 + 40 + 60) / 3) * 10) / 10, max: 90, scored: 3 });
    assert.match(String((r.data.definitions as Row).infrastructure_risk), /not an average of CVSS/);
    assert.deepEqual((k.coverage as Row), {
        organisations_scoped: 1, organisations: 2, pct: 50,
        by_state: { connected_fresh: 1, connected_stale: 0, configured_not_receiving: 0, not_connected: 1, unknown: 0 },
    });
    const sectors = r.data.sectors as Row[];
    assert.equal(sectors.length, 13);
    assert.equal(sectors.find((s) => s.id === 'water')!.organisations, 0);
    assert.equal(sectors.find((s) => s.id === 'power')!.critical_high, 1);
    assert.deepEqual(r.data.sources, { nuclei: 4 });
});

test('designated only: candidates are left out of every figure', async () => {
    const r = await get('/?designated=1', tok('super_admin', 'soc'));
    assert.equal((r.data.kpis as Row).organisations, 1);
    assert.equal((r.data.kpis as Row).assets, 1);
});

test('an analyst sees only its own and assigned organisations; others are not counted and 404', async () => {
    const an = tok('analyst', 'soc');
    const r = await get('/', an);
    assert.equal((r.data.visibility as Row).mode, 'assigned');
    assert.equal((r.data.kpis as Row).organisations, 1);
    assert.deepEqual((r.data.organisations as Row[]).map((o) => o.slug), ['grid-co']);
    assert.equal((await get('/orgs/grid-co', an)).status, 200);
    assert.equal((await get('/orgs/bank-co', an)).status, 404);
    assert.equal((await get(`/orgs/bank-co/assets/${bank.id}`, an)).status, 404);
    assert.equal((await get('/sectors/finance', an)).data.kpis.organisations, 0);
});

test('drill-down: sector → organisation → asset, from the organisation\'s own VMS records', async () => {
    const t = tok('soc_manager', 'soc');
    const s = await get('/sectors/power', t);
    assert.equal(s.status, 200);
    assert.deepEqual((s.data.organisations as Row[]).map((o) => o.slug), ['grid-co']);
    const o = await get('/orgs/grid-co', t);
    assert.equal(o.data.organisation.designation, 'designated');
    assert.equal((o.data.findings as Row[]).length, 3);
    assert.deepEqual(o.data.cves, [{ cve_id: 'CVE-2024-3400', kev: true, findings: 1 }]);
    assert.equal(o.data.remediation.findings_closed_by_status.verified, 1);
    const a = await get(`/orgs/grid-co/assets/${grid.id}`, t);
    assert.equal(a.status, 200);
    assert.equal((a.data.findings as Row[]).length, 4, 'open and closed findings, for history');
    assert.equal((await get(`/orgs/grid-co/assets/${bank.id}`, t)).status, 404, 'an asset of another organisation');
    assert.equal((await get('/orgs/other-co', t)).status, 404, 'an organisation without a CNII profile');
    assert.equal((await get('/sectors/atlantis', t)).status, 404);
});

test('R3.3B: coverage_state threads through every level; TI matches are verified-vs-contextual, never a bare count, and carry a conservative TLP', async () => {
    const t = tok('soc_manager', 'soc');
    const sector = await get('/sectors/power', t);
    assert.equal((sector.data.organisations as Row[])[0].coverage_state, 'connected_fresh');
    assert.deepEqual((sector.data.kpis as Row).coverage, { organisations_scoped: 1, assets_assessed_30d: 0, by_state: { connected_fresh: 1, connected_stale: 0, configured_not_receiving: 0, not_connected: 0, unknown: 0 } });
    const o = await get('/orgs/grid-co', t);
    assert.equal(o.data.summary.coverage_state, 'connected_fresh');
    // No indicator rows seeded yet: a clean, honest zero, not an absent field.
    assert.deepEqual(o.data.summary.threat_intelligence, { total: 0, verified: 0, contextual: 0 });

    const indicator = { id: randomUUID(), type: 'ip', value: '203.0.113.9', max_confidence: 80, malware_families: ['cobaltstrike'], threat_types: ['c2'], status: 'active' };
    db.tables.ti_indicators = [indicator];
    db.tables.ti_indicator_sources = [{ id: randomUUID(), indicator_id: indicator.id, feed_id: 'f', source_ref: 'r', tlp: 'amber+strict' }];
    db.tables.ti_matches = [
        { id: randomUUID(), org_id: 'grid-co', entity_type: 'asset', entity_id: grid.id, indicator_id: indicator.id, status: 'new', case_id: null },
        { id: randomUUID(), org_id: 'grid-co', entity_type: 'asset', entity_id: grid.id, indicator_id: indicator.id, status: 'dismissed', case_id: null }, // excluded — an analyst's call that it isn't relevant
    ];

    const o2 = await get('/orgs/grid-co', t);
    assert.deepEqual(o2.data.summary.threat_intelligence, { total: 1, verified: 0, contextual: 1 }, 'dismissed is excluded; "new" is contextual only, not verified');
    const assetRow = (o2.data.assets as Row[]).find((x) => x.id === grid.id)!;
    assert.deepEqual(assetRow.threat_intelligence, { total: 1, verified: 0, contextual: 1 });

    const a = await get(`/orgs/grid-co/assets/${grid.id}`, t);
    const ti = a.data.threat_intelligence as Row[];
    assert.equal(ti.length, 1);
    assert.equal(ti[0].verified, false, '"new" status with no case is a contextual association, never implied as verified');
    assert.equal(ti[0].tlp, 'amber+strict', 'the most restrictive marking among the indicator\'s sources');
    assert.equal(ti[0].indicator_value, '203.0.113.9');

    // Promoting the match (or linking it to a case) is what a verified association actually means.
    db.tables.ti_matches[0].status = 'promoted';
    const a2 = await get(`/orgs/grid-co/assets/${grid.id}`, t);
    assert.equal((a2.data.threat_intelligence as Row[])[0].verified, true);
});

test('client and executive roles are refused', async () => {
    assert.equal((await get('/', tok('executive', 'grid-co'))).status, 403);
    assert.equal((await get('/', tok('portal_user', 'grid-co'))).status, 403);
});
