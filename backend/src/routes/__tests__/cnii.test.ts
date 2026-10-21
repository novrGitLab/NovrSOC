// CNII Watch API (phase P9): authentication, permissions per role, tenant isolation (client roles
// never leave their organisation; staff cross-organisation access is explicit and audited), the
// sector view's confirmed/unconfirmed split, per-asset authorisation status, passive collection
// only inside active scope, a lookup that stores nothing, the legacy import gate, and that CNII
// neither imports nor needs Wazuh. Fake PostgREST; RIPE Stat answered by a stub; no network.
process.env.JWT_SECRET = 'cnii-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'SPIDERFOOT_URL', 'OPENCTI_URL', 'OPENCTI_TOKEN', 'WAZUH_HOST', 'WAZUH_INDEXER_HOST', 'WAZUH_API_PASSWORD', 'WAZUH_PASSWORD']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import path from 'path';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import cniiRouter, { authorisation } from '../cnii';
import type { ScopeEntry } from '../../lib/vmsScope';

const A = 'org-a';
const B = 'org-b';
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
// sub is stable per role and org, so the org-a analyst can be assigned to org-b (P21).
const tok = (role: string, org = A) => jwt.sign({ sub: `${role}-${org}`, email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
async function call(method: string, p: string, bearer: string | null, body?: unknown, orgHeader?: string) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    if (orgHeader) headers['X-Org-Id'] = orgHeader;
    const r = await fetch(`${base}/api/cnii${p}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const future = (d = 30) => new Date(Date.now() + d * 86_400_000).toISOString();
const past = (d = 1) => new Date(Date.now() - d * 86_400_000).toISOString();
const TABLES = ['staff_org_assignments', 'organisations', 'org_access_audit', 'audit_log', 'cnii_org_profiles', 'cnii_profile_events', 'cnii_assets', 'vms_scopes', 'vms_scan_jobs', 'vms_assets', 'vms_asset_events', 'vms_observations', 'vms_services', 'vms_findings', 'vms_finding_evidence', 'vms_finding_events', 'cve_intel', 'ti_indicators', 'ti_matches'];

before(async () => {
    db = await startFakePostgrest(
        Object.fromEntries(TABLES.map((t) => [t, []])),
        { 'ti_matches.ti_indicators': 'indicator_id' },
        {
            vms_scopes: { status: 'active', allow_discovery: true, allow_port_scan: false, allow_vuln_scan: false, include_subdomains: true, approved_at: new Date().toISOString() },
            vms_scan_jobs: { status: 'queued', attempts: 0, cancel_requested: false, progress: {}, purpose: 'assessment', requested_at: new Date().toISOString() },
            vms_assets: { status: 'active', exposure: 'internet', criticality: 'medium', confidence: 'confirmed', hostnames: [], ips: [], dns: {}, discovery_sources: [], last_seen: new Date().toISOString() },
            vms_findings: { status: 'open', evidence_class: 'scanner_check', detected_by: [], cve_ids: [], references_urls: [], risk_factors: {}, due_manual: false },
            cnii_profile_events: { at: new Date().toISOString() },
            cve_intel: { kev: false },
        },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use(express.json());
    app.use('/api/cnii', requireAuth, cniiRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => {
    for (const t of TABLES) db.tables[t].length = 0;
    db.tables.organisations.push({ slug: A, name: 'Org A Telecom' }, { slug: B, name: 'Org B Power' });
    db.tables.staff_org_assignments.push({ id: 'as-1', user_id: 'analyst-org-a', user_email: 'analyst@org-a.test', org_slug: 'org-b', assigned_by: 'root', assigned_at: '2026-10-21T00:00:00Z' });
});

const scope = (org: string, b: Partial<ScopeEntry> = {}) => {
    const s = { id: randomUUID(), org_id: org, kind: 'domain', value: 'a.test', include_subdomains: true, allow_discovery: false, allow_port_scan: false, allow_vuln_scan: false, status: 'active', expires_at: future(), approved_at: new Date().toISOString(), ...b };
    db.tables.vms_scopes.push(s as Row);
    return s as ScopeEntry;
};
const asset = (org: string, value: string, b: Row = {}) => {
    const a = { id: randomUUID(), org_id: org, asset_type: 'host', value, status: 'active', exposure: 'internet', confidence: 'confirmed', ips: [], last_seen: new Date().toISOString(), ...b };
    db.tables.vms_assets.push(a);
    return a;
};
const profile = (org: string, sector = 'ict') => db.tables.cnii_org_profiles.push({ org_id: org, sector_id: sector, designation: 'candidate', created_by: 'x', updated_by: 'x' });

test('every route needs a signed-in user; client roles get no sector view and change nothing', async () => {
    for (const [m, p] of [['GET', '/sectors'], ['GET', '/sectors/ict'], ['GET', '/organisations'], ['POST', '/lookup'], ['GET', '/legacy'], ['GET', '/profile'], ['PUT', '/profile'], ['GET', '/inventory'], ['GET', `/assets/${randomUUID()}`], ['POST', '/collect'], ['POST', `/legacy/${randomUUID()}/import`]]) {
        assert.equal((await call(m, p, null, m === 'GET' ? undefined : {})).status, 401, `${m} ${p}`);
    }
    const exec = tok('executive');
    for (const p of ['/sectors', '/organisations', '/legacy']) assert.equal((await call('GET', p, exec)).status, 403, p);
    assert.equal((await call('POST', '/lookup', exec, { ip: '192.0.2.1' })).status, 403);
    assert.equal((await call('PUT', '/profile', exec, { sector_id: 'ict', designation: 'candidate' })).status, 403);
    assert.equal((await call('POST', '/collect', exec, { scope_id: randomUUID() })).status, 403);
    assert.equal((await call('GET', '/profile', tok('portal_user'))).status, 403);
    assert.equal((await call('PUT', '/profile', tok('analyst'), { sector_id: 'ict', designation: 'candidate' })).status, 403, 'classifying is a manager decision');
});

test('tenant isolation: executives see only their own organisation, whatever they send; staff cross-org access is audited', async () => {
    asset(A, 'portal.a.test');
    asset(B, 'grid.b.test');
    const own = await call('GET', '/inventory', tok('executive'), undefined, B);
    assert.equal(own.status, 200);
    assert.deepEqual(own.data.assets.map((a: Row) => a.value), ['portal.a.test'], 'X-Org-Id is ignored for client roles');
    assert.equal(db.tables.org_access_audit.length, 0);
    const bAsset = db.tables.vms_assets.find((a) => a.org_id === B)!;
    assert.equal((await call('GET', `/assets/${bAsset.id}`, tok('executive'))).status, 404);

    const staff = await call('GET', '/inventory', tok('analyst'), undefined, B);
    assert.deepEqual(staff.data.assets.map((a: Row) => a.value), ['grid.b.test']);
    assert.equal(db.tables.org_access_audit.length, 1);
    assert.equal(db.tables.org_access_audit[0].target_org, B);
    assert.equal((await call('GET', '/inventory', tok('analyst'), undefined, 'no-such-org')).status, 400);
});

test('profile: managers classify with a reference for designation; every change is kept', async () => {
    const MGR = tok('soc_manager');
    assert.equal((await call('PUT', '/profile', MGR, { sector_id: 'nope', designation: 'candidate' })).status, 400);
    assert.equal((await call('PUT', '/profile', MGR, { sector_id: 'ict', subfield: 'Hospitals', designation: 'candidate' })).status, 400, 'sub-entity of another sector');
    assert.equal((await call('PUT', '/profile', MGR, { sector_id: 'ict', designation: 'designated' })).status, 400, 'designation needs its reference');
    assert.equal((await call('PUT', '/profile', MGR, { sector_id: 'ict', subfield: 'Communications Companies', designation: 'candidate' })).status, 201);
    const r = await call('PUT', '/profile', MGR, { sector_id: 'ict', subfield: 'NCC', designation: 'designated', designation_reference: 'NSA/CNII/2026/014' }, B);
    assert.equal(r.status, 201);
    const again = await call('PUT', '/profile', MGR, { sector_id: 'power', designation: 'designated', designation_reference: 'NSA/CNII/2026/014' }, B);
    assert.equal(again.status, 200);
    const hist = db.tables.cnii_profile_events.filter((e) => e.org_id === B);
    assert.equal(hist.length, 2);
    assert.deepEqual((hist[1].from_value as Row).sector_id, 'ict');
    assert.deepEqual((hist[1].to_value as Row).sector_id, 'power');
    const g = await call('GET', '/profile', tok('executive', B));
    assert.equal(g.data.profile.sector_id, 'power');
    assert.equal(g.data.history.length, 2);
});

test('sector view: confirmed and unconfirmed findings are counted apart; unmonitored organisations are visible', async () => {
    profile(A); profile(B);
    scope(A);
    const a1 = asset(A, 'portal.a.test');
    db.tables.cve_intel.push({ cve_id: 'CVE-2024-3400', kev: true });
    db.tables.vms_findings.push(
        { id: randomUUID(), org_id: A, asset_id: a1.id, priority: 'P1', evidence_class: 'scanner_check', status: 'open', cve_ids: ['CVE-2024-3400'] },
        { id: randomUUID(), org_id: A, asset_id: a1.id, priority: 'P3', evidence_class: 'version_match', status: 'open', cve_ids: ['CVE-2023-44487'] },
        { id: randomUUID(), org_id: A, asset_id: a1.id, priority: 'P2', evidence_class: 'scanner_check', status: 'verified', cve_ids: [] },
    );
    const r = await call('GET', '/sectors', tok('analyst'));
    assert.equal(r.status, 200);
    const ict = r.data.sectors.find((s: Row) => s.id === 'ict');
    assert.equal(ict.organisations, 2);
    assert.equal(ict.unmonitored, 1);
    assert.equal(ict.confirmed_p1_p2, 1);
    assert.equal(ict.unconfirmed_open, 1);
    assert.equal(ict.kev_open, 1);
    assert.deepEqual(ict.open_findings, { P1: 1, P2: 0, P3: 1, P4: 0 });
    assert.equal(r.data.sectors.length, 13);
    const one = await call('GET', '/sectors/ict', tok('analyst'));
    const b = one.data.organisations.find((o: Row) => (o.profile as Row).org_id === B);
    assert.deepEqual(b.gaps, ['no active authorised scope: nothing is monitored']);
    assert.equal((await call('GET', '/sectors/atlantis', tok('analyst'))).status, 404);
});

test('authorisation status per asset: authorised, expired, revoked or none', () => {
    const s = (b: Partial<ScopeEntry>): ScopeEntry => ({ id: randomUUID(), org_id: A, kind: 'domain', value: 'a.test', include_subdomains: true, allow_port_scan: false, allow_vuln_scan: false, allow_discovery: false, status: 'active', expires_at: future(), ...b });
    const live = authorisation({ asset_type: 'host', value: 'www.a.test' }, [s({ allow_vuln_scan: true })]);
    assert.deepEqual([live.status, live.passive, live.discovery, live.vuln], ['authorised', true, false, true]);
    assert.equal(authorisation({ asset_type: 'host', value: 'www.a.test' }, [s({ expires_at: past() })]).status, 'expired');
    assert.equal(authorisation({ asset_type: 'host', value: 'www.a.test' }, [s({ status: 'revoked' })]).status, 'revoked');
    assert.equal(authorisation({ asset_type: 'host', value: 'www.b.test' }, [s({})]).status, 'not_authorised');
    assert.equal(authorisation({ asset_type: 'asn', value: 'AS64500' }, [s({ kind: 'asn', value: 'AS64500' })]).status, 'authorised');
});

test('collection: only inside an active scope of the caller\'s organisation, as a passive job', async () => {
    const live = scope(A);
    const expired = scope(A, { value: 'old.a.test', expires_at: past() });
    const other = scope(B, { value: 'b.test' });
    const AN = tok('analyst');
    const ok = await call('POST', '/collect', AN, { scope_id: live.id });
    assert.equal(ok.status, 201);
    assert.equal(ok.data.job.kind, 'passive_osint');
    assert.equal((await call('POST', '/collect', AN, { scope_id: live.id })).data.existing, true, 'no duplicate job');
    assert.equal((await call('POST', '/collect', AN, { scope_id: expired.id })).status, 400);
    assert.equal((await call('POST', '/collect', AN, { scope_id: other.id })).status, 400, 'another organisation\'s scope');
    assert.equal((await call('POST', '/collect', AN, { scope_id: live.id, targets: ['www.other.test'] })).status, 400);
    assert.equal(db.tables.vms_scan_jobs.length, 1);
});

test('lookup: suggests, says who holds the address in scope, stores nothing', async () => {
    scope(B, { kind: 'ip', value: '192.0.2.44', include_subdomains: false });
    asset(B, '192.0.2.44', { asset_type: 'ip', ips: ['192.0.2.44'] });
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
        const u = String(input instanceof Request ? input.url : input);
        if (u.startsWith('https://stat.ripe.net/data/network-info/')) return new Response(JSON.stringify({ status: 'ok', data: { asns: ['64500'], prefix: '192.0.2.0/24' } }));
        if (u.startsWith('https://stat.ripe.net/data/as-overview/')) return new Response(JSON.stringify({ status: 'ok', data: { holder: 'NCC-AS Nigerian Communications Commission' } }));
        if (u.startsWith('https://')) throw new Error(`unexpected network call: ${u}`);
        return realFetch(input, init);
    }) as typeof fetch;
    try {
        const before = JSON.stringify(Object.fromEntries(TABLES.filter((t) => t !== 'audit_log').map((t) => [t, db.tables[t].length])));
        assert.equal((await call('POST', '/lookup', tok('analyst'), { ip: 'not-an-ip' })).status, 400);
        const r = await call('POST', '/lookup', tok('analyst'), { ip: '192.0.2.44' });
        assert.equal(r.status, 200);
        assert.equal(r.data.holder, 'Nigerian Communications Commission');
        assert.equal(r.data.sector_suggestion.sectorId, 'ict');
        assert.deepEqual(r.data.in_inventory_of.map((h: Row) => [h.org_id, h.authorised]), [[B, true]]);
        assert.equal(r.data.sources.opencti, 'not configured');
        assert.equal(JSON.stringify(Object.fromEntries(TABLES.filter((t) => t !== 'audit_log').map((t) => [t, db.tables[t].length]))), before);
    } finally { globalThis.fetch = realFetch; }
});

test('legacy import: needs a profile and an active scope covering the address; brings old data in as unconfirmed', async () => {
    const MGR = tok('soc_manager');
    const row = { id: randomUUID(), ip: '192.0.2.10', hostname: 'portal.a.test', owner: 'Org A', org: 'Org A', asn: 'AS64500', sector_id: 'ict', open_ports: [443, 22], vulns: [{ cve: 'CVE-2023-44487', cvss: 7.5, severity: 'high' }], last_seen: past(10), added_at: past(40) };
    db.tables.cnii_assets.push(row);
    const go = () => call('POST', `/legacy/${row.id}/import`, MGR);
    assert.equal((await go()).status, 409, 'no profile yet');
    profile(A, 'finance');
    assert.equal((await go()).status, 403, 'no scope covers the address');
    scope(A, { kind: 'cidr', value: '192.0.2.0/28', include_subdomains: false });
    const r = await go();
    assert.equal(r.status, 200);
    assert.deepEqual(r.data.sector_mismatch, { legacy: 'ict', organisation: 'finance' });
    const a = db.tables.vms_assets.find((x) => x.id === r.data.asset_id)!;
    assert.equal(a.org_id, A);
    assert.ok(db.tables.vms_observations.every((o) => o.confidence === 'low' && o.source === 'legacy_cnii'));
    assert.equal(db.tables.vms_findings[0].evidence_class, 'version_match');
    assert.equal(db.tables.cnii_assets[0].imported_org_id, A);
    assert.equal((await go()).status, 409, 'imported once');
    assert.equal((await call('POST', `/legacy/${row.id}/import`, tok('analyst'))).status, 403);
    const list = await call('GET', '/legacy', tok('analyst'));
    assert.equal(list.data.available, true);
    assert.ok(!('raw_spiderfoot' in list.data.rows[0]), 'raw payloads are not served');
});

test('CNII neither imports nor needs Wazuh', () => {
    for (const f of ['routes/cnii.ts', 'services/cniiPassive.ts', 'jobs/cniiPassiveJob.ts', 'lib/spiderfoot.ts', 'lib/opencti.ts']) {
        const src = readFileSync(path.join(__dirname, '..', '..', f), 'utf8');
        assert.ok(!/from ['"][^'"]*wazuh[^'"]*['"]/i.test(src), `${f} imports a Wazuh module`);
    }
    assert.ok(!Object.keys(process.env).some((k) => k.startsWith('WAZUH_')), 'these tests ran with no Wazuh configuration');
});
