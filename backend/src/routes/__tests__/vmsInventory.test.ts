// Phase P28 (Release 2 Stage 5): the four unified-inventory categories (Wazuh / Vulnerability /
// Cloud / Other) as predicates over vms_assets, CNII association on the assets list, and
// human-confirmed "same machine?" links. Fake PostgREST only; no scanner runs.
process.env.JWT_SECRET = 'vms-inventory-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest } from './fakePostgrest';
import vmsRouter, { assetCategories } from '../vms';

const A = 'org-a';
const B = 'org-b';
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = A) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const MGR = tok('soc_manager');
const AN = tok('analyst');
async function http(method: string, path: string, bearer?: string, body?: unknown) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const r = await fetch(`${base}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}

before(async () => {
    db = await startFakePostgrest(
        { vms_assets: [], vms_findings: [], vms_services: [], vms_asset_links: [], cnii_org_profiles: [] },
        {},
        {
            vms_assets: { org_id: A, status: 'active', exposure: 'unknown', criticality: 'medium', hostnames: [], ips: [], dns: {}, discovery_sources: [], first_seen: new Date().toISOString(), last_seen: new Date().toISOString() },
            vms_findings: { org_id: A, status: 'open' },
        },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use(express.json());
    app.use('/api/vms', requireAuth, vmsRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => {
    for (const t of ['vms_assets', 'vms_findings', 'vms_services', 'vms_asset_links', 'cnii_org_profiles']) db.tables[t].length = 0;
});

// ── Category predicates (pure) ──────────────────────────────────────────────────────────────
test('categories: an endpoint with a Wazuh agent is Wazuh; findings or a last assessment make it Vulnerability too', () => {
    assert.deepEqual(assetCategories({ asset_type: 'endpoint', wazuh_agent_id: 'wz-1' }, false), ['wazuh']);
    assert.deepEqual(assetCategories({ asset_type: 'endpoint', wazuh_agent_id: 'wz-1' }, true), ['wazuh', 'vulnerability']);
    assert.deepEqual(assetCategories({ asset_type: 'endpoint', wazuh_agent_id: 'wz-1', last_assessed_at: '2026-01-01T00:00:00Z' }, false), ['wazuh', 'vulnerability']);
});

test('categories: a cloud resource (or cloud_ref set) is Cloud, regardless of type', () => {
    assert.deepEqual(assetCategories({ asset_type: 'cloud_resource' }, false), ['cloud']);
    assert.deepEqual(assetCategories({ asset_type: 'host', cloud_ref: 'arn:aws:ec2:1:instance/i-1' }, false), ['cloud']);
});

test('categories: a plain domain/host with no findings and no cloud link is Other, alone', () => {
    assert.deepEqual(assetCategories({ asset_type: 'domain' }, false), ['other']);
});

test('categories: an asset can be in more than one category at once (Wazuh + Vulnerability + Cloud)', () => {
    assert.deepEqual(assetCategories({ asset_type: 'endpoint', wazuh_agent_id: 'wz-1', cloud_ref: 'i-1' }, true), ['wazuh', 'vulnerability', 'cloud']);
});

// ── GET /assets?category= ───────────────────────────────────────────────────────────────────
test('GET /assets?category=: filters to the matching predicate; an asset can appear under more than one', async () => {
    db.tables.vms_assets.push(
        { id: randomUUID(), org_id: A, asset_type: 'endpoint', value: 'host-1', wazuh_agent_id: 'wz-1' },
        { id: randomUUID(), org_id: A, asset_type: 'domain', value: 'example.test' },
        { id: randomUUID(), org_id: A, asset_type: 'host', value: 'cloud-host', cloud_ref: 'arn:aws:ec2:1:instance/i-1' },
    );
    const wazuh = await http('GET', '/api/vms/assets?category=wazuh', AN);
    assert.deepEqual(wazuh.data.assets.map((a: { value: string }) => a.value), ['host-1']);
    const cloud = await http('GET', '/api/vms/assets?category=cloud', AN);
    assert.deepEqual(cloud.data.assets.map((a: { value: string }) => a.value), ['cloud-host']);
    const other = await http('GET', '/api/vms/assets?category=other', AN);
    assert.deepEqual(other.data.assets.map((a: { value: string }) => a.value), ['example.test']);
    // An unfiltered read reports every asset's own categories, so a client can facet locally too.
    const all = await http('GET', '/api/vms/assets', AN);
    assert.equal(all.data.assets.length, 3);
    assert.deepEqual(all.data.assets.find((a: { value: string }) => a.value === 'host-1').categories, ['wazuh']);
});

test('GET /assets?category=vulnerability: an open finding is enough, with no explicit last_assessed_at', async () => {
    const assetId = randomUUID();
    db.tables.vms_assets.push({ id: assetId, org_id: A, asset_type: 'ip', value: '203.0.113.9' });
    db.tables.vms_findings.push({ id: randomUUID(), org_id: A, asset_id: assetId, scanner_severity: 'high', status: 'open' });
    const r = await http('GET', '/api/vms/assets?category=vulnerability', AN);
    assert.deepEqual(r.data.assets.map((a: { value: string }) => a.value), ['203.0.113.9']);
});

// ── CNII association ────────────────────────────────────────────────────────────────────────
test('GET /assets: carries this organisation\'s CNII classification on every row, or null when unclassified', async () => {
    db.tables.vms_assets.push({ id: randomUUID(), org_id: A, asset_type: 'domain', value: 'example.test' });
    const before = await http('GET', '/api/vms/assets', AN);
    assert.equal(before.data.assets[0].cnii, null);
    db.tables.cnii_org_profiles.push({ org_id: A, sector_id: 'finance', designation: 'designated' });
    const r = await http('GET', '/api/vms/assets', AN);
    assert.deepEqual(r.data.assets[0].cnii, { sector_id: 'finance', designation: 'designated' });
});

// ── Human-confirmed "same machine?" links ───────────────────────────────────────────────────
test('POST /asset-links: vms:manage only, both assets must exist in the caller\'s organisation', async () => {
    const a1 = randomUUID();
    const a2 = randomUUID();
    db.tables.vms_assets.push({ id: a1, org_id: A, asset_type: 'endpoint', value: 'ep-1', ips: ['203.0.113.5'] }, { id: a2, org_id: A, asset_type: 'ip', value: '203.0.113.5' });
    assert.equal((await http('POST', '/api/vms/asset-links', tok('executive'), { asset_a: a1, asset_b: a2, relation: 'same_machine', basis: 'confirmed' })).status, 403, 'executive has vms:read but not vms:manage');
    const bad = await http('POST', '/api/vms/asset-links', MGR, { asset_a: a1, asset_b: a1, relation: 'same_machine', basis: 'confirmed' });
    assert.equal(bad.status, 400, 'asset_a and asset_b must differ');
    const otherOrgAsset = randomUUID();
    db.tables.vms_assets.push({ id: otherOrgAsset, org_id: B, asset_type: 'ip', value: '198.51.100.9' });
    assert.equal((await http('POST', '/api/vms/asset-links', MGR, { asset_a: a1, asset_b: otherOrgAsset, relation: 'same_machine', basis: 'confirmed' })).status, 404, 'the other org\'s asset is not visible');
    const ok = await http('POST', '/api/vms/asset-links', MGR, { asset_a: a1, asset_b: a2, relation: 'same_machine', basis: 'confirmed' });
    assert.equal(ok.status, 200);
    assert.equal(ok.data.link.basis, 'confirmed');
});

test('a confirmed link appears on the asset page\'s linked record, in either asset\'s direction; re-confirming updates it, not duplicates it', async () => {
    const ep = randomUUID();
    const ip = randomUUID();
    db.tables.vms_assets.push({ id: ep, org_id: A, asset_type: 'endpoint', value: 'ep-1', ips: ['203.0.113.5'] }, { id: ip, org_id: A, asset_type: 'ip', value: '203.0.113.5' });
    const before = await http('GET', `/api/vms/assets/${ep}`, AN);
    assert.equal(before.data.linked[0].same_machine, null, 'inferred same-address lead, not yet confirmed');
    await http('POST', '/api/vms/asset-links', MGR, { asset_a: ep, asset_b: ip, relation: 'same_machine', basis: 'confirmed' });
    const afterEp = await http('GET', `/api/vms/assets/${ep}`, AN);
    assert.equal(afterEp.data.linked[0].same_machine.basis, 'confirmed');
    const afterIp = await http('GET', `/api/vms/assets/${ip}`, AN);
    assert.equal(afterIp.data.linked[0].same_machine.basis, 'confirmed', 'shows from either side of the pair');
    assert.equal(db.tables.vms_asset_links.length, 1);
    await http('POST', '/api/vms/asset-links', MGR, { asset_a: ip, asset_b: ep, relation: 'same_machine', basis: 'rejected' });
    assert.equal(db.tables.vms_asset_links.length, 1, 'the reversed pair upserts the same row, not a second one');
    assert.equal(db.tables.vms_asset_links[0].basis, 'rejected');
});
