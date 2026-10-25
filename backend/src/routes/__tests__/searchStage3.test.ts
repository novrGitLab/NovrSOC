// Global search (2026 redesign, Stage 3): the new entities (organisations are deliberately not
// among them yet — see search.ts's header comment), TLP filtering, org scoping, and that a
// source which fails to answer is reported as failed, never folded into "nothing found".
// Fake PostgREST; the Wazuh-indexer alert provider is left to fail honestly (no indexer
// configured here) — routes/__tests__/wazuhTenancy.test.ts and secopsAccess.test.ts already
// cover that source and the stored-alerts/cases providers end to end.
process.env.JWT_SECRET = 'search-stage3-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'WAZUH_INDEXER_HOST', 'WAZUH_HOST']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import searchRouter from '../search';

const A = 'org-a';
const B = 'org-b';
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = A) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const ANALYST = tok('analyst');
async function search(q: string, bearer = ANALYST) {
    const r = await fetch(`${base}/api/search?q=${encodeURIComponent(q)}`, { headers: { Authorization: `Bearer ${bearer}` } });
    return { status: r.status, data: await r.json() };
}
interface SearchResultRow { type: string; title: string; subtitle: string; badge?: string; url: string }
const entity = (data: { results: SearchResultRow[] }, t: string) => data.results.filter((r) => r.type === t);

before(async () => {
    db = await startFakePostgrest({
        organisations: [{ id: 'oa', slug: A, name: 'Org A' }, { id: 'ob', slug: B, name: 'Org B' }],
        cases: [], alerts: [], ioc_enrichments: [], nigeria_advisories: [], ti_reports: [],
        vms_assets: [], vms_findings: [], cve_intel: [], ti_indicators: [], ti_indicator_sources: [], cnii_org_profiles: [],
    });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use(express.json());
    app.use('/api/search', searchRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => {
    for (const t of ['cases', 'alerts', 'ioc_enrichments', 'nigeria_advisories', 'ti_reports', 'vms_assets', 'vms_findings', 'cve_intel', 'ti_indicators', 'ti_indicator_sources', 'cnii_org_profiles']) {
        if (Array.isArray(db.tables[t])) db.tables[t].length = 0;
    }
});

test('a query under 2 characters answers empty with no sources attempted', async () => {
    const r = await search('a');
    assert.deepEqual(r.data, { results: [], query: 'a', total: 0, sources: [] });
});

test('vms assets and findings: only the caller\'s own organisation, and a CVE-shaped query matches by CVE id', async () => {
    db.tables.vms_assets.push(
        { id: randomUUID(), org_id: A, value: 'shared-mail.example.test', asset_type: 'host', criticality: 'high' },
        { id: randomUUID(), org_id: B, value: 'shared-mail-other.example.test', asset_type: 'host', criticality: 'high' },
    );
    const byName = await search('shared-mail');
    assert.deepEqual(entity(byName.data, 'vms_asset').map((r) => r.title), ['shared-mail.example.test']);

    db.tables.vms_findings.push(
        { id: randomUUID(), org_id: A, title: 'Outdated OpenSSL', priority: 'P2', status: 'open', asset_value: 'web-01', cve_ids: ['CVE-2024-12345'] },
        { id: randomUUID(), org_id: B, title: 'Outdated OpenSSL (org B)', priority: 'P2', status: 'open', asset_value: 'web-02', cve_ids: ['CVE-2024-12345'] },
    );
    const byCve = await search('CVE-2024-12345');
    assert.deepEqual(entity(byCve.data, 'vms_finding').map((r) => r.title), ['Outdated OpenSSL']);
});

test('CVE reference data is global, not org-scoped, and shows the KEV badge', async () => {
    db.tables.cve_intel.push({ cve_id: 'CVE-2024-99999', cvss_score: 9.8, kev: true, epss_score: 0.9 });
    const r = await search('CVE-2024-99999');
    const [hit] = entity(r.data, 'cve');
    assert.equal(hit.title, 'CVE-2024-99999');
    assert.equal(hit.badge, 'critical');
    assert.match(hit.subtitle, /CISA KEV/);
});

test('TI indicator: a RED-marked source takes the whole indicator out of results for a client-ceiling viewer, not just a label', async () => {
    const id = randomUUID();
    db.tables.ti_indicators.push({ id, type: 'domain', value: 'shared-evil.example.test', status: 'active' });
    db.tables.ti_indicator_sources.push({ indicator_id: id, tlp: 'red' });
    const staff = await search('shared-evil');
    assert.deepEqual(entity(staff.data, 'ti_indicator').map((r) => r.title), ['shared-evil.example.test'], 'staff (ceiling red) sees it');
    const exec = await search('shared-evil', tok('executive'));
    assert.deepEqual(entity(exec.data, 'ti_indicator'), [], 'executive (ceiling amber) does not');
});

test('advisories merge the legacy table and ti_reports; ti_reports respects TLP against the viewer\'s own ceiling', async () => {
    db.tables.nigeria_advisories.push({ id: randomUUID(), title: 'Shared banking trojan campaign', severity: 'high', source: 'ngCERT', published_at: new Date().toISOString() });
    db.tables.ti_reports.push(
        { id: randomUUID(), title: 'Shared campaign targets Nigerian banks', threat_level: 'high', tlp: 'clear', feed_id: 'misp', published_at: new Date().toISOString() },
        { id: randomUUID(), title: 'Shared campaign — restricted internal note', threat_level: 'high', tlp: 'red', feed_id: 'misp', published_at: new Date().toISOString() },
    );
    // Staff's ceiling is 'red' (full access) — they see every marking, including this RED report.
    const staff = await search('Shared');
    const titles = entity(staff.data, 'advisory').map((r) => r.title);
    assert.ok(titles.includes('Shared banking trojan campaign'));
    assert.ok(titles.includes('Shared campaign targets Nigerian banks'));
    assert.ok(titles.includes('Shared campaign — restricted internal note'), 'staff may see RED');
    // A client role's ceiling is 'amber' — the RED report is excluded for them, nothing else is.
    const exec = await search('Shared', tok('executive'));
    const execTitles = entity(exec.data, 'advisory').map((r) => r.title);
    assert.ok(execTitles.includes('Shared banking trojan campaign'));
    assert.ok(execTitles.includes('Shared campaign targets Nigerian banks'));
    assert.ok(!execTitles.includes('Shared campaign — restricted internal note'), 'RED stays out for a client-ceiling viewer');
});

test('threat actors: curated reference data, matched by name or alias, no database involved', async () => {
    const r = await search('silverterrier');
    assert.ok(entity(r.data, 'threat_actor').some((x) => x.title === 'SilverTerrier'));
});

test('CNII organisations: cnii:sector only (an analyst has it; a search with no matching profile returns nothing, not an error)', async () => {
    db.tables.cnii_org_profiles.push({ org_id: A, sector_id: 'finance', designation: 'designated' });
    const r = await search('Org A');
    assert.deepEqual(entity(r.data, 'cnii_org').map((x) => x.title), ['Org A']);
    const none = await search('Org B'); // org-b has no cnii_org_profiles row
    assert.deepEqual(entity(none.data, 'cnii_org'), []);
});

test('a source that fails to answer is reported in `sources` with its error, never folded into zero results silently', async () => {
    db.tables.ioc_enrichments = null as unknown as Row[]; // simulate the table missing (PGRST205)
    const r = await search('shared');
    assert.equal(r.status, 200, 'other sources still answer');
    const bySource: Record<string, { ok: boolean; error?: string }> = {};
    for (const s of r.data.sources as { entity: string; ok: boolean; error?: string }[]) bySource[s.entity] = s;
    assert.equal(bySource.ioc.ok, false);
    assert.match(bySource.ioc.error!, /schema cache|ioc_enrichments/i);
    // The second 'alert' provider (the Wazuh indexer, not the stored table) also fails here
    // because no indexer is configured in this test — itself a second, independent example of
    // a reported failure, not silence. Everything else — including the FIRST 'alert' provider,
    // the stored table, which has nothing to do with either broken source — still answers ok.
    assert.equal(bySource.case.ok, true);
    assert.equal(bySource.vms_asset.ok, true);
    assert.equal(bySource.cnii_org.ok, true);
    assert.ok(r.data.sources.filter((s: { entity: string }) => s.entity === 'alert').some((s: { ok: boolean }) => s.ok === true), 'the stored-alerts provider still answers');
    assert.ok(r.data.sources.filter((s: { entity: string }) => s.entity === 'alert').some((s: { ok: boolean }) => s.ok === false), 'the indexer-backed alert provider honestly fails (no indexer configured here)');
});
