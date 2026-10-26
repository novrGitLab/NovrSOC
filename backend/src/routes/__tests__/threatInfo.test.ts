// Phase P6 Threat Information System: normalisation, feed adapters, ingestion with provenance
// (new / updated / duplicate / invalid), failed runs recorded, expiry, correlation and tenant
// isolation, the /api/ti routes (permissions, verdicts, promotion without duplicates, KEV
// relevance). Fake PostgREST, injected fetchers, no network.
process.env.JWT_SECRET = 'threat-info-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'THREATFOX_API_KEY']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import threatInfoRouter from '../threatInfo';
import {
    normalizeIndicator, fromThreatFox, fromUrlhaus, fromFeodo, fromKev, runFeed, expireIndicators, correlateOrg, alertCandidates, relevantIntel, FEEDS, type SourceRecord,
} from '../../services/threatInfo';

const A = 'org-a';
const B = 'org-b';
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = A) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const MGR = tok('soc_manager');
const AN = tok('analyst');
const EXEC = tok('executive');
const PORTAL = tok('portal_user');
async function http(method: string, path: string, bearer?: string, body?: unknown) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const r = await fetch(`${base}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const FEED_ROWS = () => [
    { id: 'threatfox', name: 'ThreatFox', url: 'x', enabled: true, validity_days: 30 },
    { id: 'urlhaus', name: 'URLhaus', url: 'x', enabled: true, validity_days: 30 },
    { id: 'feodo', name: 'Feodo', url: 'x', enabled: true, validity_days: 30 },
    { id: 'cisa_kev', name: 'KEV', url: 'x', enabled: true, validity_days: null },
];
const rec = (over: Partial<SourceRecord>): SourceRecord => ({
    type: 'ip', value: '203.0.113.9', source_ref: 'r1', confidence: null, first_seen: null, last_seen: null, tags: [], malware: null, threat_type: null, context: {}, ...over,
});

before(async () => {
    let caseNo = 0;
    db = await startFakePostgrest(
        { ti_feeds: [], ti_feed_runs: [], ti_indicators: [], ti_indicator_sources: [], ti_matches: [], ti_feedback: [], ti_correlation_state: [], alerts: [], vms_assets: [], vms_findings: [], cases: [], case_timeline: [], cve_intel: [], audit_log: [] },
        { 'ti_matches.ti_indicators': 'indicator_id', 'ti_indicator_sources.ti_feeds': 'feed_id' },
        {
            ti_matches: { status: 'new', get first_matched_at() { return new Date().toISOString(); }, get last_matched_at() { return new Date().toISOString(); } } as Row,
            ti_feedback: { get at() { return new Date().toISOString(); } } as Row,
            cases: { status: 'open', get case_number() { return `CASE-${++caseNo}`; } } as Row,
        },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use(express.json());
    app.use('/api/ti', requireAuth, threatInfoRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => {
    for (const t of Object.keys(db.tables)) db.tables[t].length = 0;
    db.tables.ti_feeds.push(...FEED_ROWS());
});

// ── Normalisation and adapters ─────────────────────────────────────────────────────────────────
test('normalizeIndicator: canonical forms, invalid values rejected', () => {
    assert.equal(normalizeIndicator('domain', ' Evil.Example.COM. '), 'evil.example.com');
    assert.equal(normalizeIndicator('domain', 'not a domain'), null);
    assert.equal(normalizeIndicator('ip', '203.0.113.9'), '203.0.113.9');
    assert.equal(normalizeIndicator('ip', '999.1.1.1'), null);
    assert.equal(normalizeIndicator('ip', '2001:DB8::1'), '2001:db8::1');
    assert.equal(normalizeIndicator('sha256', 'A'.repeat(64)), 'a'.repeat(64));
    assert.equal(normalizeIndicator('md5', 'a'.repeat(31)), null);
    assert.equal(normalizeIndicator('cve', 'cve-2024-3400'), 'CVE-2024-3400');
    assert.equal(normalizeIndicator('url', 'javascript:alert(1)'), null);
    assert.equal(normalizeIndicator('url', 'http://bad.example/x.exe'), 'http://bad.example/x.exe');
});

test('ThreatFox adapter: strips the port, keeps the source confidence, techniques only from source tags', () => {
    const r = fromThreatFox({ query_status: 'ok', data: [
        { id: '1', ioc: '198.51.100.7:443', ioc_type: 'ip:port', confidence_level: 75, malware_printable: 'Cobalt Strike', threat_type: 'botnet_cc', tags: ['T1071', 'cs'], first_seen: '2026-10-14 10:00:00 UTC' },
        { id: '2', ioc: 'x', ioc_type: 'unknown_type' },
    ] });
    assert.equal(r.length, 1);
    assert.equal(r[0].value, '198.51.100.7');
    assert.equal(r[0].confidence, 75);
    assert.equal(r[0].malware, 'Cobalt Strike');
    assert.deepEqual(r[0].context.techniques, ['T1071']);
    assert.equal(r[0].first_seen, '2026-10-14T10:00:00.000Z');
    assert.deepEqual(fromThreatFox({ query_status: 'no_result' }), []);
    assert.throws(() => fromThreatFox({ query_status: 'unknown_auth_key' }), /unknown_auth_key/);
});

test('URLhaus, Feodo and KEV adapters; malformed responses throw', () => {
    const u = fromUrlhaus({ query_status: 'ok', urls: [{ id: 9, url: 'http://bad.example/a', threat: 'malware_download', tags: ['elf'], date_added: '2026-10-14 09:00:00 UTC' }] });
    assert.equal(u[0].type, 'url');
    assert.equal(u[0].confidence, null, 'URLhaus states no confidence, so none is recorded');
    assert.throws(() => fromUrlhaus({ query_status: 'error' }));
    const f = fromFeodo([{ ip_address: '192.0.2.5', port: 443, malware: 'QakBot', first_seen: '2026-10-01 00:00:00', last_online: '2026-10-14' }]);
    assert.equal(f[0].source_ref, '192.0.2.5:443');
    assert.equal(f[0].malware, 'QakBot');
    assert.throws(() => fromFeodo({ nope: true }));
    const k = fromKev({ vulnerabilities: [{ cveID: 'CVE-2024-3400', vendorProject: 'Palo Alto', product: 'PAN-OS', dateAdded: '2024-04-12', requiredAction: 'Apply', dueDate: '2024-04-19', knownRansomwareCampaignUse: 'Unknown' }] });
    assert.equal(k[0].value, 'CVE-2024-3400');
    assert.equal(k[0].context.vendor, 'Palo Alto');
});

test('THREATFOX_API_KEY missing: the feed fails with the reason, nothing pretended', async () => {
    await assert.rejects(() => FEEDS.threatfox.fetch(), /THREATFOX_API_KEY/);
    await assert.rejects(() => FEEDS.urlhaus.fetch(), /THREATFOX_API_KEY/);
});

// ── Ingestion ──────────────────────────────────────────────────────────────────────────────────
test('runFeed: counts new, duplicate and invalid records, keeps provenance, records the run', async () => {
    const r = await runFeed('feodo', async () => [
        rec({ source_ref: 'a', malware: 'QakBot' }),
        rec({ source_ref: 'a', malware: 'QakBot' }), // same source record twice
        rec({ value: 'not-an-ip', source_ref: 'b' }),
        rec({ value: '192.0.2.10', source_ref: 'c' }),
    ]);
    assert.equal(r.status, 'ok');
    assert.deepEqual(r.counts, { fetched: 4, new: 2, updated: 0, duplicates: 1, invalid: 1 });
    assert.equal(db.tables.ti_indicators.length, 2);
    assert.equal(db.tables.ti_indicator_sources.length, 2);
    const ind = db.tables.ti_indicators.find((i) => i.value === '203.0.113.9')!;
    assert.deepEqual(ind.malware_families, ['QakBot']);
    assert.equal(ind.max_confidence, null);
    assert.ok(ind.valid_until, 'a 30-day feed sets a validity');
    const run = db.tables.ti_feed_runs[0];
    assert.equal(run.status, 'ok');
    assert.equal(run.invalid, 1);
    assert.ok(db.tables.ti_feeds.find((f) => f.id === 'feodo')!.last_success_at);
});

test('a second source for the same indicator adds provenance and merges labels; validity never shrinks', async () => {
    await runFeed('feodo', async () => [rec({ source_ref: 'a', malware: 'QakBot', last_seen: new Date().toISOString() })]);
    const before = db.tables.ti_indicators[0].valid_until as string;
    await runFeed('threatfox', async () => [rec({ source_ref: 'tf-1', confidence: 50, malware: 'Emotet', last_seen: new Date(Date.now() - 10 * 86_400_000).toISOString() })]);
    const ind = db.tables.ti_indicators[0];
    assert.equal(db.tables.ti_indicators.length, 1);
    assert.equal(ind.source_count, 2);
    assert.deepEqual([...(ind.malware_families as string[])].sort(), ['Emotet', 'QakBot']);
    assert.equal(ind.max_confidence, 50);
    assert.ok(Date.parse(ind.valid_until as string) >= Date.parse(before));
    assert.equal(db.tables.ti_feed_runs.at(-1)!.updated, 1);
});

test('a failed fetch is recorded as a failed run with the reason and shown on the feed', async () => {
    const r = await runFeed('urlhaus', async () => { throw new Error('URLhaus: HTTP 503'); });
    assert.equal(r.status, 'failed');
    assert.equal(db.tables.ti_feed_runs[0].status, 'failed');
    assert.match(String(db.tables.ti_feed_runs[0].error), /503/);
    assert.match(String(db.tables.ti_feeds.find((f) => f.id === 'urlhaus')!.last_error), /503/);
    assert.equal(db.tables.ti_indicators.length, 0);
});

test('KEV feeds mark tracked CVEs in cve_intel; KEV indicators never expire', async () => {
    db.tables.cve_intel.push({ cve_id: 'CVE-2024-3400', kev: false }, { cve_id: 'CVE-2020-0001', kev: true });
    await runFeed('cisa_kev', async () => [rec({ type: 'cve', value: 'CVE-2024-3400', source_ref: 'CVE-2024-3400' })]);
    assert.equal(db.tables.cve_intel.find((c) => c.cve_id === 'CVE-2024-3400')!.kev, true);
    assert.equal(db.tables.cve_intel.find((c) => c.cve_id === 'CVE-2020-0001')!.kev, false);
    assert.equal(db.tables.ti_indicators[0].valid_until, null);
});

test('expireIndicators marks only indicators past their validity', async () => {
    db.tables.ti_indicators.push(
        { id: randomUUID(), type: 'ip', value: '192.0.2.1', status: 'active', valid_until: new Date(Date.now() - 1000).toISOString() },
        { id: randomUUID(), type: 'ip', value: '192.0.2.2', status: 'active', valid_until: new Date(Date.now() + 86_400_000).toISOString() },
        { id: randomUUID(), type: 'cve', value: 'CVE-2024-1', status: 'active', valid_until: null },
    );
    assert.equal(await expireIndicators(), 1);
    assert.deepEqual(db.tables.ti_indicators.map((i) => i.status), ['expired', 'active', 'active']);
});

// ── Correlation ────────────────────────────────────────────────────────────────────────────────
test('alertCandidates: addresses, names and hashes from known fields; truncated alerts skipped', () => {
    const c = alertCandidates({ id: 'a1', raw: { data: { srcip: '203.0.113.9', url: 'http://bad.example/a', win: { eventdata: { queryName: 'Evil.Example.com', hashes: `SHA256=${'B'.repeat(64)},MD5=${'c'.repeat(32)}` } } } } });
    assert.deepEqual(c.map((x) => `${x.type}:${x.value}`).sort(), [`domain:evil.example.com`, `ip:203.0.113.9`, `md5:${'c'.repeat(32)}`, `sha256:${'b'.repeat(64)}`, 'url:http://bad.example/a']);
    assert.deepEqual(alertCandidates({ id: 'a2', raw: { data: { srcip: '203.0.113.9' } }, raw_truncated: true }), []);
});

async function seedIndicator(value = '203.0.113.9', status = 'active') {
    const id = randomUUID();
    db.tables.ti_indicators.push({ id, type: 'ip', value, status, source_count: 1, malware_families: ['QakBot'], threat_types: ['botnet_cc'], tags: [], max_confidence: null, first_seen: new Date().toISOString(), last_seen: new Date().toISOString() });
    db.tables.ti_indicator_sources.push({ id: randomUUID(), indicator_id: id, feed_id: 'feodo', source_ref: `${value}:443`, context: {} });
    return id;
}

test('correlateOrg matches only this organisation\'s records, ignores expired indicators, and is idempotent', async () => {
    await seedIndicator('203.0.113.9');
    await seedIndicator('192.0.2.99', 'expired');
    const now = new Date().toISOString();
    db.tables.alerts.push(
        { id: 'al-a', org_id: A, received_at: now, raw: { data: { srcip: '203.0.113.9' } } },
        { id: 'al-a2', org_id: A, received_at: now, raw: { data: { srcip: '192.0.2.99' } } },
        { id: 'al-b', org_id: B, received_at: now, raw: { data: { srcip: '203.0.113.9' } } },
    );
    db.tables.vms_assets.push({ id: 'as-a', org_id: A, status: 'active', asset_type: 'host', value: 'www.a.test', ips: ['203.0.113.9'] });
    const r1 = await correlateOrg(A);
    assert.equal(r1.matches_new, 2, 'the alert and the asset');
    assert.ok(db.tables.ti_matches.every((m) => m.org_id === A));
    assert.ok(!db.tables.ti_matches.some((m) => m.entity_id === 'al-a2'), 'expired indicators do not match');
    const r2 = await correlateOrg(A);
    assert.equal(r2.matches_new, 0);
    assert.equal(r2.matches_seen, 1, 'the asset is seen again; the alert was already processed');
    assert.equal(db.tables.ti_matches.length, 2);
});

// ── API ────────────────────────────────────────────────────────────────────────────────────────
async function seedMatch(org = A) {
    const indicatorId = await seedIndicator();
    const id = randomUUID();
    db.tables.ti_matches.push({ id, org_id: org, indicator_id: indicatorId, entity_type: 'alert', entity_id: `al-${org}`, matched_field: 'data.srcip', matched_value: '203.0.113.9', status: 'new', last_matched_at: new Date().toISOString() });
    return { id, indicatorId };
}

test('permissions: no token 401, portal users 403, executives read only, feed runs for managers only', async () => {
    assert.equal((await http('GET', '/api/ti/overview')).status, 401);
    assert.equal((await http('GET', '/api/ti/overview', PORTAL)).status, 403);
    assert.equal((await http('GET', '/api/ti/overview', EXEC)).status, 200);
    const { indicatorId } = await seedMatch();
    assert.equal((await http('POST', `/api/ti/indicators/${indicatorId}/feedback`, EXEC, { verdict: 'suspicious' })).status, 403);
    assert.equal((await http('POST', '/api/ti/feeds/feodo/run', AN)).status, 403);
    assert.equal((await http('POST', '/api/ti/feeds/nope/run', MGR)).status, 404);
});

test('overview reports stale and failing feeds honestly', async () => {
    db.tables.ti_feeds[0].last_error = 'THREATFOX_API_KEY is not set';
    const r = await http('GET', '/api/ti/overview', AN);
    assert.equal(r.status, 200);
    const tf = r.data.feeds.find((f: Row) => f.id === 'threatfox');
    assert.equal(tf.failing, true);
    assert.equal(tf.stale, true, 'never succeeded = stale');
    assert.equal(r.data.indicators.active, 0);
});

test('indicator search by value or family; detail shows provenance and this org\'s matches only', async () => {
    const { indicatorId } = await seedMatch(A);
    await seedMatch(B);
    let r = await http('GET', '/api/ti/indicators?q=203.0.113.9', AN);
    assert.equal(r.status, 200);
    assert.ok(r.data.indicators.length >= 1);
    r = await http('GET', '/api/ti/indicators?q=QakBot', AN);
    assert.ok(r.data.indicators.length >= 1);
    assert.equal((await http('GET', '/api/ti/indicators?q=%27%3B%20drop', AN)).status, 400);
    r = await http('GET', `/api/ti/indicators/${indicatorId}`, AN);
    assert.equal(r.status, 200);
    assert.equal(r.data.sources.length, 1);
    assert.ok(r.data.matches.every((m: Row) => m.org_id === A));
});

test('verdicts: benign needs a reason; recorded per organisation and audited', async () => {
    const { indicatorId } = await seedMatch();
    assert.equal((await http('POST', `/api/ti/indicators/${indicatorId}/feedback`, AN, { verdict: 'benign' })).status, 400);
    const r = await http('POST', `/api/ti/indicators/${indicatorId}/feedback`, AN, { verdict: 'false_positive', note: 'Our own scanner' });
    assert.equal(r.status, 201);
    assert.equal(db.tables.ti_feedback[0].org_id, A);
    assert.equal(db.tables.ti_indicators.find((i) => i.id === indicatorId)!.status, 'active', 'a verdict never changes what the source said');
});

test('matches: tenant isolation, review, and promotion to a case without duplicates', async () => {
    const a = await seedMatch(A);
    const b = await seedMatch(B);
    let r = await http('GET', '/api/ti/matches', AN);
    assert.deepEqual(r.data.matches.map((m: Row) => m.id), [a.id]);
    assert.equal(r.data.matches[0].ti_indicators.value, '203.0.113.9');
    assert.equal((await http('PATCH', `/api/ti/matches/${b.id}`, AN, { status: 'reviewed' })).status, 404, 'another org\'s match');
    assert.equal((await http('POST', `/api/ti/matches/${b.id}/case`, AN)).status, 404);
    r = await http('POST', `/api/ti/matches/${a.id}/case`, AN);
    assert.equal(r.status, 201);
    const again = await http('POST', `/api/ti/matches/${a.id}/case`, AN);
    assert.equal(again.status, 200);
    assert.equal(again.data.case.id, r.data.case.id);
    assert.equal(db.tables.cases.length, 1);
    assert.equal(db.tables.cases[0].source, 'intel');
    assert.equal(db.tables.cases[0].org_id, A);
    assert.equal(db.tables.ti_matches.find((m) => m.id === a.id)!.status, 'promoted');
    assert.equal((await http('PATCH', `/api/ti/matches/${a.id}`, AN, { status: 'dismissed' })).status, 404, 'a promoted match is not dismissed');
});

test('KEV view shows this organisation\'s open findings for each new KEV entry only', async () => {
    db.tables.ti_indicators.push({ id: randomUUID(), type: 'cve', value: 'CVE-2024-3400', first_seen: new Date().toISOString(), status: 'active' });
    db.tables.vms_findings.push(
        { id: 'f-a', org_id: A, cve_ids: ['CVE-2024-3400'], asset_value: 'vpn.a.test', status: 'open' },
        { id: 'f-b', org_id: B, cve_ids: ['CVE-2024-3400'], asset_value: 'vpn.b.test', status: 'open' },
        { id: 'f-a2', org_id: A, cve_ids: ['CVE-2024-3400'], asset_value: 'old.a.test', status: 'verified' },
    );
    const r = await http('GET', '/api/ti/kev?days=30', AN);
    assert.equal(r.status, 200);
    assert.deepEqual(r.data.kev[0].your_open_findings, [{ id: 'f-a', asset: 'vpn.a.test' }]);
});

// ── Relevance & reporting (R3.3D) ─────────────────────────────────────────────────────────────
async function seedIndicatorFull(over: Partial<Row> = {}) {
    const id = randomUUID();
    db.tables.ti_indicators.push({ id, type: 'ip', value: '203.0.113.9', status: 'active', max_confidence: null, malware_families: [], threat_types: [], first_seen: new Date().toISOString(), last_seen: new Date().toISOString(), ...over });
    return id;
}
const daysAgo = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString();

test('relevantIntel: tiers reflect real evidence — verified+KEV+critical asset is critical, KEV on an exposed asset without verification is high, a fresh asset-only match is medium, an old alert mention is low', async () => {
    // Critical: verified (case-linked), matched a finding whose CVE is KEV, on a critical asset.
    const cveId = await seedIndicatorFull({ type: 'cve', value: 'CVE-2024-9999' });
    db.tables.ti_indicator_sources.push({ id: randomUUID(), indicator_id: cveId, feed_id: 'cisa_kev', source_ref: 'CVE-2024-9999' });
    db.tables.vms_assets.push({ id: 'asset-crit', org_id: A, value: 'vpn.a.test', criticality: 'critical' });
    db.tables.vms_findings.push({ id: 'finding-open', org_id: A, asset_id: 'asset-crit', asset_value: 'vpn.a.test', cve_ids: ['CVE-2024-9999'], status: 'open' });
    db.tables.ti_matches.push({ id: randomUUID(), org_id: A, indicator_id: cveId, entity_type: 'finding', entity_id: 'finding-open', matched_field: 'cve_ids', status: 'new', case_id: 'case-x', last_matched_at: daysAgo(1) });

    // High: KEV, exposed asset (another finding), but never verified.
    const cveId2 = await seedIndicatorFull({ type: 'cve', value: 'CVE-2024-8888' });
    db.tables.ti_indicator_sources.push({ id: randomUUID(), indicator_id: cveId2, feed_id: 'cisa_kev', source_ref: 'CVE-2024-8888' });
    db.tables.vms_assets.push({ id: 'asset-med', org_id: A, value: 'web.a.test', criticality: 'medium' });
    db.tables.vms_findings.push({ id: 'finding-open-2', org_id: A, asset_id: 'asset-med', asset_value: 'web.a.test', cve_ids: ['CVE-2024-8888'], status: 'acknowledged' });
    db.tables.ti_matches.push({ id: randomUUID(), org_id: A, indicator_id: cveId2, entity_type: 'finding', entity_id: 'finding-open-2', matched_field: 'cve_ids', status: 'new', case_id: null, last_matched_at: daysAgo(1) });

    // Medium: matched the asset inventory directly, no KEV, not critical, but fresh.
    const ipId = await seedIndicatorFull();
    db.tables.vms_assets.push({ id: 'asset-ip', org_id: A, value: 'ws-07', criticality: 'medium' });
    db.tables.ti_matches.push({ id: randomUUID(), org_id: A, indicator_id: ipId, entity_type: 'asset', entity_id: 'asset-ip', matched_field: 'ips', status: 'new', case_id: null, last_matched_at: daysAgo(1) });

    // Low: only an old alert mention — no exposed asset, not fresh, not verified.
    const ipId2 = await seedIndicatorFull({ value: '198.51.100.1' });
    db.tables.ti_matches.push({ id: randomUUID(), org_id: A, indicator_id: ipId2, entity_type: 'alert', entity_id: 'alert-old', matched_field: 'data.srcip', status: 'new', case_id: null, last_matched_at: daysAgo(30) });

    // Excluded: dismissed, expired indicator, and a finding that has since been resolved.
    const ipId3 = await seedIndicatorFull({ value: '198.51.100.2' });
    db.tables.ti_matches.push({ id: randomUUID(), org_id: A, indicator_id: ipId3, entity_type: 'alert', entity_id: 'alert-dismissed', matched_field: 'data.srcip', status: 'dismissed', case_id: null, last_matched_at: daysAgo(1) });
    const expiredId = await seedIndicatorFull({ value: '198.51.100.3', status: 'expired' });
    db.tables.ti_matches.push({ id: randomUUID(), org_id: A, indicator_id: expiredId, entity_type: 'alert', entity_id: 'alert-expired', matched_field: 'data.srcip', status: 'new', case_id: null, last_matched_at: daysAgo(1) });
    db.tables.vms_findings.push({ id: 'finding-resolved', org_id: A, asset_id: 'asset-crit', asset_value: 'vpn.a.test', cve_ids: ['CVE-2024-9999'], status: 'resolved' });
    db.tables.ti_matches.push({ id: randomUUID(), org_id: A, indicator_id: cveId, entity_type: 'finding', entity_id: 'finding-resolved', matched_field: 'cve_ids', status: 'new', case_id: null, last_matched_at: daysAgo(1) });

    // Another org's identical evidence must never appear in A's list.
    db.tables.vms_assets.push({ id: 'asset-b', org_id: B, value: 'vpn.b.test', criticality: 'critical' });
    db.tables.ti_matches.push({ id: randomUUID(), org_id: B, indicator_id: cveId, entity_type: 'asset', entity_id: 'asset-b', matched_field: 'ips', status: 'promoted', case_id: 'case-b', last_matched_at: daysAgo(1) });

    const r = await relevantIntel(A);
    assert.equal(r.items.length, 4, 'dismissed, expired-indicator and resolved-finding matches are excluded, and org B never appears');
    assert.deepEqual(r.items.map((i) => i.tier), ['critical', 'high', 'medium', 'low'], 'sorted most relevant first');
    assert.equal(r.by_tier.critical, 1); assert.equal(r.by_tier.high, 1); assert.equal(r.by_tier.medium, 1); assert.equal(r.by_tier.low, 1);
    const critical = r.items[0];
    assert.ok(critical.reasons.some((x) => /investigation/.test(x)));
    assert.ok(critical.reasons.some((x) => /Known Exploited/.test(x)));
    assert.equal(critical.asset_criticality, 'critical');
    assert.equal(critical.kev, true);
});

// Pre-merge check (R3.3D conditional approval, item 2): correlateOrg() re-stamps a match's
// last_matched_at on every 15-minute cycle for as long as the matched entity still exists — using
// it as the freshness signal would make a months-old indicator look "just seen" forever. Freshness
// must come from the indicator's own last_seen (when a source last actually reported it).
test('relevantIntel: freshness reflects the source\'s last_seen, not the correlation engine\'s re-stamped last_matched_at', async () => {
    const staleIndicator = await seedIndicatorFull({ last_seen: daysAgo(60) }); // a source last saw this 60 days ago
    db.tables.vms_assets.push({ id: 'asset-stale', org_id: A, value: 'ws-old', criticality: 'medium' });
    // The correlation engine re-confirmed this match five minutes ago — it is still "current" in
    // the sense that the asset still exists, but the underlying intelligence itself is stale.
    db.tables.ti_matches.push({ id: randomUUID(), org_id: A, indicator_id: staleIndicator, entity_type: 'asset', entity_id: 'asset-stale', matched_field: 'ips', status: 'new', case_id: null, last_matched_at: new Date().toISOString() });
    const r = await relevantIntel(A);
    assert.equal(r.items.length, 1);
    assert.equal(r.items[0].tier, 'low', 'exposed to a real asset but the source has not reported it in 60 days, and nothing else elevates it');
    assert.ok(!r.items[0].reasons.some((x) => /last 7 days/.test(x)));
});

// Missing confidence (no source ever stated one) must never be treated as high confidence, and
// must not crash the tier computation.
test('relevantIntel: a missing confidence value is never treated as high confidence', async () => {
    const indicatorId = await seedIndicatorFull({ max_confidence: null });
    db.tables.vms_assets.push({ id: 'asset-noconf', org_id: A, value: 'ws-09', criticality: 'low' });
    db.tables.ti_matches.push({ id: randomUUID(), org_id: A, indicator_id: indicatorId, entity_type: 'asset', entity_id: 'asset-noconf', matched_field: 'ips', status: 'new', case_id: null, last_matched_at: new Date().toISOString() });
    const r = await relevantIntel(A);
    assert.equal(r.items[0].confidence, null);
    assert.ok(!r.items[0].reasons.some((x) => /confidence/.test(x)));
    // Still medium: exposed to a real asset and the source reported it recently (seedIndicatorFull's default last_seen).
    assert.equal(r.items[0].tier, 'medium');
});

test('GET /api/ti/relevant: permissions and org scoping match /api/ti/overview', async () => {
    assert.equal((await http('GET', '/api/ti/relevant')).status, 401);
    assert.equal((await http('GET', '/api/ti/relevant', tok('portal_user'))).status, 403);
    const ipId = await seedIndicatorFull();
    db.tables.ti_matches.push({ id: randomUUID(), org_id: A, indicator_id: ipId, entity_type: 'alert', entity_id: 'al-1', matched_field: 'data.srcip', status: 'new', case_id: null, last_matched_at: new Date().toISOString() });
    const r = await http('GET', '/api/ti/relevant', EXEC);
    assert.equal(r.status, 200);
    assert.equal(r.data.items.length, 1);
    assert.equal(r.data.items[0].entity_id, 'al-1');
});

test('GET /api/ti/report: counts, KEV cross-reference and honest limitations', async () => {
    const cveId = await seedIndicatorFull({ type: 'cve', value: 'CVE-2024-7777', first_seen: new Date().toISOString() });
    db.tables.ti_indicator_sources.push({ id: randomUUID(), indicator_id: cveId, feed_id: 'cisa_kev', source_ref: 'CVE-2024-7777' });
    db.tables.vms_findings.push({ id: 'f-report', org_id: A, cve_ids: ['CVE-2024-7777'], asset_value: 'db.a.test', status: 'open' });
    db.tables.ti_matches.push({ id: randomUUID(), org_id: A, indicator_id: cveId, entity_type: 'finding', entity_id: 'f-report', matched_field: 'cve_ids', status: 'promoted', case_id: 'case-y', last_matched_at: new Date().toISOString() });
    db.tables.ti_feeds[0].last_error = 'THREATFOX_API_KEY is not set'; // threatfox: not configured in this test env anyway

    const r = await http('GET', '/api/ti/report?days=30', MGR);
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.equal(r.data.matches.verified, 1);
    assert.equal(r.data.kev.new_in_period, 1);
    assert.equal(r.data.kev.your_open_findings, 1);
    assert.equal(r.data.relevant.by_tier.critical, 1, 'verified + KEV + exposed finding');
    assert.ok(r.data.limitations.some((l: string) => /not proof of compromise/.test(l)));
    assert.ok(r.data.limitations.some((l: string) => /correlation engine/.test(l)), 'the engine has not run in this test process');
    assert.equal(r.data.engine.correlation_last_run_at, null);
});

// Pre-merge check (R3.3D conditional approval, item 1): /relevant and /report reuse
// hideRestrictedLabels — the same TLP gate /indicators already relies on — but neither route had
// ever actually been exercised against a restricted source before now.
test('TLP enforcement: /relevant and /report blank malware/threat labels from a source a client role may not see; staff see them', async () => {
    const indicator = { id: randomUUID(), type: 'domain', value: 'evil.example.com', status: 'active', max_confidence: 70, malware_families: ['Cobalt Strike'], threat_types: ['c2'], first_seen: new Date().toISOString(), last_seen: new Date().toISOString() };
    db.tables.ti_indicators.push(indicator);
    db.tables.ti_indicator_sources.push(
        { id: randomUUID(), indicator_id: indicator.id, feed_id: 'f', source_ref: 'r1', tlp: 'green' },
        { id: randomUUID(), indicator_id: indicator.id, feed_id: 'f', source_ref: 'r2', tlp: 'red' },
    );
    db.tables.ti_matches.push({ id: randomUUID(), org_id: A, indicator_id: indicator.id, entity_type: 'alert', entity_id: 'al-tlp', matched_field: 'data.srcip', status: 'new', case_id: null, last_matched_at: new Date().toISOString() });

    const asExec = await http('GET', '/api/ti/relevant', EXEC);
    assert.equal(asExec.status, 200);
    assert.equal(asExec.data.items.length, 1);
    assert.deepEqual(asExec.data.items[0].malware_families, [], 'a RED source exists — a client role (ceiling AMBER) never sees its labels');
    assert.deepEqual(asExec.data.items[0].threat_types, []);
    assert.equal(asExec.data.items[0].labels_hidden, true);
    assert.equal(asExec.data.items[0].indicator_value, 'evil.example.com', 'the bare indicator value itself is not treated as restricted, same as /indicators');

    const asStaff = await http('GET', '/api/ti/relevant', AN);
    assert.deepEqual(asStaff.data.items[0].malware_families, ['Cobalt Strike'], 'staff (ceiling RED) see everything');
    assert.ok(!asStaff.data.items[0].labels_hidden);

    const report = await http('GET', '/api/ti/report', EXEC);
    assert.equal(report.status, 200);
    assert.deepEqual(report.data.relevant.top[0].malware_families, [], '/report reuses the same gate for its relevant.top list');
    assert.equal(report.data.relevant.top[0].labels_hidden, true);
});
