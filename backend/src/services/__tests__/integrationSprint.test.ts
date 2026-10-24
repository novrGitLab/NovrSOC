// Phase P26 integration sprint: incremental, paged, read-only MISP ingestion (window, pages,
// truncation, idempotency, metadata, retries, Cloudflare tunnel/Access answers, concurrency, the
// manager's one-time backfill); private intelligence in IOC enrichment (none for anonymous callers,
// marking ceilings, stored intelligence); TI context in SecOps AI with markings and tenant
// isolation; AI provider failure; and the VMS fixes (stale jobs without a heartbeat, races, and
// verification on multi-target jobs).
// MISP answers are FIXTURES shaped like MISP 2.5 restSearch JSON — not live data. A fake
// PostgREST stands in for Supabase; nothing leaves the process.
process.env.JWT_SECRET = 'integration-sprint-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'MISP_URL', 'MISP_API_KEY', 'MISP_CA_CERT', 'MISP_CF_ACCESS_CLIENT_ID', 'MISP_CF_ACCESS_CLIENT_SECRET', 'MISP_PAGE_SIZE', 'MISP_MAX_PAGES', 'MISP_BACKFILL_DAYS', 'MISP_PAGE_DELAY_MS', 'MISP_MAX_ATTEMPTS', 'NVIDIA_API_KEY', 'AI_PROVIDER', 'TI_AI_PROVIDER', 'MISP_WRITE_ENABLED']) delete process.env[k];
process.env.MISP_PAGE_DELAY_MS = '0';

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest, type Row } from '../../routes/__tests__/fakePostgrest';
import threatInfoRouter from '../../routes/threatInfo';
import { runFeed, FEEDS, mispWindowStart } from '../threatInfo';
import { REPORT_FEEDS } from '../tiReports';
import { setMispFetchForTests, setMispRetryScaleForTests, isReadOnlyMispCall, mispAnswerProblem, searchMISP, getMISPCapabilities } from '../misp';
import { enrichIOC, storedIntel } from '../iocEnrichment';
import { tiContextFor, secopsAiTlpCeiling } from '../tiAiContext';
import { aiPurpose } from '../aiPurposes';
import { generate, setAiClientForTests } from '../ai';
import { runVmsMaintenance } from '../../jobs/vmsMaintenance';
import { verificationReach } from '../vmsFindings';

const A = 'org-a';
const B = 'org-b';
const KEY = 'k'.repeat(40);
let db: FakePostgrest;
let server: Server;
let base = '';
const realFetch = globalThis.fetch;
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = A) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const MGR = tok('soc_manager');
const AN = tok('analyst');
async function api(method: string, path: string, bearer: string, body?: unknown) {
    const r = await realFetch(`${base}${path}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) as Record<string, unknown> };
}

// ── A fake MISP (fixtures in MISP 2.5 restSearch shape) ───────────────────────────────────────
interface Call { url: string; method: string; headers: Record<string, string>; body: Record<string, unknown> }
const calls: Call[] = [];
let mispHandler: (c: Call) => Response = () => new Response('{}', { status: 500 });
const json = (body: unknown, status = 200, headers: Record<string, string> = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json; charset=UTF-8', ...headers } });
const attr = (i: number, over: Record<string, unknown> = {}) => ({
    id: String(1000 + i), event_id: '42', object_id: '0', object_relation: null, category: 'Network activity', type: 'ip-dst', to_ids: true,
    uuid: `5f1c0000-0000-4000-8000-${String(i).padStart(12, '0')}`, timestamp: '1761300000', distribution: '5', sharing_group_id: '0',
    comment: `fixture C2 ${i}`, deleted: false, disable_correlation: false, first_seen: null, last_seen: null, value: `198.51.100.${i % 250}`,
    Event: { org_id: '1', distribution: '3', id: '42', info: 'Fixture: C2 infrastructure (shared)', orgc_id: '2', uuid: 'ev-uuid-42', Orgc: { id: '2', name: 'Partner CERT' }, threat_level_id: '2', analysis: '2' },
    Tag: [{ id: '3', name: 'tlp:green' }, { id: '9', name: 'admiralty-scale:information-credibility="2"' }], ...over,
});

before(async () => {
    db = await startFakePostgrest({
        ti_feeds: [], ti_feed_runs: [], ti_indicators: [], ti_indicator_sources: [], ti_reports: [], ti_matches: [], ti_indicator_geo: [],
        vms_scan_jobs: [], vms_scopes: [], vms_findings: [], vms_finding_events: [], ai_requests: [], ai_artifacts: [],
        alerts: [], cases: [], case_notes: [], case_tasks: [], case_timeline: [], soar_log: [], response_approvals: [],
    }, { 'ti_indicator_sources.ti_feeds': 'feed_id', 'vms_scan_jobs.vms_scopes': 'scope_id' }, {
        ti_indicators: { status: 'active', tags: [], malware_families: [], threat_types: [], mitre_techniques: [], source_count: 0 } as Row,
        ti_reports: { tags: [], target_countries: [], target_sectors: [], actors: [], malware: [], attack_patterns: [] } as Row,
    });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test';
    // Route: the fake database keeps the real fetch; MISP goes to the fake; nothing else leaves.
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
        const url = String(input instanceof Request ? input.url : input);
        if (url.startsWith(db.url) || url.startsWith(base)) return realFetch(input, init);
        return new Response('{}', { status: 503 });
    }) as typeof fetch;
    setMispFetchForTests((async (input: string | URL | Request, init?: RequestInit) => {
        const c: Call = { url: String(input), method: init?.method ?? 'GET', headers: (init?.headers ?? {}) as Record<string, string>, body: init?.body ? JSON.parse(String(init.body)) : {} };
        calls.push(c);
        return mispHandler(c);
    }) as typeof fetch);
    setMispRetryScaleForTests(0.001);
    const app = express();
    app.use(express.json());
    app.use('/api/ti', requireAuth, threatInfoRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); globalThis.fetch = realFetch; setMispFetchForTests(null); setAiClientForTests(null); server.close(); await db.close(); });
beforeEach(() => {
    calls.length = 0;
    process.env.MISP_URL = 'https://misp.example.test';
    process.env.MISP_API_KEY = KEY;
    for (const t of ['ti_feeds', 'ti_feed_runs', 'ti_indicators', 'ti_indicator_sources', 'ti_reports']) db.tables[t].length = 0;
    db.tables.ti_feeds.push({ id: 'misp', name: 'MISP', url: 'x', enabled: true, validity_days: 30, last_success_at: null }, { id: 'misp_events', name: 'MISP events', url: 'x', enabled: true, validity_days: null, last_success_at: null });
});

// ── A. Ingestion ──────────────────────────────────────────────────────────────────────────────
test('MISP window: incremental from the last success minus an hour; first run and backfill bounded', () => {
    const now = Date.parse('2026-10-30T12:00:00Z');
    assert.deepEqual(mispWindowStart({ since: '2026-10-30T06:00:00Z' }, now), { from: Date.parse('2026-10-30T05:00:00Z') / 1000, mode: 'incremental' });
    assert.deepEqual(mispWindowStart({ since: null }, now), { from: (now - 7 * 86_400_000) / 1000, mode: 'backfill' });
    assert.equal(mispWindowStart({ since: '2026-10-30T06:00:00Z', backfillDays: 500 }, now).from, (now - 90 * 86_400_000) / 1000, 'a manager backfill is capped at 90 days');
});

test('MISP ingestion: paged until a short page, read-only searches with the incremental window, metadata and markings kept', async () => {
    process.env.MISP_PAGE_SIZE = '50';
    mispHandler = (c) => {
        const page = Number(c.body.page);
        const n = page < 3 ? 50 : 7;
        return json({ response: { Attribute: Array.from({ length: n }, (_, i) => attr((page - 1) * 50 + i)) } });
    };
    try {
        const r = await runFeed('misp');
        assert.equal(r.status, 'ok', r.error);
        assert.deepEqual(calls.map((c) => [c.method, new URL(c.url).pathname, c.body.page]), [['POST', '/attributes/restSearch', 1], ['POST', '/attributes/restSearch', 2], ['POST', '/attributes/restSearch', 3]]);
        const b = calls[0].body;
        assert.equal(b.deleted, false); assert.equal(b.enforceWarninglist, true); assert.equal(b.includeEventTags, true); assert.equal(b.to_ids, true); assert.equal(b.limit, 50);
        assert.ok(Math.abs(Number(b.timestamp) - (Date.now() - 7 * 86_400_000) / 1000) < 120, 'first run reads the 7-day backfill window');
        assert.equal(b.last, undefined, 'no publish-time window: attributes changed in older events are read too');
        assert.equal(calls[0].headers.Authorization, KEY);
        assert.deepEqual([r.counts!.fetched, r.counts!.new], [107, 107]);
        assert.deepEqual(r.meta, { mode: 'backfill', window_from: r.meta!.window_from, pages: 3, truncated: false });
        const src = db.tables.ti_indicator_sources[0];
        assert.deepEqual([src.tlp, src.distribution], ['green', 3], 'event TLP tag and the inherited distribution');
        const ctx = src.context as Record<string, unknown>;
        assert.deepEqual([ctx.event_org, ctx.category, ctx.to_ids, ctx.event_threat_level, ctx.event_analysis, ctx.misp_type], ['Partner CERT', 'Network activity', true, 'medium', 'completed', 'ip-dst']);
        assert.deepEqual(ctx.confidence_tags, ['admiralty-scale:information-credibility="2"'], 'confidence-style tags kept as labels');
        assert.equal(src.confidence, null, 'no confidence is invented');
        const feed = db.tables.ti_feeds.find((f) => f.id === 'misp')!;
        assert.equal((feed.last_counts as Record<string, unknown>).pages, 3);
        assert.ok(Date.parse(String(feed.last_success_at)) <= Date.parse(String(feed.last_run_at)), 'last_success_at is the start of the run');
        assert.ok(calls.every((c) => isReadOnlyMispCall(c.method, new URL(c.url).pathname)), 'only read-only calls were sent');
    } finally { delete process.env.MISP_PAGE_SIZE; }
});

test('MISP ingestion is idempotent and incremental: the same pages again add nothing; the next run starts from the last success', async () => {
    process.env.MISP_PAGE_SIZE = '50';
    mispHandler = () => json({ response: { Attribute: [attr(1), attr(2), attr(2)] } });
    try {
        const first = await runFeed('misp');
        assert.deepEqual([first.counts!.new, first.counts!.duplicates], [2, 1]);
        const rows = db.tables.ti_indicators.length;
        const sources = db.tables.ti_indicator_sources.length;
        calls.length = 0;
        const second = await runFeed('misp');
        assert.deepEqual([second.counts!.new, second.counts!.updated], [0, 2]);
        assert.deepEqual([db.tables.ti_indicators.length, db.tables.ti_indicator_sources.length], [rows, sources]);
        const since = Date.parse(String(db.tables.ti_feeds.find((f) => f.id === 'misp')!.last_success_at));
        assert.ok(Math.abs(Number(calls[0].body.timestamp) * 1000 - (since - 3_600_000)) < 120_000 || second.meta?.mode === 'incremental');
        assert.equal(second.meta?.mode, 'incremental');
    } finally { delete process.env.MISP_PAGE_SIZE; }
});

test('MISP ingestion at the page limit stores what it read and reports the run as truncated', async () => {
    process.env.MISP_PAGE_SIZE = '50'; process.env.MISP_MAX_PAGES = '2';
    mispHandler = (c) => json({ response: { Attribute: Array.from({ length: 50 }, (_, i) => attr((Number(c.body.page) - 1) * 50 + i)) } });
    try {
        const r = await runFeed('misp');
        assert.equal(r.status, 'ok');
        assert.equal(calls.length, 2);
        assert.equal(r.meta?.truncated, true);
        const feed = db.tables.ti_feeds.find((f) => f.id === 'misp')!;
        assert.equal((feed.last_counts as Record<string, unknown>).truncated, true);
        assert.equal(feed.last_success_at, null, 'the sync window is not advanced past unread attributes');
        assert.match(String(feed.last_error), /page limit.*not advanced/);
    } finally { delete process.env.MISP_PAGE_SIZE; delete process.env.MISP_MAX_PAGES; }
});

test('MISP event reports use the same incremental, paged window', async () => {
    mispHandler = () => json({ response: [{ Event: { id: '7', uuid: 'ev-7', info: 'Fixture report', date: '2026-10-28', timestamp: '1761300000', distribution: '3', Tag: [{ name: 'tlp:clear' }, { name: 'misp-galaxy:target-information="Nigeria"' }] } }] });
    const r = await runFeed('misp_events');
    assert.equal(r.status, 'ok', r.error);
    assert.equal(new URL(calls[0].url).pathname, '/events/restSearch');
    assert.equal(calls[0].body.metadata, true);
    assert.ok(calls[0].body.timestamp);
    assert.deepEqual((db.tables.ti_reports[0].target_countries as string[]), ['NG']);
});

test('MISP connection: retries on tunnel/upstream errors, not on auth; Cloudflare answers explained; secrets never in messages', async () => {
    let n = 0;
    mispHandler = () => (++n === 1 ? new Response('<html>Bad gateway</html>', { status: 502, headers: { 'content-type': 'text/html' } }) : json({ response: { Attribute: [attr(1)] } }));
    assert.equal((await runFeed('misp')).status, 'ok', 'a transient 502 is retried');
    assert.equal(n, 2);

    n = 0;
    mispHandler = () => { n++; return json({ name: 'Authentication failed.' }, 403); };
    const auth = await runFeed('misp');
    assert.deepEqual([auth.status, n], ['failed', 1], 'an auth failure is not retried');
    assert.match(auth.error!, /refused the API key/);

    mispHandler = () => new Response('error code: 1033', { status: 530, headers: { 'content-type': 'text/plain' } });
    const tunnel = await runFeed('misp');
    assert.match(tunnel.error!, /Cloudflare Tunnel to MISP is down.*after 3 attempts/);

    mispHandler = () => new Response(null, { status: 302, headers: { location: 'https://team.cloudflareaccess.com/cdn-cgi/access/login/misp.example.test' } });
    assert.match((await runFeed('misp')).error!, /Cloudflare Access redirected.*MISP_CF_ACCESS_CLIENT_ID/);

    mispHandler = () => new Response('<html>login</html>', { status: 200, headers: { 'content-type': 'text/html' } });
    assert.match((await runFeed('misp')).error!, /instead of JSON/);

    for (const f of db.tables.ti_feeds) assert.ok(!JSON.stringify(f).includes(KEY), 'the API key is never stored with an error');
    for (const r of db.tables.ti_feed_runs) assert.ok(!JSON.stringify(r).includes(KEY));
});

test('MISP connection: Cloudflare Access service-token headers are sent when configured; writes are never sent', async () => {
    process.env.MISP_CF_ACCESS_CLIENT_ID = 'cf-id.access';
    process.env.MISP_CF_ACCESS_CLIENT_SECRET = 'cf-secret';
    mispHandler = (c) => (new URL(c.url).pathname === '/servers/getVersion' ? json({ version: '2.5.50' }) : new URL(c.url).pathname === '/users/view/me' ? json({ Role: { name: 'Read Only', perm_add: false, perm_modify: false } }) : json({ type: 'bundle', id: 'bundle--x', objects: [] }));
    try {
        const cap = await getMISPCapabilities();
        assert.deepEqual([cap.version, cap.key_can_write, cap.stix2_export], ['2.5.50', false, 'supported']);
        assert.ok(calls.every((c) => c.headers['CF-Access-Client-Id'] === 'cf-id.access' && c.headers['CF-Access-Client-Secret'] === 'cf-secret'));
        assert.equal(isReadOnlyMispCall('POST', '/events/add'), false);
        assert.equal(isReadOnlyMispCall('POST', '/attributes/add/1'), false);
        assert.equal(isReadOnlyMispCall('DELETE', '/attributes/delete/1'), false);
        assert.equal(isReadOnlyMispCall('POST', '/attributes/restSearch'), true);
    } finally { delete process.env.MISP_CF_ACCESS_CLIENT_ID; delete process.env.MISP_CF_ACCESS_CLIENT_SECRET; }
    assert.equal(mispAnswerProblem(new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })), null);
});

test('one-time trigger: managers only, one run at a time, backfill bounded to the MISP feeds', async () => {
    let release: () => void = () => undefined;
    mispHandler = () => json({ response: { Attribute: [attr(1)] } });
    assert.equal((await api('POST', '/api/ti/feeds/misp/run', AN, {})).status, 403);
    assert.equal((await api('POST', '/api/ti/feeds/misp/run', MGR, { backfill_days: 365 })).status, 400);
    assert.equal((await api('POST', '/api/ti/feeds/misp/run', MGR, { backfill_days: 'x' })).status, 400);
    db.tables.ti_feeds.push({ id: 'feodo', name: 'Feodo', url: 'x', enabled: true, validity_days: 30 });
    assert.equal((await api('POST', '/api/ti/feeds/feodo/run', MGR, { backfill_days: 5 })).status, 400, 'backfill is for MISP only');
    // A run in progress: the second request is refused, not run twice.
    const gate = new Promise<void>((r) => { release = r; });
    const slow = FEEDS.misp.fetch;
    FEEDS.misp.fetch = async (ctx) => { await gate; return slow(ctx); };
    try {
        const firstP = api('POST', '/api/ti/feeds/misp/run', MGR, { backfill_days: 30 });
        await new Promise((r) => setTimeout(r, 150));
        const second = await api('POST', '/api/ti/feeds/misp/run', MGR, {});
        assert.equal(second.status, 409);
        release();
        const first = await firstP;
        assert.equal(first.status, 200);
        assert.equal((first.data.meta as { mode: string }).mode, 'backfill');
        assert.ok(Math.abs(Number(calls.at(-1)!.body.timestamp) - (Date.now() - 30 * 86_400_000) / 1000) < 120);
    } finally { FEEDS.misp.fetch = slow; release(); }
    assert.ok(REPORT_FEEDS.misp_events);
});

// ── B/C. Enrichment, markings, AI ─────────────────────────────────────────────────────────────
async function seedIndicator() {
    db.tables.ti_indicators.push({ id: 'ind-1', type: 'ip', value: '203.0.113.45', status: 'active', last_seen: '2026-10-29T00:00:00Z', first_seen: '2026-10-20T00:00:00Z', source_count: 3 });
    db.tables.ti_indicator_sources.push(
        { id: 's-clear', indicator_id: 'ind-1', feed_id: 'feodo', source_ref: '203.0.113.45:443', tlp: 'clear', distribution: null, last_seen: '2026-10-29T00:00:00Z', context: { malware: 'QakBot', threat_type: 'botnet_cc' } },
        { id: 's-amber', indicator_id: 'ind-1', feed_id: 'misp', source_ref: 'u-amber', tlp: 'amber', distribution: 3, last_seen: '2026-10-29T00:00:00Z', context: { comment: 'AMBER partner context', category: 'Network activity' } },
        { id: 's-red', indicator_id: 'ind-1', feed_id: 'misp', source_ref: 'u-red', tlp: 'red', distribution: 0, last_seen: '2026-10-29T00:00:00Z', context: { comment: 'RED partner context' } },
    );
}

test('enrichment: anonymous callers consult no private intelligence (no MISP call, no stored records) — no oracle', async () => {
    await seedIndicator();
    mispHandler = () => json({ response: { Attribute: [attr(1, { value: '203.0.113.45' })] } });
    const r = await enrichIOC('203.0.113.45', 'ip', { viewerCeiling: 'none' });
    assert.equal(calls.length, 0, 'MISP was not asked');
    assert.equal(r.sources.misp, null);
    assert.equal(r.sources.ti_platform, null);
    assert.ok(!r.tags.includes('in-misp') && !r.tags.includes('in-platform-ti'));
});

test('enrichment: stored intelligence (MISP included) within the viewer\'s ceiling; live MISP filtered by TLP', async () => {
    await seedIndicator();
    const staff = await storedIntel('203.0.113.45', 'ip', 'red');
    assert.deepEqual(staff!.sources.map((s) => s.tlp).sort(), ['amber', 'clear', 'red']);
    const client = await storedIntel('203.0.113.45', 'ip', 'amber');
    assert.deepEqual([client!.sources.map((s) => s.tlp).sort(), client!.sources_hidden], [['amber', 'clear'], 1]);
    mispHandler = () => json({ response: { Attribute: [
        { ...attr(1, { value: '203.0.113.45' }), Tag: [{ name: 'tlp:red' }] },
        { ...attr(2, { value: '203.0.113.45' }), Tag: [{ name: 'tlp:green' }] },
        { ...attr(3, { value: '203.0.113.45' }), Tag: [] },
    ] } });
    const live = await searchMISP('203.0.113.45', { tlpCeiling: 'amber' });
    assert.equal(live!.count, 2, 'the RED attribute is left out for a client viewer; untagged counts as AMBER');
    assert.ok(!JSON.stringify(live).includes('Tag'));
    const full = await enrichIOC('203.0.113.45', 'ip', { viewerCeiling: 'red' });
    assert.ok(full.tags.includes('in-platform-ti'));
    assert.equal(full.sources.ti_platform!.indicator_id, 'ind-1');
});

test('SecOps AI context: this organisation\'s TI matches only, and sources within the provider\'s ceiling', async () => {
    await seedIndicator();
    db.tables.ti_matches.push(
        { id: 'm-a', org_id: A, indicator_id: 'ind-1', entity_type: 'alert', entity_id: 'al-a', matched_field: 'data.srcip', status: 'new', first_matched_at: '2026-10-29T00:00:00Z' },
        { id: 'm-b', org_id: B, indicator_id: 'ind-1', entity_type: 'alert', entity_id: 'al-a', matched_field: 'data.srcip', status: 'new', first_matched_at: '2026-10-29T00:00:00Z' },
    );
    assert.equal(secopsAiTlpCeiling(), 'green');
    const ctx = await tiContextFor(A, [{ type: 'alert', id: 'al-a' }]);
    const text = JSON.stringify(ctx.records);
    assert.deepEqual(ctx.records.filter((r) => r.kind === 'ti_match').map((r) => r.id), ['m-a'], 'org-b\'s match is not in org-a\'s context');
    assert.ok(text.includes('QakBot') && !text.includes('AMBER partner context') && !text.includes('RED partner context'), 'external provider: CLEAR/GREEN only');
    process.env.AI_PROVIDER = 'ollama';
    try {
        const internal = JSON.stringify((await tiContextFor(A, [{ type: 'alert', id: 'al-a' }])).records);
        assert.ok(internal.includes('AMBER partner context') && !internal.includes('RED partner context'), 'own model: AMBER yes, RED never');
    } finally { delete process.env.AI_PROVIDER; }
    // The alert summary carries the TI records and the attribution rule.
    db.tables.alerts.push({ id: 'al-a', org_id: A, rule_id: null, agent_id: null, rule_description: 'x', event_time: '2026-10-29T00:00:00Z', raw: {}, raw_truncated: false });
    const built = await aiPurpose('alert_summary')!.build(A, 'al-a');
    assert.ok(built!.records.some((r) => r.kind === 'ti_source_record'));
    assert.match(aiPurpose('alert_summary')!.task, /attribute them to that source/);
    assert.equal(await aiPurpose('alert_summary')!.build(B, 'al-a'), null, 'another organisation cannot load the alert at all');
});

test('AI provider down: a clear "unavailable" answer; threat intelligence keeps working', async () => {
    setAiClientForTests({ chat: { completions: { create: async () => { throw Object.assign(new Error('connect ECONNREFUSED'), { name: 'APIConnectionError' }); } } } } as never);
    try {
        const r = await generate({ purpose: 'investigation_summary', orgId: A, actor: 'a', subjectType: 'indicator', subjectId: 'ind-1', sourceRefs: [], records: [], task: 't', schema: aiPurpose('investigation_summary')!.schema });
        assert.equal(r.ok, false);
        assert.ok(!r.ok && r.unavailable);
        await seedIndicator();
        const list = await api('GET', '/api/ti/indicators?page_size=5', AN);
        assert.equal(list.status, 200, 'TI pages do not depend on the AI');
    } finally { setAiClientForTests(null); }
    const shape = aiPurpose('investigation_summary')!.schema.safeParse({ summary: 's', statements: [], related: [], next_steps: [], defensive_actions: [{ action: 'Block 203.0.113.45 at the firewall', rationale: 'Listed as C2', requires_approval: true, evidence_refs: [] }], open_questions: [], confidence: 'low' });
    assert.ok(shape.success, 'defensive actions carry requires_approval');
});

// ── D. VMS ────────────────────────────────────────────────────────────────────────────────────
test('VMS: a running job with no heartbeat at all is requeued once the claim is stale; a fresh heartbeat keeps its job', async () => {
    db.tables.vms_scan_jobs.length = 0;
    db.tables.vms_scopes.length = 0;
    db.tables.vms_scopes.push({ id: 'scope-1', status: 'active', expires_at: new Date(Date.now() + 86_400_000).toISOString() });
    const old = new Date(Date.now() - 60 * 60_000).toISOString();
    db.tables.vms_scan_jobs.push(
        { id: randomUUID(), scope_id: 'scope-1', status: 'running', attempts: 1, worker_id: 'w1', heartbeat_at: null, claimed_at: old, started_at: old },
        { id: randomUUID(), scope_id: 'scope-1', status: 'running', attempts: 1, worker_id: 'w1', heartbeat_at: null, claimed_at: null, started_at: old },
        { id: randomUUID(), scope_id: 'scope-1', status: 'running', attempts: 1, worker_id: 'w2', heartbeat_at: new Date().toISOString(), claimed_at: old, started_at: old },
        { id: randomUUID(), scope_id: 'scope-1', status: 'running', attempts: 2, worker_id: 'w3', heartbeat_at: old, claimed_at: old, started_at: old },
    );
    const r = await runVmsMaintenance();
    assert.deepEqual([r.requeued, r.failed], [2, 1]);
    assert.deepEqual(db.tables.vms_scan_jobs.map((j) => j.status), ['queued', 'queued', 'running', 'failed']);
    assert.equal(db.tables.vms_scan_jobs[0].started_at, null, 'a requeued job is not shown as started');
});

test('VMS verification: an unreachable or unreported target never verifies a finding; job-level "assessed" only for one target', () => {
    assert.equal(verificationReach({ outcome: 'assessed', target_outcomes: { 'a.test': { outcome: 'reachable_open' } } }, 'b.test', ['a.test', 'b.test']).reached, false);
    assert.equal(verificationReach({ outcome: 'assessed' }, 'b.test', ['a.test', 'b.test']).reached, false);
    assert.equal(verificationReach({ outcome: 'assessed' }, 'a.test', ['a.test']).reached, true);
    assert.equal(verificationReach({ outcome: 'unreachable', target_outcomes: { 'a.test': { outcome: 'unreachable' } } }, 'a.test', ['a.test']).reached, false);
    assert.equal(verificationReach({ target_outcomes: { 'a.test': { outcome: 'no_route' } } }, 'a.test').reached, false);
});
