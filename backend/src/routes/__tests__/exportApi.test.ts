// Phase X1 vendor export: GET /api/export/v1/events and /api/admin/export-clients, against the local
// fake PostgREST. The app sets `trust proxy` to 1 exactly as index.ts does, so X-Forwarded-For
// handling is tested the way it runs on Railway. All data here is synthetic.
process.env.JWT_SECRET = 'export-api-test-secret';
for (const k of ['EXPORT_API_ENABLED', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY']) delete process.env[k];

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID, createHash } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth, requireRole } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import exportApiRouter, { EXPORT_MAX_LIMIT } from '../exportApi';
import exportClientsRouter from '../exportClients';

const A = 'org-a';
const B = 'org-b';
const ALLOWED_IP = '203.0.113.5';   // TEST-NET-3, synthetic
const OTHER_IP = '198.51.100.7';    // TEST-NET-2, synthetic

let db: FakePostgrest;
let server: Server;
let base = '';
const tokens: string[] = [];
const logLines: string[] = [];
const realLog = { log: console.log, warn: console.warn, error: console.error };

const adminTok = (role = 'super_admin') => jwt.sign({ sub: randomUUID(), email: `${role}@x.test`, role, org_id: A }, process.env.JWT_SECRET!);

async function http(method: string, path: string, opts: { bearer?: string; body?: unknown; xff?: string } = {}) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (opts.bearer) headers.Authorization = `Bearer ${opts.bearer}`;
    if (opts.xff !== undefined) headers['X-Forwarded-For'] = opts.xff;
    const r = await fetch(`${base}${path}`, { method, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body) });
    const text = await r.text();
    let data: unknown = null;
    try { data = JSON.parse(text); } catch { /* ndjson */ }
    return { status: r.status, data: data as Record<string, unknown> & { events: Row[] }, text, type: r.headers.get('content-type') ?? '' };
}
const exportCall = (token: string, query = '', xff = ALLOWED_IP) => http('GET', `/api/export/v1/events${query}`, { bearer: token, xff });

async function createClient(body: Record<string, unknown>) {
    const r = await http('POST', '/api/admin/export-clients', { bearer: adminTok(), body });
    assert.equal(r.status, 201, JSON.stringify(r.data));
    const token = r.data.token as string;
    tokens.push(token);
    return { id: (r.data.client as Row).id as string, token };
}

let seq = 0;
function seedAlert(org: string, over: Partial<Row> = {}): Row {
    seq++;
    const row: Row = {
        id: randomUUID(), org_id: org, wazuh_alert_id: `w-${seq}`,
        event_time: `2026-10-09T08:${String(Math.floor(seq / 60) % 60).padStart(2, '0')}:${String(seq % 60).padStart(2, '0')}.000+00:00`,
        received_at: '2026-10-09T09:00:00+00:00', severity: 'high', status: 'new',
        rule_id: '5710', rule_level: 10, rule_description: 'sshd: authentication failed', agent_id: '001', agent_name: 'web-01', agent_ip: '10.0.0.5',
        mitre_ids: ['T1110'], location: '/var/log/auth.log', raw: { data: { srcip: '192.0.2.10' } }, raw_truncated: false, ...over,
    };
    db.tables.alerts.push(row);
    return row;
}

let clientA: { id: string; token: string };
let clientAB: { id: string; token: string };

before(async () => {
    db = await startFakePostgrest({
        organisations: [{ id: 'oa', slug: A }, { id: 'ob', slug: B }, { id: 'oc', slug: 'org-c' }, { id: 'od', slug: 'org-d' }],
        export_clients: [], export_access_log: [], alerts: [],
    }, {}, { export_clients: { enabled: true, redaction_profile: 'standard' } });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';

    for (const k of ['log', 'warn', 'error'] as const) console[k] = (...args: unknown[]) => { logLines.push(args.map(String).join(' ')); };

    const app = express();
    app.set('trust proxy', 1); // as index.ts
    app.use('/api/export/v1', exportApiRouter);
    app.use(express.json());
    app.use('/api/admin/export-clients', requireAuth, requireRole('super_admin'), exportClientsRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    clientA = await createClient({ name: 'Vendor A', org_ids: [A], allowed_cidrs: ['203.0.113.0/24'] });
    clientAB = await createClient({ name: 'Vendor AB', org_ids: [A, B], allowed_cidrs: [ALLOWED_IP], redaction_profile: 'no_raw' });
    for (let i = 0; i < 3; i++) seedAlert(A);
    for (let i = 0; i < 2; i++) seedAlert(B);
});
after(async () => {
    Object.assign(console, realLog);
    server.close();
    await db.close();
    delete process.env.EXPORT_API_ENABLED;
});

// ── Admin ─────────────────────────────────────────────────────────────────────────────────────

test('admin: super_admin only; inputs validated; org_ids must exist', async () => {
    const body = { name: 'x', org_ids: [A], allowed_cidrs: [ALLOWED_IP] };
    assert.equal((await http('POST', '/api/admin/export-clients', { body })).status, 401);
    for (const role of ['soc_manager', 'analyst', 'executive']) assert.equal((await http('POST', '/api/admin/export-clients', { bearer: adminTok(role), body })).status, 403, role);
    for (const bad of [
        { ...body, org_ids: [] }, { ...body, allowed_cidrs: [] }, { ...body, org_ids: ['org-nope'] },
        { ...body, allowed_cidrs: ['0.0.0.0/0'] }, { ...body, allowed_cidrs: ['10.0.0.0/33'] }, { ...body, allowed_cidrs: ['not-an-ip'] },
        { ...body, redaction_profile: 'everything' },
    ]) assert.equal((await http('POST', '/api/admin/export-clients', { bearer: adminTok(), body: bad })).status, 400, JSON.stringify(bad));
});

test('token shown once; only its SHA-256 is stored; list never returns hashes or tokens', async () => {
    const row = db.tables.export_clients.find((c) => c.id === clientA.id)!;
    assert.equal(row.token_hash, createHash('sha256').update(clientA.token).digest('hex'));
    assert.match(clientA.token, /^nsx_[A-Za-z0-9_-]{43}$/, '32 random bytes, base64url');
    for (const t of tokens) assert.ok(!JSON.stringify(db.tables.export_clients).includes(t), 'no plaintext token stored');
    const list = await http('GET', '/api/admin/export-clients', { bearer: adminTok() });
    assert.equal(list.status, 200);
    const text = JSON.stringify(list.data);
    assert.ok(!text.includes('token_hash') && !tokens.some((t) => text.includes(t)) && !text.includes(row.token_hash as string));
});

// ── Kill switch and authentication ────────────────────────────────────────────────────────────

test('global kill switch: anything but exactly "true" is 503', async () => {
    for (const v of [undefined, '', 'TRUE', '1', 'yes', 'true ']) {
        if (v === undefined) delete process.env.EXPORT_API_ENABLED; else process.env.EXPORT_API_ENABLED = v;
        assert.equal((await exportCall(clientA.token)).status, 503, String(v));
    }
    process.env.EXPORT_API_ENABLED = 'true';
    assert.equal((await exportCall(clientA.token)).status, 200);
});

test('token required: missing, malformed, wrong or user-JWT tokens get one generic 401', async () => {
    const bodies = new Set<string>();
    for (const r of [
        await http('GET', '/api/export/v1/events', { xff: ALLOWED_IP }),
        await exportCall('nsx_wrongwrongwrongwrongwrongwrongwrongwrongwro'),
        await exportCall(`${clientA.token}x`),
        await exportCall(adminTok()),
    ]) {
        assert.equal(r.status, 401);
        bodies.add(JSON.stringify(r.data));
    }
    assert.equal(bodies.size, 1, 'no hint about why');
});

test('disabled and rotated tokens are rejected; enable restores access', async () => {
    const c = await createClient({ name: 'Rotating', org_ids: [A], allowed_cidrs: [ALLOWED_IP] });
    assert.equal((await exportCall(c.token)).status, 200);
    assert.equal((await http('POST', `/api/admin/export-clients/${c.id}/disable`, { bearer: adminTok() })).status, 200);
    assert.equal((await exportCall(c.token)).status, 401);
    assert.ok(db.tables.export_access_log.some((l) => l.client_id === c.id && l.status_code === 401), 'refused call by an identifiable client is logged');
    await http('POST', `/api/admin/export-clients/${c.id}/enable`, { bearer: adminTok() });
    assert.equal((await exportCall(c.token)).status, 200);
    const rot = await http('POST', `/api/admin/export-clients/${c.id}/rotate`, { bearer: adminTok() });
    assert.equal(rot.status, 200);
    tokens.push(rot.data.token as string);
    assert.notEqual(rot.data.token, c.token);
    assert.equal((await exportCall(c.token)).status, 401, 'old token dies immediately');
    assert.equal((await exportCall(rot.data.token as string)).status, 200);
    assert.ok(db.tables.export_clients.find((x) => x.id === c.id)!.rotated_at);
});

// ── Source IP ─────────────────────────────────────────────────────────────────────────────────

test('IP allow-list: allowed, denied, spoof-prepended, undeterminable', async () => {
    assert.equal((await exportCall(clientA.token, '', '203.0.113.200')).status, 200, 'inside the /24');
    assert.equal((await exportCall(clientA.token, '', OTHER_IP)).status, 403);
    // A client can't prepend an allowed address: with one trusted hop the right-most entry wins.
    assert.equal((await exportCall(clientA.token, '', `${ALLOWED_IP}, ${OTHER_IP}`)).status, 403);
    assert.equal((await exportCall(clientA.token, '', `${OTHER_IP}, ${ALLOWED_IP}`)).status, 200);
    assert.equal((await exportCall(clientA.token, '', 'not-an-ip')).status, 403, 'undeterminable -> fail closed');
    assert.equal((await exportCall(clientA.token, '', '')).status, 403, 'no header -> the proxy peer (127.0.0.1), not allowed');
    assert.equal((await exportCall(clientA.token, '', '::ffff:203.0.113.9')).status, 200, 'IPv4-mapped IPv6 is normalised');
    const denied = db.tables.export_access_log.filter((l) => l.client_id === clientA.id && l.status_code === 403);
    assert.ok(denied.some((l) => l.source_ip === OTHER_IP));
});

// ── Org scope ─────────────────────────────────────────────────────────────────────────────────

test('cross-org isolation: client for org A never sees org B; org outside scope is 403', async () => {
    const r = await exportCall(clientA.token, '?limit=1000');
    assert.equal(r.status, 200);
    assert.ok(r.data.events.length > 0 && r.data.events.every((e) => e.org_id === A));
    assert.equal((await exportCall(clientA.token, `?org=${B}`)).status, 403);
    assert.equal((await exportCall(clientA.token, `?org=${A},${B}`)).status, 403);
    assert.equal((await exportCall(clientA.token, '?org=')).status, 403);
    const both = await exportCall(clientAB.token, '?limit=1000');
    assert.deepEqual(new Set(both.data.events.map((e) => e.org_id)), new Set([A, B]));
    const narrowed = await exportCall(clientAB.token, `?org=${B}&limit=1000`);
    assert.ok(narrowed.data.events.length > 0 && narrowed.data.events.every((e) => e.org_id === B));
});

// ── Parameters ────────────────────────────────────────────────────────────────────────────────

test('only cursor, limit, format, org — once each; malformed values 400', async () => {
    for (const q of ['?q=x', '?filter=severity:high', '?limit=1&limit=2', '?org[x]=a', '?limit=0', '?limit=-5', '?limit=ten', '?format=xml', '?cursor=@@@', '?cursor=' + Buffer.from('{"t":"x","id":"y"}').toString('base64url'), '?cursor=' + Buffer.from('not json').toString('base64url')]) {
        assert.equal((await exportCall(clientA.token, q)).status, 400, q);
    }
});

test('limit: default 500, capped at 1000', async () => {
    for (let i = 0; i < 1003; i++) seedAlert('org-d');
    const c = await createClient({ name: 'Bulk', org_ids: ['org-d'], allowed_cidrs: [ALLOWED_IP] });
    const dflt = await exportCall(c.token);
    assert.equal(dflt.data.events.length, 500);
    assert.equal(dflt.data.has_more, true);
    const big = await exportCall(c.token, '?limit=5000');
    assert.equal(big.data.events.length, EXPORT_MAX_LIMIT);
    assert.equal(big.data.has_more, true);
    const rest = await exportCall(c.token, `?limit=1000&cursor=${big.data.next_cursor}`);
    assert.equal(rest.data.events.length, 3);
    assert.equal(rest.data.has_more, false);
});

test('cursor stability: identical timestamps are neither skipped nor repeated; end of data', async () => {
    const t = '2026-10-09T12:00:00.000+00:00';
    const seeded = Array.from({ length: 7 }, () => seedAlert('org-c', { event_time: t }));
    seedAlert('org-c', { event_time: '2026-10-09T11:59:59.000+00:00' });
    seedAlert('org-c', { event_time: '2026-10-09T12:00:01.000+00:00' });
    const c = await createClient({ name: 'Pager', org_ids: ['org-c'], allowed_cidrs: [ALLOWED_IP] });

    const seen: Row[] = [];
    let cursor: string | null = null;
    const pages: boolean[] = [];
    for (let i = 0; i < 10; i++) {
        const r = await exportCall(c.token, `?limit=2${cursor ? `&cursor=${cursor}` : ''}`);
        assert.equal(r.status, 200);
        seen.push(...r.data.events);
        pages.push(r.data.has_more as boolean);
        cursor = r.data.next_cursor as string;
        if (!r.data.has_more) break;
    }
    assert.equal(seen.length, 9);
    assert.equal(new Set(seen.map((e) => e.id)).size, 9, 'no duplicates');
    const sameTs = seen.filter((e) => e.event_time === t).map((e) => e.id as string);
    assert.deepEqual(sameTs, seeded.map((s) => s.id as string).sort(), 'all 7 same-timestamp rows, ordered by id');
    assert.equal(pages.at(-1), false);
    const after = await exportCall(c.token, `?limit=2&cursor=${cursor}`);
    assert.deepEqual(after.data.events, []);
    assert.equal(after.data.has_more, false);
    assert.equal(after.data.next_cursor, cursor, 'cursor stays put at the end, so polling resumes there');
});

test('ndjson: one event per line and a final line with next_cursor', async () => {
    const r = await exportCall(clientA.token, '?format=ndjson&limit=2');
    assert.equal(r.status, 200);
    assert.match(r.type, /application\/x-ndjson/);
    const lines = r.text.trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(lines.length, 3);
    assert.ok(lines[0].id && lines[1].id);
    assert.deepEqual(Object.keys(lines[2]).sort(), ['has_more', 'next_cursor', 'schema_version']);
});

// ── Event content ─────────────────────────────────────────────────────────────────────────────

test('envelope and per-event shape', async () => {
    const r = await exportCall(clientA.token, '?limit=1');
    assert.equal(r.data.schema_version, '1');
    assert.deepEqual(Object.keys(r.data).sort(), ['events', 'has_more', 'next_cursor', 'schema_version']);
    const e = r.data.events[0];
    for (const k of ['id', 'org_id', 'event_time', 'received_at', 'severity', 'rule', 'agent', 'mitre_ids', 'location', 'network']) assert.ok(k in e, k);
    assert.deepEqual(Object.keys(e.rule as object).sort(), ['description', 'id', 'level']);
    assert.deepEqual(Object.keys(e.agent as object).sort(), ['id', 'ip', 'name']);
});

test('five-tuple from data.*, Sysmon fallback, nulls for missing or invalid', async () => {
    const c = await createClient({ name: 'Net', org_ids: ['org-n'].length ? [A] : [A], allowed_cidrs: [ALLOWED_IP] });
    const full = seedAlert(A, { event_time: '2026-10-10T00:00:01.000+00:00', raw: { data: { srcip: '192.0.2.1', srcport: '51515', dstip: '198.51.100.2', dstport: 443, protocol: 'TCP' } } });
    const sysmon = seedAlert(A, { event_time: '2026-10-10T00:00:02.000+00:00', raw: { data: { win: { eventdata: { sourceIp: '10.1.1.1', sourcePort: '50000', destinationIp: '2001:db8::5', destinationPort: '3389', protocol: 'tcp' } } } } });
    const partial = seedAlert(A, { event_time: '2026-10-10T00:00:03.000+00:00', raw: { data: { srcip: '-', srcport: '99999', dstip: 'example.com', protocol: 'tcp; rm -rf /' } } });
    const noData = seedAlert(A, { event_time: '2026-10-10T00:00:04.000+00:00', raw: { full_log: 'x' } });
    const truncated = seedAlert(A, { event_time: '2026-10-10T00:00:05.000+00:00', raw: { truncated: true, preview: '{"data":{"srcip":"1.2.3.4"' }, raw_truncated: true });
    const cursor = Buffer.from(JSON.stringify({ t: '2026-10-10T00:00:00.000+00:00', id: '00000000-0000-4000-8000-000000000000' })).toString('base64url');
    const r = await exportCall(c.token, `?cursor=${cursor}`);
    const byId = Object.fromEntries(r.data.events.map((e) => [e.id, e.network]));
    assert.deepEqual(byId[full.id as string], { src_ip: '192.0.2.1', src_port: 51515, dst_ip: '198.51.100.2', dst_port: 443, protocol: 'TCP' });
    assert.deepEqual(byId[sysmon.id as string], { src_ip: '10.1.1.1', src_port: 50000, dst_ip: '2001:db8::5', dst_port: 3389, protocol: 'tcp' });
    assert.deepEqual(byId[partial.id as string], { src_ip: null, src_port: null, dst_ip: null, dst_port: null, protocol: null });
    const empty = { src_ip: null, src_port: null, dst_ip: null, dst_port: null, protocol: null };
    assert.deepEqual(byId[noData.id as string], empty);
    assert.deepEqual(byId[truncated.id as string], empty);
});

test('raw only per profile, always redacted', async () => {
    const SECRET = 'synthetic-Secret-123';
    const row = seedAlert(A, { event_time: '2026-10-11T00:00:00.000+00:00', raw: { full_log: `login password=${SECRET} Authorization: Bearer ${SECRET}`, data: { api_key: SECRET } }, rule_description: `token=${SECRET}` });
    const cur = Buffer.from(JSON.stringify({ t: '2026-10-10T23:59:59.000+00:00', id: '00000000-0000-4000-8000-000000000000' })).toString('base64url');
    const std = await exportCall(clientA.token, `?cursor=${cur}`);
    const ev = std.data.events.find((e) => e.id === row.id)!;
    assert.ok(ev.raw, 'standard profile includes raw');
    assert.ok(!JSON.stringify(std.data).includes(SECRET), 'nothing secret leaves');
    const noRaw = await exportCall(clientAB.token, `?cursor=${cur}&org=${A}`);
    const ev2 = noRaw.data.events.find((e) => e.id === row.id)!;
    assert.ok(!('raw' in ev2), 'no_raw profile omits raw');
    assert.ok(!JSON.stringify(noRaw.data).includes(SECRET));
});

// ── Bookkeeping ───────────────────────────────────────────────────────────────────────────────

test('access log per call, no payloads; last_used_at updated', async () => {
    const before = db.tables.export_access_log.length;
    const r = await exportCall(clientA.token, '?limit=2');
    const entry = db.tables.export_access_log.at(-1)!;
    assert.equal(db.tables.export_access_log.length, before + 1);
    assert.equal(entry.client_id, clientA.id);
    assert.equal(entry.status_code, 200);
    assert.equal(entry.row_count, 2);
    assert.equal(entry.cursor_to, r.data.next_cursor);
    assert.deepEqual(entry.org_ids, [A]);
    assert.equal(entry.source_ip, ALLOWED_IP);
    for (const k of Object.keys(entry)) assert.ok(['id', 'created_at', 'client_id', 'at', 'source_ip', 'org_ids', 'row_count', 'cursor_from', 'cursor_to', 'status_code'].includes(k), k);
    assert.ok(db.tables.export_clients.find((c) => c.id === clientA.id)!.last_used_at);
});

test('no token ever appears in logs, list responses or the access log', () => {
    const everything = [...logLines, JSON.stringify(db.tables.export_access_log)].join('\n');
    for (const t of tokens) {
        assert.ok(!everything.includes(t), 'token leaked');
        assert.ok(!everything.includes(t.slice(4, 20)), 'token fragment leaked');
    }
});
