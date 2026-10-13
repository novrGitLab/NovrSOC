// Phase X3: Stellar Cyber push — config, payload (5-tuple, original fields, security context,
// redaction, several Wazuh event types), delivery (auth, ordering, settle window, 413/400/422 →
// dead letters, 401/429/5xx/timeout → retried, rate budget, backfill window, dead-letter retry) and
// the super_admin status endpoint — against the local fake PostgREST and a local fake receiver.
// All data is synthetic; nothing is sent anywhere but 127.0.0.1.
process.env.JWT_SECRET = 'push-test-secret';
for (const k of ['EXPORT_SETTLE_SECONDS', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'STELLAR_PUSH_ENABLED', 'STELLAR_PUSH_URL', 'STELLAR_PUSH_API_KEY', 'STELLAR_PUSH_ORG_IDS']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'http';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import { startFakePostgrest, type FakePostgrest, type Row } from '../../routes/__tests__/fakePostgrest';
import { pushConfig, runPushOnce, backoffMs, parseRetryAfter, perTickBudget, DESTINATION, BACKOFF_MAX_MS, type PushConfig } from '../stellarPush';
import { toStellarEvent } from '../../lib/stellarEvent';
import type { AlertRowForExport } from '../../lib/exportEvent';
import { requireAuth, requireRole } from '../../middleware/auth';
import pushStatusRouter from '../../routes/pushStatus';

const A = 'org-a';
const B = 'org-b';
const KEY = 'test-push-key-not-real';
const SETTLED = '2026-01-01T00:00:00+00:00';

let db: FakePostgrest;
let receiver: http.Server;
let receiverUrl = '';
let api: http.Server;
let apiBase = '';
const received: { headers: http.IncomingHttpHeaders; body: Row }[] = [];
type Reply = number | { status: number; headers?: Record<string, string>; delayMs?: number };
let replies: Reply[] = []; // scripted responses, 200 once exhausted
const realLog = { log: console.log, warn: console.warn, error: console.error };

let seq = 0;
function seedAlert(org: string, over: Partial<Row> = {}): Row {
    seq++;
    const row: Row = {
        id: randomUUID(), org_id: org, wazuh_alert_id: `w-${seq}`, ingest_seq: seq,
        event_time: '2026-10-09T08:15:42.000+00:00', received_at: SETTLED, severity: 'high', status: 'new',
        rule_id: '5710', rule_level: 10, rule_description: 'sshd: authentication failed', agent_id: '001', agent_name: 'web-01', agent_ip: '10.0.0.5',
        mitre_ids: ['T1110'], location: '/var/log/auth.log', raw_truncated: false,
        raw: { data: { srcip: '192.0.2.10', srcport: '51515', dstip: '10.0.0.5', dstport: '22', protocol: 'TCP' } },
        ...over,
    };
    db.tables.alerts.push(row);
    return row;
}

const cfg = (over: Partial<PushConfig> = {}): PushConfig => ({
    url: receiverUrl, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${KEY}` },
    orgs: [A], profile: 'standard', start: { kind: 'latest' }, timeoutMs: 2_000, maxPerMin: 6_000, ...over,
});
const state = () => db.tables.push_state.find((r) => r.destination === DESTINATION);
const at = (lastSeq: number) => db.tables.push_state.push({ destination: DESTINATION, last_seq: lastSeq, sent_count: 0, skipped_count: 0, retry_count: 0 });
const tok = (role: string) => jwt.sign({ sub: randomUUID(), email: `${role}@x.test`, role, org_id: A }, process.env.JWT_SECRET!);

before(async () => {
    db = await startFakePostgrest(
        { alerts: [], push_state: [], push_dead_letters: [] }, {},
        { push_state: { sent_count: 0, skipped_count: 0, retry_count: 0 }, push_dead_letters: { attempts: 1, retry_requested: false, resolved_at: null } },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    receiver = http.createServer((req, res) => {
        let body = '';
        req.on('data', (c) => { body += c; });
        req.on('end', () => {
            received.push({ headers: req.headers, body: JSON.parse(body) });
            const r = replies.shift() ?? 200;
            const reply = typeof r === 'number' ? { status: r } : r;
            setTimeout(() => {
                if (res.destroyed) return;
                res.writeHead(reply.status, reply.headers ?? {});
                res.end('{}');
            }, reply.delayMs ?? 0);
        });
    });
    await new Promise<void>((r) => receiver.listen(0, '127.0.0.1', r));
    receiverUrl = `http://127.0.0.1:${(receiver.address() as AddressInfo).port}/webhook/t/x`;

    const app = express();
    app.use(express.json());
    app.use('/api/admin/push-status', requireAuth, requireRole('super_admin'), pushStatusRouter);
    api = app.listen(0);
    apiBase = `http://127.0.0.1:${(api.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => {
    Object.assign(console, realLog);
    receiver.closeAllConnections();
    receiver.close();
    api.close();
    await db.close();
});
beforeEach(() => {
    db.tables.alerts.length = 0;
    db.tables.push_state.length = 0;
    db.tables.push_dead_letters.length = 0;
    received.length = 0;
    replies = [];
});

// ── Config ────────────────────────────────────────────────────────────────────────────────────

const OK_ENV = { STELLAR_PUSH_ENABLED: 'true', STELLAR_PUSH_URL: 'https://poc.example.test/webhook/a/b', STELLAR_PUSH_API_KEY: KEY, STELLAR_PUSH_ORG_IDS: `${A}, ${B},${A}` };

test('config: off unless exactly "true"; every required value checked; key never in a reason', () => {
    for (const v of [undefined, '', 'TRUE', '1']) assert.ok('error' in pushConfig({ ...OK_ENV, STELLAR_PUSH_ENABLED: v }));
    for (const bad of [
        { STELLAR_PUSH_URL: 'http://poc.example.test/x' }, { STELLAR_PUSH_URL: 'nope' }, { STELLAR_PUSH_URL: undefined }, { STELLAR_PUSH_API_KEY: ' ' },
        { STELLAR_PUSH_ORG_IDS: ' , ' }, { STELLAR_PUSH_PROFILE: 'everything' }, { STELLAR_PUSH_START: 'yesterday' }, { STELLAR_PUSH_START: 'hours:0' },
        { STELLAR_PUSH_START: 'hours:9999' }, { STELLAR_PUSH_TIMEOUT_MS: '50' }, { STELLAR_PUSH_TIMEOUT_MS: 'abc' }, { STELLAR_PUSH_MAX_PER_MIN: '0' },
    ]) {
        const r = pushConfig({ ...OK_ENV, ...bad });
        assert.ok('error' in r, JSON.stringify(bad));
        assert.ok(!JSON.stringify(r).includes(KEY));
    }
    const c = pushConfig(OK_ENV);
    assert.ok(!('error' in c));
    assert.deepEqual(c.orgs, [A, B]);
    assert.equal(c.headers.Authorization, `Bearer ${KEY}`);
    assert.deepEqual([c.profile, c.start, c.timeoutMs, c.maxPerMin], ['standard', { kind: 'latest' }, 10_000, 600]);
    assert.equal(perTickBudget(c), 150, '600/min over a 15 s tick');
    const h = pushConfig({ ...OK_ENV, STELLAR_PUSH_START: 'hours:24', STELLAR_PUSH_TIMEOUT_MS: '5000', STELLAR_PUSH_MAX_PER_MIN: '60' });
    assert.ok(!('error' in h) && h.start.kind === 'hours' && h.start.hours === 24 && h.timeoutMs === 5000 && perTickBudget(h) === 15);
    const bare = pushConfig({ ...OK_ENV, STELLAR_PUSH_AUTH_HEADER: 'X-API-Key', STELLAR_PUSH_AUTH_SCHEME: 'none' });
    assert.ok(!('error' in bare) && bare.headers['X-API-Key'] === KEY && !('Authorization' in bare.headers));
});

test('backoff: exponential with jitter in [½, 1], capped at 10 min; Retry-After honoured and capped', () => {
    assert.equal(backoffMs(1, null, () => 0), 15_000);
    assert.equal(backoffMs(1, null, () => 1), 30_000);
    assert.equal(backoffMs(3, null, () => 1), 120_000);
    assert.equal(backoffMs(50, null, () => 1), BACKOFF_MAX_MS);
    for (let i = 0; i < 50; i++) { const b = backoffMs(2); assert.ok(b >= 30_000 && b <= 60_000); }
    assert.equal(backoffMs(1, 90_000, () => 0), 90_000);
    assert.equal(backoffMs(1, 10 * 3_600_000, () => 0), BACKOFF_MAX_MS);
    assert.equal(parseRetryAfter('120'), 120_000);
    assert.equal(parseRetryAfter(new Date(Date.now() + 5_000).toUTCString(), Date.now()) !== null, true);
    assert.equal(parseRetryAfter('soon'), null);
    assert.equal(parseRetryAfter(null), null);
});

// ── Payload ───────────────────────────────────────────────────────────────────────────────────

const row = (over: Partial<AlertRowForExport> = {}): AlertRowForExport => ({
    id: 'id-1', org_id: A, event_time: '2026-10-09T08:15:42.000+00:00', received_at: SETTLED, severity: 'high',
    rule_id: '5710', rule_level: 10, rule_description: 'sshd: authentication failed', agent_id: '001', agent_name: 'web-01', agent_ip: '10.0.0.5',
    mitre_ids: ['T1110'], location: '/var/log/auth.log', raw: null, raw_truncated: false, ...over,
});

test('payload: flat 5-tuple, nested network, and the original alert with its own field names', () => {
    const original = { rule: { id: '5710', level: 10 }, decoder: { name: 'sshd' }, data: { srcip: '192.0.2.10', srcport: '51515', dstip: '10.0.0.5', dstport: 22, protocol: 'TCP' }, predecoder: { hostname: 'web-01' } };
    const ev = toStellarEvent(row({ raw: original }), 'standard');
    assert.deepEqual([ev.event_id, ev.event_type, ev.tenant_ref, ev.source, ev.sensor], ['id-1', 'security.alert', A, 'NovrSOC', 'wazuh']);
    assert.deepEqual([ev.srcip, ev.dstip, ev.srcport, ev.dstport, ev.proto, ev.proto_num], ['192.0.2.10', '10.0.0.5', 51515, 22, 'tcp', 6]);
    assert.deepEqual(ev.network, { src_ip: '192.0.2.10', src_port: 51515, dst_ip: '10.0.0.5', dst_port: 22, protocol: 'TCP' });
    assert.deepEqual((ev as Record<string, unknown>).raw, original, 'original fields and names preserved untouched (nothing secret in it)');
    assert.equal((ev as Record<string, unknown>).raw_truncated, false);
    // Missing or malformed → null, never a default.
    const none = toStellarEvent(row({ raw: { data: { srcip: 'not-an-ip', srcport: '99999', protocol: 'tcp; drop' } } }), 'standard');
    assert.deepEqual([none.srcip, none.dstip, none.srcport, none.dstport, none.proto, none.proto_num], [null, null, null, null, null, null]);
    const noraw = toStellarEvent(row({ raw: null }), 'standard');
    assert.equal(noraw.srcip, null);
    assert.ok(!('raw' in noraw));
});

test('payload: event types — firewall syslog, Sysmon network/process, file integrity, Windows logon', () => {
    const fw = toStellarEvent(row({ raw: { decoder: { name: 'iptables' }, rule: { groups: ['firewall', 'iptables'] }, data: { srcip: '203.0.113.9', dstip: '10.0.0.1', srcport: '4444', dstport: '3389', protocol: 'UDP', action: 'DROP' } } }), 'standard');
    assert.deepEqual([fw.srcip, fw.dstip, fw.srcport, fw.dstport, fw.proto, fw.proto_num, fw.action, fw.decoder], ['203.0.113.9', '10.0.0.1', 4444, 3389, 'udp', 17, 'DROP', 'iptables']);
    assert.deepEqual(fw.rule_groups, ['firewall', 'iptables']);

    const sysmon = toStellarEvent(row({
        raw: {
            rule: { groups: ['sysmon', 'sysmon_event3'], mitre: { tactic: ['Command and Control'], technique: ['Application Layer Protocol'] } },
            decoder: { name: 'windows_eventchannel' }, manager: { name: 'wazuh-manager' },
            data: { win: { eventdata: {
                sourceIp: '10.0.0.7', sourcePort: '49800', destinationIp: '198.51.100.9', destinationPort: '443', protocol: 'tcp',
                image: 'C:\\Windows\\System32\\curl.exe', commandLine: 'curl.exe --password hunter2 https://198.51.100.9/',
                parentImage: 'C:\\Windows\\explorer.exe', processId: '4242', user: 'CORP\\alice',
                hashes: `SHA1=${'a'.repeat(40)},MD5=${'B'.repeat(32)},SHA256=${'c'.repeat(64)},IMPHASH=${'d'.repeat(32)}`,
            } } },
            full_log: 'login failed user=bob password=hunter2 Authorization: Basic Zm9vOmJhcg==',
        },
    }), 'standard');
    assert.deepEqual([sysmon.srcip, sysmon.dstip, sysmon.srcport, sysmon.dstport, sysmon.proto], ['10.0.0.7', '198.51.100.9', 49800, 443, 'tcp']);
    assert.deepEqual([sysmon.mitre_tactics, sysmon.mitre_techniques, sysmon.decoder, sysmon.manager], [['Command and Control'], ['Application Layer Protocol'], 'windows_eventchannel', 'wazuh-manager']);
    assert.equal(sysmon.user.dst, 'CORP\\alice');
    assert.deepEqual([sysmon.process.name, sysmon.process.pid, sysmon.process.sha1, sysmon.process.md5, sysmon.process.sha256], ['C:\\Windows\\System32\\curl.exe', '4242', 'a'.repeat(40), 'b'.repeat(32), 'c'.repeat(64)]);
    assert.ok(!JSON.stringify(sysmon).includes('hunter2') && !JSON.stringify(sysmon).includes('Zm9vOmJhcg=='), 'secrets redacted everywhere, including raw');
    assert.match(sysmon.process.command_line!, /\[REDACTED\]/);
    // Sysmon's own field names survive in raw for the parser.
    assert.equal(((sysmon as Record<string, unknown>).raw as { data: { win: { eventdata: { sourceIp: string } } } }).data.win.eventdata.sourceIp, '10.0.0.7');

    const fim = toStellarEvent(row({ raw: { syscheck: { path: '/etc/passwd', event: 'modified', sha256_after: 'e'.repeat(64), md5_after: 'zz' } } }), 'no_raw');
    assert.deepEqual(fim.file, { path: '/etc/passwd', change: 'modified', md5: null, sha1: null, sha256: 'e'.repeat(64) });
    assert.equal(fim.srcip, null, 'no 5-tuple on a file-integrity event, and none invented');
    assert.ok(!('raw' in fim), 'no_raw omits raw');

    const logon = toStellarEvent(row({ raw: { data: { win: { eventdata: { targetUserName: 'bob', subjectUserName: 'SYSTEM', ipAddress: '192.0.2.44' } } } } }), 'standard');
    assert.deepEqual(logon.user, { src: 'SYSTEM', dst: 'bob' });

    const cut = toStellarEvent(row({ raw: { truncated: true, preview: '…' }, raw_truncated: true }), 'standard');
    assert.deepEqual([cut.srcip, cut.full_log, cut.file.path], [null, null, null]);
    assert.equal((cut as Record<string, unknown>).raw_truncated, true);
});

// ── Delivery ──────────────────────────────────────────────────────────────────────────────────

test('first run (latest) sends nothing old; then new alerts in order, with the key, only for configured orgs; no repeats', async () => {
    seedAlert(A); seedAlert(A);
    let r = await runPushOnce(cfg());
    assert.deepEqual([r.sent, r.error], [0, null]);
    assert.equal(received.length, 0);
    assert.equal(Number(state()!.last_seq), seq);

    const a1 = seedAlert(A); seedAlert(B); const a2 = seedAlert(A);
    r = await runPushOnce(cfg());
    assert.deepEqual([r.sent, r.skipped, r.error], [2, 0, null]);
    assert.deepEqual(received.map((x) => x.body.event_id), [a1.id, a2.id]);
    assert.equal(received[0].headers.authorization, `Bearer ${KEY}`);
    assert.equal(received[0].headers['content-type'], 'application/json');
    assert.equal(received[0].body.tenant_ref, A);
    assert.equal(Number(state()!.last_seq), a2.ingest_seq);
    assert.equal(Number(state()!.sent_count), 2);

    r = await runPushOnce(cfg());
    assert.equal(r.sent, 0, 'nothing re-sent after a restart-equivalent second pass');
});

test('start=hours:N backfills only that window; beginning sends all retained; settle window holds a just-stored alert', async () => {
    const old = new Date(Date.now() - 48 * 3_600_000).toISOString();
    const recent = new Date(Date.now() - 2 * 3_600_000).toISOString();
    seedAlert(A, { received_at: old }); const r1 = seedAlert(A, { received_at: recent });
    let r = await runPushOnce(cfg({ start: { kind: 'hours', hours: 24 } }));
    assert.equal(r.sent, 1);
    assert.deepEqual(received.map((x) => x.body.event_id), [r1.id]);

    db.tables.push_state.length = 0; received.length = 0; db.tables.alerts.length = 0;
    const b1 = seedAlert(A); seedAlert(A, { received_at: new Date().toISOString() });
    r = await runPushOnce(cfg({ start: { kind: 'beginning' } }));
    assert.equal(r.sent, 1);
    assert.deepEqual(received.map((x) => x.body.event_id), [b1.id]);
    assert.equal(Number(state()!.last_seq), b1.ingest_seq);
});

test('rate budget: a tick sends at most its budget; the rest go on later ticks', async () => {
    const first = seedAlert(A); for (let i = 0; i < 6; i++) seedAlert(A);
    at(Number(first.ingest_seq) - 1);
    let r = await runPushOnce(cfg(), 3);
    assert.equal(r.sent, 3);
    r = await runPushOnce(cfg(), 3);
    assert.equal(r.sent, 3);
    r = await runPushOnce(cfg(), 3);
    assert.equal(r.sent, 1);
    assert.equal(new Set(received.map((x) => x.body.event_id)).size, 7, 'each sent exactly once');
});

test('400/422 refused content → dead letter, feed moves on; 413 → re-sent without raw', async () => {
    const x1 = seedAlert(A); const x2 = seedAlert(A); const x3 = seedAlert(A);
    at(Number(x1.ingest_seq) - 1);
    replies = [400, 413, 200, 422];
    const r = await runPushOnce(cfg());
    assert.deepEqual([r.sent, r.skipped, r.error], [1, 2, null]);
    assert.ok('raw' in received[1].body && !('raw' in received[2].body), '413 retried once without raw');
    assert.equal(received[2].body.event_id, x2.id);
    assert.deepEqual(db.tables.push_dead_letters.map((d) => [d.alert_id, d.status_code]), [[x1.id, 400], [x3.id, 422]]);
    assert.equal(Number(state()!.last_seq), x3.ingest_seq);
    assert.equal(Number(state()!.skipped_count), 2);
    assert.match(String(state()!.last_error), /refused by receiver/);
});

test('transient failures (500, 401, 404, 429, timeout, unreachable) keep the position and are retried; nothing dropped', async () => {
    const x = seedAlert(A); const y = seedAlert(A);
    at(Number(x.ingest_seq) - 1);
    for (const [reply, expect] of [
        [500, '500'], [401, /^401 \(check STELLAR_PUSH_API_KEY/], [404, '404'],
        [{ status: 429, headers: { 'Retry-After': '90' } }, '429 rate limited'],
        [{ status: 200, delayMs: 1_500 }, 'network error or timeout'],
    ] as [Reply, string | RegExp][]) {
        replies = [reply];
        const r = await runPushOnce(cfg({ timeoutMs: 1_000 }));
        if (expect instanceof RegExp) assert.match(r.error!, expect); else assert.equal(r.error, expect);
        assert.equal(r.sent, 0);
        assert.equal(Number(state()!.last_seq), Number(x.ingest_seq) - 1, `position kept after ${JSON.stringify(reply)}`);
        if (typeof reply !== 'number' && reply.status === 429) assert.equal(r.retryAfterMs, 90_000);
    }
    const u = await runPushOnce(cfg({ url: 'http://127.0.0.1:1/unreachable', timeoutMs: 1_000 }));
    assert.equal(u.error, 'network error or timeout');
    assert.equal(Number(state()!.retry_count), 6);
    assert.ok(!String(state()!.last_error).includes(KEY));
    assert.equal(db.tables.push_dead_letters.length, 0, 'transient failures are never dead-lettered');

    // Recovery: the receiver is back; both alerts go, in order.
    const r = await runPushOnce(cfg());
    assert.deepEqual([r.sent, r.error], [2, null]);
    assert.deepEqual(received.slice(-2).map((m) => m.body.event_id), [x.id, y.id]);
});

test('dead-letter retry: only when requested; delivered ones resolved; refused again stays open; purged alert unflagged', async () => {
    const x = seedAlert(A); const gone = seedAlert(A);
    at(Number(gone.ingest_seq));
    db.tables.push_dead_letters.push(
        { id: randomUUID(), destination: DESTINATION, alert_id: x.id, ingest_seq: x.ingest_seq, status_code: 400, attempts: 1, retry_requested: false, resolved_at: null },
        { id: randomUUID(), destination: DESTINATION, alert_id: gone.id, ingest_seq: gone.ingest_seq, status_code: 400, attempts: 1, retry_requested: false, resolved_at: null },
    );
    let r = await runPushOnce(cfg());
    assert.equal(received.length, 0, 'not retried until asked');

    for (const d of db.tables.push_dead_letters) d.retry_requested = true;
    db.tables.alerts.splice(db.tables.alerts.indexOf(gone), 1); // retention purged it
    replies = [422];
    r = await runPushOnce(cfg());
    assert.equal(r.dead_letters_resent, 0);
    const dx = db.tables.push_dead_letters.find((d) => d.alert_id === x.id)!;
    assert.deepEqual([dx.retry_requested, dx.resolved_at, dx.attempts, dx.status_code], [false, null, 2, 422]);
    const dg = db.tables.push_dead_letters.find((d) => d.alert_id === gone.id)!;
    assert.deepEqual([dg.retry_requested, dg.resolved_at], [false, null]);

    dx.retry_requested = true;
    r = await runPushOnce(cfg());
    assert.equal(r.dead_letters_resent, 1);
    assert.ok(dx.resolved_at, 'resolved on delivery');
});

// ── Status endpoint ───────────────────────────────────────────────────────────────────────────

test('status: super_admin only; reports counts, backlog and dead letters; never the key or full URL', async () => {
    const get = (bearer?: string) => fetch(`${apiBase}/api/admin/push-status`, { headers: bearer ? { Authorization: `Bearer ${bearer}` } : {} });
    assert.equal((await get()).status, 401);
    for (const role of ['soc_manager', 'analyst', 'executive']) assert.equal((await get(tok(role))).status, 403, role);

    Object.assign(process.env, OK_ENV, { STELLAR_PUSH_URL: 'https://poc.example.test/webhook/secret-tenant/secret-id' });
    try {
        const x = seedAlert(A); seedAlert(A); seedAlert(B);
        at(Number(x.ingest_seq));
        db.tables.push_dead_letters.push({ id: randomUUID(), destination: DESTINATION, alert_id: x.id, ingest_seq: x.ingest_seq, status_code: 400, attempts: 1, retry_requested: false, resolved_at: null });
        const res = await get(tok('super_admin'));
        assert.equal(res.status, 200);
        const text = await res.text();
        const s = JSON.parse(text);
        assert.ok(!text.includes(KEY) && !text.includes('secret-tenant') && !text.includes('secret-id'));
        assert.equal(s.config.host, 'poc.example.test');
        assert.deepEqual([s.config.enabled, s.config.valid, s.config.auth_header], [true, true, 'Authorization']);
        assert.equal(s.backlog, 2, 'org-a and org-b alerts after the position (both orgs configured)');
        assert.equal(s.dead_letters.open, 1);

        const q = await fetch(`${apiBase}/api/admin/push-status/dead-letters/retry`, { method: 'POST', headers: { Authorization: `Bearer ${tok('super_admin')}` } });
        assert.deepEqual([q.status, (await q.json()).queued], [200, 1]);
        assert.equal(db.tables.push_dead_letters[0].retry_requested, true);
        assert.equal((await fetch(`${apiBase}/api/admin/push-status/dead-letters/retry`, { method: 'POST', headers: { Authorization: `Bearer ${tok('analyst')}` } })).status, 403);
    } finally {
        for (const k of Object.keys(OK_ENV)) delete process.env[k];
    }
});
