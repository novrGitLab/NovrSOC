// Phase X3: Stellar Cyber push — config, payload (5-tuple + security context + redaction) and
// delivery against the local fake PostgREST and a local fake receiver. All data is synthetic.
for (const k of ['EXPORT_SETTLE_SECONDS', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'http';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import { startFakePostgrest, type FakePostgrest, type Row } from '../../routes/__tests__/fakePostgrest';
import { pushConfig, runPushOnce, DESTINATION, type PushConfig } from '../stellarPush';
import { toStellarEvent } from '../../lib/stellarEvent';
import type { AlertRowForExport } from '../../lib/exportEvent';

const A = 'org-a';
const B = 'org-b';
const KEY = 'test-push-key-not-real';
const SETTLED = '2026-01-01T00:00:00+00:00';

let db: FakePostgrest;
let receiver: http.Server;
let receiverUrl = '';
const received: { headers: http.IncomingHttpHeaders; body: Row }[] = [];
let statuses: number[] = []; // scripted responses, 200 once exhausted
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
    orgs: [A], profile: 'standard', start: 'latest', ...over,
});
const state = () => db.tables.push_state.find((r) => r.destination === DESTINATION);

before(async () => {
    db = await startFakePostgrest({ alerts: [], push_state: [] }, {}, { push_state: { sent_count: 0, skipped_count: 0 } });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    receiver = http.createServer((req, res) => {
        let body = '';
        req.on('data', (c) => { body += c; });
        req.on('end', () => {
            received.push({ headers: req.headers, body: JSON.parse(body) });
            res.statusCode = statuses.shift() ?? 200;
            res.end('{}');
        });
    });
    await new Promise<void>((r) => receiver.listen(0, '127.0.0.1', r));
    receiverUrl = `http://127.0.0.1:${(receiver.address() as AddressInfo).port}/webhook/t/x`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => {
    Object.assign(console, realLog);
    receiver.close();
    await db.close();
});
beforeEach(() => {
    db.tables.alerts.length = 0;
    db.tables.push_state.length = 0;
    received.length = 0;
    statuses = [];
});

// ── Config ────────────────────────────────────────────────────────────────────────────────────

test('config: off unless exactly "true"; https URL, key and orgs required; key never in a reason', () => {
    const ok = { STELLAR_PUSH_ENABLED: 'true', STELLAR_PUSH_URL: 'https://poc.example.test/webhook/a/b', STELLAR_PUSH_API_KEY: KEY, STELLAR_PUSH_ORG_IDS: `${A}, ${B},${A}` };
    for (const v of [undefined, '', 'TRUE', '1']) assert.ok('error' in pushConfig({ ...ok, STELLAR_PUSH_ENABLED: v }));
    for (const bad of [
        { STELLAR_PUSH_URL: 'http://poc.example.test/x' }, { STELLAR_PUSH_URL: 'nope' }, { STELLAR_PUSH_API_KEY: ' ' },
        { STELLAR_PUSH_ORG_IDS: ' , ' }, { STELLAR_PUSH_PROFILE: 'everything' }, { STELLAR_PUSH_START: 'yesterday' },
    ]) {
        const r = pushConfig({ ...ok, ...bad });
        assert.ok('error' in r, JSON.stringify(bad));
        assert.ok(!JSON.stringify(r).includes(KEY));
    }
    const c = pushConfig(ok);
    assert.ok(!('error' in c));
    assert.deepEqual(c.orgs, [A, B]);
    assert.equal(c.headers.Authorization, `Bearer ${KEY}`);
    assert.equal(c.profile, 'standard');
    assert.equal(c.start, 'latest');
    const bare = pushConfig({ ...ok, STELLAR_PUSH_AUTH_HEADER: 'X-API-Key', STELLAR_PUSH_AUTH_SCHEME: 'none' });
    assert.ok(!('error' in bare) && bare.headers['X-API-Key'] === KEY && !('Authorization' in bare.headers));
});

// ── Payload ───────────────────────────────────────────────────────────────────────────────────

const row = (over: Partial<AlertRowForExport> = {}): AlertRowForExport => ({
    id: 'id-1', org_id: A, event_time: '2026-10-09T08:15:42.000+00:00', received_at: SETTLED, severity: 'high',
    rule_id: '5710', rule_level: 10, rule_description: 'sshd: authentication failed', agent_id: '001', agent_name: 'web-01', agent_ip: '10.0.0.5',
    mitre_ids: ['T1110'], location: '/var/log/auth.log', raw: null, raw_truncated: false, ...over,
});

test('payload: flat 5-tuple for Stellar plus the nested network object', () => {
    const ev = toStellarEvent(row({ raw: { data: { srcip: '192.0.2.10', srcport: '51515', dstip: '10.0.0.5', dstport: 22, protocol: 'TCP' } } }), 'standard');
    assert.equal(ev.event_id, 'id-1');
    assert.equal(ev.event_type, 'security.alert');
    assert.equal(ev.tenant_ref, A);
    assert.deepEqual([ev.srcip, ev.dstip, ev.srcport, ev.dstport, ev.proto, ev.proto_num], ['192.0.2.10', '10.0.0.5', 51515, 22, 'tcp', 6]);
    assert.deepEqual(ev.network, { src_ip: '192.0.2.10', src_port: 51515, dst_ip: '10.0.0.5', dst_port: 22, protocol: 'TCP' });
    // Missing or malformed → null, never guessed.
    const none = toStellarEvent(row({ raw: { data: { srcip: 'not-an-ip', srcport: '99999' } } }), 'standard');
    assert.deepEqual([none.srcip, none.dstip, none.srcport, none.dstport, none.proto, none.proto_num], [null, null, null, null, null, null]);
});

test('payload: Sysmon network, process and hashes; MITRE tactics; users; redacted command line', () => {
    const ev = toStellarEvent(row({
        raw: {
            rule: { groups: ['sysmon', 'sysmon_event3'], mitre: { tactic: ['Command and Control'], technique: ['Application Layer Protocol'] } },
            decoder: { name: 'windows_eventchannel' },
            manager: { name: 'wazuh-manager' },
            data: { win: { eventdata: {
                sourceIp: '10.0.0.7', sourcePort: '49800', destinationIp: '198.51.100.9', destinationPort: '443', protocol: 'tcp',
                image: 'C:\\Windows\\System32\\curl.exe', commandLine: 'curl.exe --password hunter2 https://198.51.100.9/',
                parentImage: 'C:\\Windows\\explorer.exe', processId: '4242', user: 'CORP\\alice',
                hashes: `SHA1=${'a'.repeat(40)},MD5=${'B'.repeat(32)},SHA256=${'c'.repeat(64)},IMPHASH=${'d'.repeat(32)}`,
            } } },
            full_log: 'login failed user=bob password=hunter2 Authorization: Basic Zm9vOmJhcg==',
        },
    }), 'standard');
    assert.deepEqual([ev.srcip, ev.dstip, ev.srcport, ev.dstport, ev.proto], ['10.0.0.7', '198.51.100.9', 49800, 443, 'tcp']);
    assert.deepEqual(ev.rule_groups, ['sysmon', 'sysmon_event3']);
    assert.deepEqual(ev.mitre_tactics, ['Command and Control']);
    assert.deepEqual(ev.mitre_techniques, ['Application Layer Protocol']);
    assert.equal(ev.decoder, 'windows_eventchannel');
    assert.equal(ev.manager, 'wazuh-manager');
    assert.equal(ev.user.dst, 'CORP\\alice');
    assert.equal(ev.process.name, 'C:\\Windows\\System32\\curl.exe');
    assert.equal(ev.process.pid, '4242');
    assert.deepEqual([ev.process.sha1, ev.process.md5, ev.process.sha256], ['a'.repeat(40), 'b'.repeat(32), 'c'.repeat(64)]);
    const all = JSON.stringify(ev);
    assert.ok(!all.includes('hunter2') && !all.includes('Zm9vOmJhcg=='), 'secrets redacted everywhere, including raw');
    assert.match(ev.process.command_line!, /\[REDACTED\]/);
    assert.match(ev.full_log!, /\[REDACTED\]/);
});

test('payload: file integrity; no_raw omits raw; a truncated alert has no extracted context', () => {
    const fim = toStellarEvent(row({ raw: { syscheck: { path: '/etc/passwd', event: 'modified', sha256_after: 'e'.repeat(64), md5_after: 'zz' } } }), 'no_raw');
    assert.deepEqual(fim.file, { path: '/etc/passwd', change: 'modified', md5: null, sha1: null, sha256: 'e'.repeat(64) });
    assert.ok(!('raw' in fim));
    const cut = toStellarEvent(row({ raw: { truncated: true, preview: '…' }, raw_truncated: true }), 'standard');
    assert.equal(cut.srcip, null);
    assert.equal(cut.full_log, null);
    assert.equal(cut.file.path, null);
});

// ── Delivery ──────────────────────────────────────────────────────────────────────────────────

test('first run with start=latest sends nothing old; then new alerts, in order, with the key, only for configured orgs', async () => {
    seedAlert(A); seedAlert(A);
    let r = await runPushOnce(cfg());
    assert.deepEqual(r, { sent: 0, skipped: 0, error: null });
    assert.equal(received.length, 0);
    assert.equal(Number(state()!.last_seq), 2);

    const a1 = seedAlert(A); seedAlert(B); const a2 = seedAlert(A);
    r = await runPushOnce(cfg());
    assert.deepEqual(r, { sent: 2, skipped: 0, error: null });
    assert.deepEqual(received.map((x) => x.body.event_id), [a1.id, a2.id]);
    assert.equal(received[0].headers.authorization, `Bearer ${KEY}`);
    assert.equal(received[0].body.srcip, '192.0.2.10');
    assert.equal(Number(state()!.last_seq), a2.ingest_seq);
    assert.equal(Number(state()!.sent_count), 2);

    r = await runPushOnce(cfg());
    assert.equal(r.sent, 0, 'nothing re-sent');
});

test('start=beginning sends what is retained; settle window holds back a just-stored alert', async () => {
    const old = seedAlert(A);
    seedAlert(A, { received_at: new Date().toISOString() });
    const r = await runPushOnce(cfg({ start: 'beginning' }));
    assert.equal(r.sent, 1);
    assert.deepEqual(received.map((x) => x.body.event_id), [old.id]);
    assert.equal(Number(state()!.last_seq), old.ingest_seq);
});

test('400 skips that alert and continues; 500 stops, keeps the position and resumes later', async () => {
    const x1 = seedAlert(A); const x2 = seedAlert(A); const x3 = seedAlert(A);
    db.tables.push_state.push({ destination: DESTINATION, last_seq: Number(x1.ingest_seq) - 1, sent_count: 0, skipped_count: 0 });
    statuses = [400, 500];
    let r = await runPushOnce(cfg());
    assert.deepEqual(r, { sent: 0, skipped: 1, error: '500' });
    assert.equal(Number(state()!.last_seq), x1.ingest_seq, 'x1 skipped, x2 not yet delivered');
    assert.equal(Number(state()!.skipped_count), 1);
    assert.equal(state()!.last_error, '500');

    r = await runPushOnce(cfg());
    assert.deepEqual(r, { sent: 2, skipped: 0, error: null });
    assert.deepEqual(received.slice(-2).map((x) => x.body.event_id), [x2.id, x3.id]);
    assert.equal(Number(state()!.last_seq), x3.ingest_seq);
});

test('401 is reported as a credential problem; unreachable receiver is a network error; neither moves the position', async () => {
    const x = seedAlert(A);
    db.tables.push_state.push({ destination: DESTINATION, last_seq: Number(x.ingest_seq) - 1, sent_count: 0, skipped_count: 0 });
    statuses = [401];
    let r = await runPushOnce(cfg());
    assert.match(r.error!, /^401 \(check STELLAR_PUSH_API_KEY/);
    assert.ok(!String(state()!.last_error).includes(KEY));
    r = await runPushOnce(cfg({ url: 'http://127.0.0.1:1/unreachable' }));
    assert.equal(r.error, 'network error or timeout');
    assert.equal(Number(state()!.last_seq), Number(x.ingest_seq) - 1);
});
