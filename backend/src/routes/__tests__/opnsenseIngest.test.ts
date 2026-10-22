// Phase P24: agentless Wazuh syslog (OPNsense) through the existing forwarder path. An agent-000
// alert has no group, so it is quarantined as unmapped_source until a super_admin maps its sender
// address (wazuh_source_org_map); mapping replays the quarantine into that organisation's stored
// alerts with the firewall fields preserved. Only agent 000 is ever matched by location. The
// Alerts API filters by firewall action / address, and the client portal reads its own
// organisation's alerts and firewall activity. Fake PostgREST only; fixtures are synthetic
// (fixtures/opnsense-alerts.json).
process.env.JWT_SECRET = 'opnsense-ingest-test-secret';
for (const k of ['ALERT_INGEST_TOKEN', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'WAZUH_HOST', 'WAZUH_PASSWORD', 'WAZUH_INDEXER_HOST']) delete process.env[k];

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import { readFileSync } from 'fs';
import { join } from 'path';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth, requireRole } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import ingestRouter from '../ingest';
import alertStoreRouter from '../alertStore';
import wazuhGroupMapRouter from '../wazuhGroupMap';
import clientSecopsRouter from '../clientSecops';
import { getAuditLog } from '../../lib/audit';
import { __setAgentsForTests } from '../../services/wazuh';
import { resetOrgScopeCache } from '../../lib/orgScope';

const A = 'org-a';
const B = 'org-b';
const TOKEN = 'test-ingest-token-opnsense-0123456789';
const SENDER = '10.0.0.4';

const FIXTURE = JSON.parse(readFileSync(join(__dirname, 'fixtures', 'opnsense-alerts.json'), 'utf8')) as { alerts: Record<string, unknown>[] };

let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };

const userTok = (role: string, org: string) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
async function http(method: string, path: string, opts: { bearer?: string; body?: unknown } = {}) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (opts.bearer) headers.Authorization = `Bearer ${opts.bearer}`;
    const r = await fetch(`${base}${path}`, { method, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const user = (method: string, path: string, role: string, org: string, body?: unknown) => http(method, path, { bearer: userTok(role, org), body });

/** A recent Wazuh timestamp ("+0000" form), `minutesAgo` before now. */
const wazuhTime = (minutesAgo: number) => new Date(Date.now() - minutesAgo * 60_000).toISOString().replace('Z', '+0000');

let seq = 0;
/** The fixture alert `i`, re-timed and re-identified, as the alert itself (forwarder `raw`). */
function opnsense(i: number, over: Record<string, unknown> = {}): Record<string, unknown> {
    seq++;
    return { ...structuredClone(FIXTURE.alerts[i]), id: `1729600000.${seq}`, timestamp: wazuhTime(60 - seq), ...over };
}
/** What infra/soar/soar.py to_ingest() sends for an alert (agent groups from the Manager API). */
function toIngest(alert: Record<string, unknown>, groups: string[] = []) {
    const rule = alert.rule as { id: string; level: number; description?: string };
    const agent = alert.agent as Record<string, string>;
    return {
        id: alert.id, timestamp: alert.timestamp,
        rule: { id: String(rule.id), level: rule.level, ...(rule.description ? { description: rule.description } : {}) },
        agent: Object.fromEntries(['id', 'name', 'ip'].filter((k) => agent[k]).map((k) => [k, agent[k]])),
        agent_groups: groups,
        raw: alert,
        ...(alert.location ? { location: alert.location } : {}),
    };
}
const ingest = (alerts: unknown[]) => http('POST', '/api/ingest/alerts', { bearer: TOKEN, body: { alerts } });
const alertsOf = (org: string) => db.tables.alerts.filter((a) => a.org_id === org);

before(async () => {
    process.env.ALERT_INGEST_TOKEN = TOKEN;
    db = await startFakePostgrest({
        organisations: [{ id: 'oa', slug: A, name: 'Org A' }, { id: 'ob', slug: B, name: 'Org B' }],
        wazuh_group_org_map: [{ wazuh_group: 'acme-servers', org_id: A }, { wazuh_group: 'beta-servers', org_id: B }],
        wazuh_source_org_map: [],
        alerts: [], alert_ingest_rejects: [], alert_quarantine: [],
    }, {}, {
        alerts: { status: 'new', received_at: new Date().toISOString(), raw_truncated: false },
        alert_quarantine: { received_at: new Date().toISOString() },
    });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const agent = (id: string, group: string, status = 'active') => ({ id, name: `host-${id}`, ip: '192.0.2.9', os: 'Ubuntu 24.04', status, last_keepalive: null, version: 'Wazuh v4.14.7', group: [group] });
    __setAgentsForTests(async () => [agent('001', 'acme-servers'), agent('002', 'beta-servers'), agent('004', 'acme-servers', 'disconnected')]);
    resetOrgScopeCache();

    const app = express();
    app.use('/api/ingest', ingestRouter);
    app.use(express.json());
    app.use('/api/alerts', alertStoreRouter);
    app.use('/api/admin/wazuh-group-map', requireAuth, requireRole('super_admin'), wazuhGroupMapRouter);
    app.use('/api/client/secops', requireAuth, clientSecopsRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});

after(async () => {
    Object.assign(console, realLog);
    __setAgentsForTests(null);
    resetOrgScopeCache();
    server.close();
    await db.close();
});

test('an OPNsense alert from an unmapped sender is quarantined as unmapped_source, with its firewall fields', async () => {
    const r = await ingest([toIngest(opnsense(0)), toIngest(opnsense(1)), toIngest(opnsense(2))]);
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.deepEqual([r.data.accepted, r.data.rejected, r.data.quarantined], [0, 3, 3]);
    assert.equal(db.tables.alerts.length, 0, 'never stored without an owner');
    assert.deepEqual(db.tables.alert_ingest_rejects.map((x) => x.reason), ['unmapped_source', 'unmapped_source', 'unmapped_source']);
    const q = db.tables.alert_quarantine.map((x) => x.alert as Row);
    assert.deepEqual(q.map((a) => [a.net_action, a.net_direction, a.net_interface, a.protocol]), [
        ['block', 'in', 'vtnet0', 'tcp'], ['pass', 'out', 'igb1', 'udp'], ['reject', 'in', 'vtnet0', 'tcp'],
    ]);
    assert.deepEqual([q[0].src_ip, q[0].src_port, q[0].dst_ip, q[0].dst_port], ['198.51.100.47', 51234, '203.0.113.10', 22]);
    assert.deepEqual([q[2].src_ip, q[2].dst_ip], ['2001:db8::25', '2001:db8:1::10']);
    assert.deepEqual([q[0].decoder_name, q[0].device_hostname, q[0].location, q[0].agent_id], ['opnsense-filterlog', 'OPNsense.localdomain', SENDER, '000']);
});

test('the quarantine summary lists the unmapped sender by address', async () => {
    const r = await user('GET', '/api/admin/wazuh-group-map/quarantine', 'super_admin', A);
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.deepEqual(r.data.sources.map((s: Row) => [s.location, s.alerts]), [[SENDER, 3]]);
});

test('source mappings accept IP addresses of existing organisations only, super_admin only', async () => {
    for (const location of ['/var/log/syslog', 'opnsense.local', '10.0.0.0/8', '']) {
        const r = await user('PUT', '/api/admin/wazuh-group-map/sources', 'super_admin', A, { sources: [{ location, org_id: A }] });
        assert.equal(r.status, 400, location);
    }
    assert.equal((await user('PUT', '/api/admin/wazuh-group-map/sources', 'super_admin', A, { sources: [{ location: SENDER, org_id: 'no-such-org' }] })).status, 400);
    assert.equal((await user('PUT', '/api/admin/wazuh-group-map/sources', 'soc_manager', A, { sources: [{ location: SENDER, org_id: A }] })).status, 403);
    assert.equal(db.tables.wazuh_source_org_map.length, 0);
});

test('mapping the sender replays its quarantined alerts into that organisation, firewall fields intact', async () => {
    const r = await user('PUT', '/api/admin/wazuh-group-map/sources', 'super_admin', A, { sources: [{ location: SENDER, org_id: A, device_name: 'opnsense-fw' }] });
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.deepEqual(r.data.replay, { replayed: 3, duplicates: 0, still_quarantined: 0 });
    assert.equal(db.tables.alert_quarantine.length, 0);
    assert.equal(alertsOf(A).length, 3);
    assert.equal(alertsOf(B).length, 0);
    const block = alertsOf(A).find((a) => a.net_action === 'block')!;
    assert.deepEqual([block.src_ip, block.dst_port, block.protocol, block.net_interface, block.location, block.rule_id, block.rule_level, block.severity], ['198.51.100.47', 22, 'tcp', 'vtnet0', SENDER, '100201', 5, 'low']);
    assert.match(String(block.event_time), /^\d{4}-\d\d-\d\dT/);
    assert.ok(getAuditLog().some((e) => e.action === 'WAZUH_SOURCE_MAP_CHANGED' && /10\.0\.0\.4=>org-a/.test(e.details ?? '')));
});

test('later alerts from the mapped sender are stored straight away; duplicates are ignored', async () => {
    const a = opnsense(0);
    const first = await ingest([toIngest(a)]);
    assert.deepEqual([first.data.accepted, first.data.rejected], [1, 0]);
    const again = await ingest([toIngest(a)]);
    assert.deepEqual([again.data.accepted, again.data.duplicates], [0, 1]);
    assert.equal(alertsOf(A).length, 4);
});

test('only agent 000 is matched by location: an enrolled agent with that location and no group stays quarantined', async () => {
    const enrolled = opnsense(0, { agent: { id: '005', name: 'ws-05' } });
    const r = await ingest([toIngest(enrolled)]);
    assert.deepEqual([r.data.accepted, r.data.quarantined], [0, 1]);
    assert.equal(db.tables.alert_quarantine.at(-1)?.reason, 'unmapped_group');
    assert.equal(alertsOf(A).length, 4);
    db.tables.alert_quarantine.length = 0;
});

test('a raw alert truncated at 32 KB still keeps its network fields', async () => {
    const big = opnsense(0, { full_log: 'x'.repeat(40 * 1024) });
    const r = await ingest([toIngest(big)]);
    assert.equal(r.data.accepted, 1);
    const row = db.tables.alerts.at(-1)!;
    assert.equal(row.raw_truncated, true);
    assert.deepEqual([row.net_action, row.src_ip, row.dst_port], ['block', '198.51.100.47', 22]);
});

test('before the P24 columns exist, alerts are still stored (without network fields)', async () => {
    db.missingColumns.alerts = ['src_ip'];
    try {
        const r = await ingest([toIngest(opnsense(1))]);
        assert.equal(r.status, 200, JSON.stringify(r.data));
        assert.equal(r.data.accepted, 1);
        const row = db.tables.alerts.at(-1)!;
        assert.equal(row.src_ip, undefined);
        assert.equal(row.org_id, A);
    } finally {
        db.missingColumns.alerts = [];
    }
});

test('the Alerts API filters by firewall action, address, protocol and port — within the organisation', async () => {
    const list = async (qs: string, org = A) => (await user('GET', `/api/alerts?${qs}`, 'analyst', org)).data;
    const blocks = await list('action=block');
    assert.ok(blocks.alerts.length >= 1);
    assert.ok(blocks.alerts.every((a: Row) => a.net_action === 'block'));
    assert.deepEqual((await list('action=block,reject')).alerts.map((a: Row) => a.net_action).sort().filter((x: string, i: number, s: string[]) => s.indexOf(x) === i), ['block', 'reject']);
    assert.ok((await list('ip=203.0.113.10')).alerts.every((a: Row) => a.dst_ip === '203.0.113.10' || a.src_ip === '203.0.113.10'));
    assert.ok((await list('ip=203.0.113.10')).alerts.length >= 1);
    assert.ok((await list('protocol=udp')).alerts.every((a: Row) => a.protocol === 'udp'));
    assert.ok((await list('port=3389')).alerts.every((a: Row) => a.dst_port === 3389 || a.src_port === 3389));
    assert.ok((await list('firewall=1')).alerts.every((a: Row) => a.net_action !== null));
    const one = (await list('action=block')).alerts[0];
    assert.equal(one.raw, undefined, 'the list never carries raw');
    assert.deepEqual((await list('firewall=1', B)).alerts, [], 'org B sees none of org A\'s firewall activity');
    assert.equal((await user('GET', '/api/alerts?ip=not-an-ip', 'analyst', A)).status, 400);
    assert.equal((await user('GET', '/api/alerts?action=DROP;--', 'analyst', A)).status, 400);
});

test('client portal: its own organisation\'s alerts, firewall activity and agents — nothing else', async () => {
    const sum = await user('GET', '/api/client/secops/summary', 'portal_user', A);
    assert.equal(sum.status, 200, JSON.stringify(sum.data));
    assert.ok(sum.data.firewall_7d.block >= 1 && sum.data.firewall_7d.reject >= 1 && sum.data.firewall_7d.pass >= 1);
    assert.deepEqual(sum.data.agents, { total: 2, active: 1, disconnected: 1, never_connected: 0 });
    assert.ok(sum.data.last_received_at);
    assert.equal(sum.data.stale_after_minutes, 60);

    const fw = await user('GET', '/api/client/secops/alerts?firewall=1', 'portal_user', A);
    assert.equal(fw.status, 200);
    assert.ok(fw.data.alerts.length >= 3);
    for (const a of fw.data.alerts) {
        assert.equal(a.raw, undefined);
        assert.equal(a.wazuh_groups, undefined);
        assert.equal(a.triage_note, undefined);
    }

    const other = await user('GET', '/api/client/secops/summary', 'portal_user', B);
    assert.equal(other.data.alerts_7d.total, 0);
    assert.equal(other.data.agents.total, 1);
    assert.deepEqual((await user('GET', '/api/client/secops/alerts', 'portal_user', B)).data.alerts, []);
    const agents = await user('GET', '/api/client/secops/agents', 'portal_user', A);
    assert.deepEqual(agents.data.agents.map((x: Row) => x.id).sort(), ['001', '004']);

    // A client can't widen its view with X-Org-Id, and can't reach the staff alert API at all.
    const widened = await fetch(`${base}/api/client/secops/alerts`, { headers: { Authorization: `Bearer ${userTok('portal_user', B)}`, 'X-Org-Id': A } });
    assert.deepEqual(((await widened.json()) as { alerts: unknown[] }).alerts, []);
    assert.equal((await user('GET', '/api/alerts', 'portal_user', A)).status, 403);
    assert.equal((await user('GET', '/api/client/secops/alerts', 'executive', A)).status, 403);
});
