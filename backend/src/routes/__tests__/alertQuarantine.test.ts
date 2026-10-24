// Phase P1 alert quarantine: unmapped / ambiguous alerts are kept (no org) instead of dropped,
// replayed into `alerts` once their group is mapped, never leaked across orgs, and only counted
// through the super_admin API. Runs against the local fake PostgREST only; all data synthetic.
process.env.JWT_SECRET = 'alert-quarantine-test-secret';
for (const k of ['ALERT_INGEST_TOKEN', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth, requireRole } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest } from './fakePostgrest';
import ingestRouter from '../ingest';
import wazuhGroupMapRouter from '../wazuhGroupMap';

const A = 'org-a';
const B = 'org-b';
const TOKEN = 'test-ingest-token-quarantine-0123456789';
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };

const tok = (role: string) => jwt.sign({ sub: randomUUID(), email: `${role}@x.test`, role, org_id: A }, process.env.JWT_SECRET!);
async function http(method: string, path: string, bearer: string, body?: unknown) {
    const r = await fetch(`${base}${path}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
let seq = 0;
const alert = (groups: string[], id = `1697000000.${++seq}`) => ({
    id, timestamp: '2026-10-14T08:00:00.000+0000',
    rule: { id: '5710', level: 10, description: 'sshd: authentication failed' },
    agent: { id: '007', name: 'laptop-7', ip: '10.0.0.7' },
    agent_groups: groups, location: '/var/log/auth.log', raw: { full_log: `Failed password ${seq}` },
});
const ingest = (alerts: unknown[]) => http('POST', '/api/ingest/alerts', TOKEN, { alerts });

before(async () => {
    process.env.ALERT_INGEST_TOKEN = TOKEN;
    db = await startFakePostgrest({
        organisations: [{ id: 'oa', slug: A, name: 'Org A' }, { id: 'ob', slug: B, name: 'Org B' }],
        wazuh_group_org_map: [], alerts: [], alert_ingest_rejects: [], alert_quarantine: [],
    }, {}, { alerts: { status: 'new', raw_truncated: false }, alert_quarantine: { received_at: '2026-10-14T08:00:01+00:00' } });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use('/api/ingest', ingestRouter);
    app.use(express.json());
    app.use('/api/admin/wazuh-group-map', requireAuth, requireRole('super_admin'), wazuhGroupMapRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => {
    Object.assign(console, realLog);
    server.close();
    await db.close();
    delete process.env.ALERT_INGEST_TOKEN;
});
beforeEach(() => {
    for (const t of ['wazuh_group_org_map', 'alerts', 'alert_ingest_rejects', 'alert_quarantine']) db.tables[t].length = 0;
    db.tables.wazuh_group_org_map.push({ wazuh_group: 'acme', org_id: A }, { wazuh_group: 'beta', org_id: B });
});

test('unmapped and ambiguous alerts are quarantined with their stored fields, not dropped', async () => {
    const r = await ingest([alert(['acme']), alert(['default']), alert([]), alert(['acme', 'beta'])]);
    assert.equal(r.status, 200);
    assert.deepEqual(r.data, { accepted: 1, duplicates: 0, rejected: 3, quarantined: 3, invalid: 0 });
    assert.equal(db.tables.alerts.length, 1);
    assert.deepEqual(db.tables.alert_quarantine.map((q) => q.reason).sort(), ['ambiguous_org', 'unmapped_group', 'unmapped_group']);
    const q = db.tables.alert_quarantine.find((x) => (x.wazuh_groups as string[])[0] === 'default')!;
    const stored = q.alert as Record<string, unknown>;
    assert.equal(stored.org_id, undefined, 'no org is guessed');
    assert.equal(stored.rule_level, 10);
    assert.equal(stored.severity, 'high');
    assert.deepEqual(stored.raw, { full_log: `Failed password ${seq - 2}` });
    assert.equal(db.tables.alert_ingest_rejects.length, 3, 'rejects are still recorded');
});

// ── Acknowledgement: never 2xx unless every alert is stored, quarantined, or refused as invalid ──

test('quarantine unavailable: the batch is refused (503) and nothing is acknowledged as kept', async () => {
    const batch = [alert(['acme']), alert(['default']), alert(['acme', 'beta'])];
    const saved = db.tables.alert_quarantine;
    (db.tables as Record<string, unknown>).alert_quarantine = null; // table unreachable
    try {
        const r = await ingest(batch);
        assert.equal(r.status, 503, 'a 200 would let the forwarder move past alerts kept nowhere');
        assert.match(r.data.error, /quarantine unavailable/i);
        assert.equal(r.data.accepted, undefined, 'no counts are reported for a refused batch');
        assert.equal(db.tables.alert_ingest_rejects.length, 0, 'reasons are recorded only once the alerts are kept');
    } finally {
        db.tables.alert_quarantine = saved;
    }
});

test('quarantine write error (e.g. a column the table lacks): 503, not a silent drop', async () => {
    db.missingColumns.alert_quarantine = ['alert'];
    try {
        const r = await ingest([alert(['default'])]);
        assert.equal(r.status, 503);
        assert.equal(db.tables.alert_quarantine.length, 0);
    } finally {
        db.missingColumns.alert_quarantine = [];
    }
});

test('retry after a refused batch: everything is kept once, with no duplicate alert or quarantine row', async () => {
    const batch = [alert(['acme']), alert(['default']), alert(['acme', 'beta'])];
    const saved = db.tables.alert_quarantine;
    (db.tables as Record<string, unknown>).alert_quarantine = null;
    try {
        assert.equal((await ingest(batch)).status, 503);
    } finally {
        db.tables.alert_quarantine = saved;
    }
    assert.equal(db.tables.alerts.length, 1, 'the mapped alert was stored before the refusal');
    const retry = await ingest(batch); // the forwarder resends the same batch from its checkpoint
    assert.equal(retry.status, 200);
    assert.deepEqual(retry.data, { accepted: 0, duplicates: 1, rejected: 2, quarantined: 2, invalid: 0 });
    assert.equal(db.tables.alerts.length, 1);
    assert.equal(db.tables.alert_quarantine.length, 2);
    const again = await ingest(batch); // and once more (e.g. the late sweep)
    assert.equal(again.status, 200);
    assert.equal(db.tables.alerts.length, 1);
    assert.equal(db.tables.alert_quarantine.length, 2, 'quarantine rows are keyed by alert id: no duplicates');
});

test('mixed batch: stored, quarantined and invalid alerts are each counted and kept where they belong', async () => {
    const invalid = { ...alert(['acme']), rule: { id: '1', level: 99 } }; // level out of range
    const r = await ingest([alert(['acme']), alert(['beta']), alert(['default']), alert([]), alert(['acme', 'beta']), invalid]);
    assert.equal(r.status, 200);
    assert.deepEqual(r.data, { accepted: 2, duplicates: 0, rejected: 4, quarantined: 3, invalid: 1 });
    assert.deepEqual(db.tables.alerts.map((a) => a.org_id).sort(), [A, B]);
    assert.deepEqual(db.tables.alert_quarantine.map((q) => q.reason).sort(), ['ambiguous_org', 'unmapped_group', 'unmapped_group']);
    assert.deepEqual(db.tables.alert_ingest_rejects.map((x) => String(x.reason)).sort(), ['ambiguous_org', 'invalid: rule.level', 'unmapped_group', 'unmapped_group']);
});

test('failing to record reject reasons (no payload) does not fail an otherwise kept batch', async () => {
    const saved = db.tables.alert_ingest_rejects;
    (db.tables as Record<string, unknown>).alert_ingest_rejects = null;
    try {
        const r = await ingest([alert(['default'])]);
        assert.equal(r.status, 200);
        assert.equal(r.data.quarantined, 1);
        assert.equal(db.tables.alert_quarantine.length, 1, 'the alert itself is kept');
    } finally {
        db.tables.alert_ingest_rejects = saved;
    }
});

test('alert store write failure: 502, the forwarder resends', async () => {
    db.missingColumns.alerts = ['raw'];
    try {
        assert.equal((await ingest([alert(['acme'])])).status, 502);
    } finally {
        db.missingColumns.alerts = [];
    }
});

test('when an unmapped alert cannot be quarantined the batch is refused (503) so the forwarder resends it', async () => {
    const saved = db.tables.alert_quarantine;
    const batch = [alert(['acme']), alert(['default'])];
    (db.tables as Record<string, unknown>).alert_quarantine = null; // the table unavailable
    try {
        const r = await ingest(batch);
        assert.equal(r.status, 503, 'never a 200 that would let the forwarder move past an alert kept nowhere');
        assert.match(r.data.error, /quarantine unavailable/i);
        assert.equal(db.tables.alerts.length, 1, 'the mapped alert is stored; the resend is a duplicate');
    } finally {
        db.tables.alert_quarantine = saved;
    }
    const again = await ingest(batch); // the forwarder resends the same batch
    assert.equal(again.status, 200);
    assert.equal(again.data.quarantined, 1);
    assert.equal(db.tables.alerts.length, 1);
});

test('a retried batch overwrites, never duplicates, a quarantined alert', async () => {
    const a = alert(['default']);
    await ingest([a]);
    await ingest([a]);
    assert.equal(db.tables.alert_quarantine.length, 1);
});

test('mapping the group replays its alerts into the right org; ambiguous and other groups stay', async () => {
    const d1 = alert(['default']); const d2 = alert(['default']); const other = alert(['lab']); const amb = alert(['acme', 'beta']);
    await ingest([d1, d2, other, amb]);
    const r = await http('PUT', '/api/admin/wazuh-group-map', tok('super_admin'), { mappings: [{ wazuh_group: 'default', org_id: B }] });
    assert.equal(r.status, 200);
    assert.deepEqual(r.data.replay, { replayed: 2, duplicates: 0, still_quarantined: 2 });
    const moved = db.tables.alerts.filter((x) => x.org_id === B).map((x) => x.wazuh_alert_id).sort();
    assert.deepEqual(moved, [d1.id, d2.id].sort());
    assert.equal(db.tables.alerts.filter((x) => x.org_id === A).length, 0, 'nothing leaks into another org');
    assert.deepEqual(db.tables.alert_quarantine.map((q) => q.wazuh_alert_id).sort(), [other.id, amb.id].sort());
});

test('replay is idempotent: an alert already stored for that org counts as a duplicate', async () => {
    const d = alert(['default']);
    await ingest([d]);
    db.tables.alerts.push({ id: randomUUID(), org_id: B, wazuh_alert_id: d.id, severity: 'high' });
    db.tables.wazuh_group_org_map.push({ wazuh_group: 'default', org_id: B });
    const r = await http('POST', '/api/admin/wazuh-group-map/quarantine/replay', tok('super_admin'));
    assert.deepEqual(r.data, { replayed: 0, duplicates: 1, still_quarantined: 0 });
    assert.equal(db.tables.alerts.filter((x) => x.wazuh_alert_id === d.id).length, 1);
    assert.equal(db.tables.alert_quarantine.length, 0);
});

test('summary is super_admin only and returns counts per group, never alert content', async () => {
    await ingest([alert(['default']), alert(['default']), alert([])]);
    for (const role of ['soc_manager', 'analyst', 'executive']) assert.equal((await http('GET', '/api/admin/wazuh-group-map/quarantine', tok(role))).status, 403, role);
    assert.equal((await http('POST', '/api/admin/wazuh-group-map/quarantine/replay', tok('analyst'))).status, 403);
    const r = await http('GET', '/api/admin/wazuh-group-map/quarantine', tok('super_admin'));
    assert.equal(r.status, 200);
    assert.equal(r.data.total, 3);
    assert.deepEqual(r.data.groups.map((g: { wazuh_group: string; alerts: number }) => [g.wazuh_group, g.alerts]), [['default', 2], ['(no group)', 1]]);
    assert.doesNotMatch(JSON.stringify(r.data), /Failed password|laptop-7|10\.0\.0\.7/);
});
