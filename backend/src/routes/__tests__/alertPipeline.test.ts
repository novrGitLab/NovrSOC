// Phase R2 alert pipeline: POST /api/ingest/alerts (service token, validation, size caps, org
// resolution through wazuh_group_org_map, dedupe), the watermark, the org-scoped read/triage
// routes, and the super_admin group map. Runs against the local fake PostgREST only.
process.env.JWT_SECRET = 'alert-pipeline-test-secret';
for (const k of ['ALERT_INGEST_TOKEN', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY']) delete process.env[k];

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth, requireRole } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import ingestRouter, { RAW_MAX_BYTES } from '../ingest';
import alertStoreRouter from '../alertStore';
import wazuhGroupMapRouter from '../wazuhGroupMap';
import { getAuditLog } from '../../lib/audit';

const A = 'org-a';
const B = 'org-b';
const TOKEN = 'test-ingest-token-0123456789abcdef';

let db: FakePostgrest;
let server: Server;
let base = '';

const userTok = (role: string, org?: string) =>
    jwt.sign({ sub: randomUUID(), email: `${role}@${org ?? 'none'}.test`, role, ...(org ? { org_id: org } : {}) }, process.env.JWT_SECRET!);

async function http(method: string, path: string, opts: { bearer?: string; body?: unknown; rawBody?: string } = {}) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (opts.bearer) headers.Authorization = `Bearer ${opts.bearer}`;
    const body = opts.rawBody ?? (opts.body === undefined ? undefined : JSON.stringify(opts.body));
    const r = await fetch(`${base}${path}`, { method, headers, body });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const ingest = (alerts: unknown[], bearer = TOKEN) => http('POST', '/api/ingest/alerts', { bearer, body: { alerts } });
const user = (method: string, path: string, role: string, org?: string, body?: unknown) => http(method, path, { bearer: userTok(role, org), body });

let seq = 0;
function wazuhAlert(over: Partial<{ id: string; level: number; groups: string[]; timestamp: string; agent: string; raw: unknown }> = {}) {
    seq++;
    return {
        id: over.id ?? `1696000000.${seq}`,
        timestamp: over.timestamp ?? new Date(Date.UTC(2026, 9, 9, 8, 0, seq)).toISOString().replace('Z', '+0000').replace('.000+', '.000+'),
        rule: { id: '5710', level: over.level ?? 10, description: `sshd: attempt ${seq}`, mitre: { id: ['T1110'] } },
        agent: { id: '001', name: over.agent ?? 'web-01', ip: '10.0.0.5' },
        agent_groups: over.groups ?? ['acme-servers'],
        location: '/var/log/auth.log',
        raw: over.raw ?? { full_log: `Failed password for root ${seq}` },
    };
}
const alertsOf = (org: string) => db.tables.alerts.filter((a) => a.org_id === org);

before(async () => {
    db = await startFakePostgrest({
        organisations: [{ id: 'oa', slug: A, name: 'Org A' }, { id: 'ob', slug: B, name: 'Org B' }],
        wazuh_group_org_map: [
            { wazuh_group: 'acme-servers', org_id: A },
            { wazuh_group: 'acme-laptops', org_id: A },
            { wazuh_group: 'beta-servers', org_id: B },
        ],
        alerts: [],
        alert_ingest_rejects: [],
    }, {}, { alerts: { status: 'new', received_at: new Date().toISOString(), raw_truncated: false } });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';

    const app = express();
    // Same order as index.ts: ingest before the global JSON parser.
    app.use('/api/ingest', ingestRouter);
    app.use(express.json());
    app.use('/api/alerts', alertStoreRouter);
    app.use('/api/admin/wazuh-group-map', requireAuth, requireRole('super_admin'), wazuhGroupMapRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(async () => { server.close(); await db.close(); delete process.env.ALERT_INGEST_TOKEN; });

// ── Token ─────────────────────────────────────────────────────────────────────────────────────

test('ingest fails closed with 503 while ALERT_INGEST_TOKEN is unset', async () => {
    delete process.env.ALERT_INGEST_TOKEN;
    assert.equal((await ingest([wazuhAlert()])).status, 503);
    assert.equal((await http('GET', '/api/ingest/alerts/watermark', { bearer: TOKEN })).status, 503);
    assert.equal(db.tables.alerts.length, 0);
});

test('ingest needs the exact bearer token; user JWTs do not work', async () => {
    process.env.ALERT_INGEST_TOKEN = TOKEN;
    assert.equal((await http('POST', '/api/ingest/alerts', { body: { alerts: [wazuhAlert()] } })).status, 401);
    assert.equal((await ingest([wazuhAlert()], 'wrong-token')).status, 401);
    assert.equal((await ingest([wazuhAlert()], `${TOKEN}x`)).status, 401);
    assert.equal((await ingest([wazuhAlert()], userTok('super_admin', A))).status, 401);
    assert.equal((await http('GET', '/api/ingest/alerts/watermark')).status, 401);
    assert.equal(db.tables.alerts.length, 0);
});

// ── Validation and caps ───────────────────────────────────────────────────────────────────────

test('batch envelope: 1-100 alerts in { alerts }, JSON only, 1 MB max', async () => {
    assert.equal((await http('POST', '/api/ingest/alerts', { bearer: TOKEN, body: [wazuhAlert()] })).status, 400);
    assert.equal((await ingest([])).status, 400);
    assert.equal((await ingest(Array.from({ length: 101 }, () => wazuhAlert()))).status, 400);
    assert.equal((await http('POST', '/api/ingest/alerts', { bearer: TOKEN, rawBody: '{"alerts": [' })).status, 400);
    const huge = await http('POST', '/api/ingest/alerts', { bearer: TOKEN, rawBody: JSON.stringify({ alerts: [wazuhAlert({ raw: { blob: 'x'.repeat(1_100_000) } })] }) });
    assert.equal(huge.status, 413);
    assert.equal(db.tables.alerts.length, 0);
});

test('an invalid alert is rejected on its own; the rest of the batch is stored', async () => {
    const good = wazuhAlert();
    const bad = { ...wazuhAlert(), rule: { level: 'high' } };
    const badTime = wazuhAlert({ timestamp: 'yesterday' });
    const r = await ingest([good, bad, badTime]);
    assert.equal(r.status, 200);
    assert.deepEqual(r.data, { accepted: 1, duplicates: 0, rejected: 2 });
    const reasons = db.tables.alert_ingest_rejects.map((x) => x.reason);
    assert.ok(reasons.includes('invalid: rule.level'), reasons.join());
    assert.ok(reasons.includes('invalid: timestamp'), reasons.join());
});

test('raw over 32 KB is truncated and flagged', async () => {
    const big = wazuhAlert({ raw: { full_log: 'A'.repeat(RAW_MAX_BYTES + 5000) } });
    assert.equal((await ingest([big])).data.accepted, 1);
    const row = db.tables.alerts.find((a) => a.wazuh_alert_id === big.id)!;
    assert.equal(row.raw_truncated, true);
    const raw = row.raw as { truncated: boolean; original_bytes: number; preview: string };
    assert.equal(raw.truncated, true);
    assert.ok(raw.original_bytes > RAW_MAX_BYTES);
    assert.ok(Buffer.byteLength(JSON.stringify(raw)) <= RAW_MAX_BYTES, 'stored raw stays within the cap');
});

test('NUL characters in log content are stripped, not stored', async () => {
    const a = wazuhAlert({ raw: { full_log: 'bad\u0000byte' } });
    a.rule.description = 'nul\u0000here';
    assert.equal((await ingest([a])).data.accepted, 1);
    const row = db.tables.alerts.find((x) => x.wazuh_alert_id === a.id)!;
    assert.equal(row.rule_description, 'nulhere');
    assert.equal((row.raw as { full_log: string }).full_log, 'badbyte');
});

// ── Org, severity, status ─────────────────────────────────────────────────────────────────────

test('org, severity and status come from the server, never the payload', async () => {
    const a = { ...wazuhAlert({ level: 13 }), org_id: B, severity: 'low', status: 'closed' };
    assert.equal((await ingest([a])).data.accepted, 1);
    const row = db.tables.alerts.find((x) => x.wazuh_alert_id === a.id)!;
    assert.equal(row.org_id, A, 'org from the group map');
    assert.equal(row.severity, 'critical', 'severity from rule.level');
    assert.equal(row.status, 'new', 'status is the table default');
});

test('severity boundaries 13 / 10 / 7 on ingest', async () => {
    const levels: [number, string][] = [[13, 'critical'], [12, 'high'], [10, 'high'], [9, 'medium'], [7, 'medium'], [6, 'low']];
    const batch = levels.map(([level]) => wazuhAlert({ level }));
    assert.equal((await ingest(batch)).data.accepted, levels.length);
    levels.forEach(([, expected], i) => assert.equal(db.tables.alerts.find((x) => x.wazuh_alert_id === batch[i].id)!.severity, expected, `level ${levels[i][0]}`));
});

test('an agent in no mapped group is rejected and recorded without its payload', async () => {
    const before = db.tables.alerts.length;
    const a = wazuhAlert({ groups: ['default', 'unknown-group'] });
    const r = await ingest([a]);
    assert.deepEqual(r.data, { accepted: 0, duplicates: 0, rejected: 1 });
    assert.equal(db.tables.alerts.length, before);
    const rej = db.tables.alert_ingest_rejects.at(-1)!;
    assert.equal(rej.reason, 'unmapped_group');
    assert.equal(rej.wazuh_alert_id, a.id);
    assert.deepEqual(rej.wazuh_groups, ['default', 'unknown-group']);
    for (const k of Object.keys(rej)) assert.ok(['id', 'created_at', 'received_at', 'reason', 'wazuh_alert_id', 'wazuh_groups'].includes(k), `reject row has no ${k}`);
});

test('groups that map to more than one org are rejected as ambiguous', async () => {
    const before = db.tables.alerts.length;
    const r = await ingest([wazuhAlert({ groups: ['acme-servers', 'beta-servers'] })]);
    assert.deepEqual(r.data, { accepted: 0, duplicates: 0, rejected: 1 });
    assert.equal(db.tables.alerts.length, before);
    assert.equal(db.tables.alert_ingest_rejects.at(-1)!.reason, 'ambiguous_org');
    // Two groups of the same org are fine.
    assert.equal((await ingest([wazuhAlert({ groups: ['acme-servers', 'acme-laptops'] })])).data.accepted, 1);
});

test('dedupe: resending stored alerts, or repeating one in a batch, counts duplicates', async () => {
    const batch = [wazuhAlert(), wazuhAlert()];
    assert.deepEqual((await ingest(batch)).data, { accepted: 2, duplicates: 0, rejected: 0 });
    assert.deepEqual((await ingest(batch)).data, { accepted: 0, duplicates: 2, rejected: 0 });
    const c = wazuhAlert();
    assert.deepEqual((await ingest([c, c])).data, { accepted: 1, duplicates: 1, rejected: 0 });
    // The same Wazuh id in another org's group is a different alert.
    assert.deepEqual((await ingest([{ ...c, agent_groups: ['beta-servers'] }])).data, { accepted: 1, duplicates: 0, rejected: 0 });
    assert.equal(db.tables.alerts.filter((a) => a.wazuh_alert_id === c.id).length, 2);
});

test('watermark: newest event_time per mapped org', async () => {
    const r = await http('GET', '/api/ingest/alerts/watermark', { bearer: TOKEN });
    assert.equal(r.status, 200);
    const byOrg = Object.fromEntries(r.data.orgs.map((o: Row) => [o.org_id, o]));
    const newest = (org: string) => alertsOf(org).map((a) => String(a.event_time)).sort().at(-1);
    assert.equal(byOrg[A].latest_event_time, newest(A));
    assert.equal(byOrg[B].latest_event_time, newest(B));
});

// ── Read and triage, org-scoped ───────────────────────────────────────────────────────────────

test('read routes: 401 without a token, 403 without permission or org', async () => {
    for (const p of ['/api/alerts', '/api/alerts/stats', `/api/alerts/${randomUUID()}`]) {
        assert.equal((await http('GET', p)).status, 401, p);
        assert.equal((await user('GET', p, 'executive', A)).status, 403, p);
        assert.equal((await user('GET', p, 'portal_user', A)).status, 403, p);
        assert.equal((await user('GET', p, 'analyst')).status, 403, `${p} without org`);
    }
});

test('org A lists, counts and pages only its own alerts', async () => {
    const all: Row[] = [];
    let cursor: string | null = null;
    do {
        const r = await user('GET', `/api/alerts?limit=3${cursor ? `&cursor=${cursor}` : ''}`, 'analyst', A);
        assert.equal(r.status, 200, JSON.stringify(r.data));
        assert.ok(r.data.alerts.length <= 3);
        all.push(...r.data.alerts);
        cursor = r.data.next_cursor;
    } while (cursor);
    assert.equal(all.length, alertsOf(A).length, 'every org A alert, once');
    assert.equal(new Set(all.map((a) => a.id)).size, all.length, 'no duplicates across pages');
    assert.ok(all.every((a) => a.org_id === A));
    assert.ok(all.every((a) => !('raw' in a)), 'list omits raw');
    const times = all.map((a) => String(a.event_time));
    assert.deepEqual(times, [...times].sort().reverse(), 'newest first');

    const stats = await user('GET', '/api/alerts/stats?range=30d', 'analyst', A);
    assert.equal(stats.status, 200);
    const inRange = alertsOf(A).filter((a) => String(a.event_time) >= stats.data.since);
    assert.equal(stats.data.total, inRange.length);
    assert.equal(stats.data.by_severity.critical, inRange.filter((a) => a.severity === 'critical').length);
    assert.equal(stats.data.by_status.new, inRange.filter((a) => a.status === 'new').length);
    assert.ok(stats.data.last_received_at);
});

test('filters: severity, status, agent, time range; bad values are 400', async () => {
    const crit = await user('GET', '/api/alerts?severity=critical&limit=200', 'analyst', A);
    assert.ok(crit.data.alerts.length > 0 && crit.data.alerts.every((a: Row) => a.severity === 'critical'));
    const a = wazuhAlert({ agent: 'db-07' });
    await ingest([a]);
    const byAgent = await user('GET', '/api/alerts?agent=db-07', 'analyst', A);
    assert.deepEqual(byAgent.data.alerts.map((x: Row) => x.wazuh_alert_id), [a.id]);
    const t = String(db.tables.alerts.find((x) => x.wazuh_alert_id === a.id)!.event_time);
    const ranged = await user('GET', `/api/alerts?from=${encodeURIComponent(t)}&to=${encodeURIComponent(t)}`, 'analyst', A);
    assert.deepEqual(ranged.data.alerts.map((x: Row) => x.wazuh_alert_id), [a.id]);
    for (const q of ['severity=urgent', 'status=open', 'from=notatime', 'agent=a%22b', 'cursor=junk']) {
        assert.equal((await user('GET', `/api/alerts?${q}`, 'analyst', A)).status, 400, q);
    }
});

test('org A cannot read, patch or enumerate org B alerts (404, never 403)', async () => {
    const bAlert = alertsOf(B)[0];
    assert.ok(bAlert);
    assert.equal((await user('GET', `/api/alerts/${bAlert.id}`, 'analyst', A)).status, 404);
    const patch = await user('PATCH', `/api/alerts/${bAlert.id}/status`, 'analyst', A, { status: 'closed' });
    assert.equal(patch.status, 404);
    assert.equal(db.tables.alerts.find((x) => x.id === bAlert.id)!.status, 'new');
    const list = await user('GET', '/api/alerts?limit=200', 'analyst', A);
    assert.ok(!list.data.alerts.some((x: Row) => x.org_id === B));
    // Org B sees its own.
    assert.equal((await user('GET', `/api/alerts/${bAlert.id}`, 'analyst', B)).status, 200);
});

test('triage: alerts:triage required, status validated, change audited', async () => {
    const aAlert = alertsOf(A)[0];
    assert.equal((await user('PATCH', `/api/alerts/${aAlert.id}/status`, 'executive', A, { status: 'triaged' })).status, 403);
    assert.equal((await user('PATCH', `/api/alerts/${aAlert.id}/status`, 'analyst', A, { status: 'open' })).status, 400);
    for (const role of ['analyst', 'soc_manager', 'super_admin']) {
        const r = await user('PATCH', `/api/alerts/${aAlert.id}/status`, role, A, { status: 'triaged' });
        assert.equal(r.status, 200, role);
        assert.equal(r.data.alert.status, 'triaged');
    }
    const entry = getAuditLog(50).find((e) => e.action === 'ALERT_STATUS_CHANGED' && e.resource_id === aAlert.id);
    assert.ok(entry, 'audit entry written');
    assert.match(entry!.details ?? '', /-> triaged/);
    const detail = await user('GET', `/api/alerts/${aAlert.id}`, 'analyst', A);
    assert.equal(detail.data.alert.status, 'triaged');
    assert.ok('raw' in detail.data.alert, 'detail includes raw');
});

// ── Group map admin ───────────────────────────────────────────────────────────────────────────

test('wazuh group map: super_admin only; unknown org 400; null removes; audited', async () => {
    assert.equal((await http('GET', '/api/admin/wazuh-group-map')).status, 401);
    for (const role of ['analyst', 'soc_manager', 'executive']) {
        assert.equal((await user('GET', '/api/admin/wazuh-group-map', role, A)).status, 403, role);
        assert.equal((await user('PUT', '/api/admin/wazuh-group-map', role, A, { mappings: [{ wazuh_group: 'x', org_id: A }] })).status, 403, role);
    }
    const list = await user('GET', '/api/admin/wazuh-group-map', 'super_admin', A);
    assert.equal(list.status, 200);
    assert.equal(list.data.mappings.length, 3);

    assert.equal((await user('PUT', '/api/admin/wazuh-group-map', 'super_admin', A, { mappings: [{ wazuh_group: 'new-group', org_id: 'org-nope' }] })).status, 400);
    assert.equal((await user('PUT', '/api/admin/wazuh-group-map', 'super_admin', A, { mappings: [{ wazuh_group: 'bad group!', org_id: A }] })).status, 400);

    const put = await user('PUT', '/api/admin/wazuh-group-map', 'super_admin', A, { mappings: [{ wazuh_group: 'new-group', org_id: B }, { wazuh_group: 'acme-laptops', org_id: null }] });
    assert.equal(put.status, 200);
    const groups = Object.fromEntries(put.data.mappings.map((m: Row) => [m.wazuh_group, m.org_id]));
    assert.equal(groups['new-group'], B);
    assert.equal(groups['acme-laptops'], undefined);
    assert.ok(getAuditLog(20).some((e) => e.action === 'WAZUH_GROUP_MAP_CHANGED' && /new-group=>org-b/.test(e.details ?? '')));

    // The new mapping takes effect for ingest; the removed one now rejects.
    assert.equal((await ingest([wazuhAlert({ groups: ['new-group'] })])).data.accepted, 1);
    assert.equal((await ingest([wazuhAlert({ groups: ['acme-laptops'] })])).data.rejected, 1);
});
