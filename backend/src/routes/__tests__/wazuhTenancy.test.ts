// Phase P24 tenancy: Wazuh data read straight from the indexer and the Manager API is limited to
// the request organisation (lib/orgScope.ts). A fake indexer holds documents for two
// organisations, an ambiguous agent, the manager and two syslog senders; it applies the scope
// filter a route sends and returns EVERYTHING when a query carries none — so an unscoped query
// shows up here as a leak. Organisation A must never see organisation B's alerts, agents,
// vulnerabilities, threats, IOCs or AI telemetry, whatever it sends (?group=, X-Org-Id, ids).
process.env.JWT_SECRET = 'wazuh-tenancy-test-secret';
for (const k of [
    'SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'WAZUH_HOST', 'WAZUH_PASSWORD', 'WAZUH_API_PASSWORD', 'WAZUH_INDEXER_HOST', 'WAZUH_INDEXER_PASSWORD', 'WAZUH_INDEXER_PASS',
    'NVIDIA_API_KEY', 'GEMINI_API_KEY', 'GREYNOISE_API_KEY', 'EMAIL_ENABLED', 'RESEND_API_KEY', 'BREVO_API_KEY', 'SMTP_HOST', 'CISO_EMAIL', 'ALERT_EMAIL_TO', 'DEMO_MODE',
]) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { requirePermission, requireOrg } from '../../lib/permissions';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import wazuhRouter from '../wazuh';
import threatManagementRouter from '../threatManagement';
import mitreRouter from '../mitre';
import searchRouter from '../search';
import notificationsRouter from '../notifications';
import assetsRouter from '../assets';
import orgCTIRouter from '../orgCTI';
import novrAiRouter from '../novr-ai';
import { __setSearchForTests } from '../../lib/wazuh-indexer';
import { __setAgentsForTests, type WazuhAgent } from '../../services/wazuh';
import { resetOrgScopeCache, orgScope, alertScopeFilter } from '../../lib/orgScope';
import { __resetWazuhIOCsForTests } from '../../lib/orgCtiStore';

const A = 'org-a';
const B = 'org-b';

// ── Inventory: groups, agents, senders ───────────────────────────────────────────────────────
//   001 grp-a -> A      002 grp-b -> B      003 grp-a + grp-b -> ambiguous (nobody's)
//   000 the manager: 10.0.0.4 mapped to A, 10.0.0.9 mapped to nobody
const agent = (id: string, groups: string[]): WazuhAgent => ({ id, name: `host-${id}`, ip: `192.0.2.${Number(id)}`, os: 'Ubuntu 24.04', status: 'active', last_keepalive: '2026-10-21T10:00:00Z', version: 'Wazuh v4.14.7', group: groups });
const AGENTS = [agent('000', []), agent('001', ['grp-a']), agent('002', ['grp-b']), agent('003', ['grp-a', 'grp-b'])];

interface Doc { _id: string; _source: Record<string, unknown> }
const now = Date.now();
const doc = (id: string, agentId: string, srcip: string, over: Record<string, unknown> = {}): Doc => ({
    _id: id,
    _source: {
        id: `wazuh-${id}`, timestamp: new Date(now - 3600_000).toISOString(),
        rule: { id: '5710', level: 12, description: `alert ${id}`, groups: ['sshd'], mitre: { id: ['T1110'], tactic: ['Credential Access'], technique: ['Brute Force'] } },
        agent: { id: agentId, name: `host-${agentId}` }, location: agentId === '000' ? '10.0.0.4' : '/var/log/auth.log',
        data: { srcip, dstip: '203.0.113.10', dstport: '22', protocol: 'tcp' }, full_log: `log for ${id}`,
        ...over,
    },
});
const DOCS: Doc[] = [
    doc('a-1', '001', '198.51.100.1'),
    doc('a-fw', '000', '198.51.100.2', { location: '10.0.0.4', data: { action: 'block', srcip: '198.51.100.2', dstip: '203.0.113.10', dstport: '22', protocol: 'tcp' } }),
    doc('b-1', '002', '198.51.100.99'),
    doc('amb-1', '003', '198.51.100.98'),
    doc('fw-unowned', '000', '198.51.100.97', { location: '10.0.0.9' }),
];

// ── Fake indexer ─────────────────────────────────────────────────────────────────────────────
// Understands the shapes lib/orgScope.ts emits (terms agent.id; agent 000 + terms location;
// match-none), a per-agent `term agent.id`, and an `ids` lookup. Anything else is ignored, so a
// query without a scope filter returns every document.
interface Scope { none: boolean; ids: string[] | null; locs: string[]; term: string | null; docIds: string[] | null }
function walk(node: unknown, s: Scope): void {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) { node.forEach((n) => walk(n, s)); return; }
    const o = node as Record<string, unknown>;
    const mustNot = (o.must_not as unknown[] | undefined);
    if (Array.isArray(mustNot) && mustNot.some((m) => m && typeof m === 'object' && 'match_all' in (m as object))) s.none = true;
    const terms = o.terms as Record<string, unknown> | undefined;
    if (terms && Array.isArray(terms['agent.id'])) s.ids = [...(s.ids ?? []), ...(terms['agent.id'] as string[])];
    if (terms && Array.isArray(terms.location)) s.locs.push(...(terms.location as string[]));
    const term = o.term as Record<string, unknown> | undefined;
    if (term && typeof term['agent.id'] === 'string' && term['agent.id'] !== '000') s.term = term['agent.id'] as string;
    const ids = o.ids as { values?: string[] } | undefined;
    if (ids?.values) s.docIds = ids.values;
    for (const [k, v] of Object.entries(o)) if (k !== 'aggs' && k !== 'aggregations') walk(v, s);
}
const calls: { index: string; body: Record<string, unknown> }[] = [];
function fakeSearch(index: string, body: unknown): Promise<unknown> {
    calls.push({ index, body: body as Record<string, unknown> });
    const s: Scope = { none: false, ids: null, locs: [], term: null, docIds: null };
    walk((body as Record<string, unknown>).query, s);
    let hits = index.startsWith('wazuh-alerts') ? DOCS : index.startsWith('wazuh-states-vulnerabilities') ? DOCS.map((d) => ({ _id: `v-${d._id}`, _source: { agent: d._source.agent, vulnerability: { id: `CVE-${d._id}`, severity: 'High', score: { base: 7.5 } }, package: { name: 'openssl' } } })) : [];
    const scoped = s.none || s.ids !== null || s.locs.length > 0;
    if (s.none) hits = [];
    else if (scoped) {
        hits = hits.filter((d) => {
            const ag = (d._source.agent as { id: string }).id;
            return (s.ids ?? []).includes(ag) || (ag === '000' && s.locs.includes(String(d._source.location)));
        });
    }
    if (s.term) hits = hits.filter((d) => (d._source.agent as { id: string }).id === s.term);
    if (s.docIds) hits = hits.filter((d) => s.docIds!.includes(d._id));
    const size = typeof (body as { size?: number }).size === 'number' ? (body as { size: number }).size : 10;
    return Promise.resolve({ _shards: { total: 1, failed: 0 }, hits: { total: { value: hits.length }, hits: hits.slice(0, size) } });
}

// ── Harness ──────────────────────────────────────────────────────────────────────────────────
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org: string) => jwt.sign({ sub: `${role}-${org}`, email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
async function call(method: string, path: string, role: string, org: string, opts: { body?: unknown; asOrg?: string } = {}) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json', Authorization: `Bearer ${tok(role, org)}` };
    if (opts.asOrg) headers['X-Org-Id'] = opts.asOrg;
    const r = await fetch(`${base}${path}`, { method, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
/** Every document id / agent id / IP that appears anywhere in a response. */
const leaks = (data: unknown) => {
    const s = JSON.stringify(data);
    return ['b-1', 'amb-1', 'fw-unowned', '198.51.100.99', '198.51.100.98', '198.51.100.97', 'host-002', 'host-003', '10.0.0.9'].filter((x) => s.includes(x));
};

before(async () => {
    db = await startFakePostgrest({
        organisations: [{ id: 'oa', slug: A, name: 'Org A' }, { id: 'ob', slug: B, name: 'Org B' }],
        wazuh_group_org_map: [{ wazuh_group: 'grp-a', org_id: A }, { wazuh_group: 'grp-b', org_id: B }],
        wazuh_source_org_map: [{ location: '10.0.0.4', org_id: A }],
        staff_org_assignments: [],
        cases: [], case_timeline: [], threat_triage: [], nigeria_advisories: [], ioc_enrichments: [], backup_jobs: [],
    });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    __setSearchForTests(fakeSearch);
    __setAgentsForTests(async () => AGENTS);

    const app = express();
    app.use(express.json());
    app.use('/api/wazuh', wazuhRouter);
    app.use('/api/threats', threatManagementRouter);
    app.use('/api/mitre', mitreRouter);
    app.use('/api/search', searchRouter);
    app.use('/api/notifications', notificationsRouter);
    app.use('/api/assets', requirePermission('alerts:read'), assetsRouter);
    app.use('/api/org-cti', requireAuth, requireOrg, orgCTIRouter);
    app.use('/api/novr-ai', requireAuth, novrAiRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => {
    Object.assign(console, realLog);
    __setSearchForTests(null);
    __setAgentsForTests(null);
    resetOrgScopeCache();
    server.close();
    await db.close();
});
beforeEach(() => { calls.length = 0; resetOrgScopeCache(); });

// ── Ownership ────────────────────────────────────────────────────────────────────────────────

test('ownership: agents by group map, never the manager, never an agent whose groups map to two orgs; senders by source map', async () => {
    const a = await orgScope(A);
    assert.deepEqual([a.agentIds, a.locations, a.groups], [['001'], ['10.0.0.4'], ['grp-a']]);
    const b = await orgScope(B);
    assert.deepEqual([b.agentIds, b.locations], [['002'], []]);
    // An organisation with nothing mapped matches nothing — never everything.
    const none = await orgScope('org-none');
    assert.deepEqual(alertScopeFilter(none), { bool: { must_not: [{ match_all: {} }] } });
});

// ── Every indexer-backed route, as org A ─────────────────────────────────────────────────────

const READS = [
    '/api/wazuh/alerts', '/api/wazuh/agents', '/api/wazuh/status', '/api/wazuh/incidents', '/api/wazuh/alerts-indexer', '/api/wazuh/trend',
    '/api/wazuh/mitre-stats', '/api/wazuh/notifications', '/api/wazuh/network-connections', '/api/wazuh/attack-origins', '/api/wazuh/vulnerabilities',
    '/api/wazuh/agents/001/alerts', '/api/wazuh/agents/001/vulnerabilities',
    '/api/threats/alerts', '/api/threats/stats', '/api/threats/global-map', '/api/threats',
    '/api/mitre/techniques', '/api/mitre/technique/T1110', '/api/mitre/defend',
    '/api/search?q=alert', '/api/notifications', '/api/assets',
];

test('org A reads only its own Wazuh data on every indexer-backed route, and every query it sends is scoped', async () => {
    for (const p of READS) {
        calls.length = 0;
        const r = await call('GET', p, 'analyst', A);
        assert.ok(r.status < 500, `${p}: ${r.status} ${JSON.stringify(r.data)?.slice(0, 200)}`);
        assert.deepEqual(leaks(r.data), [], `${p} leaked another organisation's data`);
        for (const c of calls) {
            if (c.index.startsWith('wazuh-monitoring')) continue;
            const s = JSON.stringify(c.body.query ?? {});
            assert.ok(/"agent\.id"/.test(s) || /match_all/.test(s), `${p}: unscoped indexer query ${s.slice(0, 160)}`);
            assert.ok(!/"002"|"003"/.test(s), `${p}: query names another organisation's agent`);
        }
    }
});

test('the organisation sees its own agent alerts and its own firewall sender', async () => {
    const r = await call('GET', '/api/wazuh/alerts', 'analyst', A);
    assert.deepEqual(r.data.map((a: Row) => a.id).sort(), ['a-1', 'a-fw']);
    const fw = r.data.find((a: Row) => a.id === 'a-fw');
    assert.deepEqual([fw.net_action, fw.src_ip, fw.dst_port, fw.location], ['block', '198.51.100.2', 22, '10.0.0.4']);
    const b = await call('GET', '/api/wazuh/alerts', 'analyst', B);
    assert.deepEqual(b.data.map((a: Row) => a.id), ['b-1']);
});

test('agents: lists and counts are the organisation\'s own; no fabricated manager entry', async () => {
    const r = await call('GET', '/api/wazuh/agents', 'analyst', A);
    assert.deepEqual(r.data.agents.map((a: Row) => a.id), ['001']);
    const s = await call('GET', '/api/wazuh/status', 'analyst', A);
    assert.deepEqual([s.data.connected, s.data.agent_count, s.data.active_agents], [true, 1, 1]);
    const assets = await call('GET', '/api/assets', 'analyst', A);
    assert.deepEqual(assets.data.agents.map((a: Row) => a.id), ['001']);
});

test('per-agent routes answer 404 for another organisation\'s agent, an ambiguous agent and the manager', async () => {
    for (const id of ['002', '003', '000', '2', 'abc']) {
        for (const p of ['', '/alerts', '/vulnerabilities', '/packages']) {
            assert.equal((await call('GET', `/api/wazuh/agents/${id}${p}`, 'analyst', A)).status, 404, `${id}${p}`);
        }
    }
    const own = await call('GET', '/api/wazuh/agents/1', 'analyst', A); // unpadded id of its own agent
    assert.equal(own.status, 200);
    assert.equal(own.data.agent.id, '001');
});

test('?group= narrows to the organisation\'s own group only; another organisation\'s group is 403', async () => {
    for (const p of ['/api/wazuh/agents?group=grp-b', '/api/wazuh/incidents?group=grp-b', '/api/wazuh/vulnerabilities?group=grp-b', '/api/wazuh/trend?group=grp-b']) {
        const r = await call('GET', p, 'analyst', A);
        assert.equal(r.status, 403, p);
        assert.deepEqual(leaks(r.data), [], p);
    }
    assert.equal((await call('GET', '/api/wazuh/agents?group=grp-a', 'analyst', A)).status, 200);
});

test('threat hunting is scoped and accepts only the builder\'s fields', async () => {
    const r = await call('POST', '/api/wazuh/hunt', 'analyst', A, { body: { conditions: [{ field: 'rule.level', op: 'greater_than', value: '1' }] } });
    assert.equal(r.status, 200);
    assert.deepEqual(r.data.results.map((x: Row) => x.id).sort(), ['a-1', 'a-fw']);
    assert.equal((await call('POST', '/api/wazuh/hunt', 'analyst', A, { body: { conditions: [{ field: 'agent.id', op: 'equals', value: '002' }] } })).status, 400);
    assert.equal((await call('POST', '/api/wazuh/hunt', 'analyst', A, { body: { conditions: [{ field: '_id', op: 'exists' }] } })).status, 400);
});

// ── Threat Management: no shared state between organisations ────────────────────────────────

test('threat management: an alert org B loaded can\'t be read, triaged or cased by org A', async () => {
    const b = await call('GET', '/api/threats/alerts', 'analyst', B);
    assert.deepEqual(b.data.alerts.map((a: Row) => a.id), ['b-1']);
    assert.equal((await call('GET', '/api/threats/alerts/b-1', 'analyst', A)).status, 404);
    assert.equal((await call('PATCH', '/api/threats/alerts/b-1', 'analyst', A, { body: { status: 'closed' } })).status, 404);
    assert.equal((await call('POST', '/api/threats/alerts/b-1/create-incident', 'analyst', A)).status, 404);
    assert.equal(db.tables.cases.length, 0, 'no case was opened from another organisation\'s alert');

    // Org A's own alert works, and its triage is not visible to org B.
    assert.equal((await call('PATCH', '/api/threats/alerts/a-1', 'analyst', A, { body: { status: 'investigating' } })).status, 200);
    const created = await call('POST', '/api/threats/alerts/a-1/create-incident', 'analyst', A);
    assert.equal(created.status, 200, JSON.stringify(created.data));
    assert.deepEqual(db.tables.cases.map((c) => c.org_id), [A]);
    const mapped = (await call('GET', '/api/threats/alerts/a-1', 'analyst', A)).data;
    assert.deepEqual([mapped.destination_ip, mapped.destination_port, mapped.protocol, mapped.raw_log], ['203.0.113.10', 22, 'tcp', 'log for a-1']);
});

// ── Organisation selection ───────────────────────────────────────────────────────────────────

test('an analyst can\'t switch to an organisation they are not assigned to; a manager can, and then sees only that organisation', async () => {
    const denied = await call('GET', '/api/wazuh/alerts', 'analyst', A, { asOrg: B });
    assert.equal(denied.status, 403);
    assert.equal(calls.length, 0, 'nothing was queried');
    const manager = await call('GET', '/api/wazuh/alerts', 'soc_manager', A, { asOrg: B });
    assert.equal(manager.status, 200);
    assert.deepEqual(manager.data.map((a: Row) => a.id), ['b-1']);
});

test('when ownership can\'t be worked out, the routes fail closed — no unfiltered query is sent', async () => {
    const saved = db.tables.wazuh_group_org_map;
    (db.tables as Record<string, Row[] | null>).wazuh_group_org_map = null; // migration not applied
    try {
        for (const p of ['/api/wazuh/alerts', '/api/wazuh/agents', '/api/threats/alerts', '/api/mitre/techniques']) {
            calls.length = 0;
            resetOrgScopeCache();
            const r = await call('GET', p, 'analyst', A);
            assert.equal(r.status, 503, p);
            assert.equal(calls.filter((c) => c.index.startsWith('wazuh-alerts')).length, 0, `${p} queried alerts without a scope`);
        }
    } finally {
        db.tables.wazuh_group_org_map = saved;
    }
});

// ── Client-visible routes ────────────────────────────────────────────────────────────────────

test('org CTI: an executive sees only IPs seen on its own organisation\'s agents and senders', async () => {
    __resetWazuhIOCsForTests(new Date(now - 24 * 3600_000).toISOString());
    const r = await call('GET', '/api/org-cti/iocs', 'executive', A);
    assert.equal(r.status, 200);
    assert.deepEqual(r.data.iocs.filter((i: Row) => i.source === 'wazuh').map((i: Row) => i.value).sort(), ['198.51.100.1', '198.51.100.2']);
    assert.deepEqual(leaks(r.data), []);
    const b = await call('GET', '/api/org-cti/stats', 'executive', B);
    assert.equal(b.data.wazuh_auto, 1);
});

test('NovrAI: accounts without alerts:read get no telemetry — the indexer is not even asked', async () => {
    const r = await call('POST', '/api/novr-ai', 'executive', A, { body: { messages: [{ role: 'user', content: 'what happened today?' }] } });
    assert.ok(r.status === 503 || r.status === 200);
    assert.equal(calls.filter((c) => c.index.startsWith('wazuh-alerts')).length, 0);
});
