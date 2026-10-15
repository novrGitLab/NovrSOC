// Phase P1 automatic case creation: config, threshold, grouping by org + rule + agent + window,
// linking every alert, SOAR-engine case reuse, per-run cap, idempotency across runs, and tenant
// isolation — against the local fake PostgREST. All data is synthetic.
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'AUTO_CASE_ENABLED', 'RESEND_API_KEY', 'BREVO_API_KEY', 'SMTP_HOST', 'SENDGRID_API_KEY']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'crypto';
import { startFakePostgrest, type FakePostgrest, type Row } from '../../routes/__tests__/fakePostgrest';
import { autoCaseConfig, runAutoCaseOnce, groupSourceId, windowStart, AUTO_CASE_ACTOR, type AutoCaseConfig } from '../autoCase';

const A = 'org-a';
const B = 'org-b';
let db: FakePostgrest;
const realLog = { log: console.log, warn: console.warn, error: console.error };
const cfg = (over: Partial<AutoCaseConfig> = {}): AutoCaseConfig => ({ minLevel: 13, groupHours: 24, lookbackHours: 24, maxNewPerRun: 25, ...over });
const ago = (min: number) => new Date(Date.now() - min * 60_000).toISOString();

let seq = 0;
function alert(over: Partial<Row> = {}): Row {
    seq++;
    const row: Row = {
        id: randomUUID(), org_id: A, wazuh_alert_id: `w-${seq}`, rule_id: '100200', rule_level: 13, severity: 'critical',
        rule_description: 'Possible ransomware activity', agent_id: '003', agent_name: 'fileserver', mitre_ids: ['T1486'],
        event_time: '2026-10-14T09:00:00.000Z', received_at: ago(5), raw: { data: { srcip: '203.0.113.9' } }, raw_truncated: false,
        case_id: null, status: 'new', ...over,
    };
    db.tables.alerts.push(row);
    return row;
}
const casesOf = (org: string) => db.tables.cases.filter((c) => c.org_id === org);

before(async () => {
    let caseNo = 0;
    db = await startFakePostgrest({ alerts: [], cases: [], case_timeline: [] }, {}, {
        cases: { status: 'open', auto_closed: false, escalated: false, get case_number() { return `CASE-${++caseNo}`; }, created_at: new Date().toISOString() } as Row,
    });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); await db.close(); });
beforeEach(() => { for (const t of ['alerts', 'cases', 'case_timeline']) db.tables[t].length = 0; });

test('config: off unless exactly "true"; ranges enforced; documented defaults', () => {
    for (const v of [undefined, '', 'TRUE', '1']) assert.ok('error' in autoCaseConfig({ AUTO_CASE_ENABLED: v }));
    assert.deepEqual(autoCaseConfig({ AUTO_CASE_ENABLED: 'true' }), { minLevel: 13, groupHours: 24, lookbackHours: 24, maxNewPerRun: 25 });
    for (const bad of [{ AUTO_CASE_MIN_LEVEL: '3' }, { AUTO_CASE_MIN_LEVEL: '17' }, { AUTO_CASE_GROUP_HOURS: '0' }, { AUTO_CASE_LOOKBACK_HOURS: 'x' }, { AUTO_CASE_MAX_NEW_PER_RUN: '1.5' }]) {
        assert.ok('error' in autoCaseConfig({ AUTO_CASE_ENABLED: 'true', ...bad }), JSON.stringify(bad));
    }
    assert.equal(windowStart('2026-10-14T09:30:00.000Z', 24), '2026-10-14T00:00:00.000Z');
    assert.equal(groupSourceId({ rule_id: '5', agent_id: '7', event_time: '2026-10-14T09:30:00Z' }, 6), '5|7|2026-10-14T06:00:00.000Z');
});

test('repeats of one rule on one agent in a window share a case; every alert is linked', async () => {
    const a1 = alert(); const a2 = alert({ event_time: '2026-10-14T15:00:00.000Z' }); const other = alert({ agent_id: '009', agent_name: 'db-01' });
    const r = await runAutoCaseOnce(cfg());
    assert.deepEqual(r, { examined: 3, linked: 3, created: 2, deferred: 0 });
    const c = casesOf(A).find((x) => x.agent_id === '003')!;
    assert.equal(c.source, 'wazuh-auto');
    assert.equal(c.severity, 'critical');
    assert.equal(c.source_ip, '203.0.113.9');
    assert.equal(c.mitre_technique, 'T1486');
    assert.equal(c.status, 'open');
    assert.equal(a1.case_id, c.id);
    assert.equal(a2.case_id, c.id);
    assert.notEqual(other.case_id, c.id);
    assert.ok(db.tables.case_timeline.some((t) => t.case_id === c.id && /2 alerts linked/.test(String(t.action)) && t.actor === AUTO_CASE_ACTOR));
    assert.equal(a1.status, 'new', 'alert triage is left to the analyst');
});

test('below the threshold, outside the lookback, unsettled or already cased: left alone', async () => {
    alert({ rule_level: 12, severity: 'high' });
    alert({ received_at: ago(26 * 60) });
    alert({ received_at: new Date().toISOString() });
    alert({ case_id: randomUUID() });
    const r = await runAutoCaseOnce(cfg());
    assert.deepEqual(r, { examined: 0, linked: 0, created: 0, deferred: 0 });
    assert.equal(db.tables.cases.length, 0);
    const lower = await runAutoCaseOnce(cfg({ minLevel: 12 }));
    assert.equal(lower.created, 1, 'the threshold is configurable');
});

test('later runs add new occurrences to the same case and never duplicate it', async () => {
    alert();
    await runAutoCaseOnce(cfg());
    const late = alert({ event_time: '2026-10-14T20:00:00.000Z' });
    const r = await runAutoCaseOnce(cfg());
    assert.deepEqual(r, { examined: 1, linked: 1, created: 0, deferred: 0 });
    assert.equal(db.tables.cases.length, 1);
    assert.equal(late.case_id, db.tables.cases[0].id);
    const again = await runAutoCaseOnce(cfg());
    assert.equal(again.examined, 0, 'linked alerts are not reprocessed');
});

test('an alert the SOAR engine already cased is linked to that case, not a new one', async () => {
    const soar = { id: randomUUID(), org_id: A, source: 'wazuh', source_id: 'w-soar', status: 'open', case_number: 'CASE-S' };
    db.tables.cases.push(soar);
    const a = alert({ wazuh_alert_id: 'w-soar' });
    const r = await runAutoCaseOnce(cfg());
    assert.deepEqual(r, { examined: 1, linked: 1, created: 0, deferred: 0 });
    assert.equal(a.case_id, soar.id);
    assert.equal(db.tables.cases.length, 1);
});

test('per-run cap: new cases beyond it wait for the next run; existing cases still get links', async () => {
    for (let i = 0; i < 4; i++) alert({ agent_id: `a${i}` });
    let r = await runAutoCaseOnce(cfg({ maxNewPerRun: 2 }));
    assert.deepEqual([r.created, r.deferred], [2, 2]);
    r = await runAutoCaseOnce(cfg({ maxNewPerRun: 2 }));
    assert.deepEqual([r.created, r.deferred], [2, 0]);
    assert.equal(db.tables.cases.length, 4);
    assert.ok(db.tables.alerts.every((a) => a.case_id));
});

test('tenant isolation: the same rule and agent id in two orgs make two cases, each linked only to its own alerts', async () => {
    const a = alert({ org_id: A }); const b = alert({ org_id: B });
    await runAutoCaseOnce(cfg());
    assert.equal(casesOf(A).length, 1);
    assert.equal(casesOf(B).length, 1);
    assert.equal(a.case_id, casesOf(A)[0].id);
    assert.equal(b.case_id, casesOf(B)[0].id);
});
