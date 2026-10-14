// Phase P2 pipeline health: each check is measured from stored data (fake PostgREST), and the
// four-day-silence case from the 2026-10-13 audit reads as "down", not green.
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'STELLAR_PUSH_ENABLED', 'AUTO_CASE_ENABLED', 'ALERT_STALE_MINUTES']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { startFakePostgrest, type FakePostgrest } from '../../routes/__tests__/fakePostgrest';
import { pipelineChecks } from '../pipelineHealth';

let db: FakePostgrest;
const realLog = { log: console.log, warn: console.warn, error: console.error };
const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();
const byName = async () => Object.fromEntries((await pipelineChecks()).map((c) => [c.name, c]));

before(async () => {
    db = await startFakePostgrest({ alerts: [], alert_quarantine: [], push_state: [], audit_log: [] });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); await db.close(); });
beforeEach(() => { for (const t of ['alerts', 'alert_quarantine', 'push_state', 'audit_log']) db.tables[t].length = 0; });

test('ingestion: fresh is up, an hour+ is degraded, the four-day outage is down, empty is down', async () => {
    assert.equal((await byName())['Alert ingestion'].status, 'down');
    db.tables.alerts.push({ id: 'a', received_at: minutesAgo(5) });
    assert.equal((await byName())['Alert ingestion'].status, 'up');
    db.tables.alerts.length = 0;
    db.tables.alerts.push({ id: 'a', received_at: minutesAgo(90) });
    assert.equal((await byName())['Alert ingestion'].status, 'degraded');
    db.tables.alerts.length = 0;
    db.tables.alerts.push({ id: 'a', received_at: minutesAgo(4 * 24 * 60) });
    const c = (await byName())['Alert ingestion'];
    assert.equal(c.status, 'down');
    assert.match(c.detail, /4 days ago/);
});

test('quarantine with held alerts is degraded and says how many; switched-off jobs read "off"', async () => {
    db.tables.alert_quarantine.push({ wazuh_alert_id: '1' }, { wazuh_alert_id: '2' });
    const c = await byName();
    assert.equal(c['Alert quarantine'].status, 'degraded');
    assert.match(c['Alert quarantine'].detail, /^2 alert/);
    assert.equal(c['Stellar push'].status, 'off');
    assert.equal(c['Automatic cases'].status, 'off');
    assert.equal(c['Audit log'].status, 'up', 'the audit table exists here');
});

test('push: a failure newer than the last success is degraded and names the error', async () => {
    Object.assign(process.env, { STELLAR_PUSH_ENABLED: 'true', STELLAR_PUSH_URL: 'https://poc.example.test/webhook/a/b', STELLAR_PUSH_API_KEY: 'k', STELLAR_PUSH_ORG_IDS: 'acme' });
    try {
        db.tables.push_state.push({ destination: 'stellar', sent_count: 10, retry_count: 1, last_success_at: minutesAgo(30), last_error: '429 rate limited', last_error_at: minutesAgo(2) });
        const c = (await byName())['Stellar push'];
        assert.equal(c.status, 'degraded');
        assert.match(c.detail, /10 delivered.*429 rate limited/);
        assert.doesNotMatch(c.detail, /\bk\b|webhook/, 'no key or URL in the detail');
    } finally {
        for (const k of ['STELLAR_PUSH_ENABLED', 'STELLAR_PUSH_URL', 'STELLAR_PUSH_API_KEY', 'STELLAR_PUSH_ORG_IDS']) delete process.env[k];
    }
});
