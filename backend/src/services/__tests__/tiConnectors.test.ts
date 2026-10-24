// Phase P9: OpenCTI and MISP as Threat Information feeds — STIX pattern parsing, what each source
// claims kept as its claim, NovrSOC's own MISP event left out, revoked indicators dropped,
// unconfigured connectors not run, and correlation of registered domains and IP assets. A local
// GraphQL stand-in replaces OpenCTI; nothing on the network is touched.
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'OPENCTI_URL', 'OPENCTI_TOKEN', 'MISP_URL', 'MISP_API_KEY']) delete process.env[k];

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { startFakePostgrest, type FakePostgrest } from '../../routes/__tests__/fakePostgrest';
import { stixToIndicator, fromOpenCti, fromMisp, FEEDS, feedConfigured, storeRecords, correlateOrg, runFeed } from '../threatInfo';

let db: FakePostgrest;
let octi: Server;
const gql: { auth?: string; variables: Record<string, unknown>[] } = { variables: [] };
const realLog = { log: console.log, warn: console.warn, error: console.error };

const node = (over: Record<string, unknown>) => ({ id: `id-${Math.random()}`, standard_id: `indicator--${Math.random()}`, name: 'x', pattern_type: 'stix', confidence: 75, revoked: false, created: '2026-10-01T00:00:00Z', updated_at: '2026-10-14T00:00:00Z', objectLabel: [{ value: 'c2' }, { value: 'T1071' }], createdBy: { name: 'CERT Example' }, indicator_types: ['malicious-activity'], ...over });

before(async () => {
    db = await startFakePostgrest({ ti_feeds: [], ti_indicators: [], ti_indicator_sources: [], ti_matches: [], ti_correlation_state: [], alerts: [], vms_assets: [], vms_findings: [], cases: [] }, {}, { ti_indicators: { status: 'active', tags: [], malware_families: [], threat_types: [], mitre_techniques: [], source_count: 0 } });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'k';
    const app = express();
    app.use(express.json());
    app.post('/graphql', (req, res) => {
        gql.auth = req.headers.authorization;
        gql.variables.push(req.body.variables);
        const page = req.body.variables.after ? 2 : 1;
        res.json({ data: { indicators: {
            pageInfo: { hasNextPage: page === 1, endCursor: page === 1 ? 'c1' : null },
            edges: page === 1
                ? [{ node: node({ pattern: "[ipv4-addr:value = '192.0.2.66']" }) }, { node: node({ pattern: "[domain-name:value = 'bad.example']", revoked: true }) }]
                : [{ node: node({ pattern: "[file:hashes.'SHA-256' = 'AA" + 'a'.repeat(62) + "']" }) }],
        } } });
    });
    octi = app.listen(0);
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); octi.close(); await db.close(); });

test('STIX: only single-comparison patterns become indicators', () => {
    assert.deepEqual(stixToIndicator("[ipv4-addr:value = '192.0.2.1']"), { type: 'ip', value: '192.0.2.1' });
    assert.deepEqual(stixToIndicator("[ipv4-addr:value = '192.0.2.1/32']"), { type: 'ip', value: '192.0.2.1' });
    assert.deepEqual(stixToIndicator("[domain-name:value = 'evil.example']"), { type: 'domain', value: 'evil.example' });
    assert.deepEqual(stixToIndicator("[url:value = 'http://evil.example/a\\'b']"), { type: 'url', value: "http://evil.example/a'b" });
    assert.deepEqual(stixToIndicator("[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']"), { type: 'md5', value: 'd41d8cd98f00b204e9800998ecf8427e' });
    assert.deepEqual(stixToIndicator("[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']")?.type, 'sha1');
    for (const p of ["[ipv4-addr:value = '1.1.1.1'] AND [domain-name:value = 'x.example']", "[network-traffic:dst_port = 443]", "[ipv4-addr:value MATCHES '^10']", '', null]) {
        assert.equal(stixToIndicator(p as string), null, String(p));
    }
});

test('OpenCTI records: revoked dropped, its confidence and labels kept as its claims, complex patterns invalid', async () => {
    const recs = fromOpenCti({ indicators: { edges: [
        { node: node({ pattern: "[ipv4-addr:value = '192.0.2.66']" }) },
        { node: node({ pattern: "[domain-name:value = 'bad.example']", revoked: true }) },
        { node: node({ pattern: "[ipv4-addr:value = '1.1.1.1'] OR [ipv4-addr:value = '1.0.0.1']" }) },
    ] } });
    assert.equal(recs.length, 2);
    assert.equal(recs[0].type, 'ip');
    assert.equal(recs[0].confidence, 75);
    assert.deepEqual(recs[0].tags, ['c2', 'T1071']);
    assert.deepEqual(recs[0].context.techniques, ['T1071']);
    assert.equal(recs[0].context.author, 'CERT Example');
    const counts = await storeRecords('opencti', recs, 30);
    assert.equal(counts.invalid, 1);
    assert.equal(counts.new, 1);
    assert.throws(() => fromOpenCti({ nope: true }), /unexpected response/);
});

// Phase P25: OpenCTI is no longer used. The feed is retired — never configured, never run, never
// contacted — even with its credentials still set; stored OpenCTI provenance is left in place.
test('OpenCTI feed is retired: not configured with credentials set, not runnable, never contacted', async () => {
    process.env.OPENCTI_URL = `http://127.0.0.1:${(octi.address() as AddressInfo).port}`;
    process.env.OPENCTI_TOKEN = 'octi-test-token';
    try {
        assert.equal(feedConfigured('opencti'), false);
        assert.equal(FEEDS.opencti, undefined);
        db.tables.ti_feeds.push({ id: 'opencti', name: 'OpenCTI', url: 'x', enabled: false, validity_days: 30 });
        const r = await runFeed('opencti');
        assert.deepEqual(r, { status: 'failed', error: 'unknown feed' });
        assert.equal(gql.variables.length, 0, 'OpenCTI was not contacted');
        assert.equal(db.tables.ti_feed_runs?.length ?? 0, 0, 'no run recorded');
    } finally { delete process.env.OPENCTI_URL; delete process.env.OPENCTI_TOKEN; }
});

test('MISP records: own collection event left out, types mapped, ports stripped, unknown types invalid', async () => {
    const recs = fromMisp({ response: { Attribute: [
        { uuid: 'u1', event_id: '7', type: 'ip-dst|port', value: '198.51.100.9|8443', timestamp: '1760000000', category: 'Network activity', Tag: [{ name: 'misp-galaxy:mitre-attack-pattern="T1571"' }], Event: { info: 'Partner sharing' } },
        { uuid: 'u2', event_id: '1', type: 'ip-dst', value: '203.0.113.200', timestamp: '1760000000' },
        { uuid: 'u3', event_id: '7', type: 'vulnerability', value: 'cve-2024-3400', timestamp: '1760000000' },
        { uuid: 'u4', event_id: '7', type: 'email-src', value: 'x@example.test', timestamp: '1760000000' },
    ] } }, '1');
    assert.deepEqual(recs.map((r) => [r.type, r.value]), [['ip', '198.51.100.9'], ['cve', 'cve-2024-3400'], [undefined, 'x@example.test']]);
    assert.equal(recs[0].confidence, null, 'MISP states no confidence; none is made up');
    assert.deepEqual(recs[0].context.techniques, ['T1571']);
    assert.equal(recs[0].context.event_info, 'Partner sharing');
    assert.equal(feedConfigured('misp'), false);
    await assert.rejects(FEEDS.misp.fetch(), /not configured/);
});

test('correlation: registered domains and bare IP assets match indicators', async () => {
    db.tables.ti_indicators.push({ id: 'i-d', type: 'domain', value: 'portal.cnii.test', status: 'active' }, { id: 'i-ip', type: 'ip', value: '192.0.2.77', status: 'active' });
    db.tables.vms_assets.push(
        { id: 'a-d', org_id: 'org-a', asset_type: 'domain', value: 'portal.cnii.test', ips: [], status: 'active' },
        { id: 'a-ip', org_id: 'org-a', asset_type: 'ip', value: '192.0.2.77', ips: [], status: 'active' },
        { id: 'a-other', org_id: 'org-b', asset_type: 'ip', value: '192.0.2.77', ips: [], status: 'active' },
    );
    const r = await correlateOrg('org-a');
    assert.equal(r.matches_new, 2);
    assert.deepEqual(db.tables.ti_matches.map((m) => [m.org_id, m.entity_id]).sort(), [['org-a', 'a-d'], ['org-a', 'a-ip']]);
});
