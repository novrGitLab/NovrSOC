// CNII Watch integrations: SpiderFoot client (against a local server that speaks SpiderFoot's
// sfwebui API — startscan / scanstatus / scaneventresults / stopscan), the result parser, the
// OpenCTI response parser and the sector classifier. The live smoke tests at the end only run
// with CNII_SMOKE=1 plus SPIDERFOOT_URL / OPENCTI_URL / OPENCTI_TOKEN set.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { scanIP, parseSpiderFootResults, pingSpiderFoot, SpiderFootError, SPIDERFOOT_MODULES } from '../spiderfoot';
import { parseLookup, severityFromConfidence, openctiQuery } from '../opencti';
import { classifySector } from '../cnii-classify';

// A SpiderFoot result row: [lastseen, data, sourceData, module, confidence, visibility, risk,
// hash, fp, parentFp, eventType], with data HTML-escaped as sfwebui does.
const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
const row = (type: string, data: string, module = 'sfp_test') => ['2026-10-01 10:00:00', esc(data), '196.46.244.1', module, 100, 100, 0, 'h', 0, 0, type];

const ROWS = [
    row('INTERNET_NAME', 'portal.inec.gov.ng', 'sfp_dnsresolve'),
    row('INTERNET_NAME', 'api.inec.gov.ng', 'sfp_dnsresolve'),
    row('INTERNET_NAME', 'portal.inec.gov.ng', 'sfp_dnsresolve'),
    row('DOMAIN_NAME', 'inec.gov.ng', 'sfp_dnsresolve'),
    row('NETBLOCK_OWNER', '196.46.244.0/22', 'sfp_ripe'),
    row('BGP_AS_MEMBER', '37282', 'sfp_ripe'),
    row('RAW_RIR_DATA', '{"data": {"records": [[{"key": "inetnum", "value": "196.46.244.0 - 196.46.247.255"}, {"key": "netname", "value": "INEC-NET"}, {"key": "descr", "value": "Independent National Electoral Commission"}]]}}', 'sfp_ripe'),
    row('RAW_RIR_DATA', "{'asn': 37282, 'name': 'MAINONE', 'description_short': 'MainOne Cable Company'}", 'sfp_bgpview'),
    row('GEOINFO', 'Abuja, FCT, NG', 'sfp_ipinfo'),
    row('TCP_PORT_OPEN', '196.46.244.1:443', 'sfp_portscan_tcp'),
    row('TCP_PORT_OPEN', '196.46.244.1:22', 'sfp_shodan'),
    row('TCP_PORT_OPEN', '196.46.244.1:443', 'sfp_shodan'),
    row('VULNERABILITY_CVE_CRITICAL', 'CVE-2024-6387\n<SFURL>https://nvd.nist.gov/vuln/detail/CVE-2024-6387</SFURL>\nScore: 8.1\nDescription: regreSSHion', 'sfp_shodan'),
    row('VULNERABILITY_CVE_HIGH', 'CVE-2023-44487\n<SFURL>https://nvd.nist.gov/vuln/detail/CVE-2023-44487</SFURL>\nScore: Unknown\nDescription: Rapid Reset', 'sfp_shodan'),
    row('MALICIOUS_IPADDR', 'VirusTotal [196.46.244.1]', 'sfp_virustotal'),
];

test('parser reads SpiderFoot event formats', () => {
    const r = parseSpiderFootResults(ROWS);
    assert.equal(r.hostname, 'portal.inec.gov.ng');
    assert.deepEqual(r.subdomains, ['api.inec.gov.ng']);
    assert.deepEqual(r.domains, ['inec.gov.ng']);
    assert.equal(r.owner, 'Independent National Electoral Commission'); // not the NETBLOCK_OWNER CIDR
    assert.equal(r.org, 'MainOne Cable Company');
    assert.equal(r.asn, 'AS37282');
    assert.equal(r.country, 'NG');
    assert.deepEqual(r.openPorts, [22, 443]);
    assert.deepEqual(r.vulns, [
        { cve: 'CVE-2024-6387', cvss: 8.1, severity: 'critical' },
        { cve: 'CVE-2023-44487', cvss: null, severity: 'high' },
    ]);
    assert.equal(r.threatIntel.length, 1);
    assert.equal(r.threatIntel[0].severity, 'high');
    assert.equal(r.raw, ROWS);
});

test('parser leaves fields empty when SpiderFoot found nothing', () => {
    const r = parseSpiderFootResults([]);
    assert.equal(r.hostname, undefined);
    assert.equal(r.owner, undefined);
    assert.equal(r.asn, undefined);
    assert.deepEqual(r.openPorts, []);
    assert.deepEqual(r.vulns, []);
});

// ── scanIP against a local sfwebui-compatible server ──────────────────────────────────────

let server: Server;
const sf = { statuses: [] as string[], started: [] as Record<string, string>[], stopped: [] as string[], startReply: null as unknown };

before(async () => {
    const app = express();
    app.use(express.urlencoded({ extended: false }));
    app.get('/ping', (_req, res) => res.json(['SUCCESS', '4.0.0']));
    app.post('/startscan', (req, res) => {
        assert.match(String(req.headers.accept), /application\/json/);
        sf.started.push(req.body);
        res.json(sf.startReply ?? ['SUCCESS', 'SCAN1']);
    });
    app.get('/scanstatus', (req, res) => {
        const status = sf.statuses.length > 1 ? sf.statuses.shift()! : sf.statuses[0];
        res.json(['name', req.query.id, 'c', 's', 'e', status, {}]);
    });
    app.get('/scaneventresults', (req, res) => {
        assert.equal(req.query.eventType, 'ALL');
        res.json(ROWS);
    });
    app.get('/stopscan', (req, res) => { sf.stopped.push(String(req.query.id)); res.json(['SUCCESS', '']); });
    server = app.listen(0);
    await new Promise((r) => server.once('listening', r));
    process.env.SPIDERFOOT_URL = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
});

after(() => { server.close(); delete process.env.SPIDERFOOT_URL; });

test('scanIP starts, polls to FINISHED and parses the results', async () => {
    sf.statuses = ['STARTING', 'RUNNING', 'FINISHED'];
    sf.startReply = null;
    const r = await scanIP('196.46.244.1', { pollMs: 5, timeoutMs: 2000 });
    const form = sf.started.at(-1)!;
    assert.equal(form.scantarget, '196.46.244.1');
    assert.equal(form.modulelist, SPIDERFOOT_MODULES.join(','));
    assert.equal(form.usecase, '');
    assert.equal(r.scanId, 'SCAN1');
    assert.equal(r.status, 'FINISHED');
    assert.equal(r.hostname, 'portal.inec.gov.ng');
});

test('scanIP stops the scan and throws on timeout', async () => {
    sf.statuses = ['RUNNING'];
    await assert.rejects(scanIP('196.46.244.1', { pollMs: 5, timeoutMs: 30 }), (e: unknown) => e instanceof SpiderFootError && e.kind === 'timeout');
    assert.equal(sf.stopped.at(-1), 'SCAN1');
});

test('scanIP reports a failed scan and a refused start', async () => {
    sf.statuses = ['ERROR-FAILED'];
    await assert.rejects(scanIP('196.46.244.1', { pollMs: 5 }), (e: unknown) => e instanceof SpiderFootError && e.kind === 'failed');
    sf.startReply = ['ERROR', 'Unrecognised target type.'];
    await assert.rejects(scanIP('196.46.244.1', { pollMs: 5 }), /Unrecognised target type/);
    sf.startReply = null;
});

test('scanIP reports an unreachable SpiderFoot', async () => {
    const saved = process.env.SPIDERFOOT_URL;
    process.env.SPIDERFOOT_URL = 'http://127.0.0.1:1';
    await assert.rejects(scanIP('196.46.244.1'), (e: unknown) => e instanceof SpiderFootError && e.kind === 'unreachable');
    process.env.SPIDERFOOT_URL = saved;
});

test('pingSpiderFoot reads the version', async () => {
    assert.equal(await pingSpiderFoot(), '4.0.0');
});

// ── OpenCTI parsing ───────────────────────────────────────────────────────────────────────

test('OpenCTI lookup parses relationships in both directions and exact indicators', () => {
    const ip = '41.203.64.1';
    const intel = parseLookup(ip, {
        stixCyberObservables: { edges: [{ node: {
            id: 'obs1',
            indicators: { edges: [{ node: { id: 'ind1', name: ip, confidence: 85, indicator_types: ['malicious-activity'] } }] },
            stixCoreRelationships: { edges: [
                { node: { relationship_type: 'related-to', confidence: 65, from: { id: 'obs1' }, to: { id: 'm1', entity_type: 'Malware', name: 'Cobalt Strike' } } },
                { node: { relationship_type: 'communicates-with', confidence: 30, from: { id: 'm2', entity_type: 'Malware', name: 'Emotet' }, to: { id: 'obs1' } } },
                { node: { relationship_type: 'uses', confidence: 50, from: { id: 'obs1' }, to: { id: 'ap', entity_type: 'Attack-Pattern', name: 'Phishing', x_mitre_id: 'T1566' } } },
            ] },
        } }] },
        indicators: { edges: [
            { node: { id: 'ind1', name: ip, confidence: 85 } },                                           // duplicate of the linked one
            { node: { id: 'ind2', name: 'x', pattern: `[ipv4-addr:value = '${ip}']`, confidence: 45 } }, // exact, via pattern
            { node: { id: 'ind3', name: '41.203.64.10', pattern: "[ipv4-addr:value = '41.203.64.10']", confidence: 90 } }, // different IP
            { node: { id: 'ind4', name: ip, confidence: 90, revoked: true } },                            // revoked
        ] },
    });
    assert.deepEqual(intel.map((i) => [i.description, i.severity]), [
        ['related-to Cobalt Strike (Malware)', 'high'],
        ['communicates-with Emotet (Malware)', 'low'],
        ['uses T1566 Phishing (Attack-Pattern)', 'medium'],
        ['Indicator: 41.203.64.1 [malicious-activity]', 'critical'],
        ["Indicator: x", 'medium'],
    ]);
    assert.equal(severityFromConfidence(undefined), 'low');
});

// ── Classifier ────────────────────────────────────────────────────────────────────────────

test('classifier matches whole words and picks the sub-entity', () => {
    assert.deepEqual(classifySector('Independent National Electoral Commission', '', '', 'portal.inec.gov.ng'), { sectorId: 'publicadmin', subfield: 'INEC', confidence: 40 });
    assert.deepEqual(classifySector('CBN', 'Central Bank of Nigeria CBN', '', 'gw.cbn.gov.ng'), { sectorId: 'finance', subfield: 'Electronic Transactions / CBN', confidence: 70 });
    assert.deepEqual(classifySector('NNPC Limited', '', '', ''), { sectorId: 'power', subfield: 'Oil & Gas', confidence: 40 });
    assert.equal(classifySector('Nigerian Army', 'Nigerian Army', 'army', 'mail.army.mil.ng').confidence, 85);
});

test('classifier does not fire inside other words and never guesses', () => {
    for (const s of ['Global Telecom', 'California Hosting', 'Amsterdam Datacenter', 'Cuba Networks']) {
        assert.deepEqual(classifySector(s, s, '', ''), { sectorId: '', subfield: '', confidence: 0 }, s);
    }
    assert.deepEqual(classifySector(), { sectorId: '', subfield: '', confidence: 0 });
});

// ── Live smoke tests (opt-in) ─────────────────────────────────────────────────────────────

const smoke = process.env.CNII_SMOKE === '1';

test('live: SpiderFoot /ping answers', { skip: !smoke && 'set CNII_SMOKE=1 and SPIDERFOOT_URL to run' }, async () => {
    process.env.SPIDERFOOT_URL = process.env.CNII_SPIDERFOOT_URL ?? process.env.SPIDERFOOT_URL;
    assert.ok(await pingSpiderFoot());
});

test('live: OpenCTI /graphql answers an introspection query', { skip: !smoke && 'set CNII_SMOKE=1, OPENCTI_URL and OPENCTI_TOKEN to run' }, async () => {
    const d = await openctiQuery<{ __schema?: { queryType?: { name?: string } } }>('query { __schema { queryType { name } } }', {});
    assert.equal(d.__schema?.queryType?.name, 'Query');
});
