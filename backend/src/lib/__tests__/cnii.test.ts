// CNII Watch integrations: SpiderFoot client (against a local server that speaks SpiderFoot's
// sfwebui API — startscan / scanstatus / scaneventresults / stopscan), the result parser, the
// OpenCTI response parser and the sector classifier. The live smoke tests at the end only run
// with CNII_SMOKE=1 plus SPIDERFOOT_URL / OPENCTI_URL / OPENCTI_TOKEN set.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { scanIP, parseSpiderFootResults, pingSpiderFoot, cleanAsHolder, SpiderFootError, SPIDERFOOT_MODULES } from '../spiderfoot';
import { parseLookup, severityFromConfidence, openctiQuery } from '../opencti';
import { classifySector, assessCnii, CNII_OPERATOR_ASNS } from '../cnii-classify';

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
    assert.equal(r.affiliateIPs, undefined);
    assert.equal(r.maliciousFlags, undefined);
    assert.equal(r.emails, undefined);
});

test('parser extracts the extended OSINT fields and omits empty ones', () => {
    const r = parseSpiderFootResults([
        row('GEOINFO', 'Lagos, Lagos, NG', 'sfp_ipinfo'),
        row('AFFILIATE_IPADDR', '8.8.8.8', 'sfp_crossref'),
        row('MALICIOUS_IPADDR', 'badguy.example', 'sfp_abusech'),
        row('BLACKLISTED_IPADDR', 'spamhaus', 'sfp_spamhaus'),
        row('LINKED_URL_INTERNAL', 'https://a.gov.ng/x', 'sfp_spider'),
        row('EMAILADDR', 'soc@a.gov.ng', 'sfp_email'),
        row('PHONE_NUMBER', '+2348000000000', 'sfp_phone'),
        row('SSL_CERTIFICATE_ISSUED', 'CN=a.gov.ng', 'sfp_sslcert'),
        row('WEBSERVER_BANNER', 'nginx/1.18.0', 'sfp_spider'),
    ]);
    assert.equal(r.city, 'Lagos');
    assert.equal(r.region, 'Lagos');
    assert.equal(r.country, 'NG');
    assert.deepEqual(r.affiliateIPs, ['8.8.8.8']);
    assert.equal(r.maliciousFlags?.length, 2);
    assert.ok(r.maliciousFlags?.some((f) => /sfp_abusech/.test(f)));
    assert.deepEqual(r.linkedURLs, ['https://a.gov.ng/x']);
    assert.deepEqual(r.emails, ['soc@a.gov.ng']);
    assert.deepEqual(r.phones, ['+2348000000000']);
    assert.deepEqual(r.sslCerts, ['CN=a.gov.ng']);
    assert.deepEqual(r.banners, ['nginx/1.18.0']);
    assert.equal(r.domains.length, 0); // no DOMAIN_NAME event → empty, not a fake value
});

test('parser reads org from GEOINFO JSON and strips the ASN prefix', () => {
    const r = parseSpiderFootResults([
        row('GEOINFO', '{"city":"Lagos","region":"Lagos","country":"NG","org":"AS29465 MTN NIGERIA Communication limited"}', 'sfp_ipinfo'),
    ]);
    assert.equal(r.org, 'MTN NIGERIA Communication limited');
    assert.equal(r.country, 'NG');
    assert.equal(r.city, 'Lagos');
});

test('parser takes owner from PROVIDER when no registry record names it', () => {
    const r = parseSpiderFootResults([row('PROVIDER', 'Example Hosting Ltd', 'sfp_provider')]);
    assert.equal(r.owner, 'Example Hosting Ltd');
});

test('assessCnii rates likelihood from independent signals', () => {
    // Known operator ASN + sector matched → confirmed.
    assert.equal(assessCnii(true, { asn: 'AS29465' }).likelihood, 'confirmed');
    // Sector matched + a core-network hostname label → likely.
    const likely = assessCnii(true, { asn: 'AS12345', hostname: 'core.gw.example.ng' });
    assert.equal(likely.likelihood, 'likely');
    assert.ok(likely.signals.some((s) => /core/.test(s)));
    // Sector matched, no other signal → possible.
    assert.equal(assessCnii(true, { asn: 'AS12345', hostname: 'www.example.ng' }).likelihood, 'possible');
    // No sector match → unlikely, whatever else.
    assert.equal(assessCnii(false, { asn: 'AS29465' }).likelihood, 'unlikely');
    // SCADA/BGP ports and malicious flags are signals too.
    assert.equal(assessCnii(true, { openPorts: [179] }).likelihood, 'likely');
    assert.equal(assessCnii(true, { openPorts: [443, 8443] }).likelihood, 'likely');
    assert.equal(assessCnii(true, { maliciousFlags: ['x: y'] }).likelihood, 'likely');
    assert.ok(CNII_OPERATOR_ASNS.AS29465);
    // Only verified Nigerian operators belong here; foreign ASNs must stay out.
    assert.deepEqual(Object.keys(CNII_OPERATOR_ASNS).sort(), ['AS29091', 'AS29465', 'AS36873', 'AS36922', 'AS36923', 'AS37018', 'AS37076', 'AS37148', 'AS37637']);
    for (const foreign of ['AS20858', 'AS37705', 'AS29614', 'AS328274', 'AS37558', 'AS30999', 'AS328088']) {
        assert.equal(CNII_OPERATOR_ASNS[foreign], undefined, foreign);
    }
});

// ── scanIP against a local sfwebui-compatible server ──────────────────────────────────────

let server: Server;
const sf = { statuses: [] as string[], started: [] as Record<string, string>[], stopped: [] as string[], startReply: null as unknown, rows: ROWS as unknown[] };

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
        res.json(sf.rows);
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

// What this SpiderFoot instance actually returns for a Nigerian IP (seen on live scans): the AS
// number and a plain-text GEOINFO, with no registry record naming the organisation.
const TYPICAL_ROWS = [
    row('ROOT', '102.89.0.1', ''),
    row('IP_ADDRESS', '102.89.0.1', 'SpiderFoot UI'),
    row('BGP_AS_MEMBER', '29465', 'sfp_ripe'),
    row('NETBLOCK_MEMBER', '102.89.0.0/24', 'sfp_ripe'),
    row('GEOINFO', 'Lagos, Lagos, NG', 'sfp_ipinfo'),
];

test('scanIP names the organisation from the AS holder when SpiderFoot has none', async () => {
    sf.statuses = ['FINISHED'];
    sf.rows = TYPICAL_ROWS;
    const asked: string[] = [];
    const r = await scanIP('102.89.0.1', { pollMs: 5, holderOf: async (asn) => { asked.push(asn); return 'VCG-AS MTN NIGERIA Communication limited'; } });
    sf.rows = ROWS;
    assert.deepEqual(asked, ['AS29465']);
    assert.equal(r.asn, 'AS29465');
    assert.equal(r.country, 'NG');
    assert.equal(r.org, 'MTN NIGERIA Communication limited');
    assert.equal(r.owner, 'MTN NIGERIA Communication limited');
    assert.deepEqual(r.warnings, []);
    assert.deepEqual(classifySector(r.owner, r.org, r.asn, r.hostname), { sectorId: 'ict', subfield: 'Communications Companies', confidence: 55 });
});

test('scanIP keeps registry names and only looks up the AS holder when needed', async () => {
    sf.statuses = ['FINISHED'];
    let called = false;
    const r = await scanIP('196.46.244.1', { pollMs: 5, holderOf: async () => { called = true; return 'X'; } });
    assert.equal(called, false);
    assert.equal(r.org, 'MainOne Cable Company');
});

test('scanIP says so when the AS holder lookup finds nothing', async () => {
    sf.statuses = ['FINISHED'];
    sf.rows = TYPICAL_ROWS;
    const r = await scanIP('102.89.0.1', { pollMs: 5, holderOf: async () => { throw new Error('down'); } });
    sf.rows = ROWS;
    assert.equal(r.org, undefined);
    assert.equal(r.owner, undefined);
    assert.match(r.warnings[0], /AS29465/);
});

test('cleanAsHolder strips the AS handle', () => {
    assert.equal(cleanAsHolder('VCG-AS MTN NIGERIA Communication limited'), 'MTN NIGERIA Communication limited');
    assert.equal(cleanAsHolder('AS29465 MTN NIGERIA Communication limited'), 'MTN NIGERIA Communication limited');
    assert.equal(cleanAsHolder('SWIFT NETWORKS LIMITED - SWIFT NETWORKS LIMITED'), 'SWIFT NETWORKS LIMITED');
    assert.equal(cleanAsHolder('Comores Telecom - Comores Telecom'), 'Comores Telecom');
    assert.equal(cleanAsHolder('Nigerian Communications Commission'), 'Nigerian Communications Commission');
    assert.equal(cleanAsHolder('MTNNS-AS'), 'MTNNS-AS');
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

test('live: RIPE Stat names AS29465 as MTN Nigeria', { skip: !smoke && 'set CNII_SMOKE=1 to run' }, async () => {
    const { asHolder } = await import('../../services/ripeStat');
    const holder = await asHolder('AS29465');
    assert.ok(holder);
    assert.equal(cleanAsHolder(holder), 'MTN NIGERIA Communication limited');
});

test('live: OpenCTI /graphql answers an introspection query', { skip: !smoke && 'set CNII_SMOKE=1, OPENCTI_URL and OPENCTI_TOKEN to run' }, async () => {
    const d = await openctiQuery<{ __schema?: { queryType?: { name?: string } } }>('query { __schema { queryType { name } } }', {});
    assert.equal(d.__schema?.queryType?.name, 'Query');
});
