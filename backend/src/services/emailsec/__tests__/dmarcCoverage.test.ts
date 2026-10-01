// DMARC / SPF / DKIM behaviour end to end through inspectDomain(), with a stubbed resolver.
// Covers the cases found live on cybernovr.com (duplicate DMARC records, Brevo selectors,
// a 1024-bit key) plus each policy level.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'crypto';
import { inspectDomain, setDnsClient } from '../dnsInspect';
import { parseDmarc, authenticationHealth, parseSpf, dmarcStatus, buildDmarcRecord } from '../authRecords';
import { parseDmarcReport } from '../dmarcReport';
import { SAMPLE_REPORT } from './fixtures';

const key = (bits: number) => generateKeyPairSync('rsa', { modulusLength: bits }).publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
const K2048 = key(2048);
const K1024 = key(1024);
function dns(records: Record<string, string[]>) {
    setDnsClient({ txt: async (n) => records[n] ?? [], mx: async () => [], reverse: async () => null });
}
after(() => setDnsClient(null));
const enforcement = (d: ReturnType<typeof parseDmarc>) => authenticationHealth(parseSpf(['v=spf1 mx -all']), d, []).parts.find((p) => p.label.startsWith('DMARC enforcement'))!.points;

test('p=none / p=quarantine / p=reject are understood and scored in order', () => {
    const none = parseDmarc(['v=DMARC1; p=none; rua=mailto:r@x.test']);
    const q = parseDmarc(['v=DMARC1; p=quarantine; rua=mailto:r@x.test']);
    const r = parseDmarc(['v=DMARC1; p=reject; rua=mailto:r@x.test']);
    assert.deepEqual([none.policy, q.policy, r.policy], ['none', 'quarantine', 'reject']);
    assert.deepEqual([enforcement(none), enforcement(q), enforcement(r)], [0, 12, 20]);
    assert.deepEqual([dmarcStatus(none), dmarcStatus(q), dmarcStatus(r)], ['warn', 'pass', 'pass']);
});

test('an invalid DMARC record set never earns enforcement credit, whatever p= says', () => {
    for (const recs of [['v=DMARC1; p=reject;', 'v=DMARC1; p=none;'], ['v=DMARC1; p=quarantine;', 'v=DMARC1; p=quarantine;'], ['v=DMARC1; p=reject; pct=150'], ['v=DMARC1; rua=mailto:a@b.test']]) {
        const d = parseDmarc(recs);
        assert.equal(dmarcStatus(d), 'fail', recs.join(' | '));
        assert.equal(enforcement(d), 0, recs.join(' | '));
    }
});

test('cybernovr.com as found live: duplicate records invalid; brevo1/brevo2 2048-bit + zmail 1024-bit found', async () => {
    dns({
        'example.test': ['v=spf1 include:zohomail.com include:zcsend.net ~all'], 'zohomail.com': ['v=spf1 ip4:1.2.3.0/24 ~all'], 'zcsend.net': ['v=spf1 ip4:5.6.7.0/24 ~all'],
        '_dmarc.example.test': ['v=DMARC1; p=quarantine;', 'v=DMARC1; p=none;'],
        'zmail._domainkey.example.test': [`v=DKIM1; k=rsa; p=${K1024}`],
        'brevo1._domainkey.example.test': [`k=rsa;p=${K2048}`], 'brevo2._domainkey.example.test': [`k=rsa;p=${K2048}`],
    });
    const i = await inspectDomain('example.test');
    assert.equal(i.statuses.dmarc, 'fail');
    assert.equal(i.dmarc.records.length, 2);
    assert.match(i.dmarc.errors.join(), /2 DMARC records/);
    assert.equal(i.health.parts.find((p) => p.label.startsWith('DMARC enforcement'))!.points, 0, 'no enforcement credit for an invalid record set');
    const found = Object.fromEntries(i.dkim.found.map((k) => [k.selector, k.keyBits]));
    assert.deepEqual(found, { zmail: 1024, brevo1: 2048, brevo2: 2048 });
    assert.equal(i.statuses.dkim, 'warn', 'one 1024-bit key → warn, not pass');
    assert.match(i.dkim.found.find((k) => k.selector === 'zmail')!.warnings.join(), /1024-bit/);
    assert.equal(i.statuses.spf, 'pass');
    assert.equal(i.spf.total_lookups, 2);
    // The fix an administrator would publish replaces BOTH records with one.
    assert.equal(buildDmarcRecord(null, 'quarantine', 'reports@novrsoc.test'), 'v=DMARC1; p=quarantine; rua=mailto:reports@novrsoc.test');
});

test('a correct single record after the fix is valid and earns enforcement credit', async () => {
    dns({ 'example.test': ['v=spf1 mx -all'], '_dmarc.example.test': ['v=DMARC1; p=quarantine; rua=mailto:r@x.test'], 'brevo1._domainkey.example.test': [`k=rsa;p=${K2048}`] });
    const i = await inspectDomain('example.test');
    assert.equal(i.statuses.dmarc, 'pass');
    assert.equal(i.health.parts.find((p) => p.label.startsWith('DMARC enforcement'))!.points, 12);
    assert.equal(i.statuses.dkim, 'pass');
});

test('custom selectors are checked alongside the common list', async () => {
    dns({ 'example.test': ['v=spf1 -all'], 'corp2026._domainkey.example.test': [`v=DKIM1; p=${K2048}`] });
    const i = await inspectDomain('example.test', ['corp2026']);
    assert.deepEqual(i.dkim.found.map((k) => k.selector), ['corp2026']);
    assert.equal(i.dkim.selectors_checked[0], 'corp2026');
});

test('alignment comes from the receiver\'s evaluation: SPF-aligned or DKIM-aligned passes DMARC', () => {
    const r = parseDmarcReport(SAMPLE_REPORT);
    const good = r.records[0];
    assert.equal(good.spf_aligned && good.dkim_aligned && good.dmarc_pass, true);
    const bad = r.records[1];
    assert.equal(bad.spf_aligned || bad.dkim_aligned || bad.dmarc_pass, false);
    const dkimOnly = parseDmarcReport(SAMPLE_REPORT.replace('<dkim>fail</dkim><spf>fail</spf>', '<dkim>pass</dkim><spf>fail</spf>')).records[1];
    assert.equal(dkimOnly.dmarc_pass, true, 'DKIM alignment alone is enough');
});
