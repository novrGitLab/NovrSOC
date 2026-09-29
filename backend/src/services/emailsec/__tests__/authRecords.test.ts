import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'crypto';
import {
    parseSpf, parseDmarc, parseDkim, buildDmarcRecord, authenticationHealth, spfStatus, dmarcStatus, dkimStatus, domainStatusFromScore,
} from '../authRecords';

const pubKey = (bits: number) => generateKeyPairSync('rsa', { modulusLength: bits }).publicKey.export({ format: 'der', type: 'spki' }).toString('base64');

// ── SPF ──

test('SPF: valid record parses mechanisms, all qualifier and lookup count', () => {
    const r = parseSpf(['google-site-verification=abc', 'v=spf1 ip4:203.0.113.0/24 include:_spf.google.com mx ~all']);
    assert.equal(r.exists, true);
    assert.equal(r.all, '~');
    assert.equal(r.lookups, 2); // include + mx
    assert.deepEqual(r.includes, ['_spf.google.com']);
    assert.deepEqual(r.errors, []);
    assert.equal(spfStatus(r), 'pass');
});

test('SPF: missing record is "missing", not a failure of a published record', () => {
    const r = parseSpf(['v=DMARC1; p=none']);
    assert.equal(r.exists, false);
    assert.equal(spfStatus(r), 'missing');
    assert.ok(r.recommendations.length > 0);
});

test('SPF: multiple records is a permerror', () => {
    const r = parseSpf(['v=spf1 -all', 'v=spf1 include:x.com -all']);
    assert.match(r.errors.join(), /2 SPF records/);
    assert.equal(spfStatus(r), 'fail');
});

test('SPF: +all is an error, ?all a warning, ptr deprecated', () => {
    assert.match(parseSpf(['v=spf1 +all']).errors.join(), /\+all/);
    assert.match(parseSpf(['v=spf1 a ?all']).warnings.join(), /neutral/);
    assert.match(parseSpf(['v=spf1 ptr -all']).warnings.join(), /deprecated/);
});

test('SPF: more than 10 lookups and bad ip4 are errors', () => {
    const many = `v=spf1 ${Array.from({ length: 11 }, (_, i) => `include:s${i}.example.com`).join(' ')} -all`;
    assert.match(parseSpf([many]).errors.join(), /11 DNS lookups/);
    assert.match(parseSpf(['v=spf1 ip4:300.1.1.1 -all']).errors.join(), /not a valid IPv4/);
    assert.deepEqual(parseSpf(['v=spf1 ip6:2001:db8::/32 -all']).errors, []);
});

test('SPF: unknown mechanism is an error; no all is a warning', () => {
    assert.match(parseSpf(['v=spf1 foo:bar -all']).errors.join(), /not a valid SPF mechanism/);
    assert.match(parseSpf(['v=spf1 mx']).warnings.join(), /no "all"/);
});

// ── DMARC ──

test('DMARC: policy extraction with defaults', () => {
    const r = parseDmarc(['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']);
    assert.equal(r.policy, 'reject');
    assert.equal(r.subdomainPolicy, 'reject');
    assert.equal(r.pct, 100);
    assert.equal(r.adkim, 'r');
    assert.deepEqual(r.rua, ['mailto:dmarc@example.com']);
    assert.equal(dmarcStatus(r), 'pass');
});

test('DMARC: sp, pct, strict alignment', () => {
    const r = parseDmarc(['v=DMARC1; p=quarantine; sp=none; pct=50; adkim=s; aspf=s; rua=mailto:a@b.com']);
    assert.equal(r.subdomainPolicy, 'none');
    assert.equal(r.pct, 50);
    assert.equal(r.adkim, 's');
    assert.match(r.warnings.join(), /pct=50/);
    assert.match(r.warnings.join(), /weaker policy/);
});

test('DMARC: missing p, invalid values and v not first are errors', () => {
    assert.match(parseDmarc(['v=DMARC1; rua=mailto:a@b.com']).errors.join(), /"p"/);
    assert.match(parseDmarc(['v=DMARC1; p=block']).errors.join(), /not a valid policy/);
    assert.match(parseDmarc(['v=DMARC1; p=none; pct=150']).errors.join(), /pct=150/);
    assert.match(parseDmarc(['v=DMARC1; p=none; rua=https://x.com']).errors.join(), /mailto/);
});

test('DMARC: p=none warns and has no rua warning', () => {
    const r = parseDmarc(['v=DMARC1; p=none']);
    assert.equal(dmarcStatus(r), 'warn');
    assert.match(r.warnings.join(), /only monitors/);
    assert.match(r.warnings.join(), /No "rua"/);
});

test('DMARC: missing and duplicate records', () => {
    assert.equal(dmarcStatus(parseDmarc([])), 'missing');
    assert.match(parseDmarc(['v=DMARC1; p=none', 'v=DMARC1; p=reject']).errors.join(), /2 DMARC records/);
});

test('buildDmarcRecord keeps existing tags and swaps the policy', () => {
    const cur = parseDmarc(['v=DMARC1; p=none; rua=mailto:r@x.com; adkim=s']);
    assert.equal(buildDmarcRecord(cur, 'reject'), 'v=DMARC1; p=reject; rua=mailto:r@x.com; adkim=s');
    assert.equal(buildDmarcRecord(null, 'quarantine', 'reports@novrsoc.com'), 'v=DMARC1; p=quarantine; rua=mailto:reports@novrsoc.com');
});

// ── DKIM ──

test('DKIM: 2048-bit RSA key passes with its size measured', () => {
    const r = parseDkim('selector1', [`v=DKIM1; k=rsa; p=${pubKey(2048)}`]);
    assert.equal(r.exists, true);
    assert.equal(r.keyBits, 2048);
    assert.deepEqual(r.errors, []);
    assert.equal(dkimStatus([r]), 'pass');
});

test('DKIM: 1024-bit key warns; revoked and garbage keys are flagged', () => {
    assert.match(parseDkim('s', [`v=DKIM1; p=${pubKey(1024)}`]).warnings.join(), /1024-bit/);
    const revoked = parseDkim('s', ['v=DKIM1; p=']);
    assert.equal(revoked.revoked, true);
    assert.match(parseDkim('s', ['v=DKIM1; p=!!notbase64']).errors.join(), /base64/);
    assert.match(parseDkim('s', ['v=DKIM1; p=QUJD']).errors.join(), /could not be decoded/);
});

test('DKIM: not found under probed selectors is "not_found", not a failure', () => {
    assert.equal(parseDkim('s', []).exists, false);
    assert.equal(dkimStatus([]), 'not_found');
});

// ── Health ──

test('Health score explains itself and maps to a status', () => {
    const good = authenticationHealth(parseSpf(['v=spf1 mx -all']), parseDmarc(['v=DMARC1; p=reject; rua=mailto:a@b.com']), [parseDkim('s', [`p=${pubKey(2048)}`])]);
    assert.equal(good.score, 100);
    assert.equal(domainStatusFromScore(good.score), 'healthy');
    const none = authenticationHealth(parseSpf([]), parseDmarc([]), []);
    assert.equal(none.score, 0);
    assert.equal(domainStatusFromScore(none.score), 'critical');
    assert.ok(none.parts.every((p) => p.label && p.max > 0));
});

test('duplicate DMARC records: invalid, all records listed, and no enforcement credit', () => {
    const d = parseDmarc(['v=DMARC1; p=quarantine;', 'v=DMARC1; p=none;']);
    assert.equal(dmarcStatus(d), 'fail');
    assert.equal(d.records.length, 2);
    const h = authenticationHealth(parseSpf(['v=spf1 mx ~all']), d, []);
    assert.equal(h.parts.find((p) => p.label.startsWith('DMARC enforcement'))!.points, 0);
    assert.equal(h.parts.find((p) => p.label === 'DMARC published and valid')!.points, 0);
});
