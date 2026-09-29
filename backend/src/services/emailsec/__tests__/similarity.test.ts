import { test } from 'node:test';
import assert from 'node:assert/strict';
import { domainToASCII } from 'url';
import { splitDomain, registrableDomain, editDistance, skeleton, isHomoglyphOf, generateCandidates, resemblance } from '../similarity';

test('splits multi-part public suffixes', () => {
    assert.deepEqual(splitDomain('login.firstbank.com.ng'), { label: 'firstbank', suffix: 'com.ng', subdomain: 'login' });
    assert.equal(registrableDomain('a.b.company.co.uk'), 'company.co.uk');
    assert.equal(registrableDomain('mail.company.com'), 'company.com');
});

test('edit distance counts transpositions as one edit', () => {
    assert.equal(editDistance('company', 'company'), 0);
    assert.equal(editDistance('company', 'compnay'), 1);
    assert.equal(editDistance('company', 'compamy'), 1);
    assert.equal(editDistance('abc', 'xyz'), 3);
});

test('homoglyph skeletons match ASCII and Unicode look-alikes', () => {
    assert.equal(skeleton('c0mpany'), skeleton('company'));
    assert.ok(isHomoglyphOf('rnicrosoft', 'microsoft'));
    assert.ok(isHomoglyphOf('раypal', 'paypal')); // Cyrillic р and а
    assert.ok(!isHomoglyphOf('company', 'company'));
});

test('typosquatting candidates cover the common techniques', () => {
    const c = generateCandidates('company.com', 2000);
    const has = (d: string) => c.some((x) => x.domain === d);
    assert.ok(has('compamy.com'), 'replacement');
    assert.ok(has('compnay.com'), 'transposition');
    assert.ok(has('compny.com'), 'omission');
    assert.ok(has('company-login.com'), 'keyword');
    assert.ok(has('company-support.com'), 'keyword');
    assert.ok(has('c0mpany.com'), 'ascii homoglyph');
    assert.ok(has('company.net'), 'tld swap');
    assert.ok(has(`${domainToASCII('cоmpany')}.com`), 'IDN homoglyph (punycode)');
    assert.ok(!has('company.com'), 'never the domain itself');
    assert.ok(c.every((x) => /^[a-z0-9.-]+$/.test(x.domain)), 'all ASCII / punycode');
});

test('candidate list respects the limit and keeps high-value techniques first', () => {
    const c = generateCandidates('company.com', 25);
    assert.equal(c.length, 25);
    assert.equal(c[0].technique, 'homoglyph');
});

test('resemblance explains how a domain imitates the brand', () => {
    const r = resemblance('company-login.com', 'company.com');
    assert.ok(r?.techniques.includes('keyword'));
    assert.match(r!.reasons.join(), /login/);
    const typo = resemblance('compamy.com', 'company.com');
    assert.ok(typo?.techniques.includes('replacement'));
    const idn = resemblance(`${domainToASCII('cоmpany')}.com`, 'company.com');
    assert.ok(idn?.techniques.includes('homoglyph'));
    assert.ok(resemblance('company.net', 'company.com')?.techniques.includes('tld_swap'));
});

test('own subdomains and unrelated domains are not look-alikes', () => {
    assert.equal(resemblance('mail.company.com', 'company.com'), null);
    assert.equal(resemblance('weather.org', 'company.com'), null);
});
