// Certificate pinning (lib/pinnedTls.ts) against a local HTTPS server with throwaway
// self-signed certificates generated per run with openssl (no key material is committed —
// the repo ignores *.pem). Skipped, with the reason shown, where openssl is unavailable.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import https from 'https';
import { readFileSync, mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { execFileSync } from 'child_process';
import type { AddressInfo } from 'net';
import { parsePin, pinnedFetch, enforceTlsVerification } from '../pinnedTls';

const dir = mkdtempSync(join(tmpdir(), 'novrsoc-tls-'));
function makeCert(name: string): boolean {
    try {
        execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, `${name}.key.pem`), '-out', join(dir, `${name}.cert.pem`), '-days', '1', '-subj', '/CN=misp.local.test'], { stdio: 'ignore' });
        return true;
    } catch { return false; }
}
const HAVE_OPENSSL = makeCert('pinned') && makeCert('other');
const skip = HAVE_OPENSSL ? false : 'openssl is not available to generate test certificates';
const fx = (f: string) => readFileSync(join(dir, f), 'utf8');
const PINNED = HAVE_OPENSSL ? fx('pinned.cert.pem') : '';
const OTHER = HAVE_OPENSSL ? fx('other.cert.pem') : '';
let url = '';
let server: https.Server | undefined;
let requestsSeen = 0;

before(async () => {
    delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    if (!HAVE_OPENSSL) return;
    const srv = https.createServer({ key: fx('pinned.key.pem'), cert: PINNED }, (req, res) => {
        requestsSeen++;
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ ok: true, method: req.method, auth: req.headers.authorization ?? null, body })); });
    });
    server = srv;
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    // Reached by IP although the certificate says CN=misp.local.test — the typical self-signed case.
    url = `https://127.0.0.1:${(srv.address() as AddressInfo).port}`;
});
after(() => { server?.close(); rmSync(dir, { recursive: true, force: true }); });

test('parsePin accepts PEM, escaped PEM and base64 PEM; rejects junk', { skip }, () => {
    const fp = parsePin(PINNED)!.fingerprint256;
    assert.match(fp, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    assert.equal(parsePin(PINNED.replace(/\n/g, '\\n'))!.fingerprint256, fp);
    assert.equal(parsePin(Buffer.from(PINNED).toString('base64'))!.fingerprint256, fp);
    assert.equal(parsePin('not a certificate'), null);
    assert.equal(parsePin(undefined), null);
});

test('the pinned certificate is trusted, by IP, with headers and body delivered', { skip }, async () => {
    const r = await pinnedFetch(`${url}/users/statistics`, { method: 'POST', headers: { Authorization: 'k', 'Content-Type': 'application/json' }, body: '{"a":1}' }, parsePin(PINNED)!);
    assert.equal(r.status, 200);
    const d = await r.json();
    assert.equal(d.method, 'POST');
    assert.equal(d.auth, 'k');
    assert.equal(d.body, '{"a":1}');
});

test('a different certificate fails the handshake BEFORE the request (and its API key) is sent', { skip }, async () => {
    const before = requestsSeen;
    await assert.rejects(pinnedFetch(`${url}/`, { headers: { Authorization: 'secret-key' } }, parsePin(OTHER)!));
    assert.equal(requestsSeen, before, 'server never received the request');
});

test('without a pin, normal verification applies: a self-signed server is rejected', { skip }, async () => {
    await assert.rejects(fetch(`${url}/`));
});

test('enforceTlsVerification removes a process-wide NODE_TLS_REJECT_UNAUTHORIZED=0', { skip }, async () => {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    const errors: string[] = [];
    const orig = console.error;
    console.error = (m: string) => errors.push(m);
    try { enforceTlsVerification(); } finally { console.error = orig; }
    assert.equal(process.env.NODE_TLS_REJECT_UNAUTHORIZED, undefined);
    assert.ok(errors.some((e) => /disables certificate/.test(e)));
    // And verification is genuinely back on for ordinary requests.
    await assert.rejects(new Promise((resolve, reject) => https.get(`${url}/`, resolve).on('error', reject)));
});
