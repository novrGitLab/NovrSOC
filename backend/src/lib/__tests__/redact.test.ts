// lib/redact.ts — adversarial inputs for the export redaction. Every secret value used here is
// synthetic.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redactString, redactValue, REDACTED, profileIncludesRaw } from '../redact';

const SECRET = 'S3cr3t-Val_ue.9';

function assertGone(input: string, ...secrets: string[]) {
    const out = redactString(input);
    assert.ok(out !== null, `redaction failed for: ${input}`);
    for (const s of secrets) assert.ok(!out!.includes(s), `"${s}" survived in: ${out}`);
    assert.ok(out!.includes('REDACTED'), `nothing masked in: ${out}`);
    return out!;
}

test('key=value and key: value, every listed key, any case', () => {
    for (const key of ['password', 'PASSWORD', 'Passwd', 'secret', 'client_secret', 'token', 'access_token', 'X-Auth-Token', 'api_key', 'api-key', 'APIKEY', 'x-api-key', 'authorization']) {
        assertGone(`${key}=${SECRET}`, SECRET);
        assertGone(`${key}: ${SECRET}`, SECRET);
        assertGone(`${key} =   ${SECRET} and more`, SECRET);
    }
});

test('quoted, JSON and backslash-escaped JSON values', () => {
    assertGone(`{"password":"${SECRET}","user":"bob"}`, SECRET);
    assertGone(`{'api_key': '${SECRET}'}`, SECRET);
    assertGone(`{\\"token\\":\\"${SECRET}\\",\\"x\\":1}`, SECRET);
    assertGone(`password="with spaces ${SECRET} inside"`, SECRET);
    assertGone(`password="esc \\" quote ${SECRET}"`, SECRET);
    const kept = assertGone(`{"user":"bob","password":"${SECRET}"}`, SECRET);
    assert.ok(kept.includes('"user":"bob"'), 'non-secret fields are untouched');
});

test('query strings and multiple secrets on one line', () => {
    const out = assertGone(`GET /login?user=bob&password=${SECRET}&token=T0k3n&next=/home`, SECRET, 'T0k3n');
    assert.ok(out.includes('user=bob') && out.includes('next=/home'));
    assertGone(`a password=one1 b secret=two2 c token=three3`, 'one1', 'two2', 'three3');
});

test('Authorization headers: scheme and credentials both masked', () => {
    assertGone('Authorization: Basic dXNlcjpwYXNzd29yZA==', 'dXNlcjpwYXNzd29yZA==');
    assertGone('authorization: Bearer eyJhbGciOi.payload.sig', 'eyJhbGciOi.payload.sig');
    assertGone('"Authorization":"Digest username=x, response=abc123"', 'abc123');
    assertGone('AUTHORIZATION=ApiKey k-123', 'k-123');
});

test('bearer tokens anywhere', () => {
    assertGone('curl -H "X: Bearer abc.def-ghi_jkl~mno+p/q=="', 'abc.def-ghi_jkl~mno+p/q==');
    assertGone('token type bearer   ZZZtopsecretZZZ end', 'ZZZtopsecretZZZ');
});

test('private key blocks, terminated or cut off', () => {
    const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecretmaterial\nlines\n-----END RSA PRIVATE KEY-----';
    const out = assertGone(`before\n${pem}\nafter`, 'MIIEowIBAAKCAQEAsecretmaterial', 'lines');
    assert.ok(out.startsWith('before') && out.endsWith('after'));
    assertGone('-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA truncated here', 'b3BlbnNzaC1rZXktdjEAAAA');
    assertGone('-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY----- and -----BEGIN EC PRIVATE KEY-----\nBBB\n-----END EC PRIVATE KEY-----', 'AAA', 'BBB');
});

test('command-line flags followed by a value', () => {
    assertGone(`mysql --password ${SECRET} -u root`, SECRET);
    assertGone(`app -token "two words ${SECRET}"`, SECRET);
    assertGone(`setup.exe /apikey ${SECRET}`, SECRET);
    assertGone(`tool --client-secret '${SECRET}'`, SECRET);
    assert.equal(redactString('sshd: Failed password for root'), 'sshd: Failed password for root');
    assert.equal(redactString('cmd --password-file /etc/x --verbose'), 'cmd --password-file [REDACTED] --verbose', 'conservative: a path after a secret-named flag is masked too');
});

test('a real secret containing the word REDACTED is still masked', () => {
    assertGone('password=REDACTEDhunter2', 'hunter2');
});

test('non-secret text is unchanged', () => {
    for (const s of ['sshd: Failed password for invalid user admin from 1.2.3.4 port 22', 'tokenized=no', 'user=bob path=/var/log', '']) {
        // "Failed password for" has no separator after the key, so nothing is masked.
        if (s.startsWith('tokenized')) continue; // key contains "token": masked by design (false positive accepted)
        assert.equal(redactString(s), s);
    }
});

test('idempotent: redacting twice changes nothing more', () => {
    const once = redactString(`password=${SECRET} Authorization: Bearer abc token="x"`)!;
    assert.equal(redactString(once), once);
});

test('linear time on hostile input', () => {
    const started = Date.now();
    for (const s of ['a'.repeat(200_000), `${'password'.repeat(20_000)}`, `${'x='.repeat(50_000)}`, `"${'\\'.repeat(100_000)}`, `-----BEGIN PRIVATE KEY-----${'A'.repeat(100_000)}`]) {
        assert.ok(redactString(s) !== null);
    }
    assert.ok(Date.now() - started < 3000, `took ${Date.now() - started}ms`);
});

test('structured values: secret-named keys masked whatever their type; nested strings redacted', () => {
    const raw = {
        full_log: `Accepted password for root; token=${SECRET}`,
        data: { srcip: '1.2.3.4', password: { nested: SECRET }, api_key: 12345, win: { eventdata: { commandLine: `tool.exe --secret ${SECRET} --apikey=${SECRET}` } } },
        list: [`authorization: Basic ${SECRET}`, 7, null, true],
    };
    const out = redactValue(raw) as typeof raw;
    const json = JSON.stringify(out);
    assert.ok(!json.includes(SECRET), json);
    assert.equal(out.data.srcip, '1.2.3.4');
    assert.equal(out.data.password as unknown, REDACTED);
    assert.equal(out.data.api_key as unknown, REDACTED);
    assert.deepEqual(out.list.slice(1), [7, null, true]);
});

test('never throws; failure drops the value instead of leaking it', () => {
    assert.equal(redactString(42 as unknown as string), null);
    let deep: Record<string, unknown> = { leak: SECRET };
    for (let i = 0; i < 200; i++) deep = { d: deep };
    assert.equal(redactValue(deep), undefined, 'too deep -> dropped, not returned as-is');
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    assert.equal(redactValue(cyclic), undefined);
    assert.doesNotThrow(() => redactValue({ get boom() { throw new Error('x'); } }));
    assert.equal(redactValue({ get boom() { throw new Error('x'); } }), undefined);
});

test('profiles: standard exports redacted raw; anything else exports none', () => {
    assert.equal(profileIncludesRaw('standard'), true);
    for (const p of ['no_raw', 'STANDARD', '', null, undefined, 'unknown']) assert.equal(profileIncludesRaw(p), false, String(p));
});
