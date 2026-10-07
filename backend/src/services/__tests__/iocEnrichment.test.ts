// enrichIOC's per-source timeout (EnrichOptions.timeoutMs). fetch is replaced for the whole file,
// so no request leaves the process.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { enrichIOC } from '../iocEnrichment';

const realFetch = globalThis.fetch;
let mode: 'hang' | 'fail' = 'hang';

before(() => {
    globalThis.fetch = (() => (mode === 'hang'
        ? new Promise<Response>(() => { /* never settles */ })
        : Promise.resolve(new Response('{}', { status: 500 })))) as typeof fetch;
});
after(() => { globalThis.fetch = realFetch; });

const HASH = '44d88612fea8a8f36de82e1278abb02f';

test('a source that never answers is cut off at timeoutMs and reported in timed_out', async () => {
    mode = 'hang';
    const started = Date.now();
    const r = await enrichIOC(HASH, 'hash', { timeoutMs: 100 });
    assert.ok(Date.now() - started < 2000, 'returned near the timeout, not after the source');
    assert.ok(r.timed_out?.includes('threatfox'), `timed_out = ${JSON.stringify(r.timed_out)}`);
    assert.deepEqual(r.sources.threatfox, null);
});

test('sources that answer before the timeout are not reported as timed out', async () => {
    mode = 'fail';
    const r = await enrichIOC(HASH, 'hash', { timeoutMs: 1000 });
    assert.deepEqual(r.timed_out, []);
});

test('without timeoutMs, timed_out is absent (existing callers unchanged)', async () => {
    mode = 'fail';
    const r = await enrichIOC(HASH, 'hash');
    assert.equal(r.timed_out, undefined);
});
