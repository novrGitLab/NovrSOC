// NVIDIA provider (services/nvidia.ts) and the NovrAI chat route that uses it: configuration,
// missing key, the key-checking health probe, answer extraction, and the chat route's success,
// malformed-answer, rate-limit and timeout paths. No network — the client and probe are faked.
for (const k of ['NVIDIA_API_KEY', 'AI_MODEL', 'AI_FALLBACK_MODEL', 'AI_TIMEOUT_MS', 'GEMINI_API_KEY', 'WAZUH_INDEXER_HOST', 'WAZUH_INDEXER_PASSWORD']) delete process.env[k];

import { test, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import OpenAI from 'openai';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import {
    NVIDIA_BASE_URL, DEFAULT_NVIDIA_MODEL, AI_MODEL, AI_FALLBACK_MODEL, AI_TIMEOUT_MS, nvidiaConfigured, getNvidiaClient,
    setNvidiaClientForTests, setNvidiaProbeFetchForTests, probeNvidia, describeNvidiaError, completionText, type NvidiaClient,
} from '../nvidia';
import { parseJsonAnswer, outputSchema } from '../ai';
import { z } from 'zod';
import novrAiRouter from '../../routes/novr-ai';

const KEY = 'nvapi-test-secret-value';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const logged: string[] = [];
let server: Server;
let base = '';

before(() => {
    const app = express();
    app.use(express.json());
    app.use('/api/novr-ai', novrAiRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = (...a: unknown[]) => { logged.push(a.map(String).join(' ')); };
});
after(() => { Object.assign(console, realLog); server.close(); });
afterEach(() => {
    for (const k of ['NVIDIA_API_KEY', 'AI_MODEL', 'AI_FALLBACK_MODEL', 'AI_TIMEOUT_MS']) delete process.env[k];
    setNvidiaClientForTests(null);
    setNvidiaProbeFetchForTests(null);
});

test('configuration: NVIDIA endpoint, confirmed default model, env overrides, placeholders count as unset', () => {
    assert.equal(NVIDIA_BASE_URL, 'https://integrate.api.nvidia.com/v1');
    assert.equal(DEFAULT_NVIDIA_MODEL, 'nvidia/nemotron-3-super-120b-a12b');
    assert.equal(AI_MODEL(), DEFAULT_NVIDIA_MODEL);
    assert.equal(AI_FALLBACK_MODEL(), null);
    assert.equal(AI_TIMEOUT_MS(), 120_000);
    process.env.AI_MODEL = '  nvidia/other  ';
    process.env.AI_TIMEOUT_MS = '30000';
    assert.equal(AI_MODEL(), 'nvidia/other');
    assert.equal(AI_TIMEOUT_MS(), 30_000);
    process.env.AI_TIMEOUT_MS = '5';
    assert.equal(AI_TIMEOUT_MS(), 120_000, 'implausibly short timeouts are ignored');
    for (const v of ['', '   ', 'your-key-here', '[GET FROM build.nvidia.com]', 'REPLACE_WHEN_OBTAINED']) {
        process.env.NVIDIA_API_KEY = v;
        assert.equal(nvidiaConfigured(), false, `"${v}" is not a key`);
    }
    process.env.NVIDIA_API_KEY = KEY;
    assert.equal(nvidiaConfigured(), true);
});

test('missing key: no client, and the probe says so without calling out', async () => {
    assert.equal(getNvidiaClient(), null);
    let called = false;
    setNvidiaProbeFetchForTests((async () => { called = true; return new Response(null, { status: 400 }); }) as typeof fetch);
    const p = await probeNvidia();
    assert.deepEqual([p.configured, p.reachable, p.status, p.detail], [false, false, 'down', 'NVIDIA_API_KEY is not set']);
    assert.equal(called, false);
});

test('real client points at NVIDIA with the key, and is rebuilt when the key rotates', () => {
    process.env.NVIDIA_API_KEY = KEY;
    const c = getNvidiaClient() as unknown as OpenAI;
    assert.ok(c instanceof OpenAI);
    assert.equal(c.baseURL, NVIDIA_BASE_URL);
    assert.equal(getNvidiaClient(), c, 'reused while the key is unchanged');
    process.env.NVIDIA_API_KEY = 'nvapi-rotated';
    assert.notEqual(getNvidiaClient(), c);
});

test('health probe: sends an empty request with the bearer key and maps every status honestly', async () => {
    process.env.NVIDIA_API_KEY = KEY;
    let seen: { url: string; init: RequestInit } | null = null;
    const answer = (status: number) => setNvidiaProbeFetchForTests((async (url: string, init: RequestInit) => { seen = { url, init }; return new Response('{}', { status }); }) as typeof fetch);
    answer(400);
    const ok = await probeNvidia();
    assert.deepEqual([ok.reachable, ok.status], [true, 'up']);
    assert.equal(seen!.url, `${NVIDIA_BASE_URL}/chat/completions`);
    assert.equal((seen!.init.headers as Record<string, string>).Authorization, `Bearer ${KEY}`);
    assert.deepEqual(JSON.parse(String(seen!.init.body)).messages, [], 'nothing to generate from');
    assert.ok(!JSON.stringify(ok).includes(KEY), 'the key never appears in the result');
    const cases: [number, boolean, string, RegExp][] = [
        [401, false, 'down', /rejected/], [403, false, 'down', /rejected/], [404, false, 'down', /not found/],
        [429, true, 'degraded', /rate limited/], [502, false, 'degraded', /502/], [422, true, 'up', /Key accepted/],
    ];
    for (const [status, reachable, state, detail] of cases) {
        answer(status);
        const p = await probeNvidia();
        assert.deepEqual([p.reachable, p.status], [reachable, state], `HTTP ${status}`);
        assert.match(p.detail, detail);
    }
    setNvidiaProbeFetchForTests((async () => { throw Object.assign(new Error('timed out'), { name: 'TimeoutError' }); }) as typeof fetch);
    assert.match((await probeNvidia()).detail, /timed out/);
    setNvidiaProbeFetchForTests((async () => { throw new TypeError('fetch failed'); }) as typeof fetch);
    assert.match((await probeNvidia()).detail, /Could not reach/);
});

test('error descriptions are short and never include provider bodies', () => {
    const h = new Headers();
    assert.equal(describeNvidiaError(new OpenAI.AuthenticationError(401, { detail: KEY }, 'x', h)), 'The API key was rejected');
    assert.equal(describeNvidiaError(new OpenAI.PermissionDeniedError(403, undefined, 'x', h)), 'The API key may not use this model');
    assert.equal(describeNvidiaError(new OpenAI.NotFoundError(404, undefined, 'x', h)), 'The configured model was not found');
    assert.match(describeNvidiaError(new OpenAI.RateLimitError(429, undefined, 'x', h)), /Rate limited/);
    assert.equal(describeNvidiaError(new OpenAI.APIConnectionTimeoutError()), 'The AI provider timed out');
    assert.equal(describeNvidiaError(new OpenAI.APIConnectionError({ message: 'x' })), 'Could not reach the AI provider');
    assert.equal(describeNvidiaError(new OpenAI.InternalServerError(500, undefined, 'x', h)), 'AI provider error 500');
});

test('answer extraction: reasoning removed, refusals surfaced, malformed shapes yield nothing', () => {
    const c = (content: unknown, extra = {}) => ({ choices: [{ finish_reason: 'stop', message: { content, ...extra } }] });
    assert.equal(completionText(c('<think>hmm</think>\n\nAnswer')).text, 'Answer');
    assert.equal(completionText(c('stray reasoning</think>Answer')).text, 'Answer');
    assert.equal(completionText(c(null, { refusal: 'no' })).refusal, 'no');
    for (const bad of [null, {}, { choices: [] }, { choices: [{}] }, c(42)]) assert.equal(completionText(bad).text, '');
    assert.deepEqual(parseJsonAnswer('{"a":1}'), { a: 1 });
    assert.deepEqual(parseJsonAnswer('```json\n{"a":1}\n```'), { a: 1 });
    assert.deepEqual(parseJsonAnswer('Here you go: {"a":1} hope that helps'), { a: 1 });
    for (const bad of ['', 'not json', '{"a":', '{oops}']) assert.equal(parseJsonAnswer(bad), undefined);
    const schema = outputSchema(z.object({ a: z.string(), b: z.enum(['x', 'y']).nullable() }));
    assert.equal(schema.$schema, undefined);
    assert.deepEqual(schema.required, ['a', 'b']);
});

// ── NovrAI chat (routes/novr-ai.ts) ─────────────────────────────────────────────────────────
let chatCalls: Record<string, unknown>[] = [];
let chatReply: () => unknown = () => ({});
const fake: NvidiaClient = { chat: { completions: { create: (async (p: Record<string, unknown>) => { chatCalls.push(p); return chatReply(); }) as never } } };
async function chat(messages: unknown) {
    const r = await fetch(`${base}/api/novr-ai`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ messages, context: { active_agents: 3, open_incidents: 1 } }) });
    return { status: r.status, data: await r.json() };
}
const useNvidia = () => { process.env.NVIDIA_API_KEY = KEY; setNvidiaClientForTests(fake); chatCalls = []; };

test('chat status: reports NVIDIA and the configured model, never the key', async () => {
    let s = await (await fetch(`${base}/api/novr-ai/status`)).json();
    assert.deepEqual(s, { configured: false, provider: 'none', model: 'none' });
    process.env.NVIDIA_API_KEY = KEY;
    s = await (await fetch(`${base}/api/novr-ai/status`)).json();
    assert.deepEqual(s, { configured: true, provider: 'nvidia', model: DEFAULT_NVIDIA_MODEL });
});

test('chat success: system prompt first, roles mapped, NVIDIA reply returned', async () => {
    useNvidia();
    chatReply = () => ({ model: DEFAULT_NVIDIA_MODEL, choices: [{ finish_reason: 'stop', message: { content: '<think>…</think>## Summary\nBrute force on web-01' } }] });
    const r = await chat([{ role: 'user', content: 'What happened?' }, { role: 'assistant', content: 'Looking' }, { role: 'user', content: 'More detail' }]);
    assert.equal(r.status, 200);
    assert.deepEqual([r.data.reply, r.data.provider, r.data.model, r.data.configured], ['## Summary\nBrute force on web-01', 'nvidia', DEFAULT_NVIDIA_MODEL, true]);
    const p = chatCalls[0] as { model: string; max_tokens: number; messages: { role: string; content: string }[] };
    assert.equal(p.model, DEFAULT_NVIDIA_MODEL);
    assert.equal(p.max_tokens, 4096);
    assert.deepEqual(p.messages.map((m) => m.role), ['system', 'user', 'assistant', 'user']);
    assert.match(p.messages[0].content, /You are NovrAI/);
    assert.match(p.messages[0].content, /Open incidents: 1/);
});

test('chat failures with no Gemini: empty answer, rate limit and timeout give an honest 502, key never logged', async () => {
    useNvidia();
    logged.length = 0;
    const failures: (() => unknown)[] = [
        () => ({ choices: [{ finish_reason: 'length', message: { content: '' } }] }),
        () => ({ unexpected: true }),
        () => { throw new OpenAI.RateLimitError(429, undefined, 'Too Many Requests', new Headers()); },
        () => { throw new OpenAI.APIConnectionTimeoutError(); },
    ];
    for (const f of failures) {
        chatReply = f;
        const r = await chat([{ role: 'user', content: 'hi' }]);
        assert.equal(r.status, 502);
        assert.equal(r.data.provider, 'none');
        assert.match(r.data.error, /NVIDIA and Gemini/);
    }
    assert.ok(logged.some((l) => /Rate limited/.test(l)) && logged.some((l) => /timed out/.test(l)));
    assert.ok(!logged.join('\n').includes(KEY));
});

test('chat with nothing configured: 503 naming NVIDIA_API_KEY; bad input: 400', async () => {
    const r = await chat([{ role: 'user', content: 'hi' }]);
    assert.equal(r.status, 503);
    assert.match(r.data.reply, /NVIDIA_API_KEY or GEMINI_API_KEY/);
    assert.equal((await chat([])).status, 400);
});
