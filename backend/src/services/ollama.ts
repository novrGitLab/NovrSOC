// Ollama provider (phase P25) for the grounded AI service (services/ai.ts) — the platform's own
// self-hosted model server, used for the Threat Intelligence analyst.
//
// Ollama has no authentication of its own, so it must never face the internet directly. The
// expected deployment is Ollama bound to 127.0.0.1 behind a TLS reverse proxy that requires a
// bearer token and only accepts the backend's outbound addresses (docs/runbooks/ti-v1.md).
//   OLLAMA_URL       the proxy's https URL (http only for localhost, for development)
//   OLLAMA_API_KEY   the proxy's bearer token, sent as Authorization: Bearer — never logged
//   OLLAMA_CA_CERT   optional PEM pinned for a self-signed proxy certificate (lib/pinnedTls.ts)
//   OLLAMA_MODEL     the model to use (default llama3.1:8b); it must already be pulled
// Native /api/chat is used with `format` set to the answer's JSON Schema (structured outputs), so
// the answer is constrained to the schema the platform then validates again. The reply is mapped
// to the chat-completions shape services/ai.ts reads.

import { parsePin, pinnedFetch } from '../lib/pinnedTls';

export const DEFAULT_OLLAMA_MODEL = 'llama3.1:8b';
export const OLLAMA_MODEL = () => process.env.OLLAMA_MODEL?.trim() || DEFAULT_OLLAMA_MODEL;
const base = () => (process.env.OLLAMA_URL ?? '').trim().replace(/\/+$/, '');

/** Configured, and on https unless it is this machine. */
export function ollamaConfigured(): boolean {
    const b = base();
    if (!b) return false;
    try {
        const u = new URL(b);
        return u.protocol === 'https:' || (u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname));
    } catch { return false; }
}

export class OllamaError extends Error {
    constructor(message: string, readonly status: number | null, readonly kind: 'auth' | 'not_found' | 'rate_limit' | 'timeout' | 'unreachable' | 'server' | 'bad_response') { super(message); }
}

let fetchOverride: typeof fetch | null = null;
/** Test hook: the fetch the provider uses (null restores the real one). */
export function setOllamaFetchForTests(f: typeof fetch | null): void { fetchOverride = f; }

async function request(path: string, init: { method?: string; body?: string; timeoutMs: number }): Promise<Response> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json', Accept: 'application/json' };
    const key = process.env.OLLAMA_API_KEY?.trim();
    if (key) headers.Authorization = `Bearer ${key}`;
    const url = `${base()}${path}`;
    try {
        if (fetchOverride) return await fetchOverride(url, { method: init.method ?? 'GET', headers, body: init.body, signal: AbortSignal.timeout(init.timeoutMs) });
        const pin = parsePin(process.env.OLLAMA_CA_CERT);
        if (pin && url.startsWith('https://')) return await pinnedFetch(url, { method: init.method, headers, body: init.body, timeoutMs: init.timeoutMs }, pin);
        return await fetch(url, { method: init.method ?? 'GET', headers, body: init.body, signal: AbortSignal.timeout(init.timeoutMs) });
    } catch (err) {
        const timedOut = err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError');
        throw new OllamaError(timedOut ? 'The model server timed out' : 'Could not reach the model server', null, timedOut ? 'timeout' : 'unreachable');
    }
}

function failure(status: number): OllamaError {
    if (status === 401 || status === 403) return new OllamaError('The model server refused the access token', status, 'auth');
    if (status === 404) return new OllamaError('The configured model is not available on the model server', status, 'not_found');
    if (status === 429) return new OllamaError('The model server is busy — try again shortly', status, 'rate_limit');
    return new OllamaError(`Model server error ${status}`, status, 'server');
}

interface ChatParams {
    model: string; max_tokens?: number;
    messages: { role: string; content: string }[];
    response_format?: { type: string; json_schema?: { schema?: Record<string, unknown> } };
}

/** A client with the chat-completions surface services/ai.ts uses. */
export const ollamaClient = {
    chat: { completions: { create: async (params: never, options?: { timeout?: number }) => {
        const p = params as unknown as ChatParams;
        const res = await request('/api/chat', {
            method: 'POST', timeoutMs: options?.timeout ?? 120_000,
            body: JSON.stringify({
                model: p.model, stream: false, messages: p.messages,
                ...(p.response_format?.json_schema?.schema ? { format: p.response_format.json_schema.schema } : {}),
                options: { temperature: 0, ...(p.max_tokens ? { num_predict: Math.min(p.max_tokens, 8192) } : {}) },
            }),
        });
        if (!res.ok) throw failure(res.status);
        const j = await res.json().catch(() => null) as { model?: string; message?: { content?: string }; done_reason?: string; prompt_eval_count?: number; eval_count?: number } | null;
        if (!j || typeof j.message?.content !== 'string') throw new OllamaError('The model server returned no answer', res.status, 'bad_response');
        return {
            model: j.model ?? p.model,
            choices: [{ finish_reason: j.done_reason ?? 'stop', message: { content: j.message.content, refusal: null } }],
            usage: { prompt_tokens: j.prompt_eval_count ?? null, completion_tokens: j.eval_count ?? null },
        };
    } } },
};

export interface OllamaProbe { configured: boolean; model: string; reachable: boolean; status: 'up' | 'degraded' | 'down'; detail: string; latency_ms: number; version: string | null }

/** Reachability, the token, the server version and whether the model is pulled. Generates nothing. */
export async function probeOllama(timeoutMs = 8000): Promise<OllamaProbe> {
    const model = OLLAMA_MODEL();
    const start = Date.now();
    const done = (reachable: boolean, status: OllamaProbe['status'], detail: string, version: string | null = null): OllamaProbe =>
        ({ configured: true, model, reachable, status, detail, latency_ms: Date.now() - start, version });
    if (!ollamaConfigured()) return { configured: false, model, reachable: false, status: 'down', detail: base() ? 'OLLAMA_URL must be https (http only for localhost)' : 'OLLAMA_URL is not set', latency_ms: 0, version: null };
    try {
        const v = await request('/api/version', { timeoutMs });
        if (!v.ok) { const f = failure(v.status); return done(f.kind !== 'unreachable', 'down', f.message); }
        const version = ((await v.json().catch(() => ({}))) as { version?: string }).version ?? null;
        const t = await request('/api/tags', { timeoutMs });
        if (!t.ok) return done(true, 'degraded', failure(t.status).message, version);
        const tags = ((await t.json().catch(() => ({}))) as { models?: { name?: string; model?: string }[] }).models ?? [];
        const names = tags.flatMap((m) => [m.name, m.model]).filter((x): x is string => !!x);
        const has = names.some((n) => n === model || n === `${model}:latest` || n.replace(/:latest$/, '') === model);
        return has ? done(true, 'up', `Model ${model} is available`, version) : done(true, 'degraded', `Model ${model} is not pulled on the model server`, version);
    } catch (err) {
        return done(false, 'down', err instanceof OllamaError ? err.message : 'Could not reach the model server');
    }
}

export const isOllamaError = (err: unknown): err is OllamaError => err instanceof OllamaError;
