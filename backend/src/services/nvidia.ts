// Shared NVIDIA AI provider configuration — the one place every AI feature (services/ai.ts,
// routes/novr-ai.ts, Platform Health) gets its client, model and error wording from.
//
// NVIDIA's hosted API Catalog speaks the OpenAI chat-completions protocol, so the OpenAI SDK is
// used with NVIDIA's base URL. The key (NVIDIA_API_KEY) stays server-side: it is read from the
// environment here and never returned in a response or written to a log.
//
// Model: AI_MODEL (default nvidia/nemotron-3-super-120b-a12b, confirmed in the API Catalog's
// /v1/models listing). AI_FALLBACK_MODEL is optional: when set, a refusal from the primary model
// is retried once on it. AI_TIMEOUT_MS defaults to 120000.

import OpenAI from 'openai';

export const NVIDIA_BASE_URL = 'https://integrate.api.nvidia.com/v1';
export const DEFAULT_NVIDIA_MODEL = 'nvidia/nemotron-3-super-120b-a12b';

export const AI_MODEL = () => process.env.AI_MODEL?.trim() || DEFAULT_NVIDIA_MODEL;
export const AI_FALLBACK_MODEL = () => process.env.AI_FALLBACK_MODEL?.trim() || null;
export const AI_TIMEOUT_MS = () => (Number(process.env.AI_TIMEOUT_MS) >= 10_000 ? Number(process.env.AI_TIMEOUT_MS) : 120_000);

export function nvidiaConfigured(): boolean {
    const key = process.env.NVIDIA_API_KEY?.trim();
    return !!key && key !== 'your-key-here' && !key.startsWith('[') && key !== 'REPLACE_WHEN_OBTAINED';
}

// The subset of the SDK the platform uses — lets tests substitute a fake without the network.
export interface NvidiaClient {
    chat: { completions: { create: (params: never, options?: { timeout?: number; signal?: AbortSignal }) => Promise<unknown> } };
}
let client: NvidiaClient | null = null;
let clientKey = '';
let clientOverride: NvidiaClient | null = null;
/** Test hook: route calls to a fake client (null restores the real one). */
export function setNvidiaClientForTests(c: NvidiaClient | null): void { clientOverride = c; }

/** The shared client, or null when NVIDIA_API_KEY is not set. */
export function getNvidiaClient(): NvidiaClient | null {
    if (clientOverride) return clientOverride;
    if (!nvidiaConfigured()) return null;
    const key = process.env.NVIDIA_API_KEY!.trim();
    // Rebuilt if the key changes (a rotated key takes effect without a restart).
    if (!client || clientKey !== key) {
        client = new OpenAI({ apiKey: key, baseURL: NVIDIA_BASE_URL, timeout: AI_TIMEOUT_MS(), maxRetries: 2 }) as unknown as NvidiaClient;
        clientKey = key;
    }
    return client;
}

export interface NvidiaProbe { configured: boolean; model: string; reachable: boolean; status: 'up' | 'degraded' | 'down'; detail: string; latency_ms: number }
let probeFetch: typeof fetch | null = null;
/** Test hook: the fetch the health probe uses (null restores the global one). */
export function setNvidiaProbeFetchForTests(f: typeof fetch | null): void { probeFetch = f; }

/**
 * Health check that proves the key is accepted without generating anything (no cost). NVIDIA's
 * /v1/models endpoints are public and answer 200 even for a bad key, so they can't be used.
 * Instead an empty chat request is sent: the gateway checks the key first (401/403 when missing
 * or rejected), then rejects the empty message list (400/422) before any inference runs.
 */
export async function probeNvidia(timeoutMs = 8000): Promise<NvidiaProbe> {
    const model = AI_MODEL();
    const start = Date.now();
    const done = (reachable: boolean, status: NvidiaProbe['status'], detail: string): NvidiaProbe =>
        ({ configured: true, model, reachable, status, detail, latency_ms: Date.now() - start });
    if (!nvidiaConfigured()) return { configured: false, model, reachable: false, status: 'down', detail: 'NVIDIA_API_KEY is not set', latency_ms: 0 };
    try {
        const res = await (probeFetch ?? fetch)(`${NVIDIA_BASE_URL}/chat/completions`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${process.env.NVIDIA_API_KEY!.trim()}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ model, messages: [], max_tokens: 1 }),
            signal: AbortSignal.timeout(timeoutMs),
        });
        if (res.status === 401 || res.status === 403) return done(false, 'down', 'The API key was rejected');
        if (res.status === 404) return done(false, 'down', 'The configured model was not found');
        if (res.status === 429) return done(true, 'degraded', 'Key accepted; rate limited by the AI provider');
        if (res.status >= 500) return done(false, 'degraded', `AI provider error ${res.status}`);
        return done(true, 'up', `Key accepted; model ${model}`);
    } catch (err) {
        const timedOut = err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError');
        return done(false, 'down', timedOut ? 'The AI provider timed out' : 'Could not reach the AI provider');
    }
}

/** A short, secret-free description of a provider failure, for responses and logs. */
export function describeNvidiaError(err: unknown): string {
    if (err instanceof OpenAI.AuthenticationError) return 'The API key was rejected';
    if (err instanceof OpenAI.PermissionDeniedError) return 'The API key may not use this model';
    if (err instanceof OpenAI.NotFoundError) return 'The configured model was not found';
    if (err instanceof OpenAI.RateLimitError) return 'Rate limited by the AI provider — try again shortly';
    if (err instanceof OpenAI.APIConnectionTimeoutError) return 'The AI provider timed out';
    if (err instanceof OpenAI.APIConnectionError) return 'Could not reach the AI provider';
    if (err instanceof OpenAI.APIError) return `AI provider error ${err.status ?? ''}`.trim();
    return err instanceof Error ? err.message.slice(0, 200) : 'AI request failed';
}

/** True for failures on the provider's side (HTTP error, unreachable, timeout) rather than ours. */
export function isProviderError(err: unknown): boolean {
    return err instanceof OpenAI.APIError;
}
export function isRateLimit(err: unknown): boolean {
    return err instanceof OpenAI.RateLimitError;
}

/**
 * The answer text of a chat completion. Reasoning models may put their thinking in a separate
 * field (ignored) or inline as <think>…</think> (stripped), so only the answer is returned.
 */
export function completionText(res: unknown): { text: string; finishReason: string | null; refusal: string | null } {
    const choice = (res as { choices?: { finish_reason?: string | null; message?: { content?: unknown; refusal?: string | null } }[] })?.choices?.[0];
    const raw = typeof choice?.message?.content === 'string' ? choice.message.content : '';
    const text = raw.replace(/<think>[\s\S]*?<\/think>/g, '').replace(/^[\s\S]*?<\/think>/, '').trim();
    return { text, finishReason: choice?.finish_reason ?? null, refusal: choice?.message?.refusal ?? null };
}
