// Live smoke test for the NVIDIA AI provider: `npm run smoke:nvidia` with NVIDIA_API_KEY in
// backend/.env. Makes three real calls with synthetic data only — the key-checking health probe,
// one structured alert_summary generation through services/ai.ts (the path every AI panel uses),
// and one NovrAI-style chat completion. Nothing is stored: the database is disconnected for the
// run. The key is never printed.
import 'dotenv/config';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY']) delete process.env[k];

import { probeNvidia, getNvidiaClient, completionText, describeNvidiaError, AI_MODEL, AI_TIMEOUT_MS } from '../services/nvidia';
import { generate } from '../services/ai';
import { aiPurpose } from '../services/aiPurposes';

async function main(): Promise<number> {
    let failed = 0;
    const step = (ok: boolean, name: string, detail: string) => { if (!ok) failed++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name} — ${detail}`); };
    console.log(`Model: ${AI_MODEL()}`);

    const health = await probeNvidia(15_000);
    step(health.reachable, 'health probe', `${health.status}: ${health.detail} (${health.latency_ms} ms)`);
    if (!health.configured) return 1;

    const purpose = aiPurpose('alert_summary')!;
    const ref = 'alert:smoke-1';
    const started = Date.now();
    const r = await generate({
        purpose: 'alert_summary', orgId: 'smoke', actor: 'smoke-test', subjectType: 'alert', subjectId: 'smoke-1',
        sourceRefs: [{ ref, type: 'alert', id: 'smoke-1', label: 'sshd: authentication failed' }],
        records: [{
            ref, kind: 'alert', rule_id: '5710', rule_level: 10, rule_description: 'sshd: authentication failed',
            agent_name: 'web-01', severity: 'high', event_time: '2026-10-19T08:00:00Z',
            raw: { full_log: 'Failed password for root from 203.0.113.9 port 52211 ssh2 (x40 in 2 minutes)', data: { srcip: '203.0.113.9' } },
        }],
        task: purpose.task, schema: purpose.schema, maxTokens: purpose.maxTokens,
    });
    if (r.ok) {
        const c = r.artifact.content as { summary?: string; evidence?: unknown[]; invalid_refs?: string[] };
        step(true, 'structured generation (alert_summary)', `schema-valid in ${Date.now() - started} ms; served by ${r.artifact.model}; ${c.evidence?.length ?? 0} evidence item(s); invalid refs: ${c.invalid_refs?.length ?? 0}`);
        console.log(`      summary: ${String(c.summary).slice(0, 200)}`);
    } else {
        step(false, 'structured generation (alert_summary)', `${r.status}: ${r.error}`);
    }

    try {
        const t = Date.now();
        const res = await getNvidiaClient()!.chat.completions.create({
            model: AI_MODEL(), max_tokens: 4096,
            messages: [{ role: 'system', content: 'You are NovrAI, a SOC copilot. Be concise.' }, { role: 'user', content: 'In two sentences: what is MITRE ATT&CK T1110?' }],
        } as never, { timeout: AI_TIMEOUT_MS() });
        const { text, finishReason } = completionText(res);
        step(!!text, 'chat completion (NovrAI)', `${text ? 'answered' : 'empty'} in ${Date.now() - t} ms (finish_reason: ${finishReason})`);
        if (text) console.log(`      reply: ${text.slice(0, 200).replace(/\s+/g, ' ')}`);
    } catch (err) {
        step(false, 'chat completion (NovrAI)', describeNvidiaError(err));
    }
    return failed ? 1 : 0;
}

main().then((code) => process.exit(code), (err) => { console.error('smoke test crashed:', err instanceof Error ? err.message : err); process.exit(1); });
