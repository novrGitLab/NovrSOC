import { Router, Request, Response } from 'express';
import Anthropic from '@anthropic-ai/sdk';
import { GoogleGenerativeAI } from '@google/generative-ai';
import { search } from '../lib/wazuh-indexer';
import { SEVERITY_MIN_LEVEL } from '../lib/severity';

const router = Router();

// Was 'claude-sonnet-4-6' — not a real Anthropic model id (doesn't match any published
// snapshot/family name), so every Claude call here 400'd before this fix. That's the actual
// reason a Gemini fallback matters: Claude wasn't silently "preferred but sometimes down", it
// was permanently broken, so "Claude first" never actually served a Claude response.
const CLAUDE_MODEL = 'claude-sonnet-5';
// Was 'gemini-1.5-flash' per the spec — confirmed live (ListModels against the real configured
// key, and the actual generateContent error) that model is retired. gemini-2.5-flash is also
// gone for new users — Google's own 404 body names its replacement explicitly: "This model
// models/gemini-2.5-flash is no longer available to new users. Please update your code to use
// models/gemini-3.6-flash". Confirmed gemini-3.6-flash actually answers (see the commit message
// for the live test).
const GEMINI_MODEL = 'gemini-3.6-flash';

function hasClaudeKey(): boolean {
    const key = process.env.ANTHROPIC_API_KEY;
    return !!key && key !== 'your-key-here' && !key.startsWith('[') && key !== 'REPLACE_WHEN_OBTAINED';
}
function hasGeminiKey(): boolean {
    const key = process.env.GEMINI_API_KEY;
    return !!key && key !== 'REPLACE_WHEN_OBTAINED';
}

const SYSTEM_INSTRUCTION = `
You are NovrAI, an expert AI Security Operations Center (SOC) Copilot and Cyber Threat Intelligence (CTI) analyst for NovrSOC (by Cybernovr).
Your mission is to provide accurate, actionable cybersecurity analysis, incident triage, and remediation advice.

Core Areas of Expertise:
- Wazuh SIEM log analysis, rule evaluation, and alert correlation.
- MITRE ATT&CK framework mapping (Techniques, Tactics, Procedures).
- Nigerian threat landscape, Telecom/ISP telemetry (MTN, Glo, Airtel, Spectranet, MainOne, IPNX), and regional threat actors.
- Cloud security, vulnerability remediation (CVEs), and compliance frameworks (NDPR, ISO 27001, SOC 2, NIST CSF).

Response Formatting Guidelines:
- Be concise, technical, and direct.
- Structure incident analyses with clear headings (## Summary, ### Threat Assessment, ### Containment & Remediation).
- Use bullet points for steps or indicators of compromise (IoCs).
- Always reference relevant MITRE technique IDs (e.g., T1059, T1078) and CVE identifiers where applicable.
`;

interface IncomingMessage {
    role: 'user' | 'assistant' | 'system';
    content: string;
}

// GET /api/novr-ai/status
router.get('/status', (_req: Request, res: Response) => {
    const claude = hasClaudeKey();
    const gemini = hasGeminiKey();
    res.json({
        configured: claude || gemini,
        provider: claude ? 'claude' : gemini ? 'gemini' : 'none',
        model: claude ? CLAUDE_MODEL : gemini ? GEMINI_MODEL : 'none',
    });
});

// Same live-telemetry grounding regardless of which provider ends up answering — built once,
// folded into whichever system prompt actually gets used below.
async function buildTelemetryContext(): Promise<string> {
    try {
        const indexerResult = await search<any>('wazuh-alerts-4.x-*', {
            size: 5,
            query: { range: { 'rule.level': { gte: SEVERITY_MIN_LEVEL.medium } } },
            _source: ['timestamp', 'rule.description', 'rule.level', 'agent.name', 'data.srcip'],
        });
        const hits = indexerResult?.hits?.hits ?? [];
        if (hits.length === 0) return 'No recent critical indexer alerts.';
        return hits.map((h: any) => {
            const level = h._source?.rule?.level ?? 'N/A';
            const desc = h._source?.rule?.description ?? 'Unknown alert';
            const agent = h._source?.agent?.name ?? 'Unknown Agent';
            const srcip = h._source?.data?.srcip ?? 'internal';
            return `- [Level ${level}] ${desc} (Agent: ${agent}, Src IP: ${srcip})`;
        }).join('\n');
    } catch {
        // Non-blocking fallback — an indexer outage must not take NovrAI down with it.
        return 'No recent critical indexer alerts.';
    }
}

async function askClaude(messages: IncomingMessage[], systemPrompt: string): Promise<string> {
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    const response = await client.messages.create({
        model: CLAUDE_MODEL,
        max_tokens: 4096,
        system: systemPrompt,
        messages: messages.map((m) => ({
            role: m.role === 'assistant' ? 'assistant' : 'user',
            content: m.content,
        })),
    });
    const reply = response.content
        .filter((block): block is Anthropic.TextBlock => block.type === 'text')
        .map((block) => block.text)
        .join('');
    if (!reply) throw new Error(`Claude returned no text content (stop_reason: ${response.stop_reason})`);
    return reply;
}

async function askGemini(messages: IncomingMessage[], systemPrompt: string): Promise<string> {
    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY as string);
    const model = genAI.getGenerativeModel({ model: GEMINI_MODEL, systemInstruction: systemPrompt });

    // Gemini's chat API wants history separate from the newest message, and 'model' instead of
    // 'assistant' for its own turns — 'system' role messages (if any slipped through from the
    // frontend) are folded into a user turn rather than dropped, since Gemini's history array
    // doesn't have a system role of its own (systemInstruction above is the only place for that).
    const history = messages.slice(0, -1).map((m) => ({
        role: m.role === 'user' ? 'user' as const : m.role === 'assistant' ? 'model' as const : 'user' as const,
        parts: [{ text: m.content }],
    }));
    const lastMessage = messages[messages.length - 1];

    const chat = model.startChat({ history });
    const result = await chat.sendMessage(lastMessage.content);
    const text = result.response.text();
    if (!text) throw new Error('Gemini returned an empty response');
    return text;
}

// POST /api/novr-ai — Claude first, Gemini fallback (only on Claude failure or if no Claude key
// at all), matching the spec exactly. Neither configured -> honest 503, not a fabricated reply.
router.post('/', async (req: Request, res: Response) => {
    const { messages, context } = req.body as {
        messages?: IncomingMessage[];
        context?: { active_agents?: number; open_incidents?: number };
    };

    if (!messages || !Array.isArray(messages) || messages.length === 0) {
        res.status(400).json({ error: 'Messages array is required.' });
        return;
    }

    const telemetry = await buildTelemetryContext();
    let systemPrompt = `${SYSTEM_INSTRUCTION}\n\nCurrent Live NovrSOC Telemetry Context:\n${telemetry}`;
    if (context) {
        systemPrompt += `\n\nCurrent platform context:\n- Active agents: ${context.active_agents ?? 0}\n- Open incidents: ${context.open_incidents ?? 0}`;
    }

    if (hasClaudeKey()) {
        try {
            const reply = await askClaude(messages, systemPrompt);
            res.json({ reply, model: CLAUDE_MODEL, provider: 'claude', configured: true, timestamp: new Date().toISOString() });
            return;
        } catch (err) {
            console.error('NovrAI Claude error, trying Gemini:', err instanceof Error ? err.message : err);
            // falls through to Gemini below
        }
    }

    if (hasGeminiKey()) {
        try {
            const reply = await askGemini(messages, systemPrompt);
            res.json({ reply, model: GEMINI_MODEL, provider: 'gemini', configured: true, timestamp: new Date().toISOString() });
            return;
        } catch (err) {
            console.error('NovrAI Gemini error:', err instanceof Error ? err.message : err);
        }
    }

    if (!hasClaudeKey() && !hasGeminiKey()) {
        res.status(503).json({
            error: 'NovrAI unavailable',
            reply: 'NovrAI is not configured. Add ANTHROPIC_API_KEY or GEMINI_API_KEY to Railway environment variables.',
            provider: 'none',
            configured: false,
        });
        return;
    }

    // Both were configured but both failed (e.g. rate limits, transient outages on both sides).
    res.status(502).json({
        error: 'Both Claude and Gemini failed to respond',
        reply: 'NovrAI could not reach either AI provider right now — try again shortly.',
        provider: 'none',
        configured: true,
    });
});

export default router;
