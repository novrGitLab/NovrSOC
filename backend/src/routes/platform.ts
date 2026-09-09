import { Router } from 'express';
import { isConfigured as wazuhConfigured, getAgents as getWazuhAgents } from '../services/wazuh';
import { getAuditLog } from '../lib/audit';
import { getMISPStats, isMISPConfigured } from '../services/misp';
import { isTheHiveConfigured, testConnection as testTheHive } from '../services/thehive';
import { isConfigured as censysConfigured } from '../services/censys';

const router = Router();

interface ServiceCheck {
    name: string;
    status: 'up' | 'degraded' | 'down';
    latency_ms: number;
}

async function checkWazuh(): Promise<ServiceCheck> {
    const start = Date.now();
    if (!wazuhConfigured()) return { name: 'Wazuh Manager', status: 'down', latency_ms: 0 };
    try {
        // Reuses the same authenticated call routes/wazuh.ts's own /status route already
        // relies on — a bare unauthenticated fetch to the Manager API (what an earlier draft
        // of this check did) gets a 401 regardless of whether Wazuh is actually healthy,
        // which would make this check permanently report "down" even when it isn't.
        await getWazuhAgents();
        return { name: 'Wazuh Manager', status: 'up', latency_ms: Date.now() - start };
    } catch {
        return { name: 'Wazuh Manager', status: 'down', latency_ms: Date.now() - start };
    }
}

async function checkDatabase(): Promise<ServiceCheck> {
    const start = Date.now();
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_KEY;
    if (!url || !key) return { name: 'Database', status: 'down', latency_ms: 0 };
    try {
        const res = await fetch(`${url}/rest/v1/`, { headers: { apikey: key }, signal: AbortSignal.timeout(4000) });
        return { name: 'Database', status: res.ok ? 'up' : 'degraded', latency_ms: Date.now() - start };
    } catch {
        return { name: 'Database', status: 'down', latency_ms: Date.now() - start };
    }
}

async function checkClaudeAI(): Promise<ServiceCheck> {
    const start = Date.now();
    const key = process.env.ANTHROPIC_API_KEY;
    if (!key || key === 'your-key-here') return { name: 'Claude AI', status: 'down', latency_ms: 0 };
    try {
        // anthropic-version is required — omitting it doesn't degrade gracefully, the API
        // 401s the same way an actually-invalid key does, which would make this check
        // indistinguishable from "no key configured" (verified live while building this).
        const res = await fetch('https://api.anthropic.com/v1/models', {
            headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01' },
            signal: AbortSignal.timeout(4000),
        });
        return { name: 'Claude AI', status: res.ok ? 'up' : 'degraded', latency_ms: Date.now() - start };
    } catch {
        return { name: 'Claude AI', status: 'down', latency_ms: Date.now() - start };
    }
}

// MISP reports three distinguishable states, so this can say WHY it's not usable rather than a
// flat "down": unconfigured, unreachable, or reachable-but-rejecting-the-key (which is the
// current state of the configured instance — see services/misp.ts's header).
async function checkMISP(): Promise<ServiceCheck & { detail?: string }> {
    const start = Date.now();
    const stats = await getMISPStats();
    const latency = Date.now() - start;
    if (!stats.configured) return { name: 'MISP', status: 'down', latency_ms: 0, detail: 'Not configured' };
    if (stats.auth_ok) return { name: 'MISP', status: 'up', latency_ms: latency, detail: `${stats.events} events, ${stats.attributes} attributes` };
    // Reachable but not authenticating is degraded, not down — the host is healthy, the
    // credential isn't, and those need different fixes.
    if (stats.reachable) return { name: 'MISP', status: 'degraded', latency_ms: latency, detail: stats.error };
    return { name: 'MISP', status: 'down', latency_ms: latency, detail: stats.error };
}

// TheHive goes through the service's own testConnection(), which sends the Basic Auth header
// this instance requires. A bare unauthenticated GET to /api/v1/status (the obvious approach)
// returns 401 whether or not TheHive is healthy, so it would report "down" permanently — the
// same trap checkWazuh() above already documents.
async function checkTheHive(): Promise<ServiceCheck & { detail?: string }> {
    const start = Date.now();
    if (!isTheHiveConfigured()) {
        return { name: 'TheHive', status: 'down', latency_ms: 0, detail: 'Not configured' };
    }
    const result = await testTheHive();
    const latency = Date.now() - start;
    if (result.ok) return { name: 'TheHive', status: 'up', latency_ms: latency };
    // Reachable but rejecting credentials is degraded, not down — same distinction as MISP.
    if (result.status > 0) return { name: 'TheHive', status: 'degraded', latency_ms: latency, detail: result.error };
    return { name: 'TheHive', status: 'down', latency_ms: latency, detail: result.error };
}

// Credential-shape diagnostics for the integrations that are keyed but not otherwise probed on
// every health poll. These answer "is the key even present, and the right shape?" without a
// network round-trip per integration, so a misconfigured key is diagnosable from the Platform
// Health page instead of only from Railway logs.
function integrationConfig() {
    const otxKey = (process.env.OTX_API_KEY || '').trim();
    // A real OTX key is 64 hex chars. The key currently in the environment is 31, which is why
    // every OTX endpoint 403s — surfacing the length makes that self-evident.
    const otxValidShape = otxKey.length === 64;

    return {
        otx: {
            configured: otxKey.length > 0,
            valid_shape: otxValidShape,
            key_length: otxKey.length,
            expected_length: 64,
            detail: !otxKey ? 'OTX_API_KEY not set'
                : otxValidShape ? 'Key is the expected length'
                : `OTX_API_KEY is ${otxKey.length} chars — a real key is 64, so OTX will reject it`,
        },
        misp: {
            configured: isMISPConfigured(),
            detail: isMISPConfigured() ? 'MISP_URL and MISP_API_KEY set' : 'MISP_URL/MISP_API_KEY not set',
        },
        censys: {
            configured: censysConfigured(),
            detail: censysConfigured() ? 'CENSYS_API_ID and CENSYS_API_SECRET set' : 'CENSYS_API_ID/CENSYS_API_SECRET not set',
        },
        anthropic: {
            configured: !!process.env.ANTHROPIC_API_KEY && process.env.ANTHROPIC_API_KEY !== 'your-key-here',
            detail: process.env.ANTHROPIC_API_KEY ? 'ANTHROPIC_API_KEY set — NovrAI uses Claude' : 'ANTHROPIC_API_KEY not set — NovrAI falls back to Gemini',
        },
    };
}

// GET /api/platform/health — real checks for Wazuh Manager, Database (Supabase), Claude AI,
// MISP and TheHive, plus a per-integration credential summary. Every other service on the
// Platform Health page stays mock until it has its own real check built — see
// frontend/src/components/features/PlatformHealth.tsx.
router.get('/health', async (_req, res) => {
    const results = await Promise.all([checkWazuh(), checkDatabase(), checkClaudeAI(), checkMISP(), checkTheHive()]);

    const allUp = results.every((r) => r.status === 'up');
    const anyDown = results.some((r) => r.status === 'down');
    const overall = allUp ? 'operational' : anyDown ? 'outage' : 'degraded';

    res.json({
        overall,
        services: results,
        integrations: integrationConfig(),
        checked_at: new Date().toISOString(),
    });
});

// GET /api/platform/audit-log — real entries for the 3 actions currently logged (LOGIN,
// CREATE_INCIDENT, ADD_EXECUTIVE — see lib/audit.ts's call sites). Everything else on the
// Audit Log page is still mock/historical data shown separately.
router.get('/audit-log', (req, res) => {
    const limit = Number(req.query.limit) || 100;
    res.json({ entries: getAuditLog(limit) });
});

export default router;
