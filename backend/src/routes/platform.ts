import { Router } from 'express';
import { isConfigured as wazuhConfigured, getAgents as getWazuhAgents } from '../services/wazuh';
import { getAuditLog } from '../lib/audit';
import { getMISPStats, isMISPConfigured } from '../services/misp';
import { isTheHiveConfigured, testConnection as testTheHive } from '../services/thehive';
import { isConfigured as leakixConfigured } from '../services/leakix';
import { isConfigured as fofaConfigured } from '../services/fofa';

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
    const threatfoxKey = (process.env.THREATFOX_API_KEY || '').trim();

    return {
        // OTX and Censys were removed on 2026-09-09. Reported explicitly as `removed` rather
        // than dropped from this response, so an operator looking at Platform Health sees why
        // they vanished instead of assuming a regression — and so nothing warns about the
        // OTX_API_KEY / CENSYS_* values that may still be sitting in Railway unused.
        otx: {
            configured: false,
            removed: true,
            detail: 'Removed — pulse feed replaced by CIRCL OSINT (keyless) and IOC corroboration by ThreatFox.',
        },
        censys: {
            configured: false,
            removed: true,
            detail: 'Removed — host exposure lookups replaced by LeakIX.',
        },
        circl: {
            configured: true,
            detail: 'CIRCL OSINT feed — public MISP feed, no key required.',
        },
        threatfox: {
            configured: threatfoxKey.length > 0,
            detail: threatfoxKey.length > 0
                ? 'THREATFOX_API_KEY set — abuse.ch IOC corroboration active'
                : 'THREATFOX_API_KEY not set — abuse.ch now requires an Auth-Key, so ThreatFox returns nothing without it',
        },
        leakix: {
            configured: leakixConfigured(),
            // The free tier still needs a registered key: an empty key returns 401 "Invalid API
            // key" (verified live). Unconfigured means lookups are skipped, NOT that hosts are clean.
            detail: leakixConfigured()
                ? 'LEAKIX_API_KEY set — host exposure lookups active'
                : 'LEAKIX_API_KEY not set — free key available at leakix.net/settings/api. Host exposure lookups are skipped, not reported as clean.',
        },
        fofa: {
            configured: fofaConfigured(),
            detail: fofaConfigured()
                ? 'FOFA_API_KEY and FOFA_EMAIL set — asset search active'
                : 'FOFA_API_KEY/FOFA_EMAIL not set — activates automatically once both are provided',
        },
        misp: {
            configured: isMISPConfigured(),
            detail: isMISPConfigured() ? 'MISP_URL and MISP_API_KEY set' : 'MISP_URL/MISP_API_KEY not set',
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
