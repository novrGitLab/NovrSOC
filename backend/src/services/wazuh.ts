import https from 'https';
import { isIP } from 'net';

// Wazuh Manager REST API (port 55000)
const WAZUH_HOST = process.env.WAZUH_HOST || '';
const WAZUH_PORT = Number(process.env.WAZUH_PORT || 55000);
const WAZUH_USER = process.env.WAZUH_USER || 'wazuh-wui';
const WAZUH_PASSWORD =
    process.env.WAZUH_API_PASSWORD || process.env.WAZUH_PASSWORD || process.env.WAZUH_PASS || '';

/** True once host + password are both present */
export function isConfigured(): boolean {
    return Boolean(WAZUH_HOST && WAZUH_PASSWORD);
}

interface WazuhHttpResponse {
    status: number;
    json: unknown;
}

function request(path: string, authHeader: string, method: 'GET' | 'POST' | 'PUT' = 'GET', body?: unknown): Promise<WazuhHttpResponse> {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    return new Promise((resolve, reject) => {
        const req = https.request(
            {
                hostname: WAZUH_HOST,
                port: WAZUH_PORT,
                path,
                method,
                headers: payload === undefined
                    ? { Authorization: authHeader }
                    : { Authorization: authHeader, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
                rejectUnauthorized: false,
            },
            (res) => {
                let body = '';
                res.on('data', (chunk) => (body += chunk));
                res.on('end', () => {
                    try {
                        resolve({ status: res.statusCode ?? 500, json: JSON.parse(body) });
                    } catch {
                        resolve({ status: res.statusCode ?? 500, json: null });
                    }
                });
            }
        );
        req.on('error', reject);
        if (payload !== undefined) req.write(payload);
        req.end();
    });
}

let cachedToken: { token: string; expires: number } | null = null;

/** POST /security/user/authenticate with Basic auth — returns a JWT, cached for 15 minutes. */
export async function authenticate(): Promise<string> {
    if (cachedToken && cachedToken.expires > Date.now()) return cachedToken.token;
    if (!WAZUH_HOST) throw new Error('WAZUH_HOST environment variable is not set');
    if (!WAZUH_PASSWORD) throw new Error('WAZUH_PASSWORD environment variable is not set');

    const basic = 'Basic ' + Buffer.from(`${WAZUH_USER}:${WAZUH_PASSWORD}`).toString('base64');
    let status: number, json: unknown;
    try {
        ({ status, json } = await request('/security/user/authenticate', basic, 'POST'));
    } catch (err) {
        console.error(`[wazuh] connection failed:`, err instanceof Error ? err.message : err);
        throw err;
    }
    const token = (json as { data?: { token?: string } } | null)?.data?.token;
    if (!token) {
        console.error(`[wazuh] authentication failed — status ${status}, response:`, JSON.stringify(json));
        throw new Error(`Wazuh authentication failed (status ${status})`);
    }

    cachedToken = { token, expires: Date.now() + 15 * 60 * 1000 };
    return token;
}

async function authedGet(path: string): Promise<WazuhHttpResponse> {
    const token = await authenticate();
    return request(path, `Bearer ${token}`, 'GET');
}

/**
 * PUT /active-response?agents_list=<id> — runs an active-response command on one agent.
 * Returns whether the manager accepted it for that agent. Acceptance is not execution: whether
 * the script succeeded is only visible in the agent's own active-responses.log.
 */
export async function runActiveResponse(agentId: string, command: string, srcip?: string): Promise<{ accepted: boolean; status: number; detail: string }> {
    const token = await authenticate();
    const { status, json } = await request(
        `/active-response?agents_list=${encodeURIComponent(agentId)}`,
        `Bearer ${token}`,
        'PUT',
        { command, alert: { data: { srcip: srcip ?? '' } } },
    );
    const data = (json as { data?: { affected_items?: unknown[]; failed_items?: { error?: { message?: string } }[] }; message?: string; detail?: string } | null);
    const accepted = status < 300 && (data?.data?.affected_items ?? []).map(String).includes(agentId);
    const detail = accepted
        ? 'accepted by Wazuh manager'
        : data?.data?.failed_items?.[0]?.error?.message ?? data?.detail ?? data?.message ?? `HTTP ${status}`;
    return { accepted, status, detail };
}

function affectedItems(json: unknown): Record<string, unknown>[] {
    const items = (json as { data?: { affected_items?: unknown[] } } | null)?.data?.affected_items;
    return Array.isArray(items) ? (items as Record<string, unknown>[]) : [];
}

// ── Agents ──────────────────────────────────────────────────────────────

export interface WazuhAgent {
    id: string;
    name: string;
    ip: string | null;
    os: string | null;
    status: string;
    last_keepalive: string | null;
    version: string | null;
    /** The agent's Wazuh groups — what organisation ownership is resolved from (lib/orgScope.ts). */
    group: string[];
}

let agentsOverride: (() => Promise<WazuhAgent[]>) | null = null;

/** Tests only: answer getAgents() with `impl` instead of the Manager API (null restores it). */
export function __setAgentsForTests(impl: (() => Promise<WazuhAgent[]>) | null): void {
    agentsOverride = impl;
}

/** Whether getAgents() has a source to ask (the Manager API is configured, or a test stub). */
export function agentsAvailable(): boolean {
    return agentsOverride !== null || isConfigured();
}

const AGENT_PAGE = 500;

/** GET /agents — every agent enrolled with the manager, all pages. Throws when the API refuses. */
export async function getAgents(): Promise<WazuhAgent[]> {
    if (agentsOverride) return agentsOverride();
    const out: WazuhAgent[] = [];
    for (let offset = 0; offset < 100_000; offset += AGENT_PAGE) {
        const { status, json } = await authedGet(`/agents?limit=${AGENT_PAGE}&offset=${offset}`);
        if (status >= 400) throw new Error(`Wazuh Manager API answered HTTP ${status} for /agents`);
        const items = affectedItems(json);
        for (const a of items) {
            const os = a.os as { name?: string; version?: string } | undefined;
            out.push({
                id: String(a.id ?? ''),
                name: String(a.name ?? 'Unknown'),
                ip: (a.ip as string) ?? null,
                os: os?.name ? `${os.name} ${os.version ?? ''}`.trim() : null,
                status: String(a.status ?? 'unknown'),
                last_keepalive: (a.lastKeepAlive as string) ?? null,
                version: (a.version as string) ?? null,
                group: Array.isArray(a.group) ? (a.group as unknown[]).filter((g): g is string => typeof g === 'string') : [],
            });
        }
        const total = Number((json as { data?: { total_affected_items?: number } } | null)?.data?.total_affected_items ?? 0);
        if (items.length < AGENT_PAGE || out.length >= total) break;
    }
    return out;
}

// ── Software inventory ──────────────────────────────────────────────────

export interface WazuhPackage {
    name: string;
    version: string;
    architecture: string | null;
    vendor: string | null;
    description: string | null;
}

/**
 * GET /syscollector/{agent_id}/netaddr — the addresses on an agent's network interfaces (phase P27
 * IP discovery for the Wazuh asset import). Loopback and link-local addresses are left out.
 */
export async function getAgentAddresses(agentId: string): Promise<{ address: string; iface: string | null; proto: string | null }[]> {
    const { json } = await authedGet(`/syscollector/${encodeURIComponent(agentId)}/netaddr?limit=100`);
    const out = new Map<string, { address: string; iface: string | null; proto: string | null }>();
    for (const r of affectedItems(json)) {
        const address = String(r.address ?? '').trim().toLowerCase().replace(/%.*$/, '');
        if (!isIP(address) || /^(127\.|169\.254\.)/.test(address) || address === '::1' || address.startsWith('fe80:')) continue;
        if (!out.has(address)) out.set(address, { address, iface: (r.iface as string) ?? null, proto: (r.proto as string) ?? null });
    }
    return [...out.values()];
}

/** GET /syscollector/{agent_id}/packages — installed software inventory for one agent. */
export async function getAgentInventory(agentId: string): Promise<WazuhPackage[]> {
    const { json } = await authedGet(`/syscollector/${encodeURIComponent(agentId)}/packages?limit=100`);
    return affectedItems(json).map((p) => ({
        name: String(p.name ?? ''),
        version: String(p.version ?? ''),
        architecture: (p.architecture as string) ?? null,
        vendor: (p.vendor as string) ?? null,
        description: (p.description as string) ?? null,
    }));
}