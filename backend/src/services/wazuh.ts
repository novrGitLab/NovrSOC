import https from 'https';

// Wazuh Manager REST API (port 55000)
const WAZUH_HOST = process.env.WAZUH_HOST || '';
const WAZUH_PORT = Number(process.env.WAZUH_PORT || 55000);
const WAZUH_USER = process.env.WAZUH_USER || 'wazuh-wui';
const WAZUH_PASSWORD =
    process.env.WAZUH_API_PASSWORD || process.env.WAZUH_PASSWORD || process.env.WAZUH_PASS || '';

// Wazuh Indexer / OpenSearch (port 9200)
const WAZUH_INDEXER_HOST = process.env.WAZUH_INDEXER_HOST || WAZUH_HOST || '10.0.0.1';
const WAZUH_INDEXER_PORT = Number(process.env.WAZUH_INDEXER_PORT || 9200);
const WAZUH_INDEXER_USER = process.env.WAZUH_INDEXER_USER || 'admin';
const WAZUH_INDEXER_PASSWORD = process.env.WAZUH_INDEXER_PASSWORD || '';

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
}

/** GET /agents — every agent enrolled with the manager. */
export async function getAgents(): Promise<WazuhAgent[]> {
    const { json } = await authedGet('/agents?limit=500');
    return affectedItems(json).map((a) => {
        const os = a.os as { name?: string; version?: string } | undefined;
        return {
            id: String(a.id ?? ''),
            name: String(a.name ?? 'Unknown'),
            ip: (a.ip as string) ?? null,
            os: os?.name ? `${os.name} ${os.version ?? ''}`.trim() : null,
            status: String(a.status ?? 'unknown'),
            last_keepalive: (a.lastKeepAlive as string) ?? null,
            version: (a.version as string) ?? null,
        };
    });
}

// ── Alerts (Queried from OpenSearch Indexer) ────────────────────────────

export interface WazuhAlert {
    id: string;
    timestamp: string | null;
    rule_id: string;
    rule_level: number;
    rule_description: string;
    rule_groups: string[];
    mitre_tactic: string | null;
    mitre_technique: string | null;
    agent_id: string;
    agent_name: string;
    source_ip: string | null;
    location: string | null;
}

/** Queries the Wazuh Indexer (OpenSearch) for the latest security alerts. */
export async function getAlerts(limit = 50): Promise<WazuhAlert[]> {
    const authHeader = 'Basic ' + Buffer.from(`${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASSWORD}`).toString('base64');
    const postData = JSON.stringify({
        size: limit,
        sort: [{ '@timestamp': { order: 'desc' } }],
    });

    return new Promise((resolve) => {
        const req = https.request(
            {
                hostname: WAZUH_INDEXER_HOST,
                port: WAZUH_INDEXER_PORT,
                path: '/wazuh-alerts-*/_search',
                method: 'POST',
                headers: {
                    Authorization: authHeader,
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(postData),
                },
                rejectUnauthorized: false,
            },
            (res) => {
                let body = '';
                res.on('data', (chunk) => (body += chunk));
                res.on('end', () => {
                    try {
                        const parsed = JSON.parse(body);
                        const hits = parsed.hits?.hits || [];

                        const alerts: WazuhAlert[] = hits.map((h: any) => {
                            const src = h._source || {};
                            const rule = src.rule || {};
                            const agent = src.agent || {};
                            const data = src.data || {};

                            const mitreTactic = Array.isArray(rule.mitre_tactics)
                                ? rule.mitre_tactics[0]
                                : rule.mitre_tactics || null;

                            const mitreTechnique = Array.isArray(rule.mitre_techniques)
                                ? rule.mitre_techniques[0]
                                : rule.mitre_techniques || null;

                            return {
                                id: String(h._id || src.id || ''),
                                timestamp: src.timestamp || src['@timestamp'] || null,
                                rule_id: String(rule.id || ''),
                                rule_level: Number(rule.level || 0),
                                rule_description: String(rule.description || 'Wazuh alert'),
                                rule_groups: Array.isArray(rule.groups) ? rule.groups : [],
                                mitre_tactic: mitreTactic,
                                mitre_technique: mitreTechnique,
                                agent_id: String(agent.id || ''),
                                agent_name: String(agent.name || 'Unknown'),
                                source_ip: data.srcip || null,
                                location: src.location || null,
                            };
                        });
                        resolve(alerts);
                    } catch (e) {
                        console.error('[wazuh] Failed to parse alerts from indexer:', e);
                        resolve([]);
                    }
                });
            }
        );

        req.on('error', (err) => {
            console.error('[wazuh] Indexer alert request error:', err);
            resolve([]);
        });

        req.write(postData);
        req.end();
    });
}

// ── Vulnerabilities ─────────────────────────────────────────────────────

export interface WazuhVulnerability {
    cve: string;
    title: string;
    severity: string;
    cvss_score: number | null;
    package: string;
    version: string;
}

/** GET /vulnerability/{agent_id} — CVE matches for one agent's installed packages. */
export async function getAgentVulnerabilities(agentId: string): Promise<WazuhVulnerability[]> {
    const { json } = await authedGet(`/vulnerability/${encodeURIComponent(agentId)}?limit=100`);
    return affectedItems(json).map((v) => ({
        cve: String(v.cve ?? ''),
        title: String(v.title ?? v.cve ?? ''),
        severity: String(v.severity ?? 'Unknown'),
        cvss_score: (v.cvss3_score as number) ?? (v.cvss2_score as number) ?? null,
        package: String(v.name ?? ''),
        version: String(v.version ?? ''),
    }));
}

// ── Software inventory ──────────────────────────────────────────────────

export interface WazuhPackage {
    name: string;
    version: string;
    architecture: string | null;
    vendor: string | null;
    description: string | null;
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