import https from 'https';

// No hardcoded host fallback on purpose — see lib/wazuh.ts's identical comment. A missing
// WAZUH_INDEXER_HOST env var should fail loudly (below), not silently reach out to whatever
// box happened to be at this IP when it was last written; that box has already moved once.
const INDEXER_HOST = process.env.WAZUH_INDEXER_HOST || '';
const INDEXER_PORT = Number(process.env.WAZUH_INDEXER_PORT || 9200);
const INDEXER_USER = process.env.WAZUH_INDEXER_USER || 'admin';
// Accepts either name — local .env has historically used WAZUH_INDEXER_PASS, Railway/newer
// setup docs use WAZUH_INDEXER_PASSWORD for the same value.
const INDEXER_PASS = process.env.WAZUH_INDEXER_PASSWORD || process.env.WAZUH_INDEXER_PASS;

type SearchImpl = (index: string, body: unknown) => Promise<unknown>;
let searchOverride: SearchImpl | null = null;

/** Tests only: answer every search() with `impl` instead of the network (null restores it). */
export function __setSearchForTests(impl: SearchImpl | null): void {
    searchOverride = impl;
}

/**
 * Shared low-level query helper for the Wazuh Indexer (OpenSearch/Elasticsearch, port 9200).
 * Every Wazuh analytics route searches a different index with a different query body, but
 * they all speak the same protocol — this consolidates what used to be ~10 duplicated copies
 * of this exact function scattered across the old src/app/api/wazuh/* route handlers.
 *
 * Resolves with the parsed reply whatever the HTTP status (callers such as the VMS sync read the
 * error body for its reason). Routes that show alerts use searchStrict() below.
 */
export function search<T = unknown>(index: string, body: unknown): Promise<T | null> {
    if (searchOverride) return searchOverride(index, body) as Promise<T | null>;
    return new Promise((resolve, reject) => {
        if (!INDEXER_HOST) {
            reject(new Error('WAZUH_INDEXER_HOST environment variable is not set'));
            return;
        }
        if (!INDEXER_PASS) {
            reject(new Error('WAZUH_INDEXER_PASS environment variable is not set'));
            return;
        }
        const payload = JSON.stringify(body);
        const auth = 'Basic ' + Buffer.from(`${INDEXER_USER}:${INDEXER_PASS}`).toString('base64');
        const agent = new https.Agent({
            rejectUnauthorized: false,
            keepAlive: true,
        });

        const req = https.request(
            {
                hostname: INDEXER_HOST,
                port: INDEXER_PORT,
                path: `/${index}/_search`,
                method: 'POST',
                agent: agent, // Use explicit permissive agent
                headers: {
                    Authorization: auth,
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(payload),
                },
                timeout: 15000,
            },
            (res) => {
                let data = '';
                res.on('data', (chunk) => (data += chunk));
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data));
                    } catch {
                        resolve(null);
                    }
                });
            }
        );
        req.on('timeout', () => req.destroy(new Error('Wazuh indexer request timed out')));
        req.on('error', reject);
        req.write(payload);
        req.end();
    });
}

interface ReplyShape { error?: unknown; status?: number; _shards?: { total?: number; failed?: number } }

/**
 * Why an indexer reply is not a usable answer, or null when it is. The indexer answers errors
 * (bad credentials, missing permission, a malformed query) with parsed JSON too, and a wildcard
 * that matches no index searches zero shards: none of those may be shown as "no alerts".
 */
export function replyProblem(r: unknown, index: string): string | null {
    if (r === null || r === undefined) return 'the indexer returned no readable answer';
    const reply = r as ReplyShape;
    if (reply.error !== undefined) {
        const e = reply.error as { type?: string } | string;
        const type = typeof e === 'string' ? e : e?.type ?? 'error';
        if (reply.status === 401 || reply.status === 403 || /security_exception/.test(String(type))) {
            return `the indexer refused the query (${type}${reply.status ? `, HTTP ${reply.status}` : ''}): check WAZUH_INDEXER_USER and its read permission on ${index}`;
        }
        return `the indexer returned ${type}${reply.status ? ` (HTTP ${reply.status})` : ''}`;
    }
    if (reply._shards && (reply._shards.total ?? 0) === 0) return `no index matches ${index}`;
    if (reply._shards && (reply._shards.failed ?? 0) > 0) return `${reply._shards.failed} of ${reply._shards.total} indexer shard(s) failed`;
    return null;
}

/** search(), but an error reply rejects with the reason instead of resolving as an empty result. */
export async function searchStrict<T = unknown>(index: string, body: unknown): Promise<T> {
    const r = await search<T>(index, body);
    const problem = replyProblem(r, index);
    if (problem) throw new Error(`Wazuh indexer: ${problem}`);
    return r as T;
}
