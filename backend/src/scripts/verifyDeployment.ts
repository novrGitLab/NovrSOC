// Deployment verification (phase P8). READ-ONLY: only GET requests, nothing is created, changed,
// queued, sent or triggered. Run it after deploying and after applying the SQL files:
//
//   NOVRSOC_API=https://<backend>  NOVRSOC_TOKEN=<a super_admin session token>  npm run verify:deployment
//
// The token is read from the environment and never printed. Without it, only the public health
// check and the unauthenticated-access checks run.
//
// It reports, for each phase, whether the backend answers and whether that phase's SQL is applied
// (the routes answer 503 "not set up yet (run sql/…)" until it is), and it checks that protected
// routes refuse requests without a token. A "PASS" means the endpoint answered as expected at the
// time of the run — not that the feature has been used or that its external services work.

const API = (process.env.NOVRSOC_API ?? '').replace(/\/+$/, '');
const TOKEN = process.env.NOVRSOC_TOKEN ?? '';

type Result = { check: string; outcome: 'PASS' | 'FAIL' | 'NOT SET UP' | 'SKIPPED'; detail: string };
const results: Result[] = [];

async function get(path: string, auth: boolean): Promise<{ status: number; body: unknown }> {
    const r = await fetch(`${API}${path}`, { headers: auth && TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {}, signal: AbortSignal.timeout(30_000) });
    return { status: r.status, body: await r.json().catch(() => null) };
}
const errorOf = (b: unknown) => (b && typeof b === 'object' && 'error' in b ? String((b as { error: unknown }).error) : '');

/** Authenticated GET: PASS on 200, NOT SET UP on 503 naming a SQL file, FAIL otherwise. */
async function probe(check: string, path: string, summarise: (b: Record<string, unknown>) => string = () => 'answered', healthy: (b: Record<string, unknown>) => boolean = () => true) {
    if (!TOKEN) { results.push({ check, outcome: 'SKIPPED', detail: 'NOVRSOC_TOKEN not set' }); return; }
    try {
        const { status, body } = await get(path, true);
        if (status === 200) { const b = (body ?? {}) as Record<string, unknown>; results.push({ check, outcome: healthy(b) ? 'PASS' : 'FAIL', detail: summarise(b) }); }
        else if (status === 503 && /sql\//.test(errorOf(body))) results.push({ check, outcome: 'NOT SET UP', detail: errorOf(body) });
        else results.push({ check, outcome: 'FAIL', detail: `HTTP ${status} ${errorOf(body)}`.trim() });
    } catch (err) {
        results.push({ check, outcome: 'FAIL', detail: err instanceof Error ? err.message : String(err) });
    }
}

async function main() {
    if (!API) { console.error('Set NOVRSOC_API to the backend URL, e.g. https://novrsoc-production-xxxx.up.railway.app'); process.exit(2); }

    // Public health
    try {
        const { status, body } = await get('/health', false);
        results.push({ check: 'Backend /health', outcome: status === 200 ? 'PASS' : 'FAIL', detail: `HTTP ${status}${(body as { version?: string } | null)?.version ? ` · deployed ${(body as { version: string }).version}` : ' · deployed version not reported'}` });
    } catch (err) {
        results.push({ check: 'Backend /health', outcome: 'FAIL', detail: err instanceof Error ? err.message : String(err) });
    }

    // Protected routes refuse anonymous requests (P1)
    for (const path of ['/api/alerts', '/api/cases', '/api/vms/overview', '/api/ti/overview', '/api/insights/weekly', '/api/platform/health', '/api/org-cti/stats', '/api/assets', '/api/cnii/sectors', '/api/cnii/inventory']) {
        try {
            const { status } = await get(path, false);
            // 401/403 = refused (good); 2xx = answered without a token (bad); 404 = route not deployed.
            results.push({ check: `Anonymous ${path.split('?')[0]} refused`, outcome: status === 401 || status === 403 ? 'PASS' : status === 404 ? 'NOT SET UP' : 'FAIL', detail: status === 404 ? 'HTTP 404: route not deployed' : `HTTP ${status}` });
        } catch (err) {
            results.push({ check: `Anonymous ${path} refused`, outcome: 'FAIL', detail: err instanceof Error ? err.message : String(err) });
        }
    }

    // Scanner worker API (P4/P10): deployed and refusing a request without the worker token. The body
    // is empty and unauthenticated, so the backend rejects it before reading anything; no job can be claimed.
    for (const path of ['/api/vms/worker/claim', '/api/vms/worker/heartbeat']) {
        try {
            const r = await fetch(`${API}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}', signal: AbortSignal.timeout(30_000) });
            const st = r.status;
            results.push({ check: `Worker ${path.split('/').pop()} without token refused`, outcome: st === 401 ? 'PASS' : st === 404 ? 'NOT SET UP' : 'FAIL',
                detail: st === 401 ? 'HTTP 401 (worker token configured on the backend)' : st === 503 ? 'HTTP 503: VMS_WORKER_TOKEN is not set (or shorter than 32) on the backend' : st === 404 ? 'HTTP 404: route not deployed' : `HTTP ${st}` });
        } catch (err) {
            results.push({ check: `Worker ${path} without token refused`, outcome: 'FAIL', detail: err instanceof Error ? err.message : String(err) });
        }
    }

    // Per phase, authenticated, read-only
    await probe('Platform health and pipelines (P2)', '/api/platform/health', (b) => {
        const p = (b.pipelines ?? []) as { name: string; status: string }[];
        return p.length ? p.map((x) => `${x.name}: ${x.status}`).join('; ') : 'no pipeline checks returned';
    });
    await probe('Durable audit log (P2)', '/api/platform/audit-log?limit=1', (b) => `source: ${String(b.source ?? 'unknown')}`);
    await probe('Alert quarantine (P1)', '/api/admin/wazuh-group-map/quarantine', (b) => `${String(b.total ?? '?')} alert(s) held for unmapped Wazuh groups`);
    await probe('Alert store (P3 triage columns)', '/api/alerts?limit=1&assigned=me');
    await probe('Response approvals (P3)', '/api/response-approvals');
    await probe('AI service (P3)', '/api/ai/health', (b) => `model ${String(b.model)}: ${String(b.detail)}`, (b) => b.reachable === true);
    await probe('VMS attack surface (P4)', '/api/vms/overview', (b) => {
        const w = b.worker as { seen_recently?: boolean; last_heartbeat_at?: string | null; source?: string; workers?: { worker_id: string; online: boolean }[] } | undefined;
        const ids = (w?.workers ?? []).filter((x) => x.online).map((x) => x.worker_id).join(', ');
        return `active scopes ${String(b.active_scopes ?? '?')}; scanner worker ${w?.seen_recently ? `connected${ids ? ` (${ids})` : ''}` : w?.last_heartbeat_at ? `last seen ${w.last_heartbeat_at}` : 'never connected'}${w?.source === 'job_heartbeat' ? '; presence SQL (P10) not applied' : ''}`;
    });
    await probe('VMS findings (P5)', '/api/vms/findings/summary');
    await probe('Threat Information System (P6)', '/api/ti/overview', (b) => {
        const f = (b.feeds ?? []) as { id: string; failing?: boolean; stale?: boolean }[];
        return f.map((x) => `${x.id}: ${x.failing ? 'failing' : x.stale ? 'stale' : 'current'}`).join('; ') || 'no feeds';
    });
    await probe('VMS schedules (P7)', '/api/vms/schedules', (b) => `${((b.schedules ?? []) as unknown[]).length} schedule(s)`);
    await probe('VMS trends (P7)', '/api/vms/trends?days=30', (b) => `${((b.snapshots ?? []) as unknown[]).length} snapshot(s)`);
    await probe('Weekly insights (P8)', '/api/insights/weekly', (b) => `${((b.limitations ?? []) as unknown[]).length} stated limitation(s)`);
    await probe('CNII Watch sectors (P9)', '/api/cnii/sectors', (b) => {
        const sec = (b.sectors ?? []) as { organisations: number; unmonitored: number }[];
        return `${sec.reduce((n, x) => n + x.organisations, 0)} organisation(s) classified, ${sec.reduce((n, x) => n + x.unmonitored, 0)} without active scope`;
    });
    await probe('CNII Watch profile (P9)', '/api/cnii/profile', (b) => (b.profile ? 'this organisation is classified' : 'this organisation is not classified'));

    const w = Math.max(...results.map((r) => r.check.length));
    for (const r of results) console.log(`${r.outcome.padEnd(10)} ${r.check.padEnd(w)}  ${r.detail}`);
    const failed = results.filter((r) => r.outcome === 'FAIL').length;
    const notSetUp = results.filter((r) => r.outcome === 'NOT SET UP').length;
    console.log(`\n${results.length} checks: ${failed} failed, ${notSetUp} not set up, ${results.filter((r) => r.outcome === 'SKIPPED').length} skipped.`);
    process.exit(failed ? 1 : 0);
}

void main();
