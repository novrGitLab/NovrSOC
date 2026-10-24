import { syncWazuhIOCs, watcherStats } from '../lib/orgCtiStore';

// Periodic background sync — pulls new Wazuh alerts since the last sync and folds any newly
// seen external IPs into the org CTI store (lib/orgCtiStore.ts). GET /api/org-cti/iocs also
// calls syncWazuhIOCs() on demand, so this interval is really just "keep the store warm even
// when nobody's looking at the page" — both callers share the same cursor, so neither
// duplicates the other's work.

export async function runCTIWatcher(): Promise<void> {
    try {
        const { newIps, hitCount } = await syncWazuhIOCs(100);
        if (hitCount > 0) {
            const stats = watcherStats();
            console.log(`[CTI Watcher] ingested ${hitCount} alert(s), ${newIps} new IP sighting(s) — ${stats.total_alerts_ingested} alert(s) read since start.`);
        }
    } catch (err) {
        // Indexer not configured/unreachable — same as threatManagement.ts's loadAlerts, this
        // is an expected steady-state on a box without a live Wazuh indexer (missing env vars,
        // network unreachable, timeout — all land here), not worth more than a log line. This
        // is a degraded state, never fatal: the interval below keeps retrying every 5 minutes,
        // and /health (index.ts) is a static, unconditional 200 that never touches this at all.
        console.log(`CTI Watcher: Wazuh indexer unavailable, will retry (${err instanceof Error ? err.message : err})`);
    }
}
