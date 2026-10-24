import { searchStrict } from './wazuh-indexer';
import type { OrgScope } from './orgScope';

// Shared in-memory org CTI store — used by both routes/orgCTI.ts and jobs/ctiWatcher.ts.
// Replace with Supabase once a real schema exists (see routes/orgCTI.ts's header comment);
// this deliberately mirrors routes/threatManagement.ts's existing "module-level mutable
// cache, live until process restart" pattern rather than inventing a new persistence style.
//
// Correctness note vs. the original spec for this feature: a naive version of this re-derives
// "seen_count"/"first_seen" from whatever the last N Wazuh alerts happen to be on every GET
// request. That both undercounts (an IOC seen 200 alerts ago silently drops off once size=100
// only covers the newest 100) and double-counts (two GETs a minute apart re-ingest overlapping
// alert windows). Fixed here with a persistent accumulator plus a moving "last synced" cursor
// that only advances on a successful indexer query — both the periodic watcher and an
// on-demand GET both call the same syncWazuhIOCs(), so repeated calls never re-ingest the same
// alerts twice.

export interface OrgIOC {
    id: string;
    org_id: string;
    value: string;
    type: 'ip' | 'domain' | 'hash' | 'url' | 'email';
    source: 'wazuh' | 'analyst' | 'shared' | 'feed';
    first_seen: string;
    last_seen: string;
    seen_count: number;
    risk_score: number;
    verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown';
    tags: string[];
    notes: string;
    shared: boolean;
    mitre_tactic: string | null;
    alert_ids: string[];
    added_by: string;
}

interface IndexerAlertHit {
    _source?: {
        timestamp?: string;
        rule?: { level?: number; description?: string; groups?: string[] };
        agent?: { id?: string; name?: string };
        location?: string;
        data?: { srcip?: string };
    };
}
interface IndexerSearchResponse {
    hits?: { hits?: IndexerAlertHit[] };
}

const PRIVATE_IP_RE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/;

function verdictForLevel(level: number): OrgIOC['verdict'] {
    if (level >= 12) return 'malicious';
    if (level >= 6) return 'suspicious';
    return 'unknown';
}

// ── WAZUH-SOURCED IOC ACCUMULATOR ──────────────────────────────────────────
//
// Tenancy (P22): sightings are kept per external IP AND per owner — the agent that saw it, or for
// syslog the manager receives itself (agent 000) the sender's address — and an organisation only
// ever aggregates the owners it holds (lib/orgScope.ts). Before this, one global per-IP tally
// was handed to every organisation stamped with its own org_id.

interface AccumulatedIp {
    count: number;
    firstSeenTs: string;
    lastSeenTs: string;
    maxLevel: number;
    latestRule: string;
    latestAgent: string;
}
/** `${ip}\n${owner}` -> sightings; owner = agent id, or `000@<location>`. */
const wazuhAccumulator = new Map<string, AccumulatedIp>();
let lastSyncTs = new Date(Date.now() - 5 * 60 * 1000).toISOString();
let totalAlertsIngested = 0;

const ownerOf = (src: NonNullable<IndexerAlertHit['_source']>): string | null => {
    const id = src.agent?.id;
    if (!id) return null;
    if (id === '000') return src.location ? `000@${src.location}` : null;
    return id;
};

function ingestAlertHits(hits: IndexerAlertHit[]): number {
    let newIps = 0;
    for (const hit of hits) {
        const src = hit._source;
        const ip = src?.data?.srcip;
        if (!src || !ip || PRIVATE_IP_RE.test(ip)) continue;
        const owner = ownerOf(src);
        if (!owner) continue; // no owner means no organisation can be shown it

        // An alert with no timestamp is skipped rather than dated "now".
        const ts = src.timestamp;
        if (!ts) continue;
        const level = src.rule?.level ?? 0;
        const key = `${ip}\n${owner}`;
        const existing = wazuhAccumulator.get(key);
        if (existing) {
            existing.count++;
            if (ts < existing.firstSeenTs) existing.firstSeenTs = ts;
            if (ts > existing.lastSeenTs) existing.lastSeenTs = ts;
            if (level >= existing.maxLevel) {
                existing.maxLevel = level;
                existing.latestRule = src.rule?.description || existing.latestRule;
            }
            existing.latestAgent = src.agent?.id === '000' ? src.location ?? existing.latestAgent : src.agent?.name || existing.latestAgent;
        } else {
            wazuhAccumulator.set(key, {
                count: 1, firstSeenTs: ts, lastSeenTs: ts, maxLevel: level,
                latestRule: src.rule?.description || '', latestAgent: src.agent?.id === '000' ? src.location ?? '' : src.agent?.name || '',
            });
            newIps++;
        }
    }
    totalAlertsIngested += hits.length;
    return newIps;
}

/**
 * Pull alerts since the last successful sync and fold new external IPs into the accumulator.
 * Oldest first: when a window holds more than `size` alerts the cursor moves only to the newest
 * one read, so the rest are picked up next time instead of skipped.
 */
export async function syncWazuhIOCs(size = 100): Promise<{ newIps: number; hitCount: number }> {
    const since = lastSyncTs;
    const startedAt = new Date().toISOString();
    const result = await searchStrict<IndexerSearchResponse>('wazuh-alerts-4.x-*', {
        size,
        sort: [{ timestamp: { order: 'asc' } }],
        query: { bool: { filter: [{ range: { timestamp: { gt: since } } }, { exists: { field: 'data.srcip' } }] } },
        _source: ['timestamp', 'data.srcip', 'rule.level', 'rule.description', 'rule.groups', 'agent.id', 'agent.name', 'location'],
    });
    // Only advance the cursor on a successful query — a thrown/failed request (indexer down,
    // not configured, an error reply) retries the same window next time rather than skipping it.
    const hits = result?.hits?.hits ?? [];
    const newest = hits.at(-1)?._source?.timestamp;
    lastSyncTs = hits.length >= size && newest ? newest : startedAt;

    const newIps = ingestAlertHits(hits);
    return { newIps, hitCount: hits.length };
}

/** The organisation's Wazuh-sighted external IPs: only sightings on agents and senders it owns. */
export function wazuhIOCsForOrg(orgId: string, scope: OrgScope): OrgIOC[] {
    const owners = new Set<string>([...scope.agentIds, ...scope.locations.map((l) => `000@${l}`)]);
    const byIp = new Map<string, AccumulatedIp>();
    for (const [key, d] of wazuhAccumulator) {
        const [ip, owner] = key.split('\n');
        if (!owners.has(owner)) continue;
        const cur = byIp.get(ip);
        if (!cur) { byIp.set(ip, { ...d }); continue; }
        cur.count += d.count;
        if (d.firstSeenTs < cur.firstSeenTs) cur.firstSeenTs = d.firstSeenTs;
        if (d.lastSeenTs > cur.lastSeenTs) { cur.lastSeenTs = d.lastSeenTs; cur.latestAgent = d.latestAgent; }
        if (d.maxLevel >= cur.maxLevel) { cur.maxLevel = d.maxLevel; cur.latestRule = d.latestRule || cur.latestRule; }
    }
    return [...byIp.entries()].map(([ip, d]) => ({
        id: `wazuh-${ip.replace(/[.:]/g, '-')}`,
        org_id: orgId,
        value: ip,
        type: 'ip',
        source: 'wazuh',
        first_seen: d.firstSeenTs,
        last_seen: d.lastSeenTs,
        seen_count: d.count,
        risk_score: Math.min(d.maxLevel * 6, 100),
        verdict: verdictForLevel(d.maxLevel),
        tags: [d.latestRule].filter(Boolean),
        notes: `Seen on: ${d.latestAgent}`,
        shared: false,
        mitre_tactic: null,
        alert_ids: [],
        added_by: 'wazuh-auto',
    }));
}

/** Watcher health. Per-organisation counts come from wazuhIOCsForOrg(); this holds no tenant data. */
export function watcherStats() {
    return { total_alerts_ingested: totalAlertsIngested, last_synced: lastSyncTs };
}

/** Tests only: forget every sighting and restart the cursor window. */
export function __resetWazuhIOCsForTests(since = new Date(Date.now() - 5 * 60 * 1000).toISOString()): void {
    wazuhAccumulator.clear();
    lastSyncTs = since;
    totalAlertsIngested = 0;
}

// ── MANUAL / ANALYST-ADDED IOC STORE ───────────────────────────────────────

const manualIOCStore = new Map<string, OrgIOC[]>();

export function getManualIOCs(orgId: string): OrgIOC[] {
    return manualIOCStore.get(orgId) ?? [];
}
export function addManualIOC(orgId: string, ioc: OrgIOC): void {
    manualIOCStore.set(orgId, [...(manualIOCStore.get(orgId) ?? []), ioc]);
}
export function removeManualIOC(orgId: string, iocId: string): boolean {
    const existing = manualIOCStore.get(orgId);
    if (!existing) return false;
    const next = existing.filter((i) => i.id !== iocId);
    manualIOCStore.set(orgId, next);
    return next.length !== existing.length;
}
export function updateManualIOC(orgId: string, iocId: string, patch: Partial<OrgIOC>): OrgIOC | null {
    const existing = manualIOCStore.get(orgId);
    if (!existing) return null;
    let updated: OrgIOC | null = null;
    const next = existing.map((i) => {
        if (i.id !== iocId) return i;
        updated = { ...i, ...patch };
        return updated;
    });
    if (updated) manualIOCStore.set(orgId, next);
    return updated;
}
/** Every analyst-added IOC across every org that's been marked shared — used by GET /shared. */
export function allSharedManualIOCs(): OrgIOC[] {
    return [...manualIOCStore.values()].flat().filter((i) => i.shared);
}
export function orgCount(): number {
    return manualIOCStore.size;
}
