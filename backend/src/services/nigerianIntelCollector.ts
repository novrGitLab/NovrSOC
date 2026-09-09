// Nigerian threat-intelligence collector — pulls from open sources, resolves IOCs to Nigerian
// states, persists what it finds, and pushes new IOCs to MISP.
//
// EVERY source below was tested live before this was written (2026-09-07), because three of the
// four don't behave the way the spec assumed:
//
//   * ngCERT (cert.gov.ng) — HTTP 403 on every path tried, including the site root, with both a
//     bot UA and a full browser UA. The whole domain refuses this network, so the scraper below
//     collects nothing from here today. It's still implemented (and still the first source
//     tried) because Railway's egress may not be blocked the way this one is — if it isn't,
//     this starts producing advisories with no code change. It fails silently to 0, never throws.
//   * CIRCL OSINT feed — replaced OTX here on 2026-09-09. OTX was removed because its key was
//     invalid (403 on every endpoint, 31 chars where a real key is 64) so it contributed
//     nothing. CIRCL needs no key. Note its published entry point is manifest.json — the
//     feed-osint/ directory URL itself serves an HTML index, not JSON.
//   * Feodo Tracker — WORKS, no key needed. This is the one source actually producing live IOCs
//     right now (botnet C2 IPs), so it's the reason the collector isn't a no-op today.
//   * IPregistry — WORKS. Used to resolve each IOC to a Nigerian state.
//
// Persistence reality, also checked live: `public.nigeria_state_threats` EXISTS (37 rows, one
// per state + FCT, pre-seeded with coordinates and zeroed counters) and is what the Nigeria map
// reads, so state aggregates are written there. There is NO advisories table — not in `public`,
// and the `nigeria_intel` / `global_intel` schemas the spec assumed don't exist either (PGRST106
// "Invalid schema"), and PostgREST can't reach a non-`public` schema unless it's explicitly
// exposed in Supabase's API settings regardless. Advisories therefore go to
// `public.nigeria_advisories` when it exists and to an in-memory ring buffer when it doesn't,
// with `advisories_persisted` in the result saying which happened. Run
// backend/sql/2026-09-threat-intel.sql to create it.

import { getSupabase } from './geoEnrichment';
import { getNigerianState } from './nigeriaGeo';
import { addAttributeToEvent, isMISPConfigured } from './misp';
import { circlSearchPulses, circlGetPulseIndicators, type CIRCLPulse } from './circl';

const NIGERIA_EVENT_ID = process.env.MISP_NIGERIA_EVENT_ID || '1';

export interface CollectedAdvisory {
    source: string;
    advisory_id: string;
    title: string;
    description: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    threat_type: string;
    tags: string[];
    source_url: string;
    published_at: string;
}

export interface CollectorResult {
    ran_at: string;
    duration_ms: number;
    advisories: number;
    ips_found: number;
    states_updated: string[];
    advisories_persisted: boolean;
    sources: Array<{ name: string; ok: boolean; items: number; note?: string }>;
}

// ── IOC EXTRACTION ────────────────────────────────────────────────

const IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const CVE_RE = /CVE-\d{4}-\d{4,}/gi;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;

// 172.x is only private inside 172.16.0.0/12 — the spec's filter dropped ALL of 172.*, which
// throws away 172.0-15.* and 172.32-255.*, both fully routable public space that regularly shows
// up in C2 lists. Narrowed to the real RFC1918 range here.
export function extractIPs(text: string): string[] {
    const matches = text.match(IP_RE) ?? [];
    return [...new Set(matches)].filter((ip) => {
        if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.') || ip.startsWith('0.')) return false;
        if (ip.startsWith('172.')) {
            const second = Number(ip.split('.')[1]);
            if (second >= 16 && second <= 31) return false;
        }
        return true;
    });
}

export function extractDomains(text: string): string[] {
    const matches = text.match(DOMAIN_RE) ?? [];
    return [...new Set(matches)].filter((d) => !/^\d+\.\d+/.test(d));
}

export function extractCVEs(text: string): string[] {
    return [...new Set((text.match(CVE_RE) ?? []).map((c) => c.toUpperCase()))];
}

export function getThreatType(text: string): string {
    const l = text.toLowerCase();
    if (l.includes('ransomware')) return 'ransomware';
    if (l.includes('phishing')) return 'phishing';
    if (l.includes('brute force') || l.includes('bruteforce')) return 'brute_force';
    if (l.includes('command and control') || l.includes('c2') || l.includes('c&c')) return 'c2';
    if (l.includes('ddos') || l.includes('denial of service')) return 'ddos';
    if (l.includes('malware') || l.includes('trojan') || l.includes('virus')) return 'malware';
    if (l.includes('exploit') || l.includes('vulnerability')) return 'exploitation';
    if (l.includes('data breach') || l.includes('leak')) return 'data_breach';
    return 'unknown';
}

// ── SOURCES ───────────────────────────────────────────────────────

async function fetchNgCERTAdvisories(): Promise<{ items: Array<{ url: string; title: string }>; note?: string }> {
    try {
        const r = await fetch('https://cert.gov.ng/advisories', {
            headers: { 'User-Agent': 'NovrSOC-CTI-Collector/1.0 (security@cybernovr.com)' },
            signal: AbortSignal.timeout(15000),
        });
        if (!r.ok) return { items: [], note: `cert.gov.ng returned HTTP ${r.status}` };
        const html = await r.text();

        const re = /<a[^>]+href="([^"]*advisor[^"]*)"[^>]*>([^<]+)<\/a>/gi;
        const items: Array<{ url: string; title: string }> = [];
        let m: RegExpExecArray | null;
        while ((m = re.exec(html)) !== null) {
            const title = m[2].trim();
            if (!title) continue;
            items.push({ url: m[1].startsWith('http') ? m[1] : `https://cert.gov.ng${m[1]}`, title });
        }
        return { items: items.slice(0, 20) };
    } catch (err) {
        return { items: [], note: err instanceof Error ? err.message : 'fetch failed' };
    }
}

async function fetchAdvisoryContent(url: string): Promise<string> {
    try {
        const r = await fetch(url, { headers: { 'User-Agent': 'NovrSOC-CTI-Collector/1.0' }, signal: AbortSignal.timeout(10000) });
        if (!r.ok) return '';
        const html = await r.text();
        return html.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
    } catch {
        return '';
    }
}

// Nigeria-relevant events from the keyless CIRCL OSINT feed, replacing the OTX pulse search
// that used to sit here (removed 2026-09-09 — its key was rejected on every call).
async function fetchCIRCLNigerianPulses(): Promise<{ items: CIRCLPulse[]; note?: string }> {
    try {
        const items = await circlSearchPulses('nigeria', 20);
        return { items, note: items.length === 0 ? 'No Nigeria-tagged events in the current CIRCL feed' : undefined };
    } catch (err) {
        return { items: [], note: err instanceof Error ? err.message : 'fetch failed' };
    }
}

async function fetchFeodoTrackerIPs(): Promise<{ items: string[]; note?: string }> {
    try {
        const r = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist.txt', { signal: AbortSignal.timeout(12000) });
        if (!r.ok) return { items: [], note: `Feodo returned HTTP ${r.status}` };
        const text = await r.text();
        const items = text
            .split('\n')
            .map((line) => line.trim())
            .filter((line) => line && !line.startsWith('#'));
        return { items };
    } catch (err) {
        return { items: [], note: err instanceof Error ? err.message : 'fetch failed' };
    }
}

// ── PERSISTENCE ───────────────────────────────────────────────────

// In-memory fallback for advisories while `nigeria_advisories` doesn't exist. Bounded so a
// long-running process can't grow this without limit.
const advisoryBuffer: CollectedAdvisory[] = [];
const ADVISORY_BUFFER_MAX = 200;

export function getBufferedAdvisories(limit = 20): CollectedAdvisory[] {
    return advisoryBuffer.slice(0, limit);
}

async function storeAdvisories(advisories: CollectedAdvisory[]): Promise<boolean> {
    for (const a of advisories) {
        if (!advisoryBuffer.some((existing) => existing.advisory_id === a.advisory_id)) advisoryBuffer.unshift(a);
    }
    advisoryBuffer.length = Math.min(advisoryBuffer.length, ADVISORY_BUFFER_MAX);

    const supabase = getSupabase();
    if (!supabase || advisories.length === 0) return false;

    const { error } = await supabase.from('nigeria_advisories').upsert(
        advisories.map((a) => ({
            source: a.source,
            advisory_id: a.advisory_id,
            title: a.title,
            description: a.description,
            severity: a.severity,
            threat_type: a.threat_type,
            tags: a.tags,
            source_url: a.source_url,
            published_at: a.published_at,
            org_id: 'global',
        })),
        { onConflict: 'advisory_id' }
    );
    if (error) {
        // PGRST205 = table missing, which is the expected state until the SQL file is run.
        if (error.code !== 'PGRST205') console.warn('[NigerianIntel] Advisory persist failed:', error.message);
        return false;
    }
    return true;
}

// Bumps a state's counters on the table the Nigeria map actually reads. Read-modify-write
// (no unique constraint on state_name to upsert against, same limitation as org_setup).
async function bumpStateThreat(state: string, threatType: string, increment: number): Promise<boolean> {
    const supabase = getSupabase();
    if (!supabase) return false;
    try {
        const { data: row } = await supabase
            .from('nigeria_state_threats')
            .select('id, attack_count, threat_score')
            .eq('state_name', state)
            .maybeSingle();
        if (!row) return false;

        const attackCount = (row.attack_count ?? 0) + increment;
        // Score is a bounded 0-100 read of volume, not a fabricated risk rating — 1 point per
        // observed IOC, capped, so the map's colour scale stays meaningful as counts grow.
        const threatScore = Math.min(100, attackCount);
        const { error } = await supabase
            .from('nigeria_state_threats')
            .update({
                attack_count: attackCount,
                threat_score: threatScore,
                dominant_type: threatType,
                critical_flag: threatScore >= 50,
                last_updated: new Date().toISOString(),
            })
            .eq('id', row.id);
        return !error;
    } catch {
        return false;
    }
}

async function pushToMISP(ioc: { value: string; comment: string }): Promise<void> {
    if (!isMISPConfigured()) return;
    await addAttributeToEvent(NIGERIA_EVENT_ID, { type: 'ip-dst', value: ioc.value, comment: ioc.comment }).catch(() => false);
}

// ── MAIN COLLECTOR ────────────────────────────────────────────────

let running = false;

export async function runNigerianIntelCollector(): Promise<CollectorResult> {
    const startedAt = Date.now();
    const sources: CollectorResult['sources'] = [];
    const statesUpdated = new Set<string>();
    const advisories: CollectedAdvisory[] = [];
    let ipsFound = 0;

    // The hourly job and the manual trigger endpoint can both fire this; overlapping runs would
    // double-count every state counter, so a second concurrent run is refused rather than queued.
    if (running) {
        return {
            ran_at: new Date().toISOString(), duration_ms: 0, advisories: 0, ips_found: 0,
            states_updated: [], advisories_persisted: false,
            sources: [{ name: 'collector', ok: false, items: 0, note: 'A collection run is already in progress' }],
        };
    }
    running = true;

    try {
        // 1. ngCERT advisories
        const ngcert = await fetchNgCERTAdvisories();
        sources.push({ name: 'ngCERT', ok: !ngcert.note, items: ngcert.items.length, note: ngcert.note });

        for (const [i, item] of ngcert.items.entries()) {
            const content = await fetchAdvisoryContent(item.url);
            const threatType = getThreatType(`${item.title} ${content}`);
            const cves = extractCVEs(content);
            advisories.push({
                source: 'ngCERT',
                advisory_id: `NGCERT-${Buffer.from(item.url).toString('base64url').slice(0, 32)}`,
                title: item.title,
                description: content.slice(0, 500),
                severity: cves.length > 0 ? 'high' : 'medium',
                threat_type: threatType,
                tags: ['ngcert', 'nigeria', threatType, ...cves.slice(0, 5)],
                source_url: item.url,
                published_at: new Date().toISOString(),
            });

            for (const ip of extractIPs(content).slice(0, 10)) {
                const state = await getNigerianState(ip);
                if (!state) continue;
                await bumpStateThreat(state, threatType, 1);
                await pushToMISP({ value: ip, comment: `ngCERT: ${item.title}` });
                statesUpdated.add(state);
                ipsFound++;
            }
            if (i < ngcert.items.length - 1) await new Promise((r) => setTimeout(r, 1000)); // be polite
        }

        // 2. CIRCL OSINT Nigeria-tagged events
        const circl = await fetchCIRCLNigerianPulses();
        sources.push({ name: 'CIRCL OSINT', ok: circl.items.length > 0, items: circl.items.length, note: circl.note });

        for (const pulse of circl.items) {
            advisories.push({
                source: 'CIRCL OSINT',
                advisory_id: `CIRCL-${pulse.id}`,
                title: pulse.name,
                description: (pulse.description ?? '').slice(0, 500),
                severity: 'medium',
                threat_type: getThreatType(`${pulse.name} ${pulse.description ?? ''}`),
                tags: [...(pulse.tags ?? []), 'nigeria', 'circl'],
                source_url: `https://www.circl.lu/doc/misp/feed-osint/${pulse.id}.json`,
                published_at: pulse.created,
            });

            // The manifest has no inline indicators, so pull this one event's attributes and use
            // its IPv4 values. Only runs for events that already matched "nigeria", so this is a
            // handful of requests per collection run, not one per feed entry.
            const indicators = await circlGetPulseIndicators(pulse.id);
            for (const indicator of indicators.filter((i) => i.type === 'ip-src' || i.type === 'ip-dst').slice(0, 20)) {
                const state = await getNigerianState(indicator.value);
                if (!state) continue;
                await bumpStateThreat(state, 'malware', 1);
                statesUpdated.add(state);
                ipsFound++;
            }
        }

        // 3. Feodo Tracker botnet C2 IPs — the only source currently returning live data.
        const feodo = await fetchFeodoTrackerIPs();
        sources.push({ name: 'Feodo Tracker', ok: !feodo.note, items: feodo.items.length, note: feodo.note });

        // Capped: each IP costs one IPregistry lookup, and the free tier is metered.
        for (const ip of feodo.items.slice(0, 40)) {
            const state = await getNigerianState(ip);
            if (!state) continue; // non-Nigerian C2s are the overwhelming majority — skipped, not faked onto the map
            await bumpStateThreat(state, 'c2', 1);
            await pushToMISP({ value: ip, comment: 'Feodo Tracker botnet C2' });
            statesUpdated.add(state);
            ipsFound++;
        }

        const persisted = await storeAdvisories(advisories);

        const result: CollectorResult = {
            ran_at: new Date().toISOString(),
            duration_ms: Date.now() - startedAt,
            advisories: advisories.length,
            ips_found: ipsFound,
            states_updated: [...statesUpdated],
            advisories_persisted: persisted,
            sources,
        };
        console.log(`[NigerianIntel] Run complete in ${result.duration_ms}ms — advisories: ${result.advisories}, Nigerian IPs: ${result.ips_found}, states touched: ${result.states_updated.length}`);
        return result;
    } catch (err) {
        console.error('[NigerianIntel] Collection error:', err);
        return {
            ran_at: new Date().toISOString(),
            duration_ms: Date.now() - startedAt,
            advisories: advisories.length,
            ips_found: ipsFound,
            states_updated: [...statesUpdated],
            advisories_persisted: false,
            sources: [...sources, { name: 'collector', ok: false, items: 0, note: err instanceof Error ? err.message : 'unknown error' }],
        };
    } finally {
        running = false;
    }
}

// Last run's result, so the API and the UI can show when intelligence was last refreshed
// without triggering a new collection.
let lastResult: CollectorResult | null = null;
export function getLastCollectorResult(): CollectorResult | null {
    return lastResult;
}
export function setLastCollectorResult(result: CollectorResult): void {
    lastResult = result;
}
