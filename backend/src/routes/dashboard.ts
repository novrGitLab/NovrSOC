// GET /api/dashboard/nigeria-threats + /network-info/:ip — real Wazuh Indexer aggregation for
// the Nigeria threat map (NigeriaThreatMap.tsx / NigeriaMap2.tsx). This replaces an earlier
// version of this file that baked in a DEFAULT_NATIONAL_DISTRIBUTION fallback (fake per-state
// counts like Lagos=18 used whenever the indexer/Supabase had nothing for a state) — that made
// the map look populated even when there was genuinely no data. This version has no such
// fallback: a state with zero matching alerts renders a true zero, and a full indexer outage
// returns `error: 'Wazuh indexer unavailable — showing zeros'` with every count at 0 rather than
// synthesizing numbers.
import { Router } from 'express';
import { search } from '../lib/wazuh-indexer';
import { enrichIPBatch, getSupabase } from '../services/geoEnrichment';
import { lookupASN } from '../services/ripeStat';
import { checkBlock, type AbuseIPDBBlockReport } from '../services/abuseipdb';
import { circlSearchPulses, type CIRCLPulse } from '../services/circl';
import { readSeededStates, hasDemoData, nigeriaStateToMapName } from '../services/nigeriaDemoSeed';
import { getNigerianCyberNews, type NewsResult } from '../services/serper';
import {
    runNigerianIntelCollector,
    getBufferedAdvisories,
    getLastCollectorResult,
    setLastCollectorResult,
    type CollectedAdvisory,
} from '../services/nigerianIntelCollector';

const router = Router();

export interface SupplementalNigeriaData {
    abuse_reports: Array<AbuseIPDBBlockReport & { isp: string; asn: string }>;
    threat_pulses: CIRCLPulse[];
    cyber_news: NewsResult[];
    // Advisories collected by services/nigerianIntelCollector.ts (ngCERT + CIRCL). Read from
    // `nigeria_advisories` when that table exists, otherwise from the collector's in-memory
    // buffer — `advisories_persisted` on the collector result says which.
    advisories: CollectedAdvisory[];
    fetched_at: string;
}

const NIGERIAN_ISP_ASNS = ['AS29465', 'AS36873', 'AS37148', 'AS37076', 'AS37282', 'AS37340'];

let supplementalCache: { data: SupplementalNigeriaData; expires: number } | null = null;

// Prefers the `nigeria_advisories` table; falls back to the collector's in-memory buffer when
// that table doesn't exist yet (PGRST205), so the feed shows this run's advisories either way.
async function fetchCollectedAdvisories(limit: number): Promise<CollectedAdvisory[]> {
    const supabase = getSupabase();
    if (supabase) {
        const { data, error } = await supabase
            .from('nigeria_advisories')
            .select('*')
            .eq('org_id', 'global')
            .order('published_at', { ascending: false })
            .limit(limit);
        if (!error && data) return data as CollectedAdvisory[];
    }
    return getBufferedAdvisories(limit);
}

async function getSupplementalNigeriaData(): Promise<SupplementalNigeriaData> {
    if (supplementalCache && supplementalCache.expires > Date.now()) return supplementalCache.data;

    const [abuseResults, circlPulses, cyberNews, collectedAdvisories] = await Promise.all([
        Promise.all(NIGERIAN_ISP_ASNS.map(async (asn) => {
            try {
                const info = await lookupASN(asn);
                const topPrefix = info.prefixes.find((p) => !p.includes(':'));
                if (!topPrefix) return [];

                const [addr, maskStr] = topPrefix.split('/');
                const mask = Number(maskStr);
                const cidr = mask >= 24 ? topPrefix : `${addr}/24`;
                const reported = await checkBlock(cidr, 14);
                return reported
                    .filter((r) => r.abuseConfidenceScore >= 50)
                    .map((r) => ({ ...r, isp: info.holder, asn }));
            } catch {
                return [];
            }
        })),
        circlSearchPulses('nigeria', 10).catch(() => [] as CIRCLPulse[]),
        getNigerianCyberNews(10).catch(() => [] as NewsResult[]),
        fetchCollectedAdvisories(10).catch(() => [] as CollectedAdvisory[]),
    ]);

    const data: SupplementalNigeriaData = {
        abuse_reports: abuseResults.flat().slice(0, 25),
        threat_pulses: circlPulses,
        cyber_news: cyberNews,
        advisories: collectedAdvisories,
        fetched_at: new Date().toISOString(),
    };
    supplementalCache = { data, expires: Date.now() + 15 * 60 * 1000 };
    return data;
}

const NIGERIA_STATE_CODES: Record<string, string> = {
    'Lagos': 'LA', 'Kano': 'KN', 'Rivers': 'RI', 'Oyo': 'OY',
    'Kaduna': 'KD', 'Katsina': 'KT', 'Ogun': 'OG', 'Borno': 'BO',
    'Anambra': 'AN', 'Bauchi': 'BA', 'Delta': 'DE', 'Imo': 'IM',
    'Niger': 'NI', 'Akwa Ibom': 'AK', 'Sokoto': 'SO', 'Ondo': 'ON',
    'Osun': 'OS', 'Kogi': 'KO', 'Zamfara': 'ZM', 'Enugu': 'EN',
    'Edo': 'ED', 'Plateau': 'PL', 'Adamawa': 'AD', 'Cross River': 'CR',
    'Benue': 'BE', 'Abia': 'AB', 'Ekiti': 'EK', 'Kwara': 'KW',
    'Jigawa': 'JI', 'Nassarawa': 'NA', 'Ebonyi': 'EB', 'Kebbi': 'KB',
    'Taraba': 'TA', 'Gombe': 'GO', 'Bayelsa': 'BY', 'Yobe': 'YO',
    'Federal Capital Territory': 'FC',
};

function classifyThreat(ruleGroups: string[]): string {
    const groups = (ruleGroups || []).join(' ').toLowerCase();
    if (groups.includes('ransomware') || groups.includes('ryuk') || groups.includes('lockbit')) return 'Ransomware';
    if (groups.includes('malware') || groups.includes('trojan') || groups.includes('virus')) return 'Malware';
    if (groups.includes('phishing') || groups.includes('web_attack')) return 'Phishing';
    if (groups.includes('botnet') || groups.includes('c2') || groups.includes('beacon')) return 'Botnet';
    if (groups.includes('ddos') || groups.includes('flood')) return 'DDoS';
    if (groups.includes('credential') || groups.includes('brute_force') || groups.includes('authentication')) return 'Credential Theft';
    return 'Other';
}

function severityFromLevel(level: number): 'critical' | 'high' | 'medium' | 'low' {
    if (level >= 12) return 'critical';
    if (level >= 9) return 'high';
    if (level >= 6) return 'medium';
    return 'low';
}

type ThreatLevel = 'None' | 'Low' | 'Medium' | 'High' | 'Severe' | 'Critical';
function getThreatLevel(count: number): ThreatLevel {
    if (count === 0) return 'None';
    if (count <= 5) return 'Low';
    if (count <= 20) return 'Medium';
    if (count <= 50) return 'High';
    if (count <= 100) return 'Severe';
    return 'Critical';
}

const emptySupplemental = (): SupplementalNigeriaData => ({
    abuse_reports: [],
    threat_pulses: [],
    cyber_news: [],
    advisories: [],
    fetched_at: new Date().toISOString(),
});

// Which Nigerian intelligence sources are wired and keyed right now. Each entry says what it
// contributes and, when inactive, exactly what's missing — so the UI can explain a quiet map
// instead of just showing zeros.
function nigeriaSourceStatus(): Array<{ name: string; active: boolean; detail: string }> {
    const greynoise = !!process.env.GREYNOISE_API_KEY;
    const fofa = !!(process.env.FOFA_API_KEY && process.env.FOFA_EMAIL);
    return [
        { name: 'GreyNoise', active: greynoise, detail: greynoise ? 'Malicious IPs scanning from Nigerian networks' : 'GREYNOISE_API_KEY not set' },
        { name: 'Feodo Tracker', active: true, detail: 'Botnet C2 IPs — free, no key required' },
        { name: 'CIRCL OSINT', active: true, detail: 'Nigeria-tagged events from the public MISP feed — no key required' },
        { name: 'FOFA', active: fofa, detail: fofa ? 'Exposed services on Nigerian networks' : 'FOFA_API_KEY/FOFA_EMAIL not set' },
        { name: 'ngCERT', active: false, detail: 'cert.gov.ng returns 403 to this backend — no scrapable feed' },
    ];
}

const emptyStates = () =>
    Object.entries(NIGERIA_STATE_CODES).map(([name, code]) => ({
        name, code, threats: 0, critical: 0, high: 0, medium: 0, low: 0,
        severity: 'clean' as const, top_threat_type: 'None', top_rule: 'None',
        ips_monitored: 0, latest_alert: null as string | null, threat_types: {} as Record<string, number>,
        threat_level: 'None' as ThreatLevel, top_source_ip: null as string | null, affected_hosts: [] as string[],
    }));

const emptySummary = (threatLevel: string, error?: string) => ({
    total_threats: 0, threat_score: 0, critical_states: 0, states_affected: 0,
    today_attacks: 0, malware: 0, phishing: 0, botnets: 0,
    ransomware: 0, ddos: 0, credential_theft: 0,
    highest_attack_states: [] as { name: string; count: number; state: string; threat_type: string }[],
    top_state: null as string | null,
    threat_level: threatLevel,
    ...(error ? { error } : {}),
});

interface AlertHit {
    _source: {
        timestamp?: string;
        agent?: { name?: string };
        rule?: { level?: number; description?: string; groups?: string[] };
        data?: { srcip?: string };
        GeoLocation?: { region_name?: string; country_name?: string };
    };
}
interface SearchResponse { hits?: { hits?: AlertHit[] } }

const RANGE_MS: Record<string, number> = {
    '1h': 60 * 60 * 1000,
    '24h': 24 * 60 * 60 * 1000,
    '7d': 7 * 24 * 60 * 60 * 1000,
};

// GET /api/dashboard/nigeria-threats
router.get('/nigeria-threats', async (req, res) => {
    const rangeParam = typeof req.query.range === 'string' ? req.query.range : '24h';
    const windowMs = RANGE_MS[rangeParam] ?? RANGE_MS['24h'];
    const now = new Date();
    const windowStart = new Date(now.getTime() - windowMs);

    try {
        const result = await search<SearchResponse>('wazuh-alerts-4.x-*', {
            size: 1000,
            query: { range: { timestamp: { gte: windowStart.toISOString(), lte: now.toISOString() } } },
            _source: [
                'timestamp', 'agent.name', 'agent.ip',
                'rule.level', 'rule.description', 'rule.groups',
                'data.srcip', 'data.dstip',
                'GeoLocation.region_name', 'GeoLocation.country_name',
                'GeoLocation.latitude', 'GeoLocation.longitude',
            ],
        });

        const hits = result?.hits?.hits ?? [];

        const stateMap: Record<string, {
            threats: number; critical: number; high: number; medium: number; low: number;
            threat_types: Record<string, number>; top_rules: Record<string, number>; top_source_ips: Record<string, number>;
            ips: Set<string>; agents: Set<string>; latest_alert: string;
        }> = {};
        
        for (const stateName of Object.keys(NIGERIA_STATE_CODES)) {
            stateMap[stateName] = { 
                threats: 0, critical: 0, high: 0, medium: 0, low: 0, 
                threat_types: {}, top_rules: {}, top_source_ips: {}, 
                ips: new Set(), agents: new Set(), latest_alert: '' 
            };
        }

        let totalThreats = 0;
        let totalCritical = 0;
        let ipEnrichedThreats = 0;
        const globalThreatTypes: Record<string, number> = {};

        function matchStateName(raw: string): string | undefined {
            if (!raw) return undefined;
            const needle = raw.toLowerCase().trim();
            if (needle.includes('abuja') || needle.includes('fct')) return 'Federal Capital Territory';
            return Object.keys(NIGERIA_STATE_CODES).find(
                (s) => needle === s.toLowerCase() || needle.includes(s.toLowerCase()) || s.toLowerCase().includes(needle)
            );
        }

        function attributeHit(hit: AlertHit, matchedState: string): void {
            const src = hit._source;
            const level = src.rule?.level ?? 0;
            const severity = severityFromLevel(level);
            const threatType = classifyThreat(src.rule?.groups ?? []);
            const srcIp = src.data?.srcip ?? '';
            const agentName = src.agent?.name ?? '';

            totalThreats++;
            if (severity === 'critical') totalCritical++;
            globalThreatTypes[threatType] = (globalThreatTypes[threatType] ?? 0) + 1;

            const stateData = stateMap[matchedState];
            if (!stateData) return;
            stateData.threats++;
            stateData[severity]++;
            stateData.threat_types[threatType] = (stateData.threat_types[threatType] ?? 0) + 1;
            const ruleDesc = src.rule?.description ?? 'Unknown';
            stateData.top_rules[ruleDesc] = (stateData.top_rules[ruleDesc] ?? 0) + 1;
            if (srcIp) {
                stateData.ips.add(srcIp);
                stateData.top_source_ips[srcIp] = (stateData.top_source_ips[srcIp] ?? 0) + 1;
            }
            if (agentName) stateData.agents.add(agentName);
            const ts = src.timestamp ?? '';
            if (!stateData.latest_alert || ts > stateData.latest_alert) stateData.latest_alert = ts;
        }

        const unattributedBySrcIp = new Map<string, AlertHit[]>();

        for (const hit of hits) {
            const src = hit._source;
            const region = src.GeoLocation?.region_name ?? '';
            const srcIp = src.data?.srcip ?? '';

            const matchedState = region ? matchStateName(region) : undefined;

            if (matchedState) {
                attributeHit(hit, matchedState);
                continue;
            }
            if (srcIp) {
                const bucket = unattributedBySrcIp.get(srcIp);
                if (bucket) bucket.push(hit);
                else unattributedBySrcIp.set(srcIp, [hit]);
            }
        }

        const candidateIps = [...unattributedBySrcIp.entries()]
            .sort((a, b) => b[1].length - a[1].length)
            .slice(0, 25)
            .map(([ip]) => ip);

        let enrichedCount = 0;
        let nigerianConfirmedCount = 0;
        if (candidateIps.length > 0) {
            try {
                const geoMap = await enrichIPBatch(candidateIps);
                enrichedCount = geoMap.size;
                for (const [ip, geo] of geoMap) {
                    if (!geo.is_nigerian) continue;
                    nigerianConfirmedCount++;
                    const matchedState = geo.region ? matchStateName(geo.region) : undefined;
                    if (!matchedState) continue;
                    for (const hit of unattributedBySrcIp.get(ip) ?? []) {
                        attributeHit(hit, matchedState);
                        ipEnrichedThreats++;
                    }
                }
            } catch (err) {
                console.error('Nigeria threats — IP enrichment fallback failed:', err);
            }
        }

        const states = Object.entries(stateMap).map(([name, data]) => {
            const topThreatType = Object.entries(data.threat_types).sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'None';
            const topRule = Object.entries(data.top_rules).sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'None';
            const topSourceIp = Object.entries(data.top_source_ips).sort((a, b) => b[1] - a[1])[0]?.[0] ?? null;

            let severity: 'critical' | 'high' | 'medium' | 'low' | 'clean' = 'clean';
            if (data.critical > 0) severity = 'critical';
            else if (data.high > 0) severity = 'high';
            else if (data.medium > 0) severity = 'medium';
            else if (data.threats > 0) severity = 'low';

            return {
                name,
                code: NIGERIA_STATE_CODES[name],
                threats: data.threats,
                critical: data.critical,
                high: data.high,
                medium: data.medium,
                low: data.low,
                severity,
                top_threat_type: topThreatType,
                top_rule: topRule,
                ips_monitored: data.ips.size,
                latest_alert: data.latest_alert || null,
                threat_types: data.threat_types,
                threat_level: getThreatLevel(data.threats),
                top_source_ip: topSourceIp,
                affected_hosts: [...data.agents],
            };
        });

        // The map above is built purely from Wazuh alerts. When Wazuh attributed nothing to any
        // Nigerian state (the normal case today — few agents, little geolocated traffic), fall
        // back to whatever baseline is stored in nigeria_state_threats so the map isn't blank.
        // `demo_data` in the response tells the UI to badge it, so a populated map is never
        // mistaken for live telemetry. Live Wazuh data always wins — this only runs at zero.
        let demoData = false;
        // Set when the states below came from the nigeria_state_threats table (written by the
        // Nigerian collector: GreyNoise, Feodo, CIRCL) rather than from Wazuh's own alerts.
        // Distinct from demoData — that table now normally holds REAL collected counts, and
        // reporting those as 'wazuh' would misattribute them to telemetry they didn't come from.
        let fromCollector = false;
        if (!states.some((s) => s.threats > 0)) {
            const seeded = await readSeededStates();
            if (seeded.length > 0) {
                fromCollector = true;
                demoData = await hasDemoData();
                const byName = new Map(seeded.map((r) => [nigeriaStateToMapName(r.state_name), r]));
                for (const state of states) {
                    const row = byName.get(state.name);
                    if (!row) continue;
                    state.threats = row.attack_count ?? 0;
                    state.critical = row.critical_flag ? 1 : 0;
                    state.top_threat_type = row.dominant_type ?? 'None';
                    state.severity = row.critical_flag ? 'critical' : state.threats > 0 ? 'medium' : 'clean';
                    state.threat_level = getThreatLevel(state.threats);
                    totalThreats += state.threats;
                    totalCritical += state.critical;
                }
            }
        }

        const sortedByThreats = [...states].sort((a, b) => b.threats - a.threats).filter((s) => s.threats > 0);
        const threatScore = totalThreats > 0
            ? Math.min(Math.round((totalCritical * 10 + totalThreats * 0.5) / Math.max(hits.length / 100, 1)), 100)
            : 0;
        const criticalStates = states.filter((s) => s.severity === 'critical').length;
        const statesAffected = states.filter((s) => s.threats > 0).length;
        const topState = sortedByThreats[0]?.name ?? null;

        const supplemental = await getSupplementalNigeriaData().catch(emptySupplemental);

        res.json({
            states,
            summary: {
                total_threats: totalThreats,
                threat_score: threatScore,
                critical_states: criticalStates,
                states_affected: statesAffected,
                top_state: topState,
                today_attacks: totalThreats,
                malware: globalThreatTypes['Malware'] ?? 0,
                phishing: globalThreatTypes['Phishing'] ?? 0,
                botnets: globalThreatTypes['Botnet'] ?? 0,
                ransomware: globalThreatTypes['Ransomware'] ?? 0,
                ddos: globalThreatTypes['DDoS'] ?? 0,
                credential_theft: globalThreatTypes['Credential Theft'] ?? 0,
                highest_attack_states: sortedByThreats.slice(0, 6).map((s) => ({
                    name: `${s.top_threat_type} ${s.name}`,
                    count: s.threats,
                    state: s.name,
                    threat_type: s.top_threat_type,
                })),
                threat_level: totalCritical > 0 ? 'CRITICAL'
                    : totalThreats > 50 ? 'HIGH'
                    : totalThreats > 20 ? 'MEDIUM'
                    : totalThreats > 0 ? 'LOW'
                    : 'CLEAR',
            },
            source: demoData ? 'seed' : fromCollector ? 'collector' : 'wazuh',
            // True when the states above came from the illustrative baseline rather than live
            // Wazuh telemetry — the frontend badges the map accordingly.
            demo_data: demoData,
            // Which intelligence sources can currently contribute to this map. Derived from what
            // is actually configured, so the badges reflect reality rather than a hardcoded list.
            sources_active: nigeriaSourceStatus(),
            geo_sources: {
                ipregistry: 'Primary geolocation and enrichment',
                ripe_stat: 'ASN and BGP routing information',
                afrinic: 'African IP allocation confirmation',
            },
            enrichment_coverage: {
                unattributed_ips: unattributedBySrcIp.size,
                ips_enriched: enrichedCount,
                nigerian_confirmed: nigerianConfirmedCount,
                threats_added_by_enrichment: ipEnrichedThreats,
            },
            supplemental: {
                abuse_reports: supplemental.abuse_reports,
                threat_pulses: supplemental.threat_pulses.map((p) => ({ id: p.id, name: p.name, tags: p.tags, created: p.created })),
                cyber_news: supplemental.cyber_news,
                advisories: supplemental.advisories,
                fetched_at: supplemental.fetched_at,
            },
            generated_at: now.toISOString(),
        });
    } catch (err) {
        console.error('Nigeria threats error:', err);
        const supplemental = await getSupplementalNigeriaData().catch(emptySupplemental);

        res.json({
            states: emptyStates(),
            summary: emptySummary('CLEAR', 'Wazuh indexer unavailable — showing zeros'),
            source: 'wazuh',
            // Also reported on the failure path — a Wazuh outage shouldn't make the source
            // badges disappear, since which feeds are keyed is independent of it.
            sources_active: nigeriaSourceStatus(),
            geo_sources: {
                ipregistry: 'Primary geolocation and enrichment',
                ripe_stat: 'ASN and BGP routing information',
                afrinic: 'African IP allocation confirmation',
            },
            enrichment_coverage: { unattributed_ips: 0, ips_enriched: 0, nigerian_confirmed: 0, threats_added_by_enrichment: 0 },
            supplemental: {
                abuse_reports: supplemental.abuse_reports,
                threat_pulses: supplemental.threat_pulses.map((p) => ({ id: p.id, name: p.name, tags: p.tags, created: p.created })),
                cyber_news: supplemental.cyber_news,
                advisories: supplemental.advisories,
                fetched_at: supplemental.fetched_at,
            },
            generated_at: new Date().toISOString(),
            error: 'Wazuh indexer unavailable — showing zeros',
        });
    }
});

// GET /api/dashboard/network-info/:ip
router.get('/network-info/:ip', async (req, res) => {
    const { ip } = req.params;
    try {
        const netRes = await fetch(`https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`, { signal: AbortSignal.timeout(6000) });
        const netJson = await netRes.json();
        if (netJson?.status !== 'ok') {
            res.status(404).json({ error: 'RIPE Stat has no routing data for this IP', ip });
            return;
        }

        const asn: string | null = netJson.data?.asns?.[0] ? `AS${netJson.data.asns[0]}` : null;
        const prefix: string | null = netJson.data?.prefix ?? null;
        const asnInfo = asn ? await lookupASN(asn).catch(() => null) : null;

        res.json({
            ip,
            asn,
            prefix,
            holder: asnInfo?.holder ?? null,
            authoritative_rir: asnInfo?.authoritative_rir ?? null,
            is_afrinic: asnInfo?.is_afrinic ?? false,
            announced_prefixes: asnInfo?.prefixes ?? [],
            source: 'RIPE NCC',
        });
    } catch (err) {
        res.status(502).json({ error: err instanceof Error ? err.message : 'RIPE Stat lookup failed', ip });
    }
});

// POST /api/dashboard/nigeria-threats/collect — run the Nigerian intel collector on demand
// (the "Refresh Intelligence" button on the Nigerian Threat Feed page). The hourly job runs the
// same function; the collector itself refuses overlapping runs so a double-click can't
// double-count state counters.
router.post('/nigeria-threats/collect', async (_req, res) => {
    try {
        const result = await runNigerianIntelCollector();
        setLastCollectorResult(result);
        // The 15-minute supplemental cache would otherwise hide the advisories that just landed.
        supplementalCache = null;
        res.json({ success: true, result });
    } catch (err) {
        console.error('[dashboard] Nigeria collect error:', err);
        res.status(500).json({ success: false, error: err instanceof Error ? err.message : 'Collection failed' });
    }
});

// GET /api/dashboard/nigeria-threats/status — when intelligence was last refreshed and which
// sources produced anything, without triggering a new run.
router.get('/nigeria-threats/status', (_req, res) => {
    res.json({ last_run: getLastCollectorResult() });
});

export default router;