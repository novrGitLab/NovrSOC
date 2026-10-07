// GET /api/dashboard/nigeria-threats — the Nigeria threat map (NigeriaThreatMap.tsx), built from
// the Nigerian intelligence collector only (no Wazuh; see the handler's comment). A state with no
// collected activity renders a true zero; nothing is synthesized. Also /network-info/:ip (RIPE
// Stat) and the collector trigger/status routes.
import { Router } from 'express';
import { getSupabase } from '../services/geoEnrichment';
import { lookupASN } from '../services/ripeStat';
import { checkBlock, type AbuseIPDBBlockReport } from '../services/abuseipdb';
import { circlSearchPulses, type CIRCLPulse } from '../services/circl';
import { readSeededStates, hasDemoData, nigeriaStateToMapName } from '../services/nigeriaStateData';
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
// Every entry's `active` is derived from whether the source can actually run, and an inactive
// one says why. Sources that were evaluated and found unusable are listed as inactive rather
// than omitted, so the same dead API isn't re-proposed and re-tried every few months.
function nigeriaSourceStatus(): Array<{ name: string; active: boolean; detail: string }> {
    const greynoise = !!process.env.GREYNOISE_API_KEY;
    const fofa = !!(process.env.FOFA_API_KEY && process.env.FOFA_EMAIL);
    const serper = !!process.env.SERPER_API_KEY;
    return [
        { name: 'GreyNoise', active: greynoise, detail: greynoise ? 'Malicious IPs scanning from Nigerian networks' : 'GREYNOISE_API_KEY not set' },
        { name: 'Feodo Tracker', active: true, detail: 'Botnet C2 IPs — free, no key required' },
        { name: 'CIRCL OSINT', active: true, detail: 'Nigeria-tagged events from the public MISP feed — no key required' },
        { name: 'NITDA', active: serper, detail: serper ? 'NITDA/CERRT advisories discovered via search' : 'SERPER_API_KEY not set' },
        { name: 'FOFA', active: fofa, detail: fofa ? 'Exposed services on Nigerian networks' : 'FOFA_API_KEY/FOFA_EMAIL not set' },
        { name: 'ngCERT', active: false, detail: 'cert.gov.ng returns 403 to this backend — no scrapable feed' },
        // Checked live on 2026-09-18. Kept visible so the same three aren't re-adopted later.
        { name: 'Check Point ThreatMap', active: false, detail: 'threatmap-api.checkpoint.com accepts the connection then never responds (45s timeout), even with browser Origin/Referer headers' },
        { name: 'ThreatMiner', active: false, detail: 'HTTP 522 on both the API and threatminer.org itself — the service is down, not just rate-limiting' },
        { name: 'Cymon', active: false, detail: 'cymon.io does not resolve — the service shut down in 2019' },
    ];
}

const emptyStates = () =>
    Object.entries(NIGERIA_STATE_CODES).map(([name, code]) => ({
        name, code, threats: 0, critical: 0, high: 0, medium: 0, low: 0,
        severity: 'clean' as const, top_threat_type: 'None', top_rule: 'None',
        ips_monitored: 0, latest_alert: null as string | null, threat_types: {} as Record<string, number>,
        threat_level: 'None' as ThreatLevel, top_source_ip: null as string | null, affected_hosts: [] as string[],
    }));

// GET /api/dashboard/nigeria-threats
//
// Built only from the Nigerian intelligence collector's nigeria_state_threats rows (GreyNoise,
// Feodo Tracker, CIRCL, geolocated by IPregistry). Wazuh endpoint telemetry is deliberately NOT
// mixed in any more (2026-10 cleanup): this map describes Nigerian networks generally, not this
// deployment's own estate, and blending the two made neither readable.
//
// The collector stores cumulative per-state counts with one dominant threat type each, so:
//   * ?range= is accepted for compatibility and ignored — there is no time window to filter by;
//   * per-type totals (malware, phishing, …) and "today" counts are null — not available;
//   * a database read failure is reported as an error, never as an all-clear.
router.get('/nigeria-threats', async (_req, res) => {
    const states = emptyStates().map((st) => ({ ...st, severity: st.severity as string }));
    let totalThreats = 0;
    let totalCritical = 0;
    let demoData = false;
    let readError: string | null = null;

    try {
        const seeded = await readSeededStates();
        if (seeded.length > 0) {
            demoData = await hasDemoData();
            const byName = new Map(seeded.map((r) => [nigeriaStateToMapName(r.state_name), r]));
            for (const state of states) {
                const row = byName.get(state.name);
                if (!row) continue;
                const collected = row.attack_count ?? 0;
                if (collected === 0) continue;
                state.threats = collected;
                state.critical = row.critical_flag ? 1 : 0;
                state.top_threat_type = row.dominant_type ?? 'None';
                state.severity = row.critical_flag ? 'critical' : 'medium';
                state.threat_level = getThreatLevel(state.threats);
                totalThreats += collected;
                if (row.critical_flag) totalCritical += 1;
            }
        }
    } catch (err) {
        console.error('Nigeria threats — collector read failed:', err);
        readError = 'Collected Nigerian threat data could not be read — this is an outage, not an all-clear';
    }

    const sortedByThreats = [...states].sort((a, b) => b.threats - a.threats).filter((s) => s.threats > 0);
    const threatScore = totalThreats > 0 ? Math.min(Math.round(totalCritical * 10 + totalThreats * 0.5), 100) : 0;
    const supplemental = await getSupplementalNigeriaData().catch(emptySupplemental);

    res.json({
        states,
        summary: {
            total_threats: totalThreats,
            threat_score: threatScore,
            critical_states: states.filter((s) => s.severity === 'critical').length,
            states_affected: states.filter((s) => s.threats > 0).length,
            top_state: sortedByThreats[0]?.name ?? null,
            today_attacks: null,
            malware: null,
            phishing: null,
            botnets: null,
            ransomware: null,
            ddos: null,
            credential_theft: null,
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
            ...(readError ? { error: readError } : {}),
        },
        source: 'collector',
        // True when rows written by the (since removed) demo seeder are still in the table.
        demo_data: demoData,
        sources_active: nigeriaSourceStatus(),
        supplemental: {
            abuse_reports: supplemental.abuse_reports,
            threat_pulses: supplemental.threat_pulses.map((p) => ({ id: p.id, name: p.name, tags: p.tags, created: p.created })),
            cyber_news: supplemental.cyber_news,
            advisories: supplemental.advisories,
            fetched_at: supplemental.fetched_at,
        },
        generated_at: new Date().toISOString(),
    });
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