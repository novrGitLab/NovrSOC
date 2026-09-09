import { Router } from 'express';
import { search } from '../lib/wazuh-indexer';
import { sendCriticalAlertEmail } from '../services/email';
import { isDemoMode } from '../lib/demoMode';
import { createCase, isTheHiveConfigured, deriveIncidentNumber } from '../services/thehive';
import { getGreyNoiseCountryStats, isGreyNoiseConfigured } from '../services/greynoise';

// SecOps Threat Management console — live security event stream from the Wazuh Indexer
// (wazuh-alerts-4.x-*, same OpenSearch backend /api/wazuh/alerts-indexer queries), falling
// back to demo data when the indexer isn't configured, unreachable, or has nothing indexed
// yet. The Manager REST API's GET /alerts (services/wazuh.ts's getAlerts) 404s on this
// deployment (Wazuh v4.7.5) — alert search only works through the indexer here. Not to be
// confused with routes/threat-intel.ts / routes/ctip.ts, which power the separate
// CTIP-backed threat-intel dashboards.

const router = Router();

type Severity = 'critical' | 'high' | 'medium' | 'low';
type AlertStatus = 'open' | 'investigating' | 'acknowledged' | 'closed';

interface ThreatAlert {
    id: string;
    rule_id: string;
    rule_level: number;
    rule_description: string;
    severity: Severity;
    status: AlertStatus;
    mitre_tactic: string;
    mitre_technique: string;
    source_ip: string | null;
    source_country: string | null;
    source_isp: string | null;
    destination_ip: string;
    destination_host: string;
    destination_port: number | null;
    protocol: string;
    agent_id: string;
    agent_name: string;
    alert_count: number;
    raw_log: string;
    detected_at: string;
    tags: string[];
    abuseipdb_confidence: number | null;
    vt_malicious: number | null;
    pulse_matches: number | null;
    assigned_to: string | null;
}

const MOCK_ALERTS: ThreatAlert[] = [
    {
        id: 'al_001',
        rule_id: 'WR-100234',
        rule_level: 14,
        rule_description: 'Tor Exit Node Communication Detected',
        severity: 'critical',
        status: 'open',
        mitre_tactic: 'Command and Control',
        mitre_technique: 'T1090 - Proxy',
        source_ip: '185.220.101.47',
        source_country: 'DE',
        source_isp: 'Stiftung Erneuerbare Freiheit (Tor)',
        destination_ip: '10.0.1.10',
        destination_host: 'ec2-app-server',
        destination_port: 443,
        protocol: 'TCP',
        agent_id: 'ec2-app-server',
        agent_name: 'EC2-1 App Server',
        alert_count: 1,
        raw_log: 'zeek:conn.log — connection from 185.220.101.47:58291 to 10.0.1.10:443 (3.2KB sent, 0.8KB received)',
        detected_at: '2026-08-12 14:23:11',
        tags: ['tor', 'c2', 'proxy'],
        abuseipdb_confidence: 94,
        vt_malicious: 16,
        pulse_matches: 8,
        assigned_to: null,
    },
    {
        id: 'al_002',
        rule_id: 'WR-100087',
        rule_level: 13,
        rule_description: 'Multiple Failed SSH Logins from Foreign IP — Possible Brute Force',
        severity: 'critical',
        status: 'investigating',
        mitre_tactic: 'Credential Access',
        mitre_technique: 'T1110 - Brute Force',
        source_ip: '45.155.205.233',
        source_country: 'CN',
        source_isp: 'Shenzhen Tencent Computer Systems',
        destination_ip: '10.0.1.20',
        destination_host: 'ec2-wazuh-server',
        destination_port: 22,
        protocol: 'TCP',
        agent_id: 'ec2-wazuh',
        agent_name: 'EC2-2 Wazuh Server',
        alert_count: 47,
        raw_log: "wazuh:auth — 47 failed SSH login attempts for root from 45.155.205.233 between 03:14:22 and 03:47:08",
        detected_at: '2026-08-12 03:47:08',
        tags: ['brute-force', 'ssh', 'china'],
        abuseipdb_confidence: 87,
        vt_malicious: 12,
        pulse_matches: 3,
        assigned_to: 'Karl Mensah',
    },
    {
        id: 'al_003',
        rule_id: 'WR-100412',
        rule_level: 13,
        rule_description: 'Known Ransomware C2 Server Communication',
        severity: 'critical',
        status: 'open',
        mitre_tactic: 'Command and Control',
        mitre_technique: 'T1071 - Application Layer Protocol',
        source_ip: '10.0.1.30',
        source_country: 'NG',
        source_isp: 'Internal — EC2 Sensor',
        destination_ip: '91.215.153.180',
        destination_host: 'ec2-sensor (outbound)',
        destination_port: 8080,
        protocol: 'HTTP',
        agent_id: 'ec2-sensor',
        agent_name: 'EC2-3 Sensor',
        alert_count: 1,
        raw_log: 'suricata:eve.json — ET MALWARE Ryuk Ransomware C2 Beacon detected. dst=91.215.153.180:8080',
        detected_at: '2026-08-12 09:15:44',
        tags: ['ransomware', 'ryuk', 'c2', 'suricata'],
        abuseipdb_confidence: 98,
        vt_malicious: 58,
        pulse_matches: 24,
        assigned_to: null,
    },
    {
        id: 'al_004',
        rule_id: 'WR-100056',
        rule_level: 10,
        rule_description: 'New File Created in Sensitive Directory',
        severity: 'high',
        status: 'open',
        mitre_tactic: 'Persistence',
        mitre_technique: 'T1543 - Create or Modify System Process',
        source_ip: null,
        source_country: null,
        source_isp: null,
        destination_ip: '10.0.1.10',
        destination_host: 'ec2-app-server',
        destination_port: null,
        protocol: 'N/A',
        agent_id: 'ec2-app-server',
        agent_name: 'EC2-1 App Server',
        alert_count: 1,
        raw_log: 'wazuh:syscheck — New file: /etc/cron.d/cleanup (md5: a3f5c2d8, sha256: b7e2d4f6...)',
        detected_at: '2026-08-12 06:44:22',
        tags: ['fim', 'persistence', 'cron'],
        abuseipdb_confidence: null,
        vt_malicious: null,
        pulse_matches: null,
        assigned_to: null,
    },
    {
        id: 'al_005',
        rule_id: 'WR-100198',
        rule_level: 8,
        rule_description: 'Outbound Connection to Newly Registered Domain',
        severity: 'medium',
        status: 'open',
        mitre_tactic: 'Exfiltration',
        mitre_technique: 'T1048 - Exfiltration Over Alternative Protocol',
        source_ip: '10.0.1.50',
        source_country: 'NG',
        source_isp: 'Internal — EC2 Auxiliary',
        destination_ip: '104.21.18.99',
        destination_host: 'novrsoc-free-tools.xyz',
        destination_port: 443,
        protocol: 'HTTPS',
        agent_id: 'ec2-auxiliary',
        agent_name: 'EC2-5 Auxiliary',
        alert_count: 3,
        raw_log: "zeek:dns.log — query: novrsoc-free-tools.xyz (registered 3 days ago, cert: Let's Encrypt)",
        detected_at: '2026-08-12 16:02:33',
        tags: ['nrd', 'suspicious-domain', 'exfil'],
        abuseipdb_confidence: 12,
        vt_malicious: 0,
        pulse_matches: 0,
        assigned_to: null,
    },
    {
        id: 'al_006',
        rule_id: 'WR-100301',
        rule_level: 6,
        rule_description: 'User Account Created Outside Business Hours',
        severity: 'low',
        status: 'acknowledged',
        mitre_tactic: 'Persistence',
        mitre_technique: 'T1136 - Create Account',
        source_ip: '10.0.1.10',
        source_country: 'NG',
        source_isp: 'Internal',
        destination_ip: '10.0.1.10',
        destination_host: 'ec2-app-server',
        destination_port: null,
        protocol: 'N/A',
        agent_id: 'ec2-app-server',
        agent_name: 'EC2-1 App Server',
        alert_count: 1,
        raw_log: 'wazuh:eventlog — New user account "deploy-svc" created by root at 02:31:14 (outside business hours)',
        detected_at: '2026-08-11 02:31:14',
        tags: ['account-creation', 'after-hours'],
        abuseipdb_confidence: null,
        vt_malicious: null,
        pulse_matches: null,
        assigned_to: null,
    },
];

const MOCK_STATS = {
    total_alerts_24h: 47,
    critical: 3,
    high: 8,
    medium: 12,
    low: 24,
    open: 18,
    investigating: 4,
    acknowledged: 25,
    active_agents: 5,
    mitre_tactics_seen: ['Command and Control', 'Credential Access', 'Persistence', 'Exfiltration'],
};

// Shape of a wazuh-alerts-4.x-* document as returned by the Indexer's _search — see
// routes/wazuh.ts's /alerts-indexer, /trend, /incidents for the same interface pattern.
interface IndexerAlertHit {
    _id: string;
    _source: {
        timestamp?: string;
        rule?: {
            id?: number | string;
            level?: number;
            description?: string;
            groups?: string[];
            mitre?: { tactic?: string[]; technique?: string[] };
        };
        agent?: { id?: string; name?: string };
        data?: { srcip?: string };
        location?: string;
    };
}
interface IndexerSearchResponse {
    hits?: { hits?: IndexerAlertHit[]; total?: { value?: number } };
}

// Wazuh alerts don't carry a NovrSOC-side triage status/incident link — 'open' is the honest
// default for anything freshly indexed. PATCH/create-incident below mutate whatever list is
// currently cached here, live or mock, so triage actions still stick between requests even
// though GET /alerts re-queries the indexer each time.
// getAlertSeverity — level 13+ critical, 10+ high, 7+ medium, matching the Security Operations
// redesign's spec exactly. LOW (below 7) is filtered out entirely in loadAlerts() below, not
// just relabeled — this route no longer shows level 1-6 alerts at all; SOAR handles them
// silently (autoClose.ts resolves the low-severity TheHive cases the Wazuh->TheHive pipeline
// still opens for them).
function getAlertSeverity(level: number): Severity {
    if (level >= 13) return 'critical';
    if (level >= 10) return 'high';
    return 'medium'; // 7-9
}

function mapIndexerAlert(hit: IndexerAlertHit): ThreatAlert {
    const src = hit._source;
    const level = src.rule?.level ?? 0;
    const severity: Severity = getAlertSeverity(level);
    return {
        id: hit._id,
        rule_id: src.rule?.id != null ? String(src.rule.id) : '',
        rule_level: level,
        rule_description: src.rule?.description ?? 'Wazuh alert',
        severity,
        status: 'open',
        mitre_tactic: src.rule?.mitre?.tactic?.[0] ?? '—',
        mitre_technique: src.rule?.mitre?.technique?.[0] ?? '—',
        source_ip: src.data?.srcip ?? null,
        source_country: null,
        source_isp: null,
        destination_ip: '—',
        destination_host: src.agent?.name ?? 'Unknown',
        destination_port: null,
        protocol: 'N/A',
        agent_id: src.agent?.id ?? '',
        agent_name: src.agent?.name ?? 'Unknown',
        alert_count: 1,
        raw_log: src.location ?? '',
        detected_at: src.timestamp ?? new Date().toISOString(),
        tags: src.rule?.groups ?? [],
        abuseipdb_confidence: null,
        vt_malicious: null,
        pulse_matches: null,
        assigned_to: null,
    };
}

function computeStats(alerts: ThreatAlert[]) {
    const countBy = (pred: (a: ThreatAlert) => boolean) => alerts.filter(pred).length;
    return {
        total_alerts_24h: alerts.length,
        critical: countBy((a) => a.severity === 'critical'),
        high: countBy((a) => a.severity === 'high'),
        medium: countBy((a) => a.severity === 'medium'),
        low: countBy((a) => a.severity === 'low'),
        open: countBy((a) => a.status === 'open'),
        investigating: countBy((a) => a.status === 'investigating'),
        acknowledged: countBy((a) => a.status === 'acknowledged'),
        active_agents: new Set(alerts.map((a) => a.agent_id)).size,
        mitre_tactics_seen: Array.from(new Set(alerts.map((a) => a.mitre_tactic).filter((t) => t && t !== '—'))),
    };
}

// Cache of whatever list GET /alerts last served — MOCK_ALERTS until (and unless) a live
// Wazuh fetch succeeds. /:id, PATCH, and create-incident all read/write this, not MOCK_ALERTS
// directly, so they stay consistent with whatever the list view is currently showing.
let liveAlerts: ThreatAlert[] = MOCK_ALERTS;
let usingMockStats = true;

// Wazuh alert ids we've already emailed about — in-memory, so it resets on redeploy (an
// occasional re-send after a restart beats the alternative of persisting yet more state for
// this). GET /alerts polls repeatedly, so without this dedup every poll would re-email every
// still-critical alert. Only checked from the live-indexer branch of loadAlerts — MOCK_ALERTS
// stays severity:'critical' by design and must never trigger a real send to ALERT_EMAIL_TO.
const emailedAlertIds = new Set<string>();

// CRITICAL and HIGH both email (via sendCriticalAlertEmail -> services/email.ts's sendEmail,
// which tries Resend first — see that file's header comment for why). MEDIUM deliberately does
// not email here — it's notification-bell-only, per the Security Operations redesign spec.
function notifyCriticalAlerts(alerts: ThreatAlert[]): void {
    const toNotify = alerts.filter((a) => (a.severity === 'critical' || a.severity === 'high') && !emailedAlertIds.has(a.id));
    for (const alert of toNotify) {
        emailedAlertIds.add(alert.id); // mark before send completes so a slow response can't duplicate-send on the next poll
        sendCriticalAlertEmail({
            to: [process.env.ALERT_EMAIL_TO || 'rayne@cybernovr.com'],
            alertTitle: alert.rule_description,
            severity: alert.severity,
            agentName: alert.agent_name,
            sourceIp: alert.source_ip || '',
            mitreId: alert.mitre_technique || 'T0000',
            mitreTactic: alert.mitre_tactic || 'Unknown',
            riskScore: alert.rule_level * 6,
            rawLog: alert.raw_log,
        }).catch((err) => console.error('Critical alert email failed:', err));
    }
}

async function loadAlerts(limit: number): Promise<ThreatAlert[]> {
    // Explicit opt-in only — see lib/demoMode.ts. Short-circuits before even attempting the
    // real indexer, same as routes/wazuh.ts's /status and /agents.
    if (isDemoMode()) {
        liveAlerts = MOCK_ALERTS;
        usingMockStats = true;
        return liveAlerts;
    }
    try {
        const result = await search<IndexerSearchResponse>('wazuh-alerts-4.x-*', {
            size: limit,
            sort: [{ timestamp: { order: 'desc' } }],
            // level 7+ only — filtered at the query itself, not just relabeled after the fact,
            // so a LOW alert never even counts against `limit` here.
            query: { range: { 'rule.level': { gte: 7 } } },
        });
        const hits = result?.hits?.hits ?? [];
        if (hits.length > 0) {
            liveAlerts = hits.map(mapIndexerAlert);
            usingMockStats = false;
            notifyCriticalAlerts(liveAlerts); // fire-and-forget — must not add latency to the alert list response
            return liveAlerts;
        }
    } catch {
        // Indexer not configured, unreachable, or auth failed — fall through to mock below.
    }
    liveAlerts = MOCK_ALERTS;
    usingMockStats = true;
    return liveAlerts;
}

router.get('/alerts', async (req, res) => {
    const { severity, status, limit = '50' } = req.query;
    const parsedLimit = parseInt(String(limit), 10) || 50;

    const all = await loadAlerts(parsedLimit);
    let alerts = [...all];
    if (severity && severity !== 'all') alerts = alerts.filter((a) => a.severity === severity);
    if (status && status !== 'all') alerts = alerts.filter((a) => a.status === status);
    alerts = alerts.slice(0, parsedLimit);

    res.json({
        alerts,
        stats: usingMockStats ? MOCK_STATS : computeStats(all),
        // usingMockStats was already tracked internally (loadAlerts sets it) but never left
        // this function — the frontend had no way to tell a real Wazuh-indexer alert queue
        // from the MOCK_ALERTS fallback it silently serves when the indexer is unreachable.
        // 'demo' vs 'mock' distinguishes *why* — DEMO_MODE was explicitly set (a presentation
        // in progress) vs. an actual unplanned indexer outage — even though both currently
        // serve the same MOCK_ALERTS; the frontend banner text differs ("Demo mode" vs
        // "Wazuh indexer unreachable") so an analyst never mistakes a real outage for a demo.
        source: usingMockStats ? (isDemoMode() ? 'demo' : 'mock') : 'wazuh',
        wazuh_connected: !usingMockStats,
    });
});

router.get('/alerts/:id', (req, res) => {
    const alert = liveAlerts.find((a) => a.id === req.params.id);
    if (!alert) {
        res.status(404).json({ error: 'Alert not found' });
        return;
    }
    res.json(alert);
});

router.patch('/alerts/:id', (req, res) => {
    const { status, assigned_to }: { status?: AlertStatus; assigned_to?: string | null } = req.body ?? {};
    const alert = liveAlerts.find((a) => a.id === req.params.id);
    if (!alert) {
        res.status(404).json({ error: 'Alert not found' });
        return;
    }
    if (status) alert.status = status;
    if (assigned_to !== undefined) alert.assigned_to = assigned_to;
    res.json({ success: true, alert });
});

// Was entirely fake before this — returned a `INC-${Date.now()}` string without creating
// anything anywhere. Now opens a real TheHive case, same as POST /api/incidents does for a
// manually-created incident.
router.post('/alerts/:id/create-incident', async (req, res) => {
    const alert = liveAlerts.find((a) => a.id === req.params.id);
    if (!alert) {
        res.status(404).json({ error: 'Alert not found' });
        return;
    }
    if (!isTheHiveConfigured()) {
        res.status(503).json({ error: 'TheHive not configured' });
        return;
    }

    const newCase = await createCase({
        title: alert.rule_description,
        description: `Alert detected by Wazuh\nAgent: ${alert.agent_name}\nSource IP: ${alert.source_ip ?? 'N/A'}\nRule ID: ${alert.rule_id}\nLevel: ${alert.rule_level}`,
        severity: alert.severity,
        tags: ['wazuh', 'manual', `level-${alert.rule_level}`, alert.agent_name].filter(Boolean),
    });
    if (!newCase) {
        res.status(502).json({ error: 'Failed to create TheHive case — see server logs' });
        return;
    }

    alert.status = 'investigating';
    res.json({ success: true, incident_id: newCase._id, incident_number: deriveIncidentNumber(newCase), message: `Incident ${deriveIncidentNumber(newCase)} created from alert ${alert.rule_id}` });
});

// GET /api/threats/global-map — country-level threat origins for the flat world map on the
// dashboard (components/geo/GlobalThreatMap.tsx).
//
// Source is the Wazuh indexer's own GeoLocation.country_name aggregation over the last 7 days —
// real observed attack sources against monitored endpoints. OTX would be a natural second
// source, but its key is currently rejected (403 on every endpoint, verified live 2026-09-07),
// so adding it would contribute nothing but latency; the merge below is written so a second
// source slots in without restructuring, and `sources` says which ones actually reported.
interface CountryAgg {
    aggregations?: { countries?: { buckets?: Array<{ key: string; doc_count: number }> } };
}

// ISO-3166 numeric codes are what world-atlas topojson keys its features on, so the map needs
// numeric — not alpha-2 — to colour a country in. Limited to the countries that realistically
// show up in this deployment's alert stream plus the major threat-origin countries; anything
// unmapped still appears in the ranked list below the map, just uncoloured.
// Covers every country GreyNoise's top-50 source_countries bucket actually returned when this
// was built, plus the ones Wazuh's own GeoLocation field can emit. A country missing from here
// still appears in the ranked list under the map — it just can't be coloured, since the map
// needs the numeric id to match a topojson feature.
const COUNTRY_CODES: Record<string, { alpha2: string; numeric: string }> = {
    Nigeria: { alpha2: 'NG', numeric: '566' },
    'United States': { alpha2: 'US', numeric: '840' },
    China: { alpha2: 'CN', numeric: '156' },
    Russia: { alpha2: 'RU', numeric: '643' },
    Germany: { alpha2: 'DE', numeric: '276' },
    'United Kingdom': { alpha2: 'GB', numeric: '826' },
    France: { alpha2: 'FR', numeric: '250' },
    India: { alpha2: 'IN', numeric: '356' },
    Brazil: { alpha2: 'BR', numeric: '076' },
    Australia: { alpha2: 'AU', numeric: '036' },
    Netherlands: { alpha2: 'NL', numeric: '528' },
    Ukraine: { alpha2: 'UA', numeric: '804' },
    'North Korea': { alpha2: 'KP', numeric: '408' },
    Iran: { alpha2: 'IR', numeric: '364' },
    'South Africa': { alpha2: 'ZA', numeric: '710' },
    Ghana: { alpha2: 'GH', numeric: '288' },
    Kenya: { alpha2: 'KE', numeric: '404' },
    Egypt: { alpha2: 'EG', numeric: '818' },
    Vietnam: { alpha2: 'VN', numeric: '704' },
    Indonesia: { alpha2: 'ID', numeric: '360' },
    Singapore: { alpha2: 'SG', numeric: '702' },
    Canada: { alpha2: 'CA', numeric: '124' },
    Japan: { alpha2: 'JP', numeric: '392' },
    'South Korea': { alpha2: 'KR', numeric: '410' },
    Turkey: { alpha2: 'TR', numeric: '792' },
    Poland: { alpha2: 'PL', numeric: '616' },
    Romania: { alpha2: 'RO', numeric: '642' },
    Pakistan: { alpha2: 'PK', numeric: '586' },
    Argentina: { alpha2: 'AR', numeric: '032' },
    Uzbekistan: { alpha2: 'UZ', numeric: '860' },
    Mexico: { alpha2: 'MX', numeric: '484' },
    'Hong Kong': { alpha2: 'HK', numeric: '344' },
    Colombia: { alpha2: 'CO', numeric: '170' },
    Taiwan: { alpha2: 'TW', numeric: '158' },
    Chile: { alpha2: 'CL', numeric: '152' },
    Spain: { alpha2: 'ES', numeric: '724' },
    Italy: { alpha2: 'IT', numeric: '380' },
    Thailand: { alpha2: 'TH', numeric: '764' },
    Bangladesh: { alpha2: 'BD', numeric: '050' },
    Philippines: { alpha2: 'PH', numeric: '608' },
    Malaysia: { alpha2: 'MY', numeric: '458' },
    Kazakhstan: { alpha2: 'KZ', numeric: '398' },
    Bulgaria: { alpha2: 'BG', numeric: '100' },
    'Czech Republic': { alpha2: 'CZ', numeric: '203' },
    Czechia: { alpha2: 'CZ', numeric: '203' },
    Sweden: { alpha2: 'SE', numeric: '752' },
    Switzerland: { alpha2: 'CH', numeric: '756' },
    Ireland: { alpha2: 'IE', numeric: '372' },
    Finland: { alpha2: 'FI', numeric: '246' },
    Norway: { alpha2: 'NO', numeric: '578' },
    Denmark: { alpha2: 'DK', numeric: '208' },
    Austria: { alpha2: 'AT', numeric: '040' },
    Belgium: { alpha2: 'BE', numeric: '056' },
    Portugal: { alpha2: 'PT', numeric: '620' },
    Greece: { alpha2: 'GR', numeric: '300' },
    Hungary: { alpha2: 'HU', numeric: '348' },
    Serbia: { alpha2: 'RS', numeric: '688' },
    Lithuania: { alpha2: 'LT', numeric: '440' },
    Latvia: { alpha2: 'LV', numeric: '428' },
    Estonia: { alpha2: 'EE', numeric: '233' },
    Moldova: { alpha2: 'MD', numeric: '498' },
    Belarus: { alpha2: 'BY', numeric: '112' },
    Georgia: { alpha2: 'GE', numeric: '268' },
    Armenia: { alpha2: 'AM', numeric: '051' },
    Azerbaijan: { alpha2: 'AZ', numeric: '031' },
    Israel: { alpha2: 'IL', numeric: '376' },
    'Saudi Arabia': { alpha2: 'SA', numeric: '682' },
    'United Arab Emirates': { alpha2: 'AE', numeric: '784' },
    Iraq: { alpha2: 'IQ', numeric: '368' },
    Morocco: { alpha2: 'MA', numeric: '504' },
    Algeria: { alpha2: 'DZ', numeric: '012' },
    Tunisia: { alpha2: 'TN', numeric: '788' },
    Ethiopia: { alpha2: 'ET', numeric: '231' },
    Tanzania: { alpha2: 'TZ', numeric: '834' },
    Uganda: { alpha2: 'UG', numeric: '800' },
    Cameroon: { alpha2: 'CM', numeric: '120' },
    Senegal: { alpha2: 'SN', numeric: '686' },
    Peru: { alpha2: 'PE', numeric: '604' },
    Ecuador: { alpha2: 'EC', numeric: '218' },
    Venezuela: { alpha2: 'VE', numeric: '862' },
    Bolivia: { alpha2: 'BO', numeric: '068' },
    Paraguay: { alpha2: 'PY', numeric: '600' },
    Uruguay: { alpha2: 'UY', numeric: '858' },
    'Dominican Republic': { alpha2: 'DO', numeric: '214' },
    Guatemala: { alpha2: 'GT', numeric: '320' },
    Cambodia: { alpha2: 'KH', numeric: '116' },
    Myanmar: { alpha2: 'MM', numeric: '104' },
    Nepal: { alpha2: 'NP', numeric: '524' },
    'Sri Lanka': { alpha2: 'LK', numeric: '144' },
    Mongolia: { alpha2: 'MN', numeric: '496' },
    'New Zealand': { alpha2: 'NZ', numeric: '554' },
    Seychelles: { alpha2: 'SC', numeric: '690' },
    Panama: { alpha2: 'PA', numeric: '591' },
    Luxembourg: { alpha2: 'LU', numeric: '442' },
    Cyprus: { alpha2: 'CY', numeric: '196' },
};

const ALLOWED_WINDOWS = new Set(['24h', '7d', '30d', '90d', 'all']);

router.get('/global-map', async (req, res) => {
    const sourcesReporting: string[] = [];
    const windowParam = typeof req.query.window === 'string' && ALLOWED_WINDOWS.has(req.query.window) ? req.query.window : '7d';

    // GreyNoise first when a key is set — it answers a question this deployment's own telemetry
    // can't: where internet-wide malicious scanning is originating right now, globally, rather
    // than only what happened to hit these monitored endpoints. Falls through to the Wazuh
    // aggregation below on any failure or empty result, so this never makes the map worse.
    if (isGreyNoiseConfigured()) {
        try {
            const stats = await getGreyNoiseCountryStats(50);
            if (stats.length > 0) {
                const countries = stats
                    .map((s) => ({
                        country: s.country,
                        countryCode: COUNTRY_CODES[s.country]?.alpha2 ?? s.country.slice(0, 2).toUpperCase(),
                        numericCode: COUNTRY_CODES[s.country]?.numeric ?? null,
                        threats: s.count,
                        threatType: 'scanning',
                    }))
                    .sort((a, b) => b.threats - a.threats);

                res.json({
                    countries,
                    total: countries.reduce((sum, c) => sum + c.threats, 0),
                    sources: ['greynoise'],
                    source: 'greynoise',
                    window: 'live',
                    generated_at: new Date().toISOString(),
                });
                return;
            }
        } catch (err) {
            console.warn('[threats] GreyNoise global map failed, falling back to Wazuh:', err instanceof Error ? err.message : err);
        }
    }

    try {
        const timeQuery = windowParam === 'all'
            ? { match_all: {} }
            : { range: { timestamp: { gte: `now-${windowParam}` } } };

        const result = await search<CountryAgg>('wazuh-alerts-4.x-*', {
            size: 0,
            query: timeQuery,
            aggs: { countries: { terms: { field: 'GeoLocation.country_name', size: 30 } } },
        }).catch(() => null);

        const buckets = result?.aggregations?.countries?.buckets ?? [];
        if (buckets.length > 0) sourcesReporting.push('wazuh');

        // When the window is empty, say WHY: no alerts at all vs. alerts present but none
        // carrying GeoLocation (which means Wazuh's GeoIP enrichment isn't populating — a
        // manager-side config issue, not a bug in this endpoint). Verified live 2026-09-07:
        // 2,493 alerts in the last 7d, 0 of them geolocated; only 8 alerts have ever had
        // GeoLocation.country_name at all.
        let diagnostic: string | undefined;
        if (buckets.length === 0) {
            const [totalHits, geoHits] = await Promise.all([
                search<{ hits?: { total?: { value?: number } } }>('wazuh-alerts-4.x-*', { size: 0, query: timeQuery }).catch(() => null),
                search<{ hits?: { total?: { value?: number } } }>('wazuh-alerts-4.x-*', { size: 0, query: { exists: { field: 'GeoLocation.country_name' } } }).catch(() => null),
            ]);
            const alerts = totalHits?.hits?.total?.value ?? 0;
            const geolocated = geoHits?.hits?.total?.value ?? 0;
            diagnostic = alerts === 0
                ? `No alerts indexed in the ${windowParam} window.`
                : `${alerts.toLocaleString()} alerts in the ${windowParam} window but none carry GeoLocation.country_name (${geolocated} geolocated alerts exist across all time) — Wazuh's GeoIP enrichment is not populating.`;
        }

        const countries = buckets
            .map((b) => ({
                country: b.key,
                countryCode: COUNTRY_CODES[b.key]?.alpha2 ?? b.key.slice(0, 2).toUpperCase(),
                numericCode: COUNTRY_CODES[b.key]?.numeric ?? null,
                threats: b.doc_count,
                threatType: 'alert',
            }))
            .sort((a, b) => b.threats - a.threats);

        res.json({
            countries,
            total: countries.reduce((sum, c) => sum + c.threats, 0),
            sources: sourcesReporting,
            // Honest empty state rather than demo countries — an empty map means the indexer
            // genuinely has no geolocated alerts in the window, which is a real answer.
            source: countries.length > 0 ? 'wazuh' : 'empty',
            window: windowParam,
            diagnostic,
            generated_at: new Date().toISOString(),
        });
    } catch (err) {
        console.error('[threats] Global map error:', err);
        res.status(500).json({ countries: [], total: 0, sources: [], source: 'error', error: 'Failed to build global map' });
    }
});

router.get('/stats', (_req, res) => {
    res.json(usingMockStats ? MOCK_STATS : computeStats(liveAlerts));
});

export default router;
