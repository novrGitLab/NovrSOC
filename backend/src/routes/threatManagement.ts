import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { search } from '../lib/wazuh-indexer';
import { sendCriticalAlertEmail, socNotificationRecipients, warnNoRecipient } from '../services/email';
import { createCase, type CaseSeverity } from '../services/cases';
import { loadThreats, readTriage, writeTriage, applyTriage, type Threat, type Triage } from '../services/threatBoard';
import { blockAddress } from '../services/responseActions';
import { getSupabase } from '../services/geoEnrichment';
import { logAudit } from '../lib/audit';
import { NIGERIAN_ACTORS, GLOBAL_ACTORS } from '../services/threatActors';
import { getGreyNoiseCountryStats, isGreyNoiseConfigured } from '../services/greynoise';
import { threatfoxGetRecent } from '../services/threatfox';
import { urlhausGetRecent } from '../services/urlhaus';
import { feodoGetBlocklist } from '../services/feodo';
import { severityFromLevel, severityFromScore, SEVERITY_MIN_LEVEL, type Severity } from '../lib/severity';
import { requirePermission, requestOrg } from '../lib/permissions';

// SecOps Threat Management console — live security event stream from the Wazuh Indexer
// (wazuh-alerts-4.x-*, same OpenSearch backend /api/wazuh/alerts-indexer queries). There is no
// demo or mock fallback: an empty index is an empty list, and an unreachable indexer is a 502
// with the real error, never fabricated alerts. The Manager REST API's GET /alerts (services/wazuh.ts's getAlerts) 404s on this
// deployment (Wazuh v4.7.5) — alert search only works through the indexer here. Not to be
// confused with routes/threat-intel.ts / routes/ctip.ts, which power the separate
// CTIP-backed threat-intel dashboards.

const router = Router();

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
    // Live alerts only. Technique ID (T1110) — mitre_technique above is the display name.
    mitre_technique_id?: string;
    // Live alerts only. Wazuh's alert id, distinct from the indexer document id in `id`.
    wazuh_alert_id?: string;
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


// Shape of a wazuh-alerts-4.x-* document as returned by the Indexer's _search — see
// routes/wazuh.ts's /alerts-indexer, /trend, /incidents for the same interface pattern.
interface IndexerAlertHit {
    _id: string;
    _source: {
        id?: string; // Wazuh's own alert id — what the SOAR engine keys cases on
        timestamp?: string;
        rule?: {
            id?: number | string;
            level?: number;
            description?: string;
            groups?: string[];
            mitre?: { tactic?: string[]; technique?: string[]; id?: string[] };
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
// Severity comes from lib/severity.ts. LOW (below level 7) is filtered out entirely in
// loadAlerts() below, not just relabeled — this route doesn't show level 1-6 alerts at all; SOAR
// handles them silently (infra/soar/soar.py cases level 7+ alerts and auto-closes tier 1).

function mapIndexerAlert(hit: IndexerAlertHit): ThreatAlert {
    const src = hit._source;
    const level = src.rule?.level ?? 0;
    const severity: Severity = severityFromLevel(level);
    return {
        id: hit._id,
        rule_id: src.rule?.id != null ? String(src.rule.id) : '',
        rule_level: level,
        rule_description: src.rule?.description ?? 'Wazuh alert',
        severity,
        status: 'open',
        mitre_tactic: src.rule?.mitre?.tactic?.[0] ?? '—',
        mitre_technique: src.rule?.mitre?.technique?.[0] ?? '—',
        mitre_technique_id: src.rule?.mitre?.id?.[0],
        wazuh_alert_id: src.id,
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

function computeStats(alerts: ThreatAlert[], day: { total: number; critical: number; high: number; medium: number } | null) {
    const countBy = (pred: (a: ThreatAlert) => boolean) => alerts.filter(pred).length;
    return {
        // null (not 0) when the 24h count query itself failed, so the page shows "—".
        total_alerts_24h: day?.total ?? null,
        critical: day?.critical ?? null,
        high: day?.high ?? null,
        medium: day?.medium ?? null,
        // Level < 7 is never queried, so there is no low count to report.
        low: null,
        // Triage state only exists for alerts in the loaded list.
        open: countBy((a) => a.status === 'open'),
        investigating: countBy((a) => a.status === 'investigating'),
        acknowledged: countBy((a) => a.status === 'acknowledged'),
        active_agents: new Set(alerts.map((a) => a.agent_id)).size,
        mitre_tactics_seen: Array.from(new Set(alerts.map((a) => a.mitre_tactic).filter((t) => t && t !== '—'))),
    };
}

// The list GET /alerts last served. /:id, PATCH and create-incident read this so they act on
// what the analyst is looking at.
let liveAlerts: ThreatAlert[] = [];

// Analyst triage (status, assignee) keyed by indexer document id. Kept apart from liveAlerts
// because that list is rebuilt from the indexer on every load — storing triage on it (as
// before) reset every alert to Open/Unassigned on the next refresh. In-process, so it survives
// refreshes but not a backend restart; anything that must be durable belongs in a case.
const triage = new Map<string, { status?: AlertStatus; assigned_to?: string | null }>();

function withTriage(alert: ThreatAlert): ThreatAlert {
    const t = triage.get(alert.id);
    if (!t) return alert;
    return { ...alert, ...(t.status ? { status: t.status } : {}), ...(t.assigned_to !== undefined ? { assigned_to: t.assigned_to } : {}) };
}

// Wazuh alert ids we've already emailed about — in-memory, so it resets on redeploy (an
// occasional re-send after a restart beats the alternative of persisting yet more state for
// this). GET /alerts polls repeatedly, so without this dedup every poll would re-email every
// still-critical alert.
const emailedAlertIds = new Set<string>();

// CRITICAL and HIGH both email (via sendCriticalAlertEmail -> services/email.ts's sendEmail,
// which tries Resend first — see that file's header comment for why). MEDIUM deliberately does
// not email here — it's notification-bell-only, per the Security Operations redesign spec.
function notifyCriticalAlerts(alerts: ThreatAlert[]): void {
    const toNotify = alerts.filter((a) => (a.severity === 'critical' || a.severity === 'high') && !emailedAlertIds.has(a.id));
    const recipients = socNotificationRecipients();
    if (toNotify.length > 0 && recipients.length === 0) {
        // Not marked as emailed, so they go out once an address is configured.
        warnNoRecipient('Critical/high alert email', 'ALERT_EMAIL_TO / CISO_EMAIL');
        return;
    }
    for (const alert of toNotify) {
        emailedAlertIds.add(alert.id); // mark before send completes so a slow response can't duplicate-send on the next poll
        sendCriticalAlertEmail({
            to: recipients,
            alertTitle: alert.rule_description,
            severity: alert.severity,
            agentName: alert.agent_name,
            sourceIp: alert.source_ip || '',
            mitreId: alert.mitre_technique_id || 'Unknown',
            mitreTactic: alert.mitre_tactic || 'Unknown',
            riskScore: alert.rule_level * 6,
            rawLog: alert.raw_log,
        }).catch((err) => console.error('Critical alert email failed:', err));
    }
}

type LoadResult = { ok: true; alerts: ThreatAlert[] } | { ok: false; error: string };

async function loadAlerts(limit: number): Promise<LoadResult> {
    try {
        const result = await search<IndexerSearchResponse>('wazuh-alerts-4.x-*', {
            size: limit,
            sort: [{ timestamp: { order: 'desc' } }],
            // level 7+ only — filtered at the query itself, not just relabeled after the fact,
            // so a LOW alert never even counts against `limit` here.
            query: { range: { 'rule.level': { gte: SEVERITY_MIN_LEVEL.medium } } },
        });
        liveAlerts = (result?.hits?.hits ?? []).map(mapIndexerAlert).map(withTriage);
        notifyCriticalAlerts(liveAlerts); // fire-and-forget — must not add latency to the alert list response
        return { ok: true, alerts: liveAlerts };
    } catch (err) {
        return { ok: false, error: err instanceof Error ? err.message : 'Wazuh indexer unreachable' };
    }
}

interface CountsResponse {
    hits?: { total?: { value?: number } };
    aggregations?: { levels?: { buckets?: Record<string, { doc_count?: number }> } };
}

// Real 24-hour counts from the indexer (level 7+), by severity. The previous "Alerts (24h)" was
// the length of the loaded list — capped at the page size, and not a 24h figure at all.
async function counts24h(): Promise<{ total: number; critical: number; high: number; medium: number } | null> {
    try {
        const r = await search<CountsResponse>('wazuh-alerts-4.x-*', {
            size: 0,
            track_total_hits: true,
            query: { bool: { filter: [{ range: { timestamp: { gte: 'now-24h' } } }, { range: { 'rule.level': { gte: SEVERITY_MIN_LEVEL.medium } } }] } },
            aggs: {
                levels: {
                    range: {
                        field: 'rule.level',
                        keyed: true,
                        ranges: [
                            { key: 'medium', from: SEVERITY_MIN_LEVEL.medium, to: SEVERITY_MIN_LEVEL.high },
                            { key: 'high', from: SEVERITY_MIN_LEVEL.high, to: SEVERITY_MIN_LEVEL.critical },
                            { key: 'critical', from: SEVERITY_MIN_LEVEL.critical },
                        ],
                    },
                },
            },
        });
        const b = r?.aggregations?.levels?.buckets ?? {};
        return {
            total: r?.hits?.total?.value ?? 0,
            critical: b.critical?.doc_count ?? 0,
            high: b.high?.doc_count ?? 0,
            medium: b.medium?.doc_count ?? 0,
        };
    } catch {
        return null;
    }
}

router.get('/alerts', requirePermission('alerts:read'), async (req, res) => {
    const { severity, status, limit = '50' } = req.query;
    const parsedLimit = parseInt(String(limit), 10) || 50;

    const checkedAt = new Date().toISOString();
    const [loaded, day] = await Promise.all([loadAlerts(parsedLimit), counts24h()]);
    if (!loaded.ok) {
        // The real reason, not an empty list that reads as "all quiet".
        res.status(502).json({ alerts: [], stats: null, source: 'error', error: loaded.error, checked_at: checkedAt });
        return;
    }

    let alerts = [...loaded.alerts];
    if (severity && severity !== 'all') alerts = alerts.filter((a) => a.severity === severity);
    if (status && status !== 'all') alerts = alerts.filter((a) => a.status === status);
    alerts = alerts.slice(0, parsedLimit);

    res.json({
        alerts,
        stats: computeStats(loaded.alerts, day),
        source: 'wazuh',
        checked_at: checkedAt,
    });
});

router.get('/alerts/:id', requirePermission('alerts:read'), (req, res) => {
    const alert = liveAlerts.find((a) => a.id === req.params.id);
    if (!alert) {
        res.status(404).json({ error: 'Alert not found' });
        return;
    }
    res.json(alert);
});

router.patch('/alerts/:id', requirePermission('cases:write'), (req, res) => {
    const { status, assigned_to }: { status?: AlertStatus; assigned_to?: string | null } = req.body ?? {};
    const alert = liveAlerts.find((a) => a.id === req.params.id);
    if (!alert) {
        res.status(404).json({ error: 'Alert not found' });
        return;
    }
    if (status) alert.status = status;
    if (assigned_to !== undefined) alert.assigned_to = assigned_to;
    triage.set(alert.id, { ...triage.get(alert.id), ...(status ? { status } : {}), ...(assigned_to !== undefined ? { assigned_to } : {}) });
    res.json({ success: true, alert });
});

// Opens a case from an alert. Keyed on the Wazuh alert id (source 'wazuh'), the same key the
// SOAR engine uses, so an alert the engine already cased returns that case instead of a
// duplicate. Refused while the list is serving demo/mock alerts — a real case must never be
// opened from a fabricated alert.
router.post('/alerts/:id/create-incident', requirePermission('cases:write'), async (req: AuthRequest, res) => {
    const alert = liveAlerts.find((a) => a.id === req.params.id);
    if (!alert) {
        res.status(404).json({ error: 'Alert not found' });
        return;
    }
    const result = await createCase({
        title: alert.rule_description,
        description: `Alert detected by Wazuh\nAgent: ${alert.agent_name}\nSource IP: ${alert.source_ip ?? 'N/A'}\nRule ID: ${alert.rule_id}\nLevel: ${alert.rule_level}`,
        severity: alert.severity as CaseSeverity,
        source: 'wazuh',
        source_id: alert.wazuh_alert_id ?? alert.id,
        org_id: requestOrg(req),
        agent_id: alert.agent_id || null,
        agent_name: alert.agent_name,
        source_ip: alert.source_ip,
        rule_id: alert.rule_id,
        rule_level: alert.rule_level,
        mitre_technique: alert.mitre_technique_id ?? null,
        mitre_tactic: alert.mitre_tactic !== '—' ? alert.mitre_tactic : null,
        tags: ['wazuh', 'manual', `level-${alert.rule_level}`],
    }, req.user?.email || 'analyst');
    if (!result.ok) {
        res.status(result.status).json({ error: result.error });
        return;
    }

    alert.status = 'investigating';
    triage.set(alert.id, { ...triage.get(alert.id), status: 'investigating' });
    const n = result.case.case_number;
    res.json({
        success: true, case_id: result.case.id, case_number: n, created: result.created,
        message: result.created ? `Case ${n} created from alert ${alert.rule_id}` : `Alert already has case ${n}`,
    });
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

router.get('/global-map', requirePermission('alerts:read'), async (req, res) => {
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

router.get('/stats', requirePermission('alerts:read'), async (_req, res) => {
    res.json(computeStats(liveAlerts, await counts24h()));
});

// GET /api/threats/actors — threat actor reference library.
//
// Served from services/threatActors.ts, not Supabase: there is no threat_actors table in this
// database (the `nigeria_intel` and `global_intel` schemas this was specced against don't exist
// at all). Every entry is publicly documented by a named vendor or MITRE and carries its own
// reference URL — this is a curated reference library, not NovrSOC telemetry, and the response
// says so via `source` so the page can label it accurately.
router.get('/actors', requirePermission('alerts:read'), (_req, res) => {
    res.json({
        nigerian: NIGERIAN_ACTORS,
        global: GLOBAL_ACTORS,
        source: 'curated-reference',
        note: 'Publicly documented threat actors, each linked to its originating vendor or MITRE ATT&CK entry. Not derived from this platform’s own telemetry.',
        generated_at: new Date().toISOString(),
    });
});

// GET /api/threats/live-ioc?type=&source=&limit=
//
// The live IOC feed. This is NOT /api/cti/feed — that one reads the Supabase `ioc_enrichments`
// table, which is a cache of IOCs an analyst has manually looked up, so it is empty until
// somebody runs a lookup and was never a feed of fresh threat intel. Confirmed live: it returned
// {"iocs":[],"count":0} on a fully working deployment. This route pulls from the upstream feeds
// directly instead.
//
// Three sources, all already credentialed or keyless:
//   ThreatFox  — ~1,500 IOCs/day across hash/domain/url/ip. Carries the volume.
//   URLhaus    — recent malicious URLs. NOTE: its /urls/recent/ endpoint is GET-only.
//   Feodo      — botnet C2 IPs, keyless. Small by design (single digits is normal).
//
// Promise.allSettled, not Promise.all: one upstream being rate-limited or down must degrade the
// feed, not empty it. `sources` in the response reports what each one actually returned so the
// UI can say which feeds contributed rather than implying all three always do.
type LiveIOCType = 'ip' | 'domain' | 'url' | 'hash';

interface LiveIOC {
    value: string;
    type: LiveIOCType;
    threat: string;
    source: string;
    confidence: number;
    tags: string[];
    first_seen: string;
    severity: Severity;
    reference: string | null;
}

// ThreatFox's ioc_type is finer-grained than the feed's four buckets (md5_hash, sha256_hash,
// ip:port, …), so it is normalised rather than passed through — otherwise the UI's type filter
// would need to know every abuse.ch variant.
function normaliseThreatFoxType(raw: string | undefined): LiveIOCType | null {
    if (!raw) return null;
    if (raw.includes('hash')) return 'hash';
    if (raw.startsWith('ip')) return 'ip';
    if (raw === 'domain') return 'domain';
    if (raw === 'url') return 'url';
    return null;
}

const severityFromConfidence = (confidence: number): Severity => severityFromScore(confidence);

router.get('/live-ioc', requirePermission('alerts:read'), async (req, res) => {
    const typeFilter = typeof req.query.type === 'string' && req.query.type !== 'all' ? req.query.type : null;
    const sourceFilter = typeof req.query.source === 'string' && req.query.source !== 'all' ? req.query.source : null;
    const limit = Math.min(Number(req.query.limit) || 100, 500);

    const [threatfox, urlhaus, feodo] = await Promise.allSettled([
        threatfoxGetRecent(1),
        urlhausGetRecent(100),
        feodoGetBlocklist(),
    ]);

    const tfList = threatfox.status === 'fulfilled' ? threatfox.value : [];
    const uhList = urlhaus.status === 'fulfilled' ? urlhaus.value : [];
    const fdList = feodo.status === 'fulfilled' ? feodo.value : [];

    const fromThreatFox: LiveIOC[] = tfList.flatMap((i) => {
        const type = normaliseThreatFoxType(i.ioc_type);
        if (!type || !i.ioc) return [];
        const confidence = Number(i.confidence_level) || 50;
        return [{
            value: String(i.ioc),
            type,
            threat: i.malware_printable || i.malware || 'Unknown malware',
            source: 'ThreatFox',
            confidence,
            // get_iocs doesn't always return `tags` (search_ioc does), hence the array guard —
            // the malware family is appended so a tagless entry still carries something useful.
            tags: [...(Array.isArray(i.tags) ? i.tags : []), i.malware_printable].filter((t): t is string => Boolean(t)),
            first_seen: i.first_seen ?? '',
            severity: severityFromConfidence(confidence),
            reference: i.reference ?? null,
        }];
    });

    const fromURLhaus: LiveIOC[] = uhList.flatMap((u) => {
        if (!u.url) return [];
        // URLhaus publishes no confidence score. 75 is assigned as a fixed editorial value for
        // a curated abuse.ch listing — it is NOT a figure returned by the API, and it must not
        // be presented as one.
        const confidence = 75;
        return [{
            value: u.url,
            type: 'url' as const,
            threat: u.threat || 'Malicious URL',
            source: 'URLhaus',
            confidence,
            tags: Array.isArray(u.tags) ? u.tags : [],
            first_seen: u.date_added ?? '',
            severity: u.url_status === 'online' ? ('high' as Severity) : ('medium' as Severity),
            reference: u.urlhaus_reference ?? null,
        }];
    });

    const fromFeodo: LiveIOC[] = fdList.flatMap((f) => {
        if (!f.ip_address) return [];
        const online = f.status === 'online';
        return [{
            value: f.ip_address,
            type: 'ip' as const,
            threat: `${f.malware ?? 'Botnet'} C2${f.port ? ` (port ${f.port})` : ''}`,
            source: 'Feodo Tracker',
            confidence: online ? 95 : 60,
            tags: [f.malware, f.country, f.as_name].filter((t): t is string => Boolean(t)),
            first_seen: f.first_seen ?? '',
            severity: online ? ('critical' as Severity) : ('medium' as Severity),
            reference: null,
        }];
    });

    const all = [...fromThreatFox, ...fromURLhaus, ...fromFeodo]
        .filter((i) => !typeFilter || i.type === typeFilter)
        .filter((i) => !sourceFilter || i.source === sourceFilter)
        // Newest first. first_seen is an ISO-ish 'YYYY-MM-DD HH:MM:SS UTC' string from every
        // source, so lexical comparison orders it correctly without parsing.
        .sort((a, b) => b.first_seen.localeCompare(a.first_seen));

    res.json({
        iocs: all.slice(0, limit),
        // Total BEFORE the limit, so the UI can say "showing 100 of 1,531" honestly.
        total: all.length,
        returned: Math.min(all.length, limit),
        sources: [
            { name: 'ThreatFox', ok: threatfox.status === 'fulfilled', count: fromThreatFox.length },
            { name: 'URLhaus', ok: urlhaus.status === 'fulfilled', count: fromURLhaus.length },
            { name: 'Feodo Tracker', ok: feodo.status === 'fulfilled', count: fromFeodo.length },
        ],
        last_updated: new Date().toISOString(),
    });
});

// ── Threat board (/admin/secops/threats) ────────────────────────────────────────────────────
// Distinct threats derived from live Wazuh alerts (services/threatBoard.ts), with analyst
// decisions layered on. Each route in this router is gated individually with requirePermission.

const RANGE_HOURS: Record<string, number> = { '24h': 24, '7d': 168, '30d': 720 };
// Keyed by org and threat id: each entry carries that org's triage decisions, so one org's
// cached view must never be served to another.
const threatCache = new Map<string, Threat>();
const cacheKey = (orgId: string, id: string) => `${orgId}:${id}`;

async function findThreat(orgId: string, id: string): Promise<Threat | null> {
    const cached = threatCache.get(cacheKey(orgId, id));
    if (cached) return cached;
    const { map } = await readTriage(orgId);
    for (const t of await loadThreats(720)) threatCache.set(cacheKey(orgId, t.id), applyTriage(t, map.get(t.id)));
    return threatCache.get(cacheKey(orgId, id)) ?? null;
}

// GET /api/threats?range=24h|7d|30d
router.get('/', requirePermission('alerts:read'), async (req: AuthRequest, res) => {
    const orgId = requestOrg(req);
    const range = typeof req.query.range === 'string' && RANGE_HOURS[req.query.range] ? req.query.range : '7d';
    const checkedAt = new Date().toISOString();
    try {
        const [raw, { map, store }] = await Promise.all([loadThreats(RANGE_HOURS[range]), readTriage(orgId)]);
        const threats = raw.map((t) => applyTriage(t, map.get(t.id)));
        for (const t of threats) threatCache.set(cacheKey(orgId, t.id), t);
        const weekAgo = Date.now() - 7 * 24 * 3600_000;
        res.json({
            threats,
            summary: {
                active: threats.filter((t) => t.status === 'active').length,
                contained: threats.filter((t) => t.status === 'contained').length,
                resolved_this_week: [...map.values()].filter((t) => t.status === 'resolved' && Date.parse(t.updated_at) >= weekAgo).length,
                critical_unresolved: threats.filter((t) => t.severity === 'critical' && t.status !== 'resolved').length,
            },
            store, range, checked_at: checkedAt,
        });
    } catch (err) {
        res.status(502).json({ threats: [], summary: null, error: err instanceof Error ? err.message : 'Wazuh indexer unreachable', checked_at: checkedAt });
    }
});

async function decide(req: AuthRequest, threat: Threat, patch: Partial<Triage>): Promise<'supabase' | 'memory'> {
    const orgId = requestOrg(req);
    const { map } = await readTriage(orgId);
    const prev = map.get(threat.id);
    const next: Triage = {
        threat_id: threat.id, org_id: orgId,
        status: prev?.status ?? null, assigned_to: prev?.assigned_to ?? null,
        case_id: prev?.case_id ?? null, case_number: prev?.case_number ?? null, note: prev?.note ?? null,
        ...patch,
        updated_by: req.user?.email ?? 'analyst', updated_at: new Date().toISOString(),
    };
    const store = await writeTriage(next);
    threatCache.set(cacheKey(orgId, threat.id), applyTriage(threat, next));
    logAudit({
        user: req.user?.email ?? 'unknown', action: 'THREAT_DECISION', resource: 'threat', resource_id: threat.id, ip: req.ip ?? 'unknown',
        result: 'success', details: `${threat.name.slice(0, 80)}: ${JSON.stringify(patch).slice(0, 100)}`, severity: 'info',
    });
    return store;
}

async function withThreat(req: AuthRequest, res: import('express').Response): Promise<Threat | null> {
    const threat = await findThreat(requestOrg(req), req.params.id).catch(() => null);
    if (!threat) res.status(404).json({ success: false, error: 'Threat not found — refresh the list' });
    return threat;
}

// POST /api/threats/:id/contain { reason? } — blocks the threat's source IP at the firewall (real
// action). Marked contained only when the block succeeded; host-only threats have no IP to block.
router.post('/:id/contain', requirePermission('response:contain'), async (req: AuthRequest, res) => {
    const threat = await withThreat(req, res);
    if (!threat) return;
    if (!threat.source_ip) {
        res.json({ success: false, outcome: 'skipped', message: 'This threat has no source IP to block — contain the affected host from its case instead (escalate it first).' });
        return;
    }
    const reason = typeof req.body?.reason === 'string' && req.body.reason.trim() ? req.body.reason.trim() : `Threat ${threat.id}: ${threat.name}`;
    const result = await blockAddress(threat.source_ip, { reason });
    if (result.outcome !== 'success') {
        res.status(result.outcome === 'failed' ? 502 : 200).json({ success: false, outcome: result.outcome, message: result.message });
        return;
    }
    const store = await decide(req, threat, { status: 'contained', note: reason });
    res.json({ success: true, outcome: 'success', message: result.message, store });
});

// POST /api/threats/:id/escalate — opens a case (real) for the threat; repeat calls return it.
router.post('/:id/escalate', requirePermission('cases:write'), async (req: AuthRequest, res) => {
    const threat = await withThreat(req, res);
    if (!threat) return;
    const result = await createCase({
        title: threat.name,
        description: `Escalated from threat ${threat.id} (${threat.type}).\nRule ${threat.rule_id} (level ${threat.rule_level}), ${threat.alert_count} alerts.\nSource IP: ${threat.source_ip ?? 'none'}\nAssets: ${threat.assets.join(', ')}\nFirst seen ${threat.first_seen}, last seen ${threat.last_seen}.`,
        severity: threat.severity as CaseSeverity,
        source: 'threat',
        source_id: threat.id,
        org_id: requestOrg(req),
        agent_name: threat.assets[0] ?? null,
        source_ip: threat.source_ip,
        rule_id: threat.rule_id,
        rule_level: threat.rule_level,
        mitre_technique: threat.mitre_technique_id,
        mitre_tactic: threat.mitre_tactic,
        tags: ['threat', threat.type.toLowerCase().replace(/\s+/g, '-')],
    }, req.user?.email || 'analyst');
    if (!result.ok) { res.status(result.status).json({ success: false, error: result.error }); return; }
    const store = await decide(req, threat, { case_id: result.case.id, case_number: result.case.case_number });
    res.json({
        success: true, store, case_id: result.case.id, case_number: result.case.case_number,
        message: result.created ? `Case ${result.case.case_number} opened` : `Already escalated as ${result.case.case_number}`,
    });
});

// POST /api/threats/:id/resolve { note? }
router.post('/:id/resolve', requirePermission('cases:write'), async (req: AuthRequest, res) => {
    const threat = await withThreat(req, res);
    if (!threat) return;
    const note = typeof req.body?.note === 'string' ? req.body.note.trim() || null : null;
    const store = await decide(req, threat, { status: 'resolved', note });
    res.json({ success: true, store, message: 'Marked resolved — it will show as Active again if the rule fires after now.' });
});

// POST /api/threats/:id/assign { analyst_id } — a team member's email (platform_users).
router.post('/:id/assign', requirePermission('cases:write'), async (req: AuthRequest, res) => {
    const threat = await withThreat(req, res);
    if (!threat) return;
    const email = typeof req.body?.analyst_id === 'string' ? req.body.analyst_id.trim().toLowerCase() : '';
    const { data: member } = email ? await getSupabase()!.from('platform_users').select('email, name, status').ilike('email', email).maybeSingle() : { data: null };
    if (!member || (member.status && member.status !== 'active')) { res.status(400).json({ success: false, error: 'That analyst is not an active team member' }); return; }
    const name = member.name || member.email;
    const store = await decide(req, threat, { assigned_to: name });
    res.json({ success: true, store, message: `Assigned to ${name}` });
});

export default router;
