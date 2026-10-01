// CNII Watch — asset inventory, sector alerts, vulnerabilities and the IP scanner.
//
//   POST /scan  { ip }      SpiderFoot scan + OpenCTI lookup in parallel → ScanResult with a
//                           suggested sector. Nothing is saved; the analyst confirms the sector.
//   POST /assets            { ip, sectorId, subfield? } → upsert into cnii_assets, using the
//                           server's cached scan for that IP (raw data, CVEs) when there is one.
//   GET  /assets            cnii_assets rows (?sector=, ?ip=)
//   GET  /alerts            Wazuh alerts (indexer) whose agent.ip / data.srcip / data.dstip is a
//                           monitored asset (?sector=, ?ip=)
//   GET  /vulns             CVEs stored from each asset's last scan, plus Wazuh vulnerability
//                           state for any monitored IP that is also a Wazuh agent (?sector=, ?ip=)
//
// Response shapes: frontend/src/lib/cnii-types.ts. When a dependency is missing or down the route
// says so (503 not_connected / 502) — it never substitutes sample data or reports a save that
// didn't happen. Mounted behind requireAuth in index.ts; roles are checked per route.
import { Router, Response } from 'express';
import { isIP } from 'net';
import { AuthRequest, requireRole } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';
import { search } from '../lib/wazuh-indexer';
import { wazuhGet } from '../lib/wazuh';
import { scanIP, spiderfootConfigured, SpiderFootError, type SpiderFootVuln } from '../lib/spiderfoot';
import { lookupIP, openctiConfigured } from '../lib/opencti';
import { classifySector } from '../lib/cnii-classify';
import { SECTOR_BY_ID } from '../lib/cnii-sectors';

const router = Router();

const canRead = requireRole('super_admin', 'soc_manager', 'analyst', 'executive');
const canWrite = requireRole('super_admin', 'soc_manager', 'analyst');

function notConnected(res: Response, feed: string, message: string) {
    return res.status(503).json({ error: 'not_connected', feed, message });
}

// ── Filters ───────────────────────────────────────────────────────────────────────────────

interface Filter { sector?: string; ip?: string }

// Returns the parsed filter, or null after answering 400.
function readFilter(req: AuthRequest, res: Response): Filter | null {
    const { sector, ip } = req.query;
    if (sector !== undefined && (typeof sector !== 'string' || !SECTOR_BY_ID[sector])) {
        res.status(400).json({ error: 'Unknown sector' });
        return null;
    }
    if (ip !== undefined && (typeof ip !== 'string' || !isIP(ip))) {
        res.status(400).json({ error: 'Invalid IP address' });
        return null;
    }
    return { sector: sector as string | undefined, ip: ip as string | undefined };
}

// ── cnii_assets ───────────────────────────────────────────────────────────────────────────

interface AssetRow {
    id: string; ip: string; hostname: string | null; owner: string | null; org: string | null; asn: string | null;
    country: string | null; sector_id: string; subfield: string | null; domains: string[] | null; subdomains: string[] | null;
    open_ports: number[] | null; alert_count: number | null; vuln_count: number | null; risk_score: number | null;
    scan_status: string | null; last_seen: string; added_at: string; vulns: SpiderFootVuln[] | null;
}

const ASSET_COLUMNS = 'id, ip, hostname, owner, org, asn, country, sector_id, subfield, domains, subdomains, open_ports, alert_count, vuln_count, risk_score, scan_status, last_seen, added_at, vulns';

const toAsset = (r: AssetRow) => ({
    id: r.id, ip: r.ip, hostname: r.hostname ?? undefined, owner: r.owner ?? undefined, org: r.org ?? undefined,
    asn: r.asn ?? undefined, country: r.country ?? undefined, sectorId: r.sector_id, subfield: r.subfield ?? undefined,
    domains: r.domains ?? [], subdomains: r.subdomains ?? [], openPorts: r.open_ports ?? [],
    alertCount: r.alert_count ?? 0, vulnCount: r.vuln_count ?? 0, riskScore: r.risk_score ?? 0,
    scanStatus: r.scan_status ?? 'pending', lastSeen: r.last_seen, addedAt: r.added_at,
});

class FeedError extends Error {
    constructor(public status: 503 | 500, public feed: string, message: string) { super(message); }
}

const isMissingTable = (e: { code?: string; message?: string }) =>
    e.code === '42P01' || e.code === 'PGRST205' || /cnii_assets/.test(e.message ?? '') && /does not exist|schema cache/.test(e.message ?? '');

async function loadAssets(filter: Filter): Promise<AssetRow[]> {
    const db = getSupabase();
    if (!db) throw new FeedError(503, 'assets', 'Supabase is not configured (SUPABASE_URL, SUPABASE_SERVICE_KEY).');
    let q = db.from('cnii_assets').select(ASSET_COLUMNS).order('risk_score', { ascending: false });
    if (filter.sector) q = q.eq('sector_id', filter.sector);
    if (filter.ip) q = q.eq('ip', filter.ip);
    const { data, error } = await q;
    if (error) {
        if (isMissingTable(error)) throw new FeedError(503, 'assets', 'The cnii_assets table does not exist yet — run backend/sql/2026-10-cnii-assets.sql.');
        throw new FeedError(500, 'assets', `Supabase error: ${error.message}`);
    }
    return (data ?? []) as AssetRow[];
}

function sendFeedError(res: Response, err: unknown) {
    if (err instanceof FeedError) {
        return err.status === 503 ? notConnected(res, err.feed, err.message) : res.status(500).json({ error: err.message });
    }
    console.error('[cnii]', err);
    return res.status(500).json({ error: (err as Error).message ?? 'Internal error' });
}

router.get('/assets', canRead, async (req: AuthRequest, res) => {
    const filter = readFilter(req, res);
    if (!filter) return;
    try {
        res.json((await loadAssets(filter)).map(toAsset));
    } catch (err) {
        sendFeedError(res, err);
    }
});

// ── Scan ──────────────────────────────────────────────────────────────────────────────────

// Scan results kept briefly so POST /assets can store the raw data and CVEs without the browser
// round-tripping them (SpiderFoot's raw output easily exceeds the JSON body limit).
interface CachedScan { at: number; result: ScanResult }
const SCAN_TTL_MS = 60 * 60 * 1000;
const scanCache = new Map<string, CachedScan>();
function cacheScan(result: ScanResult) {
    for (const [k, v] of scanCache) if (Date.now() - v.at > SCAN_TTL_MS) scanCache.delete(k);
    if (scanCache.size >= 50) scanCache.delete(scanCache.keys().next().value!);
    scanCache.set(result.ip, { at: Date.now(), result });
}
const cachedScan = (ip: string) => {
    const c = scanCache.get(ip);
    return c && Date.now() - c.at <= SCAN_TTL_MS ? c.result : null;
};

interface ScanResult {
    ip: string; hostname?: string; owner?: string; org?: string; asn?: string; country?: string;
    domains: string[]; subdomains: string[]; openPorts: number[];
    vulns: SpiderFootVuln[];
    threatIntel: { source: string; description: string; severity: string }[];
    suggestedSectorId: string; suggestedSubfield: string; confidence: number;
    warnings: string[];
    rawSpiderfoot: unknown; rawOpencti: unknown;
}

// SpiderFoot scans are heavy (and sfp_portscan_tcp actively scans the target); cap how many run at once.
const MAX_CONCURRENT_SCANS = 3;
let runningScans = 0;

router.post('/scan', canWrite, async (req: AuthRequest, res) => {
    const ip = typeof req.body?.ip === 'string' ? req.body.ip.trim() : '';
    if (!isIP(ip)) return res.status(400).json({ error: 'Invalid IP address' });
    if (!spiderfootConfigured()) return notConnected(res, 'scan', 'SpiderFoot is not configured (SPIDERFOOT_URL).');
    if (runningScans >= MAX_CONCURRENT_SCANS) return res.status(429).json({ error: `${MAX_CONCURRENT_SCANS} scans are already running — try again shortly.` });

    runningScans++;
    try {
        const [sf, octi] = await Promise.allSettled([
            scanIP(ip),
            openctiConfigured() ? lookupIP(ip) : Promise.reject(new Error('OpenCTI is not configured (OPENCTI_URL, OPENCTI_TOKEN).')),
        ]);

        if (sf.status === 'rejected') {
            const e = sf.reason as Error;
            const status = e instanceof SpiderFootError && e.kind === 'timeout' ? 504 : 502;
            return res.status(status).json({ error: e.message });
        }

        const warnings: string[] = [];
        if (octi.status === 'rejected') {
            console.error('[cnii] OpenCTI lookup failed:', (octi.reason as Error).message);
            warnings.push(`OpenCTI lookup failed: ${(octi.reason as Error).message}`);
        }

        const s = sf.value;
        const cls = classifySector(s.owner, s.org, s.asn, [s.hostname, ...s.domains].filter(Boolean).join(' '));
        if (!cls.sectorId) warnings.push('No CNII sector matched the owner, organisation, ASN or hostname — choose one before adding.');

        const result: ScanResult = {
            ip, hostname: s.hostname, owner: s.owner, org: s.org, asn: s.asn, country: s.country,
            domains: s.domains, subdomains: s.subdomains, openPorts: s.openPorts, vulns: s.vulns,
            threatIntel: [...s.threatIntel, ...(octi.status === 'fulfilled' ? octi.value.threatIntel : [])],
            suggestedSectorId: cls.sectorId, suggestedSubfield: cls.subfield, confidence: cls.confidence,
            warnings,
            rawSpiderfoot: s.raw, rawOpencti: octi.status === 'fulfilled' ? octi.value.raw : null,
        };
        cacheScan(result);
        // The raw payloads stay server-side; the browser gets the parsed result.
        res.json({ ...result, rawSpiderfoot: {}, rawOpencti: {} });
    } finally {
        runningScans--;
    }
});

// ── Assets: add / update ─────────────────────────────────────────────────────────────────

const str = (v: unknown) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, 500) : null);
const strList = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string').slice(0, 500) : []);
const portList = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is number => Number.isInteger(x) && x > 0 && x < 65536).slice(0, 1000) : []);

// 0-100 from the CVEs found: average CVSS × 10.
const riskFrom = (vulns: SpiderFootVuln[]) => {
    const scored = vulns.map((v) => v.cvss).filter((c): c is number => typeof c === 'number');
    return scored.length ? Math.round((scored.reduce((a, b) => a + b, 0) / scored.length) * 10) : 0;
};

router.post('/assets', canWrite, async (req: AuthRequest, res) => {
    const body = req.body ?? {};
    const ip = typeof body.ip === 'string' ? body.ip.trim() : '';
    if (!isIP(ip)) return res.status(400).json({ error: 'Invalid IP address' });
    const sector = typeof body.sectorId === 'string' ? SECTOR_BY_ID[body.sectorId] : undefined;
    if (!sector) return res.status(400).json({ error: 'Unknown sector' });
    const subfield = str(body.subfield);
    if (subfield && !sector.subfields.includes(subfield)) return res.status(400).json({ error: 'Unknown sub-entity for this sector' });

    const db = getSupabase();
    if (!db) return notConnected(res, 'assets', 'Supabase is not configured (SUPABASE_URL, SUPABASE_SERVICE_KEY).');

    // Prefer the server's own scan of this IP; otherwise take the scan fields the client sent.
    const scan = cachedScan(ip);
    const vulns = scan?.vulns ?? [];
    const row = {
        ip,
        sector_id: sector.id,
        subfield,
        hostname: scan ? scan.hostname ?? null : str(body.hostname),
        owner: scan ? scan.owner ?? null : str(body.owner),
        org: scan ? scan.org ?? null : str(body.org),
        asn: scan ? scan.asn ?? null : str(body.asn),
        country: scan ? scan.country ?? null : str(body.country),
        domains: scan ? scan.domains : strList(body.domains),
        subdomains: scan ? scan.subdomains : strList(body.subdomains),
        open_ports: scan ? scan.openPorts : portList(body.openPorts),
        vulns,
        vuln_count: vulns.length,
        risk_score: riskFrom(vulns),
        scan_status: scan ? 'done' : 'pending',
        last_seen: new Date().toISOString(),
        ...(scan ? { raw_spiderfoot: scan.rawSpiderfoot, raw_opencti: scan.rawOpencti } : {}),
    };

    const { data, error } = await db.from('cnii_assets').upsert(row, { onConflict: 'ip' }).select(ASSET_COLUMNS).single();
    if (error) {
        if (isMissingTable(error)) return notConnected(res, 'assets', 'The cnii_assets table does not exist yet — run backend/sql/2026-10-cnii-assets.sql. The asset was not saved.');
        return res.status(500).json({ error: `Could not save the asset: ${error.message}` });
    }
    res.json(toAsset(data as AssetRow));
});

// ── Alerts ────────────────────────────────────────────────────────────────────────────────

const severityFromLevel = (level: number) => (level >= 12 ? 'critical' : level >= 7 ? 'high' : level >= 4 ? 'medium' : 'low');

interface AlertHit {
    _id: string;
    _source: { timestamp?: string; rule?: { description?: string; level?: number }; agent?: { ip?: string }; data?: { srcip?: string; dstip?: string } };
}

router.get('/alerts', canRead, async (req: AuthRequest, res) => {
    const filter = readFilter(req, res);
    if (!filter) return;
    try {
        const assets = await loadAssets(filter);
        if (!assets.length) return res.json([]);
        if (!process.env.WAZUH_INDEXER_HOST) return notConnected(res, 'alerts', 'The Wazuh indexer is not configured (WAZUH_INDEXER_HOST).');

        const sectorOf = new Map(assets.map((a) => [a.ip, a.sector_id]));
        const ips = [...sectorOf.keys()];
        let result: { hits?: { hits?: AlertHit[] } } | null;
        try {
            result = await search('wazuh-alerts-4.x-*', {
                size: 200,
                sort: [{ timestamp: 'desc' }],
                _source: ['timestamp', 'rule.description', 'rule.level', 'agent.ip', 'data.srcip', 'data.dstip'],
                query: {
                    bool: {
                        filter: [{ range: { timestamp: { gte: 'now-7d' } } }],
                        should: [{ terms: { 'agent.ip': ips } }, { terms: { 'data.srcip': ips } }, { terms: { 'data.dstip': ips } }],
                        minimum_should_match: 1,
                    },
                },
            });
        } catch (err) {
            return res.status(502).json({ error: `Wazuh indexer query failed: ${(err as Error).message}` });
        }

        const alerts = (result?.hits?.hits ?? []).flatMap((h) => {
            const s = h._source;
            const ip = [s.agent?.ip, s.data?.srcip, s.data?.dstip].find((x): x is string => !!x && sectorOf.has(x));
            if (!ip) return [];
            return [{
                id: h._id, ip, sectorId: sectorOf.get(ip)!, title: s.rule?.description ?? 'Wazuh alert',
                severity: severityFromLevel(s.rule?.level ?? 0), timestamp: s.timestamp ?? '', source: 'wazuh' as const,
            }];
        });
        res.json(alerts);
    } catch (err) {
        sendFeedError(res, err);
    }
});

// ── Vulnerabilities ──────────────────────────────────────────────────────────────────────

const vulnSeverity = (s: string | undefined): CniiVulnOut['severity'] => {
    const x = (s ?? '').toLowerCase();
    return x === 'critical' || x === 'high' || x === 'medium' || x === 'low' ? x : 'low';
};

interface CniiVulnOut {
    id: string; ip: string; sectorId: string; cve: string; title: string; cvss: number;
    severity: 'critical' | 'high' | 'medium' | 'low'; affectedService?: string; complianceImpact: string[];
    status: 'open'; discoveredAt: string; source: 'spiderfoot' | 'wazuh';
}

interface VulnHit {
    _id: string;
    _source: { agent?: { id?: string }; package?: { name?: string; version?: string }; vulnerability?: { id?: string; description?: string; severity?: string; score?: { base?: number }; detected_at?: string } };
}

// Monitored IPs that are also Wazuh agents → their agent ids. Wazuh's vulnerability state
// index identifies hosts by agent, not by IP.
async function agentIdsFor(ips: Set<string>): Promise<Map<string, string>> {
    const r = await wazuhGet('/agents?select=ip&limit=10000');
    const items = (r.json as { data?: { affected_items?: { id: string; ip?: string }[] } } | null)?.data?.affected_items ?? [];
    return new Map(items.filter((a) => a.ip && ips.has(a.ip)).map((a) => [a.id, a.ip!]));
}

router.get('/vulns', canRead, async (req: AuthRequest, res) => {
    const filter = readFilter(req, res);
    if (!filter) return;
    try {
        const assets = await loadAssets(filter);
        if (!assets.length) return res.json([]);
        const byIp = new Map(assets.map((a) => [a.ip, a]));
        const complianceFor = (ip: string) => SECTOR_BY_ID[byIp.get(ip)!.sector_id]?.compliance ?? [];

        // 1. CVEs stored from each asset's last scan.
        const vulns: CniiVulnOut[] = assets.flatMap((a) => (a.vulns ?? []).map((v): CniiVulnOut => ({
            id: `${a.ip}:${v.cve}`, ip: a.ip, sectorId: a.sector_id, cve: v.cve, title: v.cve,
            cvss: v.cvss ?? 0, severity: v.severity, affectedService: v.service,
            complianceImpact: complianceFor(a.ip), status: 'open', discoveredAt: a.last_seen, source: 'spiderfoot',
        })));

        // 2. Wazuh vulnerability state for monitored IPs that run a Wazuh agent. If Wazuh is
        //    unavailable the scan CVEs are still returned, and the response says what's missing.
        if (process.env.WAZUH_HOST && process.env.WAZUH_INDEXER_HOST) {
            try {
                const agents = await agentIdsFor(new Set(byIp.keys()));
                if (agents.size) {
                    const r = await search<{ hits?: { hits?: VulnHit[] } }>('wazuh-states-vulnerabilities-*', {
                        size: 500,
                        sort: [{ 'vulnerability.score.base': { order: 'desc' } }],
                        query: { terms: { 'agent.id': [...agents.keys()] } },
                    });
                    for (const h of r?.hits?.hits ?? []) {
                        const ip = agents.get(h._source.agent?.id ?? '');
                        const v = h._source.vulnerability;
                        if (!ip || !v?.id) continue;
                        const pkg = [h._source.package?.name, h._source.package?.version].filter(Boolean).join(' ');
                        vulns.push({
                            id: h._id, ip, sectorId: byIp.get(ip)!.sector_id, cve: v.id, title: v.description?.slice(0, 200) || v.id,
                            cvss: v.score?.base ?? 0, severity: vulnSeverity(v.severity), affectedService: pkg || undefined,
                            complianceImpact: complianceFor(ip), status: 'open', discoveredAt: v.detected_at ?? '', source: 'wazuh',
                        });
                    }
                }
            } catch (err) {
                console.error('[cnii] Wazuh vulnerability lookup failed:', (err as Error).message);
                res.setHeader('X-CNII-Partial', 'wazuh-unavailable');
            }
        } else {
            res.setHeader('X-CNII-Partial', 'wazuh-not-configured');
        }
        res.json(vulns);
    } catch (err) {
        sendFeedError(res, err);
    }
});

export default router;
