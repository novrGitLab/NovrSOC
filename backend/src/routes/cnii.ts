// CNII Watch — asset inventory, sector alerts, vulnerabilities and the IP scanner.
//
//   POST /scan  { ip }      SpiderFoot scan + OpenCTI lookup in parallel → ScanResult with a
//                           suggested sector. Nothing is saved; the analyst confirms the sector.
//   POST /assets            { ip, sectorId, subfield? } → upsert into cnii_assets, using the
//                           server's cached scan for that IP (raw data, CVEs) when there is one.
//   GET  /assets            cnii_assets rows (?sector=, ?ip=)
//   GET  /alerts            not available: always 503 not_connected (?sector=, ?ip= still validated).
//                           CNII Watch no longer reads Wazuh endpoint alerts (2026-10 cleanup) and no
//                           other alert source is connected.
//   GET  /vulns             CVEs stored from each asset's last SpiderFoot scan (?sector=, ?ip=).
//                           Wazuh vulnerability state is no longer merged in.
//
// Response shapes: frontend/src/lib/cnii-types.ts. When a dependency is missing or down the route
// says so (503 not_connected / 502) — it never substitutes sample data or reports a save that
// didn't happen. Mounted behind requireAuth in index.ts; roles are checked per route.
import { Router, Response } from 'express';
import { isIP } from 'net';
import { AuthRequest, requireRole } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';
import { scanIP, spiderfootConfigured, SpiderFootError, type SpiderFootVuln } from '../lib/spiderfoot';
import { lookupIP, openctiConfigured } from '../lib/opencti';
import { classifySector, assessCnii, type CniiLikelihood } from '../lib/cnii-classify';
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
    ip: string; hostname?: string; owner?: string; org?: string; asn?: string; country?: string; city?: string; region?: string;
    domains: string[]; subdomains: string[]; openPorts: number[];
    vulns: SpiderFootVuln[];
    threatIntel: { source: string; description: string; severity: string }[];
    affiliateIPs?: string[]; maliciousFlags?: string[]; linkedURLs?: string[]; emails?: string[]; phones?: string[]; sslCerts?: string[]; banners?: string[];
    suggestedSectorId: string; suggestedSubfield: string; confidence: number;
    cniiLikelihood: CniiLikelihood; cniiSignals: string[];
    warnings: string[];
    rawSpiderfoot: unknown; rawOpencti: unknown;
}

// SpiderFoot scans are heavy (sfp_portscan_tcp actively connects to the target), so a bulk
// request does NOT fire every scan at once — at most MAX_CONCURRENT_SCANS run together, across
// all callers. The slot is released as each scan finishes.
const MAX_CONCURRENT_SCANS = 3;
const MAX_BULK_IPS = 10;
let runningScans = 0;
const waiters: (() => void)[] = [];
async function acquireScanSlot(): Promise<() => void> {
    if (runningScans >= MAX_CONCURRENT_SCANS) await new Promise<void>((r) => waiters.push(r));
    runningScans++;
    return () => { runningScans--; waiters.shift()?.(); };
}

// One IP: SpiderFoot scan + OpenCTI lookup in parallel, classified and rated. Throws only when
// the SpiderFoot scan itself failed (OpenCTI failure is a warning, not a failure).
async function runScan(ip: string): Promise<ScanResult> {
    const release = await acquireScanSlot();
    try {
        const [sf, octi] = await Promise.allSettled([
            scanIP(ip),
            openctiConfigured() ? lookupIP(ip) : Promise.reject(new Error('OpenCTI is not configured (OPENCTI_URL, OPENCTI_TOKEN).')),
        ]);
        if (sf.status === 'rejected') throw sf.reason;

        const s = sf.value;
        const warnings = [...s.warnings];
        if (octi.status === 'rejected') {
            console.error('[cnii] OpenCTI lookup failed:', (octi.reason as Error).message);
            warnings.push(`OpenCTI lookup failed: ${(octi.reason as Error).message}`);
        }

        const cls = classifySector(s.owner, s.org, s.asn, [s.hostname, ...s.domains].filter(Boolean).join(' '));
        if (!cls.sectorId) warnings.push('No CNII sector matched the owner, organisation, ASN or hostname — choose one before adding.');
        const cnii = assessCnii(!!cls.sectorId, { asn: s.asn, hostname: s.hostname, org: s.org, owner: s.owner, openPorts: s.openPorts, maliciousFlags: s.maliciousFlags });

        const result: ScanResult = {
            ip, hostname: s.hostname, owner: s.owner, org: s.org, asn: s.asn, country: s.country, city: s.city, region: s.region,
            domains: s.domains, subdomains: s.subdomains, openPorts: s.openPorts, vulns: s.vulns,
            threatIntel: [...s.threatIntel, ...(octi.status === 'fulfilled' ? octi.value.threatIntel : [])],
            affiliateIPs: s.affiliateIPs, maliciousFlags: s.maliciousFlags, linkedURLs: s.linkedURLs,
            emails: s.emails, phones: s.phones, sslCerts: s.sslCerts, banners: s.banners,
            suggestedSectorId: cls.sectorId, suggestedSubfield: cls.subfield, confidence: cls.confidence,
            cniiLikelihood: cnii.likelihood, cniiSignals: cnii.signals,
            warnings,
            rawSpiderfoot: s.raw, rawOpencti: octi.status === 'fulfilled' ? octi.value.raw : null,
        };
        cacheScan(result);
        return result;
    } finally {
        release();
    }
}

const scanFailStatus = (e: unknown) => (e instanceof SpiderFootError && e.kind === 'timeout' ? 504 : 502);
// Raw payloads stay server-side (POST /assets reads them from the cache); the browser gets the parsed result.
const forClient = (r: ScanResult) => ({ ...r, rawSpiderfoot: {}, rawOpencti: {} });

// Accepts { ip: "1.2.3.4" }, { ips: ["…", …] }, or { ip: "a, b, c" }. A single string ip stays
// backward-compatible (one object back); any multi-IP form returns an array.
router.post('/scan', canWrite, async (req: AuthRequest, res) => {
    const body = req.body ?? {};
    const raw: unknown[] = Array.isArray(body.ips) ? body.ips
        : typeof body.ips === 'string' ? body.ips.split(',')
        : typeof body.ip === 'string' ? body.ip.split(',')
        : [];
    const ips = [...new Set(raw.map((x) => (typeof x === 'string' ? x.trim() : '')).filter(Boolean))];
    const bulk = Array.isArray(body.ips) || ips.length > 1;

    if (ips.length === 0) return res.status(400).json({ error: 'Provide an IP address (ip) or a list of IP addresses (ips).' });
    if (ips.length > MAX_BULK_IPS) return res.status(400).json({ error: `At most ${MAX_BULK_IPS} IP addresses per request (got ${ips.length}).` });
    const invalid = ips.filter((ip) => !isIP(ip));
    if (invalid.length) return res.status(400).json({ error: `Invalid IP address${invalid.length > 1 ? 'es' : ''}: ${invalid.join(', ')}` });
    if (!spiderfootConfigured()) return notConnected(res, 'scan', 'SpiderFoot is not configured (SPIDERFOOT_URL).');

    if (!bulk) {
        try {
            res.json(forClient(await runScan(ips[0])));
        } catch (e) {
            res.status(scanFailStatus(e)).json({ error: (e as Error).message });
        }
        return;
    }

    // Bulk: one failed IP doesn't sink the batch — each entry reports ok or its error.
    const settled = await Promise.all(ips.map(async (ip) => {
        try {
            return { ip, ok: true as const, result: forClient(await runScan(ip)) };
        } catch (e) {
            return { ip, ok: false as const, error: (e as Error).message };
        }
    }));
    res.json({ results: settled });
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
//
// No CNII alert source is connected. This used to match Wazuh endpoint alerts against monitored
// IPs; Wazuh was decoupled from CNII Watch, so the feed now says it is not available.

router.get('/alerts', canRead, async (req: AuthRequest, res) => {
    if (!readFilter(req, res)) return;
    return notConnected(res, 'alerts', 'CNII alerts are not available — no alert source is connected to CNII Watch.');
});

// ── Vulnerabilities ──────────────────────────────────────────────────────────────────────

interface CniiVulnOut {
    id: string; ip: string; sectorId: string; cve: string; title: string; cvss: number;
    severity: 'critical' | 'high' | 'medium' | 'low'; affectedService?: string; complianceImpact: string[];
    status: 'open'; discoveredAt: string; source: 'spiderfoot';
}

router.get('/vulns', canRead, async (req: AuthRequest, res) => {
    const filter = readFilter(req, res);
    if (!filter) return;
    try {
        const assets = await loadAssets(filter);
        if (!assets.length) return res.json([]);
        const byIp = new Map(assets.map((a) => [a.ip, a]));
        const complianceFor = (ip: string) => SECTOR_BY_ID[byIp.get(ip)!.sector_id]?.compliance ?? [];

        // CVEs stored from each asset's last scan.
        const vulns: CniiVulnOut[] = assets.flatMap((a) => (a.vulns ?? []).map((v): CniiVulnOut => ({
            id: `${a.ip}:${v.cve}`, ip: a.ip, sectorId: a.sector_id, cve: v.cve, title: v.cve,
            cvss: v.cvss ?? 0, severity: v.severity, affectedService: v.service,
            complianceImpact: complianceFor(a.ip), status: 'open', discoveredAt: a.last_seen, source: 'spiderfoot',
        })));

        res.json(vulns);
    } catch (err) {
        sendFeedError(res, err);
    }
});

export default router;
