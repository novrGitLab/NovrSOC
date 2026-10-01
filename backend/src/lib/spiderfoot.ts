// SpiderFoot client (open-source SpiderFoot's web UI API, sfwebui.py). The endpoints and
// formats below were checked against SpiderFoot's source — it has no /api/v1/... routes:
//
//   POST /startscan        form: scanname, scantarget, modulelist, typelist, usecase
//                          with Accept: application/json → ["SUCCESS", scanId] | ["ERROR", message]
//   GET  /scanstatus?id=   → [name, target, created, started, ended, status, riskmatrix]
//                          status: INITIALIZING | STARTING | RUNNING | FINISHED | ABORTED | ERROR-FAILED
//   GET  /scaneventresults?id=&eventType=ALL
//                          → rows [lastseen, data, sourceData, module, confidence, visibility, risk,
//                                  hash, fp, parentFp, eventType]; data is HTML-escaped
//   GET  /stopscan?id=     (used when a scan runs past our timeout)
//   GET  /ping             → ["SUCCESS", version]
//
// Event data formats the parser relies on (from the producing modules):
//   INTERNET_NAME / DOMAIN_NAME   hostname
//   NETBLOCK_OWNER                a CIDR (e.g. 197.255.224.0/20) — not an owner name
//   BGP_AS_MEMBER                 bare AS number ("36873")
//   GEOINFO                       "City, Region, CC" (sfp_ipinfo)
//   TCP_PORT_OPEN                 "ip:port"
//   VULNERABILITY_CVE_<SEVERITY>  "CVE-…\n<SFURL>…</SFURL>\nScore: 7.5\nDescription: …"
//   RAW_RIR_DATA / NETBLOCK_WHOIS registry records — where the organisation name actually lives

export const SPIDERFOOT_MODULES = [
    'sfp_dnsresolve',   // reverse DNS → INTERNET_NAME, DOMAIN_NAME
    'sfp_ripe',         // NETBLOCK_OWNER, BGP_AS_MEMBER, RAW_RIR_DATA (RIPEstat; covers AfriNIC space)
    'sfp_bgpview',      // BGP_AS_MEMBER, RAW_RIR_DATA
    'sfp_arin',         // RAW_RIR_DATA
    'sfp_whois',        // NETBLOCK_WHOIS
    'sfp_ipinfo',       // GEOINFO (needs an ipinfo key in SpiderFoot)
    'sfp_shodan',       // TCP_PORT_OPEN, VULNERABILITY_CVE_* (needs a Shodan key in SpiderFoot)
    'sfp_portscan_tcp', // TCP_PORT_OPEN — an active scan of the target
    'sfp_censys',       // needs a Censys key in SpiderFoot
    'sfp_virustotal',   // MALICIOUS_IPADDR (needs a VirusTotal key in SpiderFoot)
];

export type SpiderFootErrorKind = 'not_configured' | 'unreachable' | 'failed' | 'timeout';

export class SpiderFootError extends Error {
    constructor(public kind: SpiderFootErrorKind, message: string) {
        super(message);
    }
}

export interface SpiderFootVuln { cve: string; cvss: number | null; severity: 'critical' | 'high' | 'medium' | 'low'; service?: string }
export interface SpiderFootIntel { source: string; description: string; severity: string }

export interface SpiderFootResult {
    scanId: string;
    status: string;
    hostname?: string;
    owner?: string;
    org?: string;
    asn?: string;
    country?: string;
    domains: string[];
    subdomains: string[];
    openPorts: number[];
    vulns: SpiderFootVuln[];
    threatIntel: SpiderFootIntel[];
    raw: unknown[];
}

export const spiderfootConfigured = () => !!process.env.SPIDERFOOT_URL;
const base = () => process.env.SPIDERFOOT_URL!.replace(/\/$/, '');

async function sfFetch(path: string, init: RequestInit = {}): Promise<unknown> {
    let r: Response;
    try {
        r = await fetch(`${base()}${path}`, {
            ...init,
            headers: { Accept: 'application/json', ...(init.headers ?? {}) },
            signal: AbortSignal.timeout(30_000),
        });
    } catch (err) {
        throw new SpiderFootError('unreachable', `SpiderFoot at ${base()} could not be reached: ${(err as Error).message}`);
    }
    const body = await r.json().catch(() => null);
    if (!r.ok) throw new SpiderFootError('failed', `SpiderFoot answered HTTP ${r.status} on ${path.split('?')[0]}`);
    return body;
}

export async function pingSpiderFoot(): Promise<string> {
    if (!spiderfootConfigured()) throw new SpiderFootError('not_configured', 'SPIDERFOOT_URL is not set.');
    const d = await sfFetch('/ping');
    if (!Array.isArray(d) || d[0] !== 'SUCCESS') throw new SpiderFootError('failed', 'SpiderFoot /ping did not answer SUCCESS.');
    return String(d[1] ?? '');
}

const TERMINAL = new Set(['FINISHED', 'ABORTED', 'ERROR-FAILED']);

export async function scanIP(ip: string, opts: { pollMs?: number; timeoutMs?: number } = {}): Promise<SpiderFootResult> {
    if (!spiderfootConfigured()) throw new SpiderFootError('not_configured', 'SPIDERFOOT_URL is not set.');
    const pollMs = opts.pollMs ?? 4_000;
    const timeoutMs = opts.timeoutMs ?? 180_000;

    // 1. Start the scan.
    const started = await sfFetch('/startscan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ scanname: `NovrSOC CNII ${ip}`, scantarget: ip, modulelist: SPIDERFOOT_MODULES.join(','), typelist: '', usecase: '' }).toString(),
    });
    if (!Array.isArray(started) || started[0] !== 'SUCCESS' || typeof started[1] !== 'string') {
        const why = Array.isArray(started) && started[0] === 'ERROR' ? String(started[1]) : 'unexpected response';
        throw new SpiderFootError('failed', `SpiderFoot did not start the scan: ${why}`);
    }
    const scanId = started[1];

    // 2. Poll until the scan ends or we give up.
    const deadline = Date.now() + timeoutMs;
    let status = '';
    for (;;) {
        const s = await sfFetch(`/scanstatus?id=${encodeURIComponent(scanId)}`);
        status = Array.isArray(s) ? String(s[5] ?? '') : '';
        if (TERMINAL.has(status)) break;
        if (Date.now() + pollMs > deadline) {
            await sfFetch(`/stopscan?id=${encodeURIComponent(scanId)}`).catch(() => undefined);
            throw new SpiderFootError('timeout', `SpiderFoot scan ${scanId} was still ${status || 'running'} after ${Math.round(timeoutMs / 1000)}s and was stopped.`);
        }
        await new Promise((r) => setTimeout(r, pollMs));
    }
    if (status === 'ERROR-FAILED') throw new SpiderFootError('failed', `SpiderFoot scan ${scanId} failed.`);

    // 3. Fetch and parse the results.
    const rows = await sfFetch(`/scaneventresults?id=${encodeURIComponent(scanId)}&eventType=ALL`);
    return { scanId, status, ...parseSpiderFootResults(Array.isArray(rows) ? rows : []) };
}

// ── Parsing ───────────────────────────────────────────────────────────────────────────────

const unescapeHtml = (s: string) => s
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&amp;/g, '&');

interface SfEvent { type: string; data: string; module: string }

function toEvents(rows: unknown[]): SfEvent[] {
    return rows.filter(Array.isArray).map((r) => ({
        type: String(r[10] ?? ''),
        data: unescapeHtml(String(r[1] ?? '')),
        module: String(r[3] ?? ''),
    }));
}

const uniq = <T>(xs: T[]) => [...new Set(xs)];

// Organisation names from registry data. Field order is preference order.
const OWNER_FIELDS = ['org-name', 'OrgName', 'owner', 'descr', 'netname'];
function registryName(texts: string[]): string | undefined {
    for (const field of OWNER_FIELDS) {
        for (const t of texts) {
            // RIPEstat JSON records: {"key": "descr", "value": "…"}
            const json = t.match(new RegExp(`"key"\\s*:\\s*"${field}"\\s*,\\s*"value"\\s*:\\s*"([^"]+)"`, 'i'));
            if (json) return json[1].trim();
            // Plain whois text: "descr:   …"
            const plain = t.match(new RegExp(`^\\s*${field}\\s*:\\s*(.+)$`, 'im'));
            if (plain) return plain[1].trim();
        }
    }
    return undefined;
}

// AS holder description: BGPView's Python-dict dump ('description_short': '…') or RIPEstat's as-name.
function asDescription(texts: string[]): string | undefined {
    for (const t of texts) {
        const m = t.match(/'description_short'\s*:\s*'([^']+)'/) ?? t.match(/"description_short"\s*:\s*"([^"]+)"/);
        if (m) return m[1].trim();
    }
    for (const t of texts) {
        const m = t.match(/"key"\s*:\s*"as-name"\s*,\s*"value"\s*:\s*"([^"]+)"/i) ?? t.match(/^\s*as-name\s*:\s*(.+)$/im);
        if (m) return m[1].trim();
    }
    return undefined;
}

const CVE_SEVERITY: Record<string, SpiderFootVuln['severity']> = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };

export function parseSpiderFootResults(rows: unknown[]): Omit<SpiderFootResult, 'scanId' | 'status'> {
    const events = toEvents(rows);
    const of = (type: string) => events.filter((e) => e.type === type);
    const first = (type: string) => of(type)[0]?.data;

    const hostname = first('INTERNET_NAME');
    const registry = [...of('RAW_RIR_DATA'), ...of('NETBLOCK_WHOIS')].map((e) => e.data);
    const owner = registryName(registry);
    const org = asDescription(registry) ?? owner;
    const asnRaw = first('BGP_AS_MEMBER')?.match(/\d+/)?.[0];
    const geo = first('GEOINFO');
    const country = geo ? geo.split(',').map((s) => s.trim()).filter(Boolean).pop() : undefined;

    const openPorts = uniq(of('TCP_PORT_OPEN')
        .map((e) => Number.parseInt(e.data.slice(e.data.lastIndexOf(':') + 1), 10))
        .filter((n) => Number.isInteger(n) && n > 0 && n < 65536))
        .sort((a, b) => a - b);

    const vulnByCve = new Map<string, SpiderFootVuln>();
    for (const e of events.filter((x) => x.type.startsWith('VULNERABILITY_CVE_'))) {
        const cve = e.data.match(/CVE-\d{4}-\d+/i)?.[0]?.toUpperCase();
        if (!cve || vulnByCve.has(cve)) continue;
        const score = Number.parseFloat(e.data.match(/Score:\s*([\d.]+)/i)?.[1] ?? '');
        vulnByCve.set(cve, {
            cve,
            cvss: Number.isFinite(score) ? score : null,
            severity: CVE_SEVERITY[e.type.slice('VULNERABILITY_CVE_'.length)] ?? 'low',
        });
    }

    const threatIntel: SpiderFootIntel[] = [
        ...of('MALICIOUS_IPADDR').map((e) => ({ source: `SpiderFoot (${e.module})`, description: `Reported malicious: ${e.data}`, severity: 'high' })),
        ...of('BLACKLISTED_IPADDR').map((e) => ({ source: `SpiderFoot (${e.module})`, description: `On a blocklist: ${e.data}`, severity: 'medium' })),
    ];

    return {
        hostname,
        owner,
        org,
        asn: asnRaw ? `AS${asnRaw}` : undefined,
        country,
        domains: uniq(of('DOMAIN_NAME').map((e) => e.data)),
        subdomains: uniq(of('INTERNET_NAME').map((e) => e.data)).filter((h) => h !== hostname),
        openPorts,
        vulns: [...vulnByCve.values()],
        threatIntel,
        raw: rows,
    };
}
