import { Router } from 'express';
import { z } from 'zod';
import { validate } from '../middleware/validate';
import { searchCTLogs, type CertEntry } from '../services/crtsh';
import { lookupDomain, type ParsedWhois } from '../services/rdap';

// Deliberately loose on `domain` itself (no strict hostname regex) — the handler below
// accepts a pasted https://... URL and cleans it, so a strict format check here would
// reject input the route is specifically written to tolerate.
const AddDomainSchema = z.object({
    domain: z.string().min(3).max(253).trim(),
    brand_keywords: z.array(z.string().max(100)).max(20).optional(),
    similarity_threshold: z.number().min(0).max(100).optional(),
    alerts: z.object({
        lookalike: z.boolean().optional(),
        dns_change: z.boolean().optional(),
        expiry: z.boolean().optional(),
        new_cert: z.boolean().optional(),
    }).optional(),
});

// Brand Protection > Domain Suite — monitored brand domains, scanned for lookalikes, DNS
// changes, expiring registrations, and unauthorized SSL certs. Real crt.sh (CT logs) and
// RDAP (WHOIS) lookups; Cloudflare DoH for live DNS. In-memory store — same pattern as
// routes/brand.ts (which this replaces the /domains section of; see index.ts wiring).

const router = Router();

interface DomainAlerts {
    lookalike: boolean;
    dns_change: boolean;
    expiry: boolean;
    new_cert: boolean;
}

interface DomainLookalike {
    domain: string;
    similarity: number;
    risk: 'HIGH' | 'MEDIUM' | 'LOW';
    registered?: string;
}

interface DomainCTLogEntry {
    domain: string;
    issuer: string;
    not_before: string;
    not_after: string;
    suspicious: boolean;
}

interface DomainDnsRecord {
    type: string;
    name: string;
    value: string;
    ttl: number;
}

interface DomainAlertEvent {
    type: string;
    message: string;
    severity: 'HIGH' | 'MEDIUM' | 'LOW';
    time: string;
}

// Cached results shown immediately on GET / (no click required) — refreshed in place by
// GET /:id/scan (real RDAP + crt.sh) and GET /:id/dns (real Cloudflare DoH) when called.
interface DomainScanCache {
    scanned_at: string;
    whois: ParsedWhois | null;
    ssl_grade: string | null;
    ct_logs: DomainCTLogEntry[];
    lookalikes: DomainLookalike[];
    dns_records: DomainDnsRecord[];
    email_security: { spf: boolean; dmarc: boolean; dkim: boolean } | null;
    alert_history: DomainAlertEvent[];
}

interface MonitoredDomain {
    id: string;
    domain: string;
    brand_keywords: string[];
    similarity_threshold: number;
    alerts: DomainAlerts;
    status: 'active';
    added_at: string;
    last_scan: DomainScanCache | null;
}

const monitoredDomains: MonitoredDomain[] = [
    {
        id: 'dom_001',
        domain: 'cybernovr.com',
        brand_keywords: ['cybernovr', 'novrsoc'],
        similarity_threshold: 80,
        alerts: { lookalike: true, dns_change: true, expiry: true, new_cert: true },
        status: 'active',
        added_at: '2026-01-15',
        last_scan: {
            scanned_at: '2026-08-16T06:00:00.000Z',
            whois: {
                domain: 'cybernovr.com', registrar: 'Namecheap Inc.', created: '2022-05-09T00:00:00Z',
                updated: '2026-04-09T00:00:00Z', expires: '2027-05-09T00:00:00Z',
                nameservers: ['ns1.namecheap.com', 'ns2.namecheap.com'], status: ['active'],
                dnssec: false, daysUntilExpiry: 268,
            },
            ssl_grade: 'A',
            ct_logs: [
                { domain: 'cybernovr.com', issuer: "Let's Encrypt", not_before: '2026-06-01', not_after: '2026-09-01', suspicious: false },
                { domain: '*.cybernovr.com', issuer: "Let's Encrypt", not_before: '2026-06-01', not_after: '2026-09-01', suspicious: false },
                { domain: 'cybernovr.ng', issuer: "Let's Encrypt", not_before: '2026-08-01', not_after: '2026-11-01', suspicious: true },
                { domain: 'cybernovre.com', issuer: 'ZeroSSL', not_before: '2026-07-15', not_after: '2026-10-15', suspicious: true },
            ],
            lookalikes: [
                { domain: 'cybernovr.ng', similarity: 95, risk: 'HIGH', registered: '2026-08-01' },
                { domain: 'cybernovre.com', similarity: 91, risk: 'HIGH', registered: '2026-07-15' },
                { domain: 'cybernovr-official.com', similarity: 82, risk: 'MEDIUM', registered: '2026-06-20' },
                { domain: 'cybernovrsecurity.com', similarity: 79, risk: 'MEDIUM', registered: '2026-05-10' },
            ],
            dns_records: [
                { type: 'A', name: 'cybernovr.com', value: '76.76.21.21', ttl: 3600 },
                { type: 'MX', name: 'cybernovr.com', value: 'mail.proton.me', ttl: 3600 },
                { type: 'TXT', name: 'cybernovr.com', value: 'v=spf1 include:_spf.protonmail.ch ~all', ttl: 3600 },
            ],
            email_security: { spf: true, dmarc: true, dkim: true },
            alert_history: [
                { type: 'LOOKALIKE', message: 'New domain cybernovr.ng registered 15 days ago', severity: 'HIGH', time: '2026-08-01' },
                { type: 'CT_LOG', message: 'SSL cert issued for cybernovre.com', severity: 'HIGH', time: '2026-07-15' },
            ],
        },
    },
    {
        id: 'dom_002',
        domain: 'novrsoc.com',
        brand_keywords: ['novrsoc', 'cybernovr'],
        similarity_threshold: 80,
        alerts: { lookalike: true, dns_change: true, expiry: true, new_cert: true },
        status: 'active',
        added_at: '2026-01-15',
        last_scan: {
            scanned_at: '2026-08-16T06:00:00.000Z',
            whois: {
                domain: 'novrsoc.com', registrar: 'GoDaddy LLC', created: '2024-01-10T00:00:00Z',
                updated: '2026-01-10T00:00:00Z', expires: '2027-01-10T00:00:00Z',
                nameservers: ['ns1.vercel-dns.com', 'ns2.vercel-dns.com'], status: ['active'],
                dnssec: false, daysUntilExpiry: 147,
            },
            ssl_grade: 'A+',
            ct_logs: [
                { domain: 'novrsoc.com', issuer: "Let's Encrypt", not_before: '2026-07-01', not_after: '2026-10-01', suspicious: false },
                { domain: 'novrsoc.ng', issuer: "Let's Encrypt", not_before: '2026-08-10', not_after: '2026-11-10', suspicious: true },
            ],
            lookalikes: [
                { domain: 'novrsoc.ng', similarity: 93, risk: 'HIGH', registered: '2026-08-10' },
                { domain: 'novsoc.com', similarity: 78, risk: 'MEDIUM', registered: '2026-07-01' },
            ],
            dns_records: [
                { type: 'A', name: 'novrsoc.com', value: '76.76.21.21', ttl: 3600 },
            ],
            email_security: { spf: true, dmarc: false, dkim: false },
            alert_history: [
                { type: 'DMARC', message: 'DMARC record missing — domain can be spoofed for phishing', severity: 'HIGH', time: '2026-08-16' },
                { type: 'LOOKALIKE', message: 'novrsoc.ng registered 6 days ago', severity: 'HIGH', time: '2026-08-10' },
            ],
        },
    },
];

let nextId = 100;
const newId = () => `dom_${nextId++}`;

// GET /api/brand/domains — list all monitored domains
router.get('/', (_req, res) => {
    res.json({ domains: monitoredDomains });
});

// POST /api/brand/domains — add a domain
router.post('/', validate(AddDomainSchema), (req, res) => {
    const { domain, brand_keywords, similarity_threshold, alerts }: {
        domain?: string;
        brand_keywords?: string[];
        similarity_threshold?: number;
        alerts?: Partial<DomainAlerts>;
    } = req.body ?? {};

    if (!domain || typeof domain !== 'string') {
        res.status(400).json({ error: 'domain required' });
        return;
    }

    const cleaned = domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');
    if (monitoredDomains.some((d) => d.domain === cleaned)) {
        res.status(409).json({ error: 'Domain already monitored' });
        return;
    }

    const entry: MonitoredDomain = {
        id: newId(),
        domain: cleaned,
        brand_keywords: brand_keywords && brand_keywords.length > 0 ? brand_keywords : [cleaned.split('.')[0]],
        similarity_threshold: similarity_threshold ?? 80,
        alerts: { lookalike: true, dns_change: true, expiry: true, new_cert: true, ...alerts },
        status: 'active',
        added_at: new Date().toISOString().split('T')[0],
        last_scan: null,
    };

    monitoredDomains.push(entry);
    res.status(201).json(entry);
});

// POST /api/brand/domains/investigate { domain } — ad-hoc RDAP/WHOIS + typosquat candidates
// for ANY domain, without it having to be added as a monitored domain first.
//
// The Domain Intelligence page needs this because every other route in this file is keyed on a
// monitored domain's `:id` — GET /:id/scan and GET /:id/dns both 404 for a domain the operator
// has merely typed into a search box. Registered here (before the /:id routes, so 'investigate'
// isn't swallowed as an id) rather than loosening those to accept a bare hostname, which would
// change what an existing id-keyed URL means.
//
// DNS records and certificates deliberately aren't returned: POST /api/dns/lookup already does
// both for an arbitrary domain, and duplicating the crt.sh call here would mean two round trips
// to the same upstream for one investigation.
const InvestigateSchema = z.object({ domain: z.string().min(3).max(253).trim() });

router.post('/investigate', validate(InvestigateSchema), async (req, res) => {
    const raw = String(req.body?.domain ?? '');
    const cleaned = raw.toLowerCase().trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^\*\./, '');
    if (!cleaned || !cleaned.includes('.')) {
        res.status(400).json({ error: 'Enter a valid domain, e.g. example.com' });
        return;
    }

    let whois: ParsedWhois | null = null;
    try {
        whois = await lookupDomain(cleaned);
    } catch {
        // Non-fatal: RDAP is frequently unavailable for some TLDs, and the rest of the
        // investigation is still worth returning.
    }

    // Pattern-generated typosquat candidates. These are NOT checked for registration or
    // resolution — same limitation as GET /:id/scan's lookalikes — so the response labels them
    // as candidates and the UI must not present them as confirmed hostile registrations.
    const base = cleaned.split('.')[0];
    const tld = cleaned.split('.').slice(1).join('.');
    const lookalikes = [
        { domain: `${base}-official.com`, similarity: 82, risk: 'MEDIUM' as const },
        { domain: `${base}security.com`, similarity: 79, risk: 'MEDIUM' as const },
        { domain: `${base}.ng`, similarity: 95, risk: 'HIGH' as const },
        { domain: `${base.slice(0, -1)}k.${tld}`, similarity: 91, risk: 'HIGH' as const },
    ].filter((l) => l.domain !== cleaned);

    res.json({
        domain: cleaned,
        investigated_at: new Date().toISOString(),
        whois,
        lookalikes,
        lookalikes_note: 'Pattern-generated candidates — registration and resolution are not verified.',
    });
});

// DELETE /api/brand/domains/:id
router.delete('/:id', (req, res) => {
    const idx = monitoredDomains.findIndex((d) => d.id === req.params.id);
    if (idx === -1) {
        res.status(404).json({ error: 'Domain not found' });
        return;
    }
    monitoredDomains.splice(idx, 1);
    res.status(204).end();
});

interface DomainScanResult {
    domain: string;
    scanned_at: string;
    whois: ParsedWhois | null;
    ct_logs: Array<{ domain: string; issuer: string; not_before: string; not_after: string; suspicious: boolean }>;
    lookalikes: Array<{ domain: string; similarity: number; risk: 'HIGH' | 'MEDIUM' | 'LOW' }>;
}

// GET /api/brand/domains/:id/scan — run live scan on domain (real RDAP + real crt.sh)
router.get('/:id/scan', async (req, res) => {
    const domain = monitoredDomains.find((d) => d.id === req.params.id);
    if (!domain) {
        res.status(404).json({ error: 'Domain not found' });
        return;
    }

    const results: DomainScanResult = {
        domain: domain.domain,
        scanned_at: new Date().toISOString(),
        whois: null,
        ct_logs: [],
        lookalikes: [],
    };

    try {
        results.whois = await lookupDomain(domain.domain);
    } catch {
        // non-fatal
    }

    try {
        const certs: CertEntry[] = await searchCTLogs(domain.domain);
        results.ct_logs = certs.slice(0, 10).map((c) => ({
            domain: c.common_name,
            issuer: c.issuer_name,
            not_before: c.not_before,
            not_after: c.not_after,
            suspicious: c.common_name !== domain.domain && !c.common_name.endsWith(`.${domain.domain}`),
        }));
    } catch {
        // non-fatal
    }

    // Generated typosquat candidates — real registration/resolution status isn't checked here,
    // just pattern generation (same approach as the mock lookalikes routes/brand.ts used to serve).
    const base = domain.domain.split('.')[0];
    const tld = domain.domain.split('.').slice(1).join('.');
    results.lookalikes = (
        [
            { domain: `${base}-official.com`, similarity: 82, risk: 'MEDIUM' },
            { domain: `${base}security.com`, similarity: 79, risk: 'MEDIUM' },
            { domain: `${base}.ng`, similarity: 95, risk: 'HIGH' },
            { domain: `${base.slice(0, -1)}k.${tld}`, similarity: 91, risk: 'HIGH' },
        ] as const
    ).filter((l) => l.domain !== domain.domain);

    // Persist into the cache GET / serves, keeping whatever DNS/alert history already exists.
    domain.last_scan = {
        scanned_at: results.scanned_at,
        whois: results.whois,
        ssl_grade: domain.last_scan?.ssl_grade ?? null,
        ct_logs: results.ct_logs,
        lookalikes: results.lookalikes,
        dns_records: domain.last_scan?.dns_records ?? [],
        email_security: domain.last_scan?.email_security ?? null,
        alert_history: domain.last_scan?.alert_history ?? [],
    };

    res.json(results);
});

interface DnsRecord {
    type: string;
    name: string;
    value: string;
    ttl: number;
}

interface DoHAnswer {
    name: string;
    type: number;
    TTL: number;
    data: string;
}

interface DoHResponse {
    Answer?: DoHAnswer[];
}

// GET /api/brand/domains/:id/dns — live DNS check via Cloudflare DoH
router.get('/:id/dns', async (req, res) => {
    const domain = monitoredDomains.find((d) => d.id === req.params.id);
    if (!domain) {
        res.status(404).json({ error: 'Domain not found' });
        return;
    }

    const records: DnsRecord[] = [];

    for (const type of ['A', 'MX', 'TXT', 'NS']) {
        try {
            const dohRes = await fetch(
                `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain.domain)}&type=${type}`,
                { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(5000) }
            );
            const data = (await dohRes.json()) as DoHResponse;
            (data.Answer ?? []).forEach((a) => {
                records.push({ type, name: a.name, value: a.data, ttl: a.TTL });
            });
        } catch {
            // skip record type on error
        }
    }

    const txtRecords = records.filter((r) => r.type === 'TXT').map((r) => r.value);
    const hasSPF = txtRecords.some((t) => t.includes('v=spf1'));
    const hasDMARC = txtRecords.some((t) => t.includes('v=DMARC1'));
    const hasDKIM = txtRecords.some((t) => t.includes('DKIM1') || t.includes('v=DKIM1'));

    // Only overwrite the cache if the live lookup actually found records — otherwise a DoH
    // hiccup would blank out the pre-seeded/previously-known DNS picture on GET /.
    if (records.length > 0 && domain.last_scan) {
        domain.last_scan.dns_records = records;
        domain.last_scan.email_security = { spf: hasSPF, dmarc: hasDMARC, dkim: hasDKIM };
    } else if (records.length > 0) {
        domain.last_scan = {
            scanned_at: new Date().toISOString(),
            whois: null,
            ssl_grade: null,
            ct_logs: [],
            lookalikes: [],
            dns_records: records,
            email_security: { spf: hasSPF, dmarc: hasDMARC, dkim: hasDKIM },
            alert_history: [],
        };
    }

    res.json({
        domain: domain.domain,
        records,
        email_security: { spf: hasSPF, dmarc: hasDMARC, dkim: hasDKIM },
        checked_at: new Date().toISOString(),
    });
});

export default router;
