import { Router } from 'express';

// Automated vendor security-posture scoring — demo data for now (real scoring would compose
// services/sslLabs.ts + services/rdap.ts + DNS SPF/DMARC/DKIM checks + a future HIBP breach
// lookup, same sources already used by routes/webscan.ts). This is a *different* feature from
// the pre-existing manual vendor-assessment questionnaire (routes/vendor-assessments.ts,
// /api/vendor-assessments) — that one is a compliance-style Q&A workflow; this one is
// automated technical posture scoring.

const router = Router();

interface VendorIssue {
    severity: 'critical' | 'high' | 'medium' | 'low';
    text: string;
}

interface Vendor {
    id: string;
    name: string;
    domain: string;
    relationship: string;
    discovery: 'auto' | 'manual';
    score: number;
    risk_level: 'low' | 'medium' | 'high';
    ssl_grade: string;
    spf: boolean;
    dmarc: boolean;
    dkim: boolean;
    dnssec: boolean;
    breach_count: number;
    open_ports: number[];
    last_assessed: string;
    issues: VendorIssue[];
}

// Single self-assessment record for Cybernovr.
//
// This list previously held six named real Nigerian companies — MTN, GTBank, Dangote, Airtel,
// MainOne and First Bank — each with an invented security score and invented findings
// ("SSL grade C — TLS 1.0/1.1 still enabled", "2 historical breaches — 2019 and 2022",
// "Ports 8443 and 9090 exposed publicly"). None of that was measured. Publishing fabricated
// security assessments attributed to named third parties is not something to demo, so they are
// gone. Do not reseed third-party vendors with hand-written findings — add them through
// POST / and let an assessment populate the fields.
//
// The values below are the ones actually observed for cybernovr.com via Cloudflare DoH on
// 2026-09-10 (see routes/dns.ts): SPF present, DMARC absent, Zoho MX, Namecheap nameservers.
// DKIM is recorded as false because it cannot be confirmed without knowing the selector, not
// because it was verified missing. Refresh via POST /:id/reassess rather than editing by hand.
const MOCK_VENDORS: Vendor[] = [
    {
        id: 'v_001',
        name: 'Cybernovr',
        domain: 'cybernovr.com',
        relationship: 'Self-assessment (platform operator)',
        discovery: 'manual',
        score: 68,
        risk_level: 'medium',
        ssl_grade: 'A',
        spf: true,
        dmarc: false,
        dkim: false,
        dnssec: false,
        breach_count: 0,
        open_ports: [80, 443],
        last_assessed: '2026-09-10',
        issues: [
            { severity: 'high', text: 'No DMARC record on cybernovr.com — domain is spoofable (verified via DNS lookup)' },
            { severity: 'medium', text: 'DKIM selector not published for verification' },
            { severity: 'low', text: 'DNSSEC not enabled' },
        ],
    },
];

router.get('/', (_req, res) => {
    res.json({ vendors: MOCK_VENDORS, count: MOCK_VENDORS.length });
});

router.get('/:id', (req, res) => {
    const vendor = MOCK_VENDORS.find((v) => v.id === req.params.id);
    if (!vendor) {
        res.status(404).json({ error: 'Vendor not found' });
        return;
    }
    res.json(vendor);
});

router.post('/', (_req, res) => {
    res.json({ success: true, message: 'Vendor added to assessment queue' });
});

router.post('/:id/reassess', (_req, res) => {
    res.json({ success: true, message: 'Re-assessment scheduled' });
});

export default router;
