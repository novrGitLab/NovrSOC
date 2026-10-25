import { Router } from 'express';
import { analyzeSSL, type SSLReport } from '../services/sslLabs';
import { getSupabase } from '../services/geoEnrichment';
import { lookupDomain, type ParsedWhois } from '../services/rdap';
import type { AuthRequest } from '../middleware/auth';
import { requireOrg, requestOrg } from '../lib/permissions';

const router = Router();

// Mounted behind requireAuth (index.ts); requireOrg resolves the organisation this request acts
// on (lib/resolveOrg.ts). Fixes F-02: scans used to be written under a single shared placeholder
// org id and history was returned to anyone signed in, with no tenant filter at all.
router.use(requireOrg);

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface Finding {
    severity: Severity;
    title: string;
    description: string;
    recommendation: string;
}

interface WebScanResult {
    domain: string;
    scan_type: string;
    started_at: string;
    completed_at?: string;
    ssl: { grade: string; status: string; endpoints: SSLReport['endpoints'] } | null;
    rdap: ParsedWhois | null;
    findings: Finding[];
    vuln_critical: number;
    vuln_high: number;
    vuln_medium: number;
    vuln_low: number;
}

interface CloudflareDnsAnswer {
    name: string;
    type: number;
    TTL: number;
    data: string;
}
interface CloudflareDnsResponse {
    Status: number;
    Answer?: CloudflareDnsAnswer[];
}

// POST /api/webscan/start
// Body: { domain: "cybernovr.com", scan_type: "quick" | "full", authorised: true }
router.post('/start', async (req: AuthRequest, res) => {
    const { domain, scan_type = 'quick', authorised } = req.body ?? {};

    if (!domain) {
        res.status(400).json({ error: 'domain required' });
        return;
    }
    if (!authorised) {
        res.status(400).json({ error: 'Authorisation required' });
        return;
    }

    const cleanDomain = String(domain).replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();

    try {
        const results: WebScanResult = {
            domain: cleanDomain,
            scan_type,
            started_at: new Date().toISOString(),
            ssl: null,
            rdap: null,
            findings: [],
            vuln_critical: 0,
            vuln_high: 0,
            vuln_medium: 0,
            vuln_low: 0,
        };

        const [sslResult, rdapResult] = await Promise.allSettled([analyzeSSL(cleanDomain), lookupDomain(cleanDomain)]);

        if (sslResult.status === 'fulfilled' && sslResult.value) {
            const ssl = sslResult.value;
            results.ssl = { grade: ssl.bestGrade, status: ssl.status, endpoints: ssl.endpoints };

            if (['B', 'C', 'D', 'E', 'F'].includes(ssl.bestGrade)) {
                const sev: Severity = ssl.bestGrade === 'B' ? 'medium' : 'high';
                results.findings.push({
                    severity: sev,
                    title: `SSL/TLS Grade: ${ssl.bestGrade}`,
                    description: `SSL configuration is below optimal. Grade ${ssl.bestGrade} indicates potential weak ciphers or protocol support.`,
                    recommendation: 'Review TLS configuration, disable old protocols (TLS 1.0/1.1), remove weak cipher suites.',
                });
                if (sev === 'high') results.vuln_high++;
                else results.vuln_medium++;
            }

            if (ssl.endpoints?.some((e) => e.hasWarnings)) {
                results.findings.push({
                    severity: 'medium',
                    title: 'SSL Certificate Warnings',
                    description: 'One or more SSL endpoints have configuration warnings.',
                    recommendation: 'Review SSL Labs report for specific warning details.',
                });
                results.vuln_medium++;
            }
        }

        if (rdapResult.status === 'fulfilled' && rdapResult.value) {
            const rdap = rdapResult.value;
            results.rdap = rdap;

            if (rdap.daysUntilExpiry !== null && rdap.daysUntilExpiry < 30) {
                const sev: Severity = rdap.daysUntilExpiry < 7 ? 'critical' : 'high';
                results.findings.push({
                    severity: sev,
                    title: `Domain Expiring in ${rdap.daysUntilExpiry} Days`,
                    description: `Domain ${cleanDomain} expires on ${rdap.expires}. Failure to renew risks domain hijacking.`,
                    recommendation: 'Renew domain immediately. Enable auto-renew with registrar.',
                });
                if (sev === 'critical') results.vuln_critical++;
                else results.vuln_high++;
            }

            if (!rdap.dnssec) {
                results.findings.push({
                    severity: 'medium',
                    title: 'DNSSEC Not Enabled',
                    description: 'Domain does not have DNSSEC configured, leaving it vulnerable to DNS spoofing attacks.',
                    recommendation: 'Enable DNSSEC through your domain registrar or DNS provider.',
                });
                results.vuln_medium++;
            }
        }

        // DNS checks via Cloudflare DoH — check for missing security records
        try {
            const txtRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${cleanDomain}&type=TXT`, {
                headers: { Accept: 'application/dns-json' },
                signal: AbortSignal.timeout(5000),
            }).then((r) => r.json() as Promise<CloudflareDnsResponse>);

            const answers = (txtRes.Answer || []).map((a) => a.data);
            const hasSPF = answers.some((a) => a.includes('v=spf1'));
            const hasDMARC = answers.some((a) => a.includes('v=DMARC1'));

            if (!hasSPF) {
                results.findings.push({
                    severity: 'high',
                    title: 'Missing SPF Record',
                    description: 'No SPF DNS TXT record found. Domain can be spoofed for email phishing attacks.',
                    recommendation: 'Add SPF record: v=spf1 include:your-mail-provider.com ~all',
                });
                results.vuln_high++;
            }

            if (!hasDMARC) {
                results.findings.push({
                    severity: 'high',
                    title: 'Missing DMARC Record',
                    description: 'No DMARC DNS TXT record found. Without DMARC, you cannot enforce email authentication.',
                    recommendation: 'Add DMARC record starting with p=none, then move to p=quarantine and p=reject.',
                });
                results.vuln_high++;
            }
        } catch {
            // non-fatal DNS check
        }

        results.completed_at = new Date().toISOString();

        // Note: Nuclei/Nmap/full DAST scanning requires EC2-4
        if (scan_type === 'full') {
            results.findings.push({
                severity: 'info',
                title: 'Full DAST Scan Pending EC2-4',
                description: 'Nuclei vulnerability scanner and port scanning require the EC2-4 Scanner instance. Available after AWS provisioning.',
                recommendation: 'Provision EC2-4 to enable full DAST scanning with 5000+ Nuclei templates.',
            });
        }

        try {
            const supabase = getSupabase();
            if (supabase) {
                await supabase.from('website_scans').insert({
                    org_id: requestOrg(req),
                    target_domain: cleanDomain,
                    scan_type,
                    ssl_grade: results.ssl?.grade || null,
                    vuln_critical: results.vuln_critical,
                    vuln_high: results.vuln_high,
                    vuln_medium: results.vuln_medium,
                    vuln_low: results.vuln_low,
                    findings: results.findings,
                });
            }
        } catch {
            // non-fatal
        }

        res.json(results);
    } catch (err) {
        console.error('[WebScan] Error:', err);
        res.status(500).json({ error: 'Scan failed' });
    }
});

// GET /api/webscan/history — this organisation's own scans only (F-02).
router.get('/history', async (req: AuthRequest, res) => {
    try {
        const supabase = getSupabase();
        if (!supabase) {
            res.json({ scans: [] });
            return;
        }
        const { data } = await supabase.from('website_scans').select('*').eq('org_id', requestOrg(req)).order('scanned_at', { ascending: false }).limit(20);
        res.json({ scans: data || [] });
    } catch {
        res.status(500).json({ error: 'History failed' });
    }
});

export default router;
