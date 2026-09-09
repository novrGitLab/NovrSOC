import { Router } from 'express';
import { normalizeDomain, resolveIpAddresses, fetchSubdomains, fetchWhois, fetchCertificates, checkCtipIoc, findSuspiciousSubdomains } from '../lib/dns-intel';

const router = Router();
import { APP_BACKEND_URL as BACKEND_URL, isAppBackendConfigured, warnUnconfiguredOnce } from '../lib/legacyBackend';

function saveScanHistory(domain: string, resultJson: unknown, orgId: number | null) {
    fetch(`${BACKEND_URL}/api/scan-history`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            value: domain, type: 'domain', verdict: null, confidence: null,
            scanned_by: orgId ? 'Portal User' : 'Admin User', result_json: resultJson, org_id: orgId,
        }),
        signal: AbortSignal.timeout(5000),
    }).catch(() => {});
}

// POST /api/domains/analyse
router.post('/analyse', async (req, res) => {
    try {
        const body = req.body;
        const domain = normalizeDomain(String(body?.domain ?? ''));
        if (!domain) {
            res.status(400).json({ error: 'Domain is required' });
            return;
        }

        const [whois, subdomains, ipAddresses, certificates, domainCtip] = await Promise.all([
            fetchWhois(domain),
            fetchSubdomains(domain),
            resolveIpAddresses(domain),
            fetchCertificates(domain),
            checkCtipIoc(domain),
        ]);

        const ipChecks = await Promise.all(ipAddresses.map(async (ip) => ({ ip, ctip: await checkCtipIoc(ip) })));
        const malicious_ips = ipChecks.filter((c) => c.ctip.found).map((c) => c.ip);

        const domain_in_ctip = domainCtip.found;
        const verdict = domain_in_ctip
            ? (domainCtip.matches[0]?.threat_type ?? 'Malicious')
            : malicious_ips.length > 0
                ? 'Resolves to known-malicious infrastructure'
                : 'Not found in threat intelligence database';

        const risk_factors: string[] = [];
        let risk_score = 0;

        const recentlyRegistered = whois.days_until_expiry !== null && whois.registered
            ? (Date.now() - new Date(whois.registered).getTime()) < 30 * 24 * 60 * 60 * 1000
            : false;
        if (recentlyRegistered) {
            risk_factors.push('Domain registered recently (< 30 days)');
            risk_score += 25;
        }
        if (domain_in_ctip) {
            risk_factors.push('Domain found in CTIP blocklist');
            risk_score += 40;
        }
        const hasValidCert = certificates.some((c) => !c.expired);
        if (!hasValidCert) {
            risk_factors.push('No valid SSL certificate found');
            risk_score += 15;
        }
        if (malicious_ips.length > 0) {
            risk_factors.push(`${malicious_ips.length} resolving IP(s) flagged as malicious`);
            risk_score += 20;
        }
        const suspiciousSubdomains = findSuspiciousSubdomains(subdomains);
        if (suspiciousSubdomains.length > 0) {
            risk_factors.push(`${suspiciousSubdomains.length} suspicious-looking subdomain(s) detected`);
            risk_score += 10;
        }

        const result = {
            domain,
            whois,
            subdomains,
            ip_addresses: ipAddresses,
            threat_intel: { domain_in_ctip, verdict, malicious_ips },
            risk_score: Math.min(risk_score, 100),
            risk_factors,
        };

        const orgId: number | null = typeof body?.orgId === 'number' ? body.orgId : null;
        saveScanHistory(domain, result, orgId);

        res.json(result);
    } catch {
        res.status(500).json({ error: 'Domain analysis failed' });
    }
});

export default router;
