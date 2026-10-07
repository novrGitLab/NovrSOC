import { Router } from 'express';
import { DNS_RECORD_TYPES, DnsRecordType, normalizeDomain, resolveRecords, fetchCertificates } from '../lib/dns-intel';

const router = Router();
// POST /api/dns/lookup
router.post('/lookup', async (req, res) => {
    try {
        const body = req.body;
        const domain = normalizeDomain(String(body?.domain ?? ''));
        if (!domain) {
            res.status(400).json({ error: 'Domain is required' });
            return;
        }

        const requested: string[] = Array.isArray(body?.record_types) ? body.record_types : [...DNS_RECORD_TYPES];
        const types = DNS_RECORD_TYPES.filter((t) => requested.includes(t)) as DnsRecordType[];
        const typesToQuery = types.length > 0 ? types : [...DNS_RECORD_TYPES];

        const [records, certificates] = await Promise.all([
            resolveRecords(domain, typesToQuery),
            fetchCertificates(domain),
        ]);

        const now = Date.now();
        const thirtyDays = 30 * 24 * 60 * 60 * 1000;
        const expired_certs = certificates.filter((c) => c.expired).length;
        const expiring_soon = certificates.filter((c) => !c.expired && new Date(c.not_after).getTime() - now <= thirtyDays).length;

        const total_records =
            records.A.length + records.AAAA.length + records.MX.length + records.TXT.length +
            records.NS.length + records.CNAME.length + records.SOA.length;

        const result = {
            domain,
            records,
            certificates,
            summary: { total_records, total_certs: certificates.length, expired_certs, expiring_soon },
        };

        res.json(result);
    } catch {
        res.status(500).json({ error: 'DNS lookup failed' });
    }
});

export default router;
