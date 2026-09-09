import { Router } from 'express';
import { z } from 'zod';
import { validate } from '../middleware/validate';
import { enrichIOC, type IOCType } from '../services/iocEnrichment';
import { getCVEById, getRecentCVEs, getCVSSScore, getCVEDescription } from '../services/nvd';
import { isInKEV, getKEVCatalog } from '../services/cisa';
import { circlGetPulses } from '../services/circl';
import { analyzeSSL } from '../services/sslLabs';
import { getSupabase } from '../services/geoEnrichment';

const router = Router();

const IOCLookupSchema = z.object({
    value: z.string().min(1).max(500).trim(),
    type: z.enum(['ip', 'domain', 'hash', 'url']),
});

// ── IOC Enrichment ────────────────────────────────────────────────

// POST /api/threat/ioc/lookup
// Body: { value: "1.2.3.4", type: "ip" }
router.post('/ioc/lookup', validate(IOCLookupSchema), async (req, res) => {
    const { value, type }: { value: string; type: IOCType } = req.body;

    try {
        const result = await enrichIOC(value, type);
        res.json(result);
    } catch {
        res.status(500).json({ error: 'Enrichment failed' });
    }
});

// GET /api/threat/feeds/circl — CIRCL OSINT feed, replacing the old /feeds/otx route.
// /feeds/otx is kept as an alias so any bookmarked link or cached frontend bundle still
// resolves instead of 404ing; both serve CIRCL data now.
async function servePulses(req: import('express').Request, res: import('express').Response) {
    try {
        const limit = Number(req.query.limit) || 20;
        const pulses = await circlGetPulses(limit);
        res.json({ pulses, count: pulses.length, source: 'circl' });
    } catch {
        res.status(500).json({ error: 'CIRCL feed fetch failed' });
    }
}

router.get('/feeds/circl', servePulses);
router.get('/feeds/otx', servePulses);

// ── Threat Advisory ───────────────────────────────────────────────

// GET /api/threat/advisory/recent?days=7&severity=CRITICAL
router.get('/advisory/recent', async (req, res) => {
    try {
        const days = Number(req.query.days) || 7;
        const severity = typeof req.query.severity === 'string' ? req.query.severity : undefined;
        const cves = await getRecentCVEs(days, severity);

        const enriched = await Promise.all(cves.slice(0, 50).map(async (cve) => {
            const cvss = getCVSSScore(cve);
            const kev = await isInKEV(cve.id);
            return {
                id: cve.id,
                description: getCVEDescription(cve),
                cvss_score: cvss.score,
                severity: cvss.severity,
                published: cve.published,
                is_kev: !!kev,
                kev_due: kev?.dueDate ?? null,
            };
        }));

        res.json({ cves: enriched, count: enriched.length });
    } catch {
        res.status(500).json({ error: 'NVD fetch failed' });
    }
});

// GET /api/threat/advisory/cve/:id
router.get('/advisory/cve/:id', async (req, res) => {
    try {
        const cve = await getCVEById(req.params.id);
        if (!cve) {
            res.status(404).json({ error: 'CVE not found' });
            return;
        }

        const cvss = getCVSSScore(cve);
        const kev = await isInKEV(cve.id);

        res.json({
            id: cve.id,
            description: getCVEDescription(cve),
            cvss_score: cvss.score,
            severity: cvss.severity,
            vector: cvss.version,
            published: cve.published,
            modified: cve.lastModified,
            references: cve.references?.slice(0, 5),
            is_kev: !!kev,
            kev_entry: kev || null,
        });
    } catch {
        res.status(500).json({ error: 'CVE lookup failed' });
    }
});

// GET /api/threat/advisory/kev
router.get('/advisory/kev', async (_req, res) => {
    try {
        const catalog = await getKEVCatalog();
        if (!catalog) {
            res.status(503).json({ error: 'KEV catalog unavailable' });
            return;
        }
        res.json({
            version: catalog.catalogVersion,
            released: catalog.dateReleased,
            count: catalog.count,
            // Return most recently added 50
            recent: catalog.vulnerabilities.slice(-50).reverse(),
        });
    } catch {
        res.status(500).json({ error: 'KEV fetch failed' });
    }
});

// GET /api/threat/advisory/assets
// Returns vulnerability matches grouped by host from Supabase. Nothing populates
// host_packages/vulnerability_matches yet (see novrsoc_supabase_schema.sql) — this returns an
// empty list until a Wazuh syscollector sync exists, which is expected, not an error.
router.get('/advisory/assets', async (_req, res) => {
    try {
        const supabase = getSupabase();
        if (!supabase) {
            res.json({ assets: [] });
            return;
        }

        const { data, error } = await supabase
            .from('vulnerability_matches')
            .select('*, host_packages ( agent_id, agent_name, package_name, version, os )')
            .order('priority_score', { ascending: false })
            .limit(100);

        if (error) throw error;
        res.json({ assets: data || [] });
    } catch {
        res.status(500).json({ error: 'Asset vuln fetch failed' });
    }
});

// ── Website Scanning ──────────────────────────────────────────────

// POST /api/threat/webscan/ssl
// Body: { domain: "cybernovr.com" }
router.post('/webscan/ssl', async (req, res) => {
    const { domain } = req.body ?? {};
    if (!domain) {
        res.status(400).json({ error: 'domain required' });
        return;
    }

    try {
        const result = await analyzeSSL(domain);
        if (!result) {
            res.status(503).json({ error: 'SSL Labs unavailable' });
            return;
        }
        res.json(result);
    } catch {
        res.status(500).json({ error: 'SSL analysis failed' });
    }
});

export default router;
