import { Router } from 'express';
import { z } from 'zod';
import { validate } from '../middleware/validate';
import { enrichIOC, type IOCType } from '../services/iocEnrichment';
import { getCVEById, getRecentCVEs, getCVSSScore, getCVEDescription } from '../services/nvd';
import { isInKEV, getKEVCatalog } from '../services/cisa';
import { circlGetPulses } from '../services/circl';
import { analyzeSSL } from '../services/sslLabs';
import { getSupabase } from '../services/geoEnrichment';
import { search } from '../lib/wazuh-indexer';

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

// GET /api/threat/advisory/affected-agents
//
// Which of this estate's own agents carry each CVE, so the CVE feed can mark an advisory as
// "2 agents affected" rather than leaving an analyst to guess whether a published CVE is
// actually their problem.
//
// Derived from Wazuh's own vulnerability index, NOT by string-matching NVD's affected-product
// names against a package inventory. Wazuh has already done that matching properly (CPE-based,
// per agent); re-deriving it here from product name text would produce both false positives
// ("openssl" matching "openssl-legacy") and false negatives on any vendor naming difference.
//
// Returns a { [cve]: agentNames[] } map — the CVE page holds a few hundred advisories and does
// the join client-side, which is one request rather than one per CVE.
router.get('/advisory/affected-agents', async (_req, res) => {
    interface Bucket { key: string; agents?: { buckets?: { key: string }[] } }
    interface AggSearch { aggregations?: { by_cve?: { buckets?: Bucket[] } } }

    try {
        const result = await search<AggSearch>('wazuh-states-vulnerabilities-*', {
            size: 0,
            aggs: {
                by_cve: {
                    terms: { field: 'vulnerability.id', size: 1000 },
                    aggs: { agents: { terms: { field: 'agent.name', size: 50 } } },
                },
            },
        });

        const buckets = result?.aggregations?.by_cve?.buckets ?? [];
        const map: Record<string, string[]> = {};
        for (const b of buckets) {
            if (!b.key) continue;
            map[b.key] = (b.agents?.buckets ?? []).map((a) => a.key).filter(Boolean);
        }

        res.json({ affected: map, cve_count: Object.keys(map).length });
    } catch (err) {
        console.error('[threat/advisory/affected-agents] failed:', err instanceof Error ? err.message : err);
        // 200 with an empty map: the CVE feed must still render its advisories when the
        // vulnerability index is unreachable, just without the affected-agent badges.
        res.json({ affected: {}, cve_count: 0, error: 'Vulnerability index unreachable' });
    }
});

export default router;
