// Threat intelligence export. Mounted at /api/intelligence behind requireAuth — a STIX bundle
// is the org's accumulated intelligence in one file, so it is not a public endpoint.

import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';
import { buildStixBundle, type ExportableIOC } from '../services/stix';

const router = Router();

// GET /api/intelligence/stix
//   ?min_risk=0..100   omit IOCs below this composite risk score (default 0 — export everything)
//   ?limit=1..10000    cap the number of IOCs considered (default 5000)
//   ?download=true     send Content-Disposition so a browser saves it rather than rendering it
//
// Source is the `ioc_enrichments` table — every IOC that has been through the CTI platform's
// enrichment pipeline. That table starts empty and fills as analysts scan indicators, so an
// empty bundle here means nothing has been enriched yet, not that the export is broken. The
// response says so explicitly via `exported`.
router.get('/stix', async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) {
        res.status(503).json({ error: 'Supabase not configured — no IOC store to export from.' });
        return;
    }

    const minRisk = Math.max(0, Math.min(100, Number(req.query.min_risk) || 0));
    const limit = Math.max(1, Math.min(10000, Number(req.query.limit) || 5000));
    const wantsDownload = req.query.download === 'true';

    try {
        const { data, error } = await supabase
            .from('ioc_enrichments')
            .select('ioc_value, ioc_type, risk_score, tags, first_seen, last_seen, country_name, isp')
            .gte('risk_score', minRisk)
            .order('risk_score', { ascending: false })
            .limit(limit);
        if (error) throw error;

        const { bundle, exported, skipped } = buildStixBundle((data ?? []) as ExportableIOC[], {
            orgName: req.user?.org_id ? `NovrSOC (${req.user.org_id})` : 'NovrSOC',
            minRiskScore: minRisk,
        });

        // application/stix+json is the registered media type; browsers that don't know it fall
        // back to treating it as JSON, which is fine.
        res.setHeader('Content-Type', 'application/stix+json; version=2.1');
        if (wantsDownload) {
            const stamp = new Date().toISOString().slice(0, 10);
            res.setHeader('Content-Disposition', `attachment; filename="novrsoc-stix-${stamp}.json"`);
        }
        // Non-standard, but lets the UI report what happened without parsing the bundle.
        res.setHeader('X-Stix-Exported', String(exported));
        res.setHeader('X-Stix-Skipped', String(skipped));

        res.status(200).send(JSON.stringify(bundle, null, 2));
    } catch (err) {
        console.error('[intelligence/stix] export failed:', err instanceof Error ? err.message : err);
        res.status(502).json({ error: 'Failed to build STIX bundle' });
    }
});

// GET /api/intelligence/stix/summary — how many IOCs an export would contain, without
// building the bundle. Lets the download button show a count and disable itself when empty.
router.get('/stix/summary', async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) {
        res.json({ available: false, total: 0, reason: 'Supabase not configured' });
        return;
    }

    const minRisk = Math.max(0, Math.min(100, Number(req.query.min_risk) || 0));
    try {
        const { count, error } = await supabase
            .from('ioc_enrichments')
            .select('ioc_value', { count: 'exact', head: true })
            .gte('risk_score', minRisk);
        if (error) throw error;
        res.json({ available: true, total: count ?? 0, min_risk: minRisk });
    } catch (err) {
        console.error('[intelligence/stix] summary failed:', err instanceof Error ? err.message : err);
        res.json({ available: false, total: 0, reason: 'Could not read the IOC store' });
    }
});

export default router;
