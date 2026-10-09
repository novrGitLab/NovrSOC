import { Router } from 'express';
import { urlhausLookupURL, urlhausLookupHost, type URLHausResult, type URLHausHostResult } from '../services/urlhaus';
import { threatfoxSearchIOC, type ThreatFoxIOC } from '../services/threatfox';
import { getSupabase } from '../services/geoEnrichment';
import { searchURL, searchDomain, isConfigured as urlscanConfigured, type URLScanSearchResult } from '../services/urlscanio';
import { checkURLSafety } from '../services/google';
import type { AuthRequest } from '../middleware/auth';
import { verdictFromScore } from '../lib/severity';

const router = Router();

// Placeholder single-tenant org id — this route is one of the ones shared with the client
// portal (UrlScanSuite.tsx is rendered by both /admin and /client), so it isn't behind
// requireAuth yet (see index.ts's block comment on why). req.user is therefore always
// undefined here today and this fallback is what actually runs; the `req.user?.org_id ||`
// below is forward-prep for once shared-route auth exists, not a live behavior change.
const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001';

interface UrlScanResult {
    url: string;
    scanned_at: string;
    sources: {
        urlhaus?: { status: string; threat: string; tags: string[]; reference: string };
        urlhaus_host?: { url_count: number; urls_sample: URLHausHostResult['urls'] };
        threatfox?: { malware: string; confidence: number; threat_type: string };
        safe_browsing?: { threat_type: string; platform: string };
        urlscan?: { total_scans: number; latest_malicious: boolean; latest_score: number; latest_scan_time: string | null; screenshot: string | null };
    };
    risk_score: number;
    verdict: 'clean' | 'suspicious' | 'malicious';
    tags: string[];
    redirect_chain: string[];
    threat_type: string | null;
    scan_duration_ms: number;
}

// POST /api/urlscan/submit
// Body: { url: "https://suspicious.com/path" }
router.post('/submit', async (req: AuthRequest, res) => {
    const { url } = req.body ?? {};
    if (!url || typeof url !== 'string') {
        res.status(400).json({ error: 'url required' });
        return;
    }

    let host: string;
    try {
        host = new URL(url).hostname;
    } catch {
        res.status(400).json({ error: 'Invalid URL format' });
        return;
    }

    const startTime = Date.now();
    const results: UrlScanResult = {
        url,
        scanned_at: new Date().toISOString(),
        sources: {},
        risk_score: 0,
        verdict: 'clean',
        tags: [],
        redirect_chain: [url],
        threat_type: null,
        scan_duration_ms: 0,
    };

    try {
        const [urlhausURL, urlhausHost, threatfox, safeBrowsing, urlscanHistory] = await Promise.allSettled([
            urlhausLookupURL(url),
            urlhausLookupHost(host),
            threatfoxSearchIOC(url),
            checkURLSafety(url),
            searchURL(url),
        ]);

        const uhUrl: URLHausResult | null = urlhausURL.status === 'fulfilled' ? urlhausURL.value : null;
        if (uhUrl) {
            results.sources.urlhaus = { status: uhUrl.url_status, threat: uhUrl.threat, tags: uhUrl.tags || [], reference: uhUrl.urlhaus_reference };
            results.risk_score += 40;
            results.threat_type = uhUrl.threat;
            results.tags.push(...(uhUrl.tags || []));
        }

        const uhHost: URLHausHostResult | null = urlhausHost.status === 'fulfilled' ? urlhausHost.value : null;
        if (uhHost && uhHost.url_count > 0) {
            results.sources.urlhaus_host = { url_count: uhHost.url_count, urls_sample: uhHost.urls?.slice(0, 3) ?? [] };
            results.risk_score += Math.min(20, uhHost.url_count * 2);
        }

        const tf: ThreatFoxIOC[] = threatfox.status === 'fulfilled' ? threatfox.value : [];
        if (tf.length > 0) {
            results.sources.threatfox = { malware: tf[0].malware_printable, confidence: tf[0].confidence_level, threat_type: tf[0].threat_type };
            results.risk_score += Math.floor((tf[0].confidence_level || 0) * 0.25);
            results.tags.push(tf[0].malware_printable);
        }

        const safeBrowsingResult = safeBrowsing.status === 'fulfilled' ? safeBrowsing.value : null;
        if (safeBrowsingResult && !safeBrowsingResult.is_safe) {
            results.sources.safe_browsing = { threat_type: safeBrowsingResult.threat_type ?? 'unknown', platform: safeBrowsingResult.platform ?? 'unknown' };
            results.risk_score += 35;
            results.tags.push((safeBrowsingResult.threat_type ?? 'unsafe').toLowerCase());
        }

        const urlscan: URLScanSearchResult | null = urlscanHistory.status === 'fulfilled' ? urlscanHistory.value : null;
        if (urlscan && urlscan.total > 0) {
            const latestMalicious = urlscan.results.some((r) => r.malicious);
            results.sources.urlscan = {
                total_scans: urlscan.total,
                latest_malicious: latestMalicious,
                latest_score: urlscan.results[0]?.score ?? 0,
                latest_scan_time: urlscan.results[0]?.time ?? null,
                screenshot: urlscan.results[0]?.screenshot ?? null,
            };
            if (latestMalicious) {
                results.risk_score += 20;
                results.tags.push('urlscan-flagged');
            }
        }

        results.risk_score = Math.min(100, results.risk_score);
        results.verdict = verdictFromScore(results.risk_score);
        results.scan_duration_ms = Date.now() - startTime;

        try {
            const supabase = getSupabase();
            if (supabase) {
                await supabase.from('url_scans').insert({
                    org_id: req.user?.org_id || DEFAULT_ORG_ID,
                    submitted_url: url,
                    final_url: url,
                    risk_score: results.risk_score,
                    verdict: results.verdict,
                    redirect_chain: results.redirect_chain,
                    gsb_verdict: safeBrowsingResult && !safeBrowsingResult.is_safe ? (safeBrowsingResult.threat_type ?? 'unsafe') : null,
                    urlscan_verdict: uhUrl ? uhUrl.url_status : null,
                    scan_duration_ms: results.scan_duration_ms,
                });
            }
        } catch {
            // non-fatal — caching failure should not break the response
        }

        res.json(results);
    } catch (err) {
        console.error('[URLScan] Error:', err);
        res.status(500).json({ error: 'Scan failed' });
    }
});

// GET /api/urlscan/domain/:domain — search URLScan.io history for a domain
router.get('/domain/:domain', async (req, res) => {
    if (!urlscanConfigured()) {
        res.json({ configured: false, results: [] });
        return;
    }
    try {
        const result = await searchDomain(req.params.domain);
        res.json(result ?? { total: 0, results: [] });
    } catch {
        res.status(500).json({ error: 'URLScan domain search failed' });
    }
});

// GET /api/urlscan/history?limit=20
router.get('/history', async (req, res) => {
    const limit = Math.min(Number(req.query.limit) || 20, 100);
    try {
        const supabase = getSupabase();
        if (!supabase) {
            res.json({ scans: [] });
            return;
        }

        const { data } = await supabase.from('url_scans').select('*').order('scanned_at', { ascending: false }).limit(limit);
        res.json({ scans: data || [] });
    } catch {
        res.status(500).json({ error: 'History fetch failed' });
    }
});

export default router;
