// Unauthenticated endpoints for the marketing site. Mounted at /api/public.
//
// This is the only route in the app that runs the full enrichment pipeline for an anonymous
// caller, so it's deliberately tight:
//   * 10 scans per IP per hour, via express-rate-limit (already a dependency, and it honours the
//     `trust proxy` setting so the limit keys on the real client IP rather than Railway's edge).
//     A hand-rolled Map would never evict its entries — an unbounded, publicly-reachable object
//     keyed by client IP is a memory leak with a stranger holding the pen.
//   * the target must look like an IP, domain or http(s) URL before anything is dispatched, so
//     the paid upstreams (VirusTotal, AbuseIPDB) can't be made to burn quota on junk.
//   * the response is a summary only. Per-source detail stays behind sign-in.

import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { enrichIOC, type IOCType, type EnrichedIOC } from '../services/iocEnrichment';

const router = Router();

const scanLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: true, message: 'Rate limit exceeded — 10 free scans per hour. Sign in for unlimited scans.' },
});

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
// Hostname with at least one dot and a 2+ char TLD. Deliberately conservative.
const DOMAIN_RE = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,}$/;

function classifyTarget(raw: string): { type: IOCType; value: string } | null {
    const value = raw.trim();
    if (!value || value.length > 2048) return null;

    if (/^https?:\/\//i.test(value)) {
        try {
            new URL(value);
            return { type: 'url', value };
        } catch {
            return null;
        }
    }
    if (IPV4_RE.test(value)) {
        // Reject anything with an octet out of range — enriching "999.1.1.1" just wastes calls.
        if (value.split('.').some((o) => Number(o) > 255)) return null;
        return { type: 'ip', value };
    }
    if (DOMAIN_RE.test(value)) return { type: 'domain', value };
    return null;
}

// How many sources actually came back with an answer, and how many of those consider the target
// a threat. Computed per-source against each one's real shape — a generic
// `s.malicious || s.detected` check would silently report ~0 detections for every scan, because
// only VirusTotal has a field by either of those names.
function summarise(result: EnrichedIOC): { checked: number; detections: number } {
    const s = result.sources;
    const answered = Object.values(s).filter((v) => v !== null).length;

    let detections = 0;
    if (s.abuseipdb && s.abuseipdb.confidence >= 25) detections++;
    if (s.urlhaus) detections++;                                    // presence == listed
    if (s.threatfox) detections++;                                  // presence == known IOC
    if (s.virustotal && s.virustotal.malicious > 0) detections++;
    if (s.greynoise?.classification === 'malicious') detections++;
    if (s.leakix?.status === 'ok' && s.leakix.leak_count > 0) detections++;
    if (s.misp) detections++;                                       // curated in-house hit

    return { checked: answered, detections };
}

// POST /api/public/scan { target }
router.post('/scan', scanLimiter, async (req, res) => {
    const target = typeof req.body?.target === 'string' ? req.body.target : '';
    const classified = classifyTarget(target);
    if (!classified) {
        res.status(400).json({ error: true, message: 'Enter a valid domain, IPv4 address, or http(s) URL.' });
        return;
    }

    try {
        const result = await enrichIOC(classified.value, classified.type);
        const { checked, detections } = summarise(result);

        res.json({
            target: classified.value,
            ioc_type: classified.type,
            verdict: result.verdict,
            risk_score: result.risk_score,
            sources_checked: checked,
            detections,
            summary: (() => {
                const src = `${checked} source${checked === 1 ? '' : 's'}`;
                if (result.verdict === 'malicious') return `${classified.value} was flagged by ${detections} of ${src} that responded.`;
                if (result.verdict === 'suspicious') return `${classified.value} shows suspicious indicators across ${src}. Further investigation recommended.`;
                return `No threats detected for ${classified.value} across ${src} that responded.`;
            })(),
            // Per-source detail intentionally omitted — that's the signed-in product.
        });
    } catch (err) {
        console.error('[public/scan] failed:', err instanceof Error ? err.message : err);
        res.status(500).json({ error: true, message: 'Scan failed. Please try again.' });
    }
});

export default router;
