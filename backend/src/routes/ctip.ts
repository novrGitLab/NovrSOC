import { Router } from 'express';

const router = Router();
import { CTIP_URL, isCTIPConfigured, warnUnconfiguredOnce } from '../lib/legacyBackend';
import { APP_BACKEND_URL as BACKEND_URL, isAppBackendConfigured } from '../lib/legacyBackend';

const COUNTRY_MAP: Record<string, { name: string; flag: string }> = {
    CN: { name: 'China', flag: '🇨🇳' },
    RU: { name: 'Russia', flag: '🇷🇺' },
    US: { name: 'USA', flag: '🇺🇸' },
    BR: { name: 'Brazil', flag: '🇧🇷' },
    IN: { name: 'India', flag: '🇮🇳' },
    DE: { name: 'Germany', flag: '🇩🇪' },
    NL: { name: 'Netherlands', flag: '🇳🇱' },
    FR: { name: 'France', flag: '🇫🇷' },
    GB: { name: 'UK', flag: '🇬🇧' },
    UA: { name: 'Ukraine', flag: '🇺🇦' },
};

interface IOCItem {
    country?: string | null;
    malware_family?: string | null;
    threat_type?: string | null;
    last_seen?: string | null;
}

// GET /api/ctip/countries
router.get('/countries', async (_req, res) => {
    try {
        // The CTIP API caps `limit` at 500 (a literal 1000 request 422s), and the
        // unfiltered/most-recent IOC stream is ~100% null-country (dominated by a
        // URL-based malware feed with no geolocation). Filtering to type=ip yields
        // real, populated country data instead.
        const response = await fetch(`${CTIP_URL}/api/ctip/iocs?type=ip&limit=500`, { cache: 'no-store', signal: AbortSignal.timeout(5000) });
        const data = await response.json();
        const items: IOCItem[] = Array.isArray(data?.items) ? data.items : [];

        const counts: Record<string, number> = {};
        for (const item of items) {
            if (item.country) counts[item.country] = (counts[item.country] ?? 0) + 1;
        }

        const top5 = Object.entries(counts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([code, count]) => {
                const info = COUNTRY_MAP[code] ?? { name: code, flag: '🌐' };
                return { country: code, name: info.name, count, flag: info.flag };
            });

        res.json(top5);
    } catch {
        res.status(502).json([]);
    }
});

// GET /api/ctip/campaigns
router.get('/campaigns', async (_req, res) => {
    try {
        const response = await fetch(`${CTIP_URL}/api/ctip/iocs?limit=500`, { cache: 'no-store', signal: AbortSignal.timeout(5000) });
        const data = await response.json();
        const items: IOCItem[] = Array.isArray(data?.items) ? data.items : [];

        const groups: Record<string, IOCItem[]> = {};
        for (const item of items) {
            if (!item.malware_family) continue;
            (groups[item.malware_family] ??= []).push(item);
        }

        const campaigns = Object.entries(groups)
            .filter(([, group]) => group.length > 5)
            .map(([name, group]) => {
                const threatTypeCounts: Record<string, number> = {};
                for (const g of group) {
                    if (g.threat_type) threatTypeCounts[g.threat_type] = (threatTypeCounts[g.threat_type] ?? 0) + 1;
                }
                const threat_type = Object.entries(threatTypeCounts).sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'Unknown';
                const seenDates = group.map((g) => g.last_seen).filter((d): d is string => Boolean(d)).sort();

                return {
                    name,
                    ioc_count: group.length,
                    threat_type,
                    first_seen: seenDates[0] ?? null,
                    last_seen: seenDates[seenDates.length - 1] ?? null,
                    severity: group.length > 50 ? 'Critical' : group.length > 20 ? 'High' : 'Medium',
                };
            })
            .sort((a, b) => b.ioc_count - a.ioc_count)
            .slice(0, 10);

        res.json(campaigns);
    } catch {
        res.status(502).json([]);
    }
});

// GET /api/ctip/actors
router.get('/actors', async (_req, res) => {
    try {
        const response = await fetch(`${CTIP_URL}/api/ctip/threat-actors`, { cache: 'no-store', signal: AbortSignal.timeout(5000) });
        const data = await response.json();
        res.json(Array.isArray(data) ? data : []);
    } catch {
        res.status(502).json([]);
    }
});

// GET /api/ctip/feed-status
router.get('/feed-status', async (_req, res) => {
    try {
        const response = await fetch(`${BACKEND_URL}/api/ctip/feed-status`, { cache: 'no-store', signal: AbortSignal.timeout(5000) });
        const data = await response.json();
        res.status(response.status).json(data);
    } catch {
        res.status(502).json({ feeds: [] });
    }
});

export default router;
