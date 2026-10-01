// CNII Watch — asset inventory, sector alerts, vulnerabilities and the IP scanner.
//
// None of the data sources behind these routes exist yet: there is no cnii_assets table, no
// alert-to-asset correlation, no vulnerability store, and the SpiderFoot + OpenCTI scan pipeline
// is not built. Until each one is, its route answers 503 { error: 'not_connected' } so the UI
// says the feed is not connected instead of showing invented assets, alerts or CVEs, and so a
// write never reports success without storing anything.
//
// Response shapes once connected (types live in frontend/src/lib/cnii-types.ts):
//   GET  /assets            → CniiAsset[]   (optional ?sector=<id>, ?ip=<ip>)
//   POST /assets            → CniiAsset     (body: CniiAsset minus id)
//   GET  /alerts            → CniiAlert[]   (optional ?sector=<id>, ?ip=<ip>)
//   GET  /vulns             → CniiVuln[]    (optional ?sector=<id>, ?ip=<ip>)
//   POST /scan  { ip }      → ScanResult
//
// Mounted behind requireAuth in index.ts. Reads are open to staff roles; writes and scans are
// limited to the roles that run investigations.
import { Router, Response } from 'express';
import { isIP } from 'net';
import { AuthRequest, requireRole } from '../middleware/auth';

const router = Router();

const canRead = requireRole('super_admin', 'soc_manager', 'analyst', 'executive');
const canWrite = requireRole('super_admin', 'soc_manager', 'analyst');

const SECTOR_IDS = new Set([
    'power', 'water', 'ict', 'finance', 'health', 'publicadmin', 'education',
    'defence', 'transport', 'food', 'safety', 'industrial', 'mines',
]);

function notConnected(res: Response, feed: string, detail: string) {
    return res.status(503).json({ error: 'not_connected', feed, message: detail });
}

// Rejects malformed filters with 400 so callers find out now, not after the feed is wired up.
function badFilter(req: AuthRequest, res: Response): boolean {
    const { sector, ip } = req.query;
    if (sector !== undefined && (typeof sector !== 'string' || !SECTOR_IDS.has(sector))) {
        res.status(400).json({ error: 'Unknown sector' });
        return true;
    }
    if (ip !== undefined && (typeof ip !== 'string' || !isIP(ip))) {
        res.status(400).json({ error: 'Invalid IP address' });
        return true;
    }
    return false;
}

router.get('/assets', canRead, (req: AuthRequest, res) => {
    if (badFilter(req, res)) return;
    notConnected(res, 'assets', 'The CNII asset inventory is not built yet (no cnii_assets table).');
});

router.post('/assets', canWrite, (req: AuthRequest, res) => {
    const body = req.body ?? {};
    if (typeof body.ip !== 'string' || !isIP(body.ip)) return res.status(400).json({ error: 'Invalid IP address' });
    if (typeof body.sectorId !== 'string' || !SECTOR_IDS.has(body.sectorId)) return res.status(400).json({ error: 'Unknown sector' });
    notConnected(res, 'assets', 'The CNII asset inventory is not built yet, so the asset was not saved.');
});

router.get('/alerts', canRead, (req: AuthRequest, res) => {
    if (badFilter(req, res)) return;
    notConnected(res, 'alerts', 'Alerts are not correlated to CNII assets yet.');
});

router.get('/vulns', canRead, (req: AuthRequest, res) => {
    if (badFilter(req, res)) return;
    notConnected(res, 'vulns', 'The CNII vulnerability store is not built yet.');
});

router.post('/scan', canWrite, (req: AuthRequest, res) => {
    const ip = typeof req.body?.ip === 'string' ? req.body.ip.trim() : '';
    if (!isIP(ip)) return res.status(400).json({ error: 'Invalid IP address' });
    notConnected(res, 'scan', 'The SpiderFoot + OpenCTI scanner is not connected yet.');
});

export default router;
