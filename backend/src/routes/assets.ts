import { Router } from 'express';
import { requireScope } from '../lib/orgScope';

// Digital Assets — the request organisation's enrolled Wazuh agents (lib/orgScope.ts: agents
// whose groups map to it), from the Manager REST API or the indexer's wazuh-monitoring snapshot
// when the API can't be reached. No mock data — an asset inventory pretending to have hosts it
// doesn't is worse than an honest empty state, and an inventory it can't read answers 503 with
// the reason. Mounted behind requirePermission('alerts:read') (index.ts).
const router = Router();

// GET /api/assets
router.get('/', async (req, res) => {
    const scope = await requireScope(req, res);
    if (!scope) return;
    const agents = scope.agents.map((a) => ({
        id: a.id, name: a.name, ip: a.ip, os: a.os, status: a.status,
        last_keepalive: a.lastKeepAlive, version: a.version, group: a.group,
    }));
    res.json({ agents, count: agents.length, source: scope.agentSource });
});

export default router;
