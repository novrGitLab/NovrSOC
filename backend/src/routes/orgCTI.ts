import { Router } from 'express';
import {
    syncWazuhIOCs, wazuhIOCsForOrg, watcherStats,
    getManualIOCs, addManualIOC, removeManualIOC, updateManualIOC, allSharedManualIOCs, orgCount,
    type OrgIOC,
} from '../lib/orgCtiStore';
import { lookupASN } from '../services/ripeStat';

// Organisation CTI store — org-scoped threat intelligence (Wazuh-derived + analyst-added),
// cross-client threat sharing, and RIPE Stat network intelligence. In-memory for now (see
// lib/orgCtiStore.ts's header comment) — swap for Supabase once a schema exists.
//
// MUST FIX BEFORE FIRST CLIENT — every request here is treated as the single 'cybernovr' org.
// This is NOT just "read org_id off the token" — investigated while wiring real tenancy in:
//   1. requireAuth (middleware/auth.ts) is built but deliberately not mounted anywhere yet
//      (see index.ts's comment) — the admin dev-bypass token now carries org_id (routes/auth.ts),
//      but nothing currently verifies/reads it on incoming requests.
//   2. The client portal already issues its OWN org-scoped JWT (lib/portal-auth.ts's
//      PortalUser has a real orgId/orgName) — but that token is minted and verified by a
//      SEPARATE external backend (APP_API_BASE_URL), not this one. requireAuth verifies
//      against JWT_SECRET/DEV_TOKEN_SECRET, which will never match a portal-issued token's
//      signature — mounting requireAuth here as-is would 401 every legitimate client-portal
//      request while admin dev-bypass requests kept working, which is a worse and much
//      harder-to-notice bug than the current single-tenant placeholder.
//   3. So: this route needs to accept EITHER token shape and resolve org_id from whichever
//      is present — verify the admin token locally (requireAuth's existing logic), but for a
//      portal token, either introspect it against the external backend (see routes/portal.ts
//      for the existing proxy pattern) or decode-without-verify and treat the external
//      backend as already having done the verification at issuance. Once that's decided and
//      built, replace the `|| 'cybernovr'` fallback below with a real 401 on missing org_id.
const router = Router();

function getOrgId(req: { user?: { org_id?: string } }): string {
    return req.user?.org_id || 'cybernovr';
}

// GET /api/org-cti/iocs — org's own IOCs (Wazuh-derived + analyst-added)
router.get('/iocs', async (req, res) => {
    const orgId = getOrgId(req as never);
    const { type, verdict, source, limit = '100' } = req.query;
    const parsedLimit = parseInt(String(limit), 10) || 100;

    try {
        await syncWazuhIOCs(100);
    } catch (err) {
        console.error('[org-cti] on-demand Wazuh sync failed:', err instanceof Error ? err.message : err);
    }

    const wazuhIOCs = wazuhIOCsForOrg(orgId);
    const manualIOCs = getManualIOCs(orgId);
    let combined = [...wazuhIOCs, ...manualIOCs];

    if (type) combined = combined.filter((i) => i.type === type);
    if (verdict) combined = combined.filter((i) => i.verdict === verdict);
    if (source) combined = combined.filter((i) => i.source === source);

    res.json({
        iocs: combined.slice(0, parsedLimit),
        total: combined.length,
        summary: {
            total: combined.length,
            malicious: combined.filter((i) => i.verdict === 'malicious').length,
            suspicious: combined.filter((i) => i.verdict === 'suspicious').length,
            by_type: {
                ip: combined.filter((i) => i.type === 'ip').length,
                domain: combined.filter((i) => i.type === 'domain').length,
                hash: combined.filter((i) => i.type === 'hash').length,
                url: combined.filter((i) => i.type === 'url').length,
            },
            wazuh_sourced: wazuhIOCs.length,
            analyst_added: manualIOCs.length,
        },
    });
});

interface AddIOCBody {
    value?: string;
    type?: OrgIOC['type'];
    verdict?: OrgIOC['verdict'];
    tags?: string[];
    notes?: string;
    shared?: boolean;
}

// POST /api/org-cti/iocs — manually add an IOC
router.post('/iocs', (req, res) => {
    const orgId = getOrgId(req as never);
    const { value, type, verdict, tags, notes, shared }: AddIOCBody = req.body ?? {};

    if (!value || !type) {
        res.status(400).json({ error: 'value and type required' });
        return;
    }

    const ioc: OrgIOC = {
        id: `manual-${Date.now()}`,
        org_id: orgId,
        value,
        type,
        source: 'analyst',
        first_seen: new Date().toISOString(),
        last_seen: new Date().toISOString(),
        seen_count: 1,
        risk_score: verdict === 'malicious' ? 90 : verdict === 'suspicious' ? 60 : 10,
        verdict: verdict || 'unknown',
        tags: tags || [],
        notes: notes || '',
        shared: shared || false,
        mitre_tactic: null,
        alert_ids: [],
        added_by: (req as { user?: { email?: string } }).user?.email || 'analyst',
    };

    addManualIOC(orgId, ioc);
    res.json({ success: true, ioc });
});

// PATCH /api/org-cti/iocs/:id — update notes/verdict/shared on a manually-added IOC.
// (Wazuh-derived IOCs are recomputed from the indexer each sync and aren't editable here.)
router.patch('/iocs/:id', (req, res) => {
    const orgId = getOrgId(req as never);
    const patch: Partial<OrgIOC> = {};
    const { verdict, notes, shared, tags } = req.body ?? {};
    if (verdict !== undefined) patch.verdict = verdict;
    if (notes !== undefined) patch.notes = notes;
    if (shared !== undefined) patch.shared = shared;
    if (tags !== undefined) patch.tags = tags;

    const updated = updateManualIOC(orgId, req.params.id, patch);
    if (!updated) {
        res.status(404).json({ error: 'IOC not found (Wazuh-sourced IOCs are read-only)' });
        return;
    }
    res.json({ success: true, ioc: updated });
});

// DELETE /api/org-cti/iocs/:id — remove a manually-added IOC
router.delete('/iocs/:id', (req, res) => {
    const orgId = getOrgId(req as never);
    const removed = removeManualIOC(orgId, req.params.id);
    if (!removed) {
        res.status(404).json({ error: 'IOC not found (Wazuh-sourced IOCs are read-only)' });
        return;
    }
    res.json({ success: true });
});

// GET /api/org-cti/shared — cross-client shared IOCs (anonymised)
router.get('/shared', (_req, res) => {
    const all = allSharedManualIOCs();
    // How many distinct organisations shared each value — counted, not assumed.
    const orgsByValue = new Map<string, Set<string>>();
    for (const i of all) orgsByValue.set(i.value, (orgsByValue.get(i.value) ?? new Set()).add(i.org_id));
    const realShared = all.map((i) => ({
        ...i,
        shared_by_clients: orgsByValue.get(i.value)?.size ?? 1,
        org_id: '[anonymised]',
        added_by: 'NovrSOC Client',
        notes: '', // strip internal notes before sharing
    }));

    res.json({
        shared_iocs: realShared,
        total: realShared.length,
        participating_clients: orgCount(),
    });
});

// GET /api/org-cti/stats — org CTI statistics
router.get('/stats', (req, res) => {
    const orgId = getOrgId(req as never);
    const wazuhIOCs = wazuhIOCsForOrg(orgId);
    const manualIOCs = getManualIOCs(orgId);
    const combined = [...wazuhIOCs, ...manualIOCs];

    const tagCounts = new Map<string, number>();
    for (const ioc of combined) {
        for (const tag of ioc.tags) tagCounts.set(tag, (tagCounts.get(tag) ?? 0) + 1);
    }
    const topTags = [...tagCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([tag, count]) => ({ tag, count }));

    res.json({
        total_iocs: combined.length,
        malicious: combined.filter((i) => i.verdict === 'malicious').length,
        suspicious: combined.filter((i) => i.verdict === 'suspicious').length,
        shared_count: combined.filter((i) => i.shared).length,
        wazuh_auto: wazuhIOCs.length,
        analyst_added: manualIOCs.filter((i) => i.source === 'analyst').length,
        top_tags: topTags,
        watcher: watcherStats(),
    });
});

// GET /api/org-cti/network/asn/:asn — RIPE Stat ASN lookup (Network Intelligence tab)
router.get('/network/asn/:asn', async (req, res) => {
    try {
        const info = await lookupASN(req.params.asn);
        res.json(info);
    } catch (err) {
        res.status(502).json({ error: err instanceof Error ? err.message : 'ASN lookup failed' });
    }
});

export default router;
