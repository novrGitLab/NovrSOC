// /api/admin/wazuh-group-map — which organisation owns each Wazuh agent group (phase R2). The
// alert ingest endpoint resolves every alert's org through this map and nothing else, so it is
// super_admin only (mounted behind requireAuth + requireRole('super_admin') in index.ts).
//
//   GET  -> { mappings: [{ wazuh_group, org_id, created_at }] }
//   PUT  { mappings: [{ wazuh_group, org_id }] }  upserts each; org_id: null removes that group.
//        org_id must be an existing organisations.slug. Every change is audited.

import { Router } from 'express';
import { z } from 'zod';
import type { AuthRequest } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';
import { dbErrorMessage } from '../services/cases';
import { logAudit } from '../lib/audit';

const router = Router();

// Wazuh group names: letters, digits, '.', '_' and '-'.
const GROUP_RE = /^[A-Za-z0-9._-]{1,128}$/;
const PutBody = z.object({
    mappings: z.array(z.object({
        wazuh_group: z.string().regex(GROUP_RE),
        org_id: z.string().min(1).max(128).nullable(),
    })).min(1).max(500),
});

router.get('/', async (_req, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const { data, error } = await supabase.from('wazuh_group_org_map').select('wazuh_group, org_id, created_at').order('wazuh_group');
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    res.json({ mappings: data ?? [] });
});

router.put('/', async (req: AuthRequest, res) => {
    const parsed = PutBody.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: 'Body must be { mappings: [{ wazuh_group, org_id | null }] } (1-500 entries; group names use letters, digits, . _ -)' });
        return;
    }
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const entries = parsed.data.mappings;
    if (new Set(entries.map((e) => e.wazuh_group)).size !== entries.length) {
        res.status(400).json({ error: 'Each wazuh_group may appear once' });
        return;
    }

    const orgIds = [...new Set(entries.map((e) => e.org_id).filter((o): o is string => o !== null))];
    if (orgIds.length > 0) {
        const { data, error } = await supabase.from('organisations').select('slug').in('slug', orgIds);
        if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
        const known = new Set((data ?? []).map((o) => o.slug as string));
        const unknown = orgIds.filter((o) => !known.has(o));
        if (unknown.length > 0) { res.status(400).json({ error: `Unknown organisation: ${unknown.join(', ')}` }); return; }
    }

    const upserts = entries.filter((e) => e.org_id !== null).map((e) => ({ wazuh_group: e.wazuh_group, org_id: e.org_id as string }));
    const removals = entries.filter((e) => e.org_id === null).map((e) => e.wazuh_group);
    if (upserts.length > 0) {
        const { error } = await supabase.from('wazuh_group_org_map').upsert(upserts, { onConflict: 'wazuh_group' });
        if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    }
    if (removals.length > 0) {
        const { error } = await supabase.from('wazuh_group_org_map').delete().in('wazuh_group', removals);
        if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    }

    logAudit({
        user: req.user?.email ?? 'unknown', action: 'WAZUH_GROUP_MAP_CHANGED', resource: 'wazuh_group_org_map',
        ip: req.ip ?? 'unknown', result: 'success', severity: 'warning',
        details: [...upserts.map((u) => `${u.wazuh_group}=>${u.org_id}`), ...removals.map((g) => `${g}=>removed`)].join(', ').slice(0, 200),
    });

    const { data, error } = await supabase.from('wazuh_group_org_map').select('wazuh_group, org_id, created_at').order('wazuh_group');
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    res.json({ success: true, mappings: data ?? [] });
});

export default router;
