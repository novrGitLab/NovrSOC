// /api/admin/wazuh-group-map — which organisation owns each Wazuh agent group (phase R2). The
// alert ingest endpoint resolves every alert's org through this map and nothing else, so it is
// super_admin only (mounted behind requireAuth + requireRole('super_admin') in index.ts).
//
//   GET  -> { mappings: [{ wazuh_group, org_id, created_at }] }
//   PUT  { mappings: [{ wazuh_group, org_id }] }  upserts each; org_id: null removes that group.
//        org_id must be an existing organisations.slug. Every change is audited.
//
//   GET  /sources -> { sources: [{ location, org_id, device_name, device_type, created_at, updated_at }] }
//   PUT  /sources { sources: [{ location, org_id | null, device_name?, device_type? }] } (phase P24)
//        Which organisation owns a syslog sender the manager receives itself (OPNsense): agent-000
//        alerts whose `location` is that address. location must be an IP address — a log file path
//        is shared by every agent and is refused. Audited; replays the quarantine.

import { Router } from 'express';
import { z } from 'zod';
import type { AuthRequest } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';
import { dbErrorMessage } from '../services/cases';
import { logAudit } from '../lib/audit';
import { quarantineSummary, replayQuarantine, type ReplayResult } from '../services/alertQuarantine';
import { resetOrgScopeCache } from '../lib/orgScope';
import { isIP } from 'net';

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
    // Ownership of indexer data (lib/orgScope.ts) follows the new map at once, not after its cache expires.
    resetOrgScopeCache();

    logAudit({
        user: req.user?.email ?? 'unknown', action: 'WAZUH_GROUP_MAP_CHANGED', resource: 'wazuh_group_org_map',
        ip: req.ip ?? 'unknown', result: 'success', severity: 'warning',
        details: [...upserts.map((u) => `${u.wazuh_group}=>${u.org_id}`), ...removals.map((g) => `${g}=>removed`)].join(', ').slice(0, 200),
    });

    // A newly mapped group releases its quarantined alerts. A replay failure doesn't undo the
    // mapping; it is reported, and POST /quarantine/replay can be retried.
    let replay: ReplayResult | { error: string } | null = null;
    if (upserts.length > 0) {
        try { replay = await replayQuarantine(); } catch (err) { replay = { error: err instanceof Error ? err.message : 'replay failed' }; }
    }

    const { data, error } = await supabase.from('wazuh_group_org_map').select('wazuh_group, org_id, created_at').order('wazuh_group');
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    res.json({ success: true, mappings: data ?? [], replay });
});

// ── Syslog sources (phase P24) ───────────────────────────────────────────────────────────────

const DEVICE_TYPES = ['firewall', 'ids', 'syslog', 'other'] as const;
const PutSources = z.object({
    sources: z.array(z.object({
        location: z.string().trim().min(2).max(45).refine((l) => isIP(l) !== 0, 'location must be an IP address'),
        org_id: z.string().min(1).max(128).nullable(),
        device_name: z.string().trim().max(128).nullable().optional(),
        device_type: z.enum(DEVICE_TYPES).optional(),
    })).min(1).max(200),
});
const SOURCE_COLUMNS = 'location, org_id, device_name, device_type, created_at, updated_at';
const P24_MISSING = 'Syslog source mapping is not available yet (run sql/2026-10-29_p24_wazuh_sources.sql)';
const missingSources = (e: { message?: string } | null) => !!e && /wazuh_source_org_map/.test(e.message ?? '');

router.get('/sources', async (_req, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const { data, error } = await supabase.from('wazuh_source_org_map').select(SOURCE_COLUMNS).order('location');
    if (missingSources(error)) { res.status(503).json({ error: P24_MISSING, sources: [] }); return; }
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    res.json({ sources: data ?? [] });
});

router.put('/sources', async (req: AuthRequest, res) => {
    const parsed = PutSources.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: `Body must be { sources: [{ location (an IP address), org_id | null, device_name?, device_type? }] } (1-200 entries): ${parsed.error.issues[0]?.message ?? 'invalid'}` });
        return;
    }
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const entries = parsed.data.sources;
    if (new Set(entries.map((e) => e.location)).size !== entries.length) { res.status(400).json({ error: 'Each location may appear once' }); return; }

    const orgIds = [...new Set(entries.map((e) => e.org_id).filter((o): o is string => o !== null))];
    if (orgIds.length > 0) {
        const { data, error } = await supabase.from('organisations').select('slug').in('slug', orgIds);
        if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
        const known = new Set((data ?? []).map((o) => o.slug as string));
        const unknown = orgIds.filter((o) => !known.has(o));
        if (unknown.length > 0) { res.status(400).json({ error: `Unknown organisation: ${unknown.join(', ')}` }); return; }
    }

    const now = new Date().toISOString();
    const upserts = entries.filter((e) => e.org_id !== null).map((e) => ({
        location: e.location, org_id: e.org_id as string, device_name: e.device_name ?? null, device_type: e.device_type ?? 'firewall', updated_at: now,
    }));
    const removals = entries.filter((e) => e.org_id === null).map((e) => e.location);
    if (upserts.length > 0) {
        const { error } = await supabase.from('wazuh_source_org_map').upsert(upserts, { onConflict: 'location' });
        if (missingSources(error)) { res.status(503).json({ error: P24_MISSING }); return; }
        if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    }
    if (removals.length > 0) {
        const { error } = await supabase.from('wazuh_source_org_map').delete().in('location', removals);
        if (missingSources(error)) { res.status(503).json({ error: P24_MISSING }); return; }
        if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    }
    resetOrgScopeCache();

    logAudit({
        user: req.user?.email ?? 'unknown', action: 'WAZUH_SOURCE_MAP_CHANGED', resource: 'wazuh_source_org_map',
        ip: req.ip ?? 'unknown', result: 'success', severity: 'warning',
        details: [...upserts.map((u) => `${u.location}=>${u.org_id}`), ...removals.map((l) => `${l}=>removed`)].join(', ').slice(0, 200),
    });

    // A newly owned sender releases its quarantined alerts; a replay failure is reported, not fatal.
    let replay: ReplayResult | { error: string } | null = null;
    if (upserts.length > 0) {
        try { replay = await replayQuarantine(); } catch (err) { replay = { error: err instanceof Error ? err.message : 'replay failed' }; }
    }

    const { data, error } = await supabase.from('wazuh_source_org_map').select(SOURCE_COLUMNS).order('location');
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    res.json({ success: true, sources: data ?? [], replay });
});

// GET /quarantine — per-group (and per-sender) counts of alerts held because nothing maps them.
router.get('/quarantine', async (_req, res) => {
    const summary = await quarantineSummary();
    if (!summary) { res.status(503).json({ error: 'Quarantine not available (run sql/2026-10-14_p1_quarantine.sql)' }); return; }
    res.json(summary);
});

// POST /quarantine/replay — move quarantined alerts that now resolve to one org into alerts.
router.post('/quarantine/replay', async (req: AuthRequest, res) => {
    try {
        const result = await replayQuarantine();
        logAudit({
            user: req.user?.email ?? 'unknown', action: 'ALERT_QUARANTINE_REPLAYED', resource: 'alert_quarantine',
            ip: req.ip ?? 'unknown', result: 'success', severity: 'info',
            details: `replayed ${result.replayed}, duplicates ${result.duplicates}, still quarantined ${result.still_quarantined}`,
        });
        res.json(result);
    } catch (err) {
        res.status(502).json({ error: err instanceof Error ? err.message : 'replay failed' });
    }
});

export default router;
