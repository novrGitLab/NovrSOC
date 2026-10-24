// /api/vms/import — asset onboarding (phase P27). Mounted behind requireAuth with its own 1 MB JSON
// parser (a CSV can be up to 512 KB). Every route works on the caller's organisation only.
//
//   GET  /wazuh/groups                         vms:read    the Wazuh groups mapped to this organisation
//   GET  /wazuh/groups/:group/preview?discover vms:manage  its agents as they would be imported (IP discovery with discover=1)
//   POST /wazuh                                vms:manage  { group, agent_ids[], discover_ips? }
//   POST /assets                               vms:manage  { entries: [{ value, type?, owner?, criticality? }], dry_run? }
//   POST /csv                                  vms:manage  { csv, dry_run? }
//
// Imports add assets to the inventory; they never create or widen scan scope. Each result says
// whether the asset is inside an approved scope ("authorised"), only in a pending request, or not.

import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import type { AuthRequest } from '../middleware/auth';
import { requirePermission, requestOrg } from '../lib/permissions';
import { logAudit } from '../lib/audit';
import { importRows, parseCsv, orgGroups, previewGroup, importGroup, MAX_IMPORT_ROWS, MAX_CSV_BYTES } from '../services/vmsImport';

const router = Router();
const actor = (req: AuthRequest) => req.user?.email ?? 'unknown';
const limiter = rateLimit({ windowMs: 60_000, max: 30, standardHeaders: true, legacyHeaders: false, keyGenerator: (req) => (req as AuthRequest).user?.sub ?? 'anonymous', message: { error: 'Too many imports — wait a minute' } });
const GROUP = /^[\w.-]{1,128}$/;

router.get('/wazuh/groups', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    try { res.json({ groups: await orgGroups(requestOrg(req)) }); }
    catch (err) { res.status(503).json({ error: `Group map unavailable: ${err instanceof Error ? err.message : String(err)}`.slice(0, 200) }); }
});

router.get('/wazuh/groups/:group/preview', requirePermission('vms:manage'), limiter, async (req: AuthRequest, res) => {
    if (!GROUP.test(req.params.group)) { res.status(400).json({ error: 'Invalid group name' }); return; }
    const r = await previewGroup(requestOrg(req), req.params.group, req.query.discover === '1' || req.query.discover === 'true');
    if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
    res.json({ group: req.params.group, agents: r.agents });
});

const WazuhImport = z.object({ group: z.string().regex(GROUP), agent_ids: z.array(z.string().regex(/^\d{1,6}$/)).min(1).max(500), discover_ips: z.boolean().default(false) }).strict();
router.post('/wazuh', requirePermission('vms:manage'), limiter, async (req: AuthRequest, res) => {
    const p = WazuhImport.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: 'Body must be { group, agent_ids: ["001", …] (1..500), discover_ips? }' }); return; }
    const org = requestOrg(req);
    const r = await importGroup(org, actor(req), p.data.group, [...new Set(p.data.agent_ids)], p.data.discover_ips);
    if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
    logAudit({ user: actor(req), action: 'VMS_ASSETS_IMPORTED', resource: 'vms_assets', resource_id: `wazuh:${p.data.group}`, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: `Wazuh group ${p.data.group}: ${r.imported} new, ${r.updated} updated, ${r.skipped.length} skipped` });
    res.json(r);
});

const Entry = z.object({ value: z.string().max(300), type: z.string().max(20).optional(), owner: z.string().max(120).optional(), criticality: z.string().max(20).optional() }).strict();
router.post('/assets', requirePermission('vms:manage'), limiter, async (req: AuthRequest, res) => {
    const p = z.object({ entries: z.array(Entry).min(1).max(MAX_IMPORT_ROWS), dry_run: z.boolean().default(false) }).strict().safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: `Body must be { entries: [{ value, type?: ip|domain|host|cidr, owner?, criticality? }] (1..${MAX_IMPORT_ROWS}), dry_run? }` }); return; }
    const org = requestOrg(req);
    const r = await importRows(org, actor(req), p.data.entries, 'manual', p.data.dry_run);
    if (!p.data.dry_run) logAudit({ user: actor(req), action: 'VMS_ASSETS_IMPORTED', resource: 'vms_assets', resource_id: 'manual', org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: JSON.stringify(r.counts) });
    res.json({ dry_run: p.data.dry_run, ...r });
});

router.post('/csv', requirePermission('vms:manage'), limiter, async (req: AuthRequest, res) => {
    const p = z.object({ csv: z.string().min(1).max(MAX_CSV_BYTES * 2), dry_run: z.boolean().default(false) }).strict().safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: `Body must be { csv: "value,type,owner,criticality\\n…" (at most ${MAX_CSV_BYTES / 1024} KB), dry_run? }` }); return; }
    const parsed = parseCsv(p.data.csv);
    if (!parsed.ok) { res.status(400).json({ error: parsed.error }); return; }
    const org = requestOrg(req);
    const r = await importRows(org, actor(req), parsed.rows, 'csv', p.data.dry_run);
    if (!p.data.dry_run) logAudit({ user: actor(req), action: 'VMS_ASSETS_IMPORTED', resource: 'vms_assets', resource_id: 'csv', org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: JSON.stringify(r.counts) });
    res.json({ dry_run: p.data.dry_run, ...r });
});

export default router;
