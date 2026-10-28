// Collector Management API (phase P31). Staff only (collectors:read / collectors:manage — see
// lib/permissions.ts): enroll a collector, list and inspect this organisation's collectors,
// revoke one, rotate its credential, and read its recent log sample for diagnostics.
//
// An enrollment secret is returned exactly once, in the response to the call that issues it
// (POST / or POST /:id/rotate) — never again afterwards, not even to a later GET. There is no
// "view secret" route, by design.

import { Router } from 'express';
import { z } from 'zod';
import type { AuthRequest } from '../middleware/auth';
import { requirePermission, requestOrg } from '../lib/permissions';
import { isUuid, dbErrorMessage } from '../services/cases';
import { getSupabase } from '../services/geoEnrichment';
import { createCollector, listCollectors, getCollector, revokeCollector, rotateCredential, effectiveStatus } from '../services/collectors';

const router = Router();
const db = () => getSupabase()!;
const actor = (req: AuthRequest) => req.user?.email ?? 'unknown';

router.get('/', requirePermission('collectors:read'), async (req: AuthRequest, res) => {
    const collectors = await listCollectors(requestOrg(req));
    res.json({ collectors: collectors.map((c) => ({ ...c, effective_status: effectiveStatus(c) })) });
});

const CreateBody = z.object({ name: z.string().trim().min(1).max(200) }).strict();
router.post('/', requirePermission('collectors:manage'), async (req: AuthRequest, res) => {
    const p = CreateBody.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: p.error.issues[0]?.message ?? 'A name is required' }); return; }
    const r = await createCollector(requestOrg(req), p.data.name, actor(req));
    if ('error' in r) { res.status(400).json({ error: r.error }); return; }
    res.status(201).json({ collector: r.collector, enrollment_token: r.token, note: 'This credential is shown once. Store it in the collector appliance\'s environment file now — it cannot be retrieved again (use "Rotate" to issue a new one if it is lost).' });
});

router.get('/:id', requirePermission('collectors:read'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Collector not found' }); return; }
    const org = requestOrg(req);
    const collector = await getCollector(req.params.id, org);
    if (!collector) { res.status(404).json({ error: 'Collector not found' }); return; }
    const [{ data: sources }, { data: heartbeats }] = await Promise.all([
        db().from('collector_sources').select('*').eq('collector_id', req.params.id).order('last_event_at', { ascending: false }),
        db().from('collector_heartbeats').select('at, events_received, events_forwarded, delivery_failures, buffer_pct').eq('collector_id', req.params.id).order('at', { ascending: false }).limit(288), // ~48h at one heartbeat every 10 min
    ]);
    res.json({ collector: { ...collector, effective_status: effectiveStatus(collector) }, sources: sources ?? [], heartbeats: (heartbeats ?? []).reverse() });
});

router.get('/:id/events', requirePermission('collectors:read'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Collector not found' }); return; }
    const org = requestOrg(req);
    const collector = await getCollector(req.params.id, org);
    if (!collector) { res.status(404).json({ error: 'Collector not found' }); return; }
    const limit = Math.min(Number(req.query.limit) || 100, 500);
    const { data, error } = await db().from('collector_log_events').select('id, source_key, host, received_at, event_time, message, truncated').eq('collector_id', req.params.id).order('received_at', { ascending: false }).limit(limit);
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    res.json({ events: data ?? [] });
});

router.post('/:id/revoke', requirePermission('collectors:manage'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Collector not found' }); return; }
    const r = await revokeCollector(req.params.id, requestOrg(req), actor(req));
    if (!r.ok) { res.status(400).json({ error: r.error }); return; }
    res.json({ ok: true });
});

router.post('/:id/rotate', requirePermission('collectors:manage'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Collector not found' }); return; }
    const r = await rotateCredential(req.params.id, requestOrg(req), actor(req));
    if ('error' in r) { res.status(400).json({ error: r.error }); return; }
    res.json({ enrollment_token: r.token, note: 'This credential is shown once — update the collector appliance\'s environment file and restart it now.' });
});

export default router;
