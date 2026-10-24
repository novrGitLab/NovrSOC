// /api/vms — VMS Release 3, continuous monitoring (phase P7). Behind requireAuth.
//
//   GET    /schedules                 vms:read   this organisation's scan schedules
//   POST   /schedules                 vms:scope  { scope_id, kind, targets?, ports?, interval_hours, first_run_at? }
//   PATCH  /schedules/:id             vms:scope  { enabled?, interval_hours? } — re-enabling re-checks the scope
//   DELETE /schedules/:id             vms:scope
//   GET    /trends?days=90            vms:read   daily snapshots, time to remediate, recurring problems
//   GET    /report?days=30            vms:read   what happened in the period, with sources and limitations
//   GET    /notifications             vms:read   whether change digests are on, and the last run
//
// Schedules are created by those who can authorise scope (managers), because they keep scanning
// without anyone pressing a button; every run still passes the scope checks of a manual scan.

import { Router } from 'express';
import { z } from 'zod';
import type { AuthRequest } from '../middleware/auth';
import { requirePermission, requestOrg } from '../lib/permissions';
import { getSupabase } from '../services/geoEnrichment';
import { dbErrorMessage, isUuid } from '../services/cases';
import { logAudit } from '../lib/audit';
import { validateScan, NewScan } from './vms';
import { riskTrends, periodReport, notifyEnabled } from '../services/vmsContinuous';

const router = Router();
const P7_MISSING = 'VMS Release 3 is not set up yet (run sql/2026-10-16_p7_vms_continuous.sql)';
const missing = (e: { message?: string } | null) => !!e && /vms_(scan_schedules|risk_snapshots|notify_state)/.test(e.message ?? '') && /does not exist|Could not find/i.test(e.message ?? '');
const fail = (res: import('express').Response, e: { message?: string }) => res.status(missing(e) ? 503 : 502).json({ error: missing(e) ? P7_MISSING : dbErrorMessage(e) });
const actor = (req: AuthRequest) => req.user?.email ?? 'unknown';
const clampDays = (v: unknown, def: number) => Math.min(Math.max(Number(v) || def, 1), 365);

const NewSchedule = NewScan.extend({
    interval_hours: z.number().int().min(24).max(2160),
    first_run_at: z.string().datetime().optional(),
}).strict();

router.get('/schedules', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const { data, error } = await getSupabase()!.from('vms_scan_schedules').select('*, vms_scopes(value, kind, expires_at, status)').eq('org_id', requestOrg(req)).order('created_at', { ascending: false }).limit(200);
    if (error) { fail(res, error); return; }
    res.json({ schedules: data ?? [] });
});

// Verification rescans on a schedule (phase P27): findings marked fixed inside the scope entry.
const NewVerificationSchedule = z.object({
    scope_id: z.string().uuid(), kind: z.literal('verification'),
    targets: z.array(z.string().max(253)).max(256).optional(),
    interval_hours: z.number().int().min(24).max(2160),
    first_run_at: z.string().datetime().optional(),
}).strict();

router.post('/schedules', requirePermission('vms:scope'), async (req: AuthRequest, res) => {
    if (req.body?.kind === 'verification') {
        const pv = NewVerificationSchedule.safeParse(req.body);
        if (!pv.success) { res.status(400).json({ error: 'Body must be { scope_id, kind: "verification", targets?, interval_hours: 24..2160, first_run_at? (ISO) }' }); return; }
        const org = requestOrg(req);
        const { data: scope } = await getSupabase()!.from('vms_scopes').select('*').eq('id', pv.data.scope_id).eq('org_id', org).maybeSingle();
        if (!scope || scope.status !== 'active' || Date.parse(scope.expires_at) <= Date.now()) { res.status(400).json({ error: 'That scope is not active (pending, revoked, expired or not found)' }); return; }
        if (!scope.allow_vuln_scan) { res.status(403).json({ error: 'This scope does not authorise vulnerability scanning' }); return; }
        const first = pv.data.first_run_at ? Date.parse(pv.data.first_run_at) : Date.now();
        if (first > Date.parse(scope.expires_at)) { res.status(400).json({ error: 'The first run would be after the scope expires' }); return; }
        const { data, error } = await getSupabase()!.from('vms_scan_schedules').insert({
            org_id: org, scope_id: scope.id, kind: 'verification', targets: pv.data.targets ?? [], interval_hours: pv.data.interval_hours, next_run_at: new Date(first).toISOString(), created_by: actor(req),
        }).select('*').single();
        if (error) {
            if (/kind_check/.test(error.message)) { res.status(503).json({ error: 'Verification schedules are not set up yet (run sql/2026-11-01_p27_vms_onboarding.sql)' }); return; }
            fail(res, error); return;
        }
        logAudit({ user: actor(req), action: 'VMS_SCHEDULE_CREATED', resource: 'vms_scan_schedule', resource_id: data.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: `verification every ${pv.data.interval_hours} h on scope ${scope.id}` });
        res.status(201).json({ schedule: data });
        return;
    }
    const p = NewSchedule.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: 'Body must be { scope_id, kind, targets?, ports?, interval_hours: 24..2160, first_run_at? (ISO) }' }); return; }
    const org = requestOrg(req);
    const { interval_hours, first_run_at, ...scan } = p.data;
    const v = await validateScan(org, scan);
    if (!v.ok) { res.status(v.status).json({ error: v.error }); return; }
    const first = first_run_at ? Date.parse(first_run_at) : Date.now();
    if (first > Date.parse(v.scope.expires_at)) { res.status(400).json({ error: 'The first run would be after the scope expires' }); return; }
    const { data, error } = await getSupabase()!.from('vms_scan_schedules').insert({
        org_id: org, scope_id: scan.scope_id, kind: scan.kind, targets: scan.targets?.length ? v.targets : [], ports: scan.ports ?? null,
        interval_hours, next_run_at: new Date(first).toISOString(), created_by: actor(req),
    }).select('*').single();
    if (error) { fail(res, error); return; }
    logAudit({ user: actor(req), action: 'VMS_SCHEDULE_CREATED', resource: 'vms_scan_schedule', resource_id: data.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: `${scan.kind} every ${interval_hours} h on scope ${scan.scope_id}` });
    res.status(201).json({ schedule: data });
});

const PatchSchedule = z.object({ enabled: z.boolean().optional(), interval_hours: z.number().int().min(24).max(2160).optional() }).strict();
router.patch('/schedules/:id', requirePermission('vms:scope'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Schedule not found' }); return; }
    const p = PatchSchedule.safeParse(req.body);
    if (!p.success || Object.keys(p.data).length === 0) { res.status(400).json({ error: 'Body must be { enabled?, interval_hours? }' }); return; }
    const supabase = getSupabase()!;
    const org = requestOrg(req);
    const { data: s, error } = await supabase.from('vms_scan_schedules').select('*').eq('id', req.params.id).eq('org_id', org).maybeSingle();
    if (error) { fail(res, error); return; }
    if (!s) { res.status(404).json({ error: 'Schedule not found' }); return; }
    const patch: Record<string, unknown> = { ...p.data, updated_at: new Date().toISOString() };
    if (p.data.enabled === true && !s.enabled) {
        if (s.kind === 'verification') {
            // P27: a verification schedule needs an active scope that permits vulnerability testing.
            const { data: sc } = await supabase.from('vms_scopes').select('status, expires_at, allow_vuln_scan').eq('id', s.scope_id).eq('org_id', org).maybeSingle();
            if (!sc || sc.status !== 'active' || Date.parse(sc.expires_at) <= Date.now() || !sc.allow_vuln_scan) { res.status(400).json({ error: 'Cannot re-enable: its scope is not active or does not permit vulnerability testing' }); return; }
        } else {
            const v = await validateScan(org, { scope_id: s.scope_id, kind: s.kind, targets: s.targets?.length ? s.targets : undefined, ports: s.ports ?? undefined });
            if (!v.ok) { res.status(v.status).json({ error: `Cannot re-enable: ${v.error}` }); return; }
        }
        if (Date.parse(s.next_run_at) < Date.now()) patch.next_run_at = new Date().toISOString();
        patch.last_result = `Re-enabled by ${actor(req)}`;
    }
    const { data, error: uErr } = await supabase.from('vms_scan_schedules').update(patch).eq('id', s.id).eq('org_id', org).select('*').single();
    if (uErr) { fail(res, uErr); return; }
    logAudit({ user: actor(req), action: 'VMS_SCHEDULE_UPDATED', resource: 'vms_scan_schedule', resource_id: s.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: JSON.stringify(p.data) });
    res.json({ schedule: data });
});

router.delete('/schedules/:id', requirePermission('vms:scope'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Schedule not found' }); return; }
    const org = requestOrg(req);
    const { data, error } = await getSupabase()!.from('vms_scan_schedules').delete().eq('id', req.params.id).eq('org_id', org).select('id');
    if (error) { fail(res, error); return; }
    if (!data?.length) { res.status(404).json({ error: 'Schedule not found' }); return; }
    logAudit({ user: actor(req), action: 'VMS_SCHEDULE_DELETED', resource: 'vms_scan_schedule', resource_id: req.params.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success' });
    res.json({ deleted: true });
});

router.get('/trends', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    try { res.json(await riskTrends(requestOrg(req), clampDays(req.query.days, 90))); } catch (err) { fail(res, { message: err instanceof Error ? err.message : String(err) }); }
});

router.get('/report', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    try { res.json(await periodReport(requestOrg(req), clampDays(req.query.days, 30))); } catch (err) { fail(res, { message: err instanceof Error ? err.message : String(err) }); }
});

router.get('/notifications', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const { data, error } = await getSupabase()!.from('vms_notify_state').select('*').eq('org_id', requestOrg(req)).maybeSingle();
    if (error) { fail(res, error); return; }
    res.json({ enabled: notifyEnabled(), state: data ?? null });
});

export default router;
