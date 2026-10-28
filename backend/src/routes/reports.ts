// /api/reports — the Reporting Center (phase P30, R3.3E). Behind requireAuth; reports:read /
// reports:manage. Every route resolves its organisation through lib/resolveOrg.ts exactly like
// every other SecOps/VMS/CNII/TI route — portal/client roles are confined to their own org
// regardless of X-Org-Id, staff may act on another org only with it (audited).
//
//   GET   /types                       available report types, and whether this org's module is enabled for each
//   GET   /schedules                   this org's schedules
//   POST  /schedules                   create or replace this org's schedule for one report type
//   PATCH /schedules/:id               enable/disable, change cadence/format
//   DELETE /schedules/:id
//   GET   /recipients                  this org's recipients
//   POST  /recipients                  add one (validated; external_email starts unauthorised)
//   PATCH /recipients/:id              edit, enable/disable
//   DELETE /recipients/:id
//   POST  /recipients/:id/authorise    explicitly authorise an external_email recipient
//   POST  /generate                    generate now (optionally deliver) — reports:read for view-only, reports:manage to also deliver
//   GET   /history                     this org's report_jobs, newest first, with delivery summary
//   GET   /:jobId/download             stream the stored PDF or CSV artifact
//   POST  /deliveries/:id/retry        retry one failed delivery
//
// Operational routes (staff only, not org-scoped — matches routes/securityAssessment.ts's admin
// overview precedent):
//   GET   /ops/health                  scheduler last-run, queue depth, stuck jobs, across every org

import { Router } from 'express';
import { z } from 'zod';
import type { AuthRequest } from '../middleware/auth';
import { requireRole } from '../middleware/auth';
import { requirePermission, requestOrg } from '../lib/permissions';
import { getSupabase } from '../services/geoEnrichment';
import { dbErrorMessage, isUuid } from '../services/cases';
import { logAudit } from '../lib/audit';
import { hasServiceAccess, SERVICE_LABEL, type ServiceKey } from '../lib/serviceAccess';
import { nextRunAt } from '../lib/reportScheduling';
import { validateRecipient, authoriseExternalRecipient, type RecipientKind } from '../services/reportRecipients';
import { generateReportData, type ReportType, type ReportFormat } from '../services/reportGeneration';
import { renderReportPdf } from '../services/reportPdf';
import { reportToCsv } from '../services/reportCsv';
import { storeArtifact, getArtifact } from '../services/reportArtifacts';
import { deliverReport, retryDelivery } from '../services/reportDelivery';
import { lastReportSchedulerRun } from '../jobs/reportSchedulerJob';
import { randomUUID } from 'crypto';

const router = Router();
const db = () => getSupabase()!;
const actor = (req: AuthRequest) => req.user?.email ?? 'unknown';
const REPORT_TYPES: ReportType[] = ['vms', 'cnii', 'threat_intel', 'executive_summary'];
const SERVICE_FOR: Record<ReportType, ServiceKey | null> = { vms: 'vms', cnii: 'cnii_watch', threat_intel: 'threat_intel', executive_summary: null };
const REPORT_TYPE_LABEL: Record<ReportType, string> = { vms: 'Vulnerability & Exposure', cnii: 'CNII Watch', threat_intel: 'Threat Intelligence', executive_summary: 'Unified Executive Summary' };

router.get('/types', requirePermission('reports:read'), async (req: AuthRequest, res) => {
    const org = requestOrg(req);
    const types = await Promise.all(REPORT_TYPES.map(async (t) => {
        const service = SERVICE_FOR[t];
        const available = service ? await hasServiceAccess(org, service) : true; // executive_summary degrades gracefully instead of being all-or-nothing
        return { report_type: t, label: REPORT_TYPE_LABEL[t], available, module: service ? SERVICE_LABEL[service] : null };
    }));
    res.json({ types });
});

// ── Schedules ──────────────────────────────────────────────────────────────────────────────────
router.get('/schedules', requirePermission('reports:read'), async (req: AuthRequest, res) => {
    const { data, error } = await db().from('report_schedules').select('*').eq('org_id', requestOrg(req)).order('report_type');
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    res.json({ schedules: data ?? [] });
});

const ScheduleBody = z.object({
    report_type: z.enum(['vms', 'cnii', 'threat_intel', 'executive_summary']),
    format: z.enum(['executive', 'technical']).default('executive'),
    cadence: z.enum(['weekly', 'monthly']),
    day_of_week: z.number().int().min(0).max(6).optional(),
    day_of_month: z.number().int().min(1).max(28).optional(),
    hour_local: z.number().int().min(0).max(23).default(8),
    timezone: z.string().trim().min(1).max(64).default('Africa/Lagos'),
    enabled: z.boolean().default(false),
}).strict();

router.post('/schedules', requirePermission('reports:manage'), async (req: AuthRequest, res) => {
    const p = ScheduleBody.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: p.error.issues[0]?.message ?? 'Invalid schedule' }); return; }
    const b = p.data;
    if (b.cadence === 'weekly' && b.day_of_week === undefined) { res.status(400).json({ error: 'day_of_week is required for a weekly cadence' }); return; }
    if (b.cadence === 'monthly' && b.day_of_month === undefined) { res.status(400).json({ error: 'day_of_month is required for a monthly cadence' }); return; }
    const org = requestOrg(req);
    const service = SERVICE_FOR[b.report_type];
    if (service && !(await hasServiceAccess(org, service))) { res.status(403).json({ error: `${SERVICE_LABEL[service]} is not enabled for this organisation` }); return; }
    const next = nextRunAt({ ...b, day_of_week: b.day_of_week ?? null, day_of_month: b.day_of_month ?? null }).toISOString();
    const { data, error } = await db().from('report_schedules').upsert({
        org_id: org, report_type: b.report_type, format: b.format, cadence: b.cadence,
        day_of_week: b.cadence === 'weekly' ? b.day_of_week : null, day_of_month: b.cadence === 'monthly' ? b.day_of_month : null,
        hour_local: b.hour_local, timezone: b.timezone, enabled: b.enabled, next_run_at: next,
        created_by: actor(req), updated_by: actor(req), updated_at: new Date().toISOString(),
    }, { onConflict: 'org_id,report_type' }).select('*').single();
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    logAudit({ user: actor(req), action: 'REPORT_SCHEDULE_SAVED', resource: 'report_schedule', resource_id: data.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: `${b.report_type} ${b.cadence}, enabled=${b.enabled}` });
    res.status(201).json({ schedule: data });
});

const SchedulePatch = z.object({ enabled: z.boolean().optional(), format: z.enum(['executive', 'technical']).optional(), hour_local: z.number().int().min(0).max(23).optional() }).strict();
router.patch('/schedules/:id', requirePermission('reports:manage'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Schedule not found' }); return; }
    const p = SchedulePatch.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: 'Invalid update' }); return; }
    const org = requestOrg(req);
    const { data: existing } = await db().from('report_schedules').select('*').eq('id', req.params.id).eq('org_id', org).maybeSingle();
    if (!existing) { res.status(404).json({ error: 'Schedule not found' }); return; }
    const merged = { ...existing, ...p.data };
    const updates: Record<string, unknown> = { ...p.data, updated_by: actor(req), updated_at: new Date().toISOString() };
    // Re-enabling (or any change) recomputes next_run_at from now, so flipping a schedule back on
    // after a long pause doesn't immediately fire for every missed occurrence.
    if (p.data.enabled || p.data.hour_local !== undefined) updates.next_run_at = nextRunAt(merged).toISOString();
    const { data, error } = await db().from('report_schedules').update(updates).eq('id', req.params.id).eq('org_id', org).select('*').maybeSingle();
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    logAudit({ user: actor(req), action: 'REPORT_SCHEDULE_UPDATED', resource: 'report_schedule', resource_id: req.params.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: JSON.stringify(p.data) });
    res.json({ schedule: data });
});

router.delete('/schedules/:id', requirePermission('reports:manage'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Schedule not found' }); return; }
    const org = requestOrg(req);
    const { data, error } = await db().from('report_schedules').delete().eq('id', req.params.id).eq('org_id', org).select('id').maybeSingle();
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    if (!data) { res.status(404).json({ error: 'Schedule not found' }); return; }
    logAudit({ user: actor(req), action: 'REPORT_SCHEDULE_DELETED', resource: 'report_schedule', resource_id: req.params.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success' });
    res.json({ ok: true });
});

// ── Recipients ─────────────────────────────────────────────────────────────────────────────────
router.get('/recipients', requirePermission('reports:read'), async (req: AuthRequest, res) => {
    const { data, error } = await db().from('report_recipients').select('*').eq('org_id', requestOrg(req)).order('added_at', { ascending: false });
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    res.json({ recipients: data ?? [] });
});

const RecipientBody = z.object({
    kind: z.enum(['portal_user', 'external_email']),
    email: z.string().trim().email(),
    display_name: z.string().trim().max(200).nullable().optional(),
    report_types: z.array(z.enum(['vms', 'cnii', 'threat_intel', 'executive_summary'])).default([]),
}).strict();

router.post('/recipients', requirePermission('reports:manage'), async (req: AuthRequest, res) => {
    const p = RecipientBody.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: p.error.issues[0]?.message ?? 'Invalid recipient' }); return; }
    const org = requestOrg(req);
    const v = await validateRecipient(org, p.data.kind as RecipientKind, p.data.email);
    if (!v.ok) { res.status(400).json({ error: v.error }); return; }
    const { data, error } = await db().from('report_recipients').insert({
        org_id: org, kind: p.data.kind, email: p.data.email.trim().toLowerCase(), display_name: p.data.display_name ?? null,
        report_types: p.data.report_types, added_by: actor(req),
    }).select('*').single();
    if (error) { res.status(error.code === '23505' ? 409 : 502).json({ error: error.code === '23505' ? 'That recipient already exists for this organisation' : dbErrorMessage(error) }); return; }
    logAudit({ user: actor(req), action: 'REPORT_RECIPIENT_ADDED', resource: 'report_recipient', resource_id: data.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: `${p.data.kind}: ${data.email}` });
    res.status(201).json({ recipient: data });
});

const RecipientPatch = z.object({ enabled: z.boolean().optional(), display_name: z.string().trim().max(200).nullable().optional(), report_types: z.array(z.enum(['vms', 'cnii', 'threat_intel', 'executive_summary'])).optional() }).strict();
router.patch('/recipients/:id', requirePermission('reports:manage'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Recipient not found' }); return; }
    const p = RecipientPatch.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: 'Invalid update' }); return; }
    const org = requestOrg(req);
    const { data, error } = await db().from('report_recipients').update({ ...p.data, updated_by: actor(req), updated_at: new Date().toISOString() }).eq('id', req.params.id).eq('org_id', org).select('*').maybeSingle();
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    if (!data) { res.status(404).json({ error: 'Recipient not found' }); return; }
    logAudit({ user: actor(req), action: 'REPORT_RECIPIENT_UPDATED', resource: 'report_recipient', resource_id: req.params.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: JSON.stringify(p.data) });
    res.json({ recipient: data });
});

router.delete('/recipients/:id', requirePermission('reports:manage'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Recipient not found' }); return; }
    const org = requestOrg(req);
    const { data, error } = await db().from('report_recipients').delete().eq('id', req.params.id).eq('org_id', org).select('id').maybeSingle();
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    if (!data) { res.status(404).json({ error: 'Recipient not found' }); return; }
    logAudit({ user: actor(req), action: 'REPORT_RECIPIENT_REMOVED', resource: 'report_recipient', resource_id: req.params.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success' });
    res.json({ ok: true });
});

router.post('/recipients/:id/authorise', requirePermission('reports:manage'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Recipient not found' }); return; }
    const r = await authoriseExternalRecipient(req.params.id, requestOrg(req), actor(req));
    if (!r.ok) { res.status(400).json({ error: r.error }); return; }
    res.json({ ok: true });
});

// ── Generate now ───────────────────────────────────────────────────────────────────────────────
const GenerateBody = z.object({
    report_type: z.enum(['vms', 'cnii', 'threat_intel', 'executive_summary']),
    format: z.enum(['executive', 'technical']).default('executive'),
    period_days: z.number().int().min(1).max(365).default(30),
    deliver: z.boolean().default(false),
}).strict();

router.post('/generate', requirePermission('reports:read'), async (req: AuthRequest, res) => {
    const p = GenerateBody.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: p.error.issues[0]?.message ?? 'Invalid request' }); return; }
    if (p.data.deliver && !req.user?.role) { res.status(403).json({ error: 'Not authorised' }); return; }
    // Delivering to configured recipients is an administrative action (it can reach an external
    // address); view-only generation only needs the same read access the live report page needs.
    const { hasPermission } = await import('../lib/permissions');
    if (p.data.deliver && !hasPermission(req.user?.role, 'reports:manage')) { res.status(403).json({ error: 'Only a manager can generate and deliver — view-only generation does not need this' }); return; }
    const org = requestOrg(req);
    const service = SERVICE_FOR[p.data.report_type];
    if (service && !(await hasServiceAccess(org, service))) { res.status(403).json({ error: `${SERVICE_LABEL[service]} is not enabled for this organisation` }); return; }
    const jobId = randomUUID();
    const { error: insertError } = await db().from('report_jobs').insert({ id: jobId, org_id: org, report_type: p.data.report_type, format: p.data.format, period_days: p.data.period_days, trigger: 'manual', requested_by: actor(req), status: 'running', claimed_at: new Date().toISOString(), started_at: new Date().toISOString(), worker_id: 'inline' });
    if (insertError) { res.status(502).json({ error: dbErrorMessage(insertError) }); return; }
    try {
        // An interactive "generate now" by a signed-in viewer may use their own role's real TLP
        // ceiling (matching what they already see on the live report page) — but the moment
        // `deliver` is true, this becomes an emailed artifact, so it drops to the conservative
        // client ceiling regardless of who clicked the button. See services/reportGeneration.ts.
        const ceiling = p.data.deliver ? 'amber' : (req.user && ['super_admin', 'soc_manager', 'analyst'].includes(req.user.role) ? 'red' : 'amber');
        const report = await generateReportData(org, p.data.report_type, p.data.format, p.data.period_days, ceiling);
        const pdf = await renderReportPdf(report);
        const csv = reportToCsv(report);
        await storeArtifact(jobId, 'pdf', `${p.data.report_type}-${org}-${new Date().toISOString().slice(0, 10)}.pdf`, pdf);
        await storeArtifact(jobId, 'csv', `${p.data.report_type}-${org}-${new Date().toISOString().slice(0, 10)}.csv`, Buffer.from(csv, 'utf8'));
        const status = report.warnings.length && Object.keys(report.data).length === 0 ? 'failed' : report.warnings.length ? 'partial' : 'completed';
        await db().from('report_jobs').update({ status, finished_at: new Date().toISOString(), last_error: report.warnings.join('; ').slice(0, 500) || null }).eq('id', jobId);
        let deliveries: Awaited<ReturnType<typeof deliverReport>> = [];
        if (p.data.deliver && status !== 'failed') deliveries = await deliverReport(jobId, report, actor(req));
        logAudit({ user: actor(req), action: 'REPORT_GENERATED', resource: 'report_job', resource_id: jobId, org_id: org, ip: req.ip ?? 'unknown', result: status === 'failed' ? 'failed' : 'success', details: `${p.data.report_type} (${status}), manual` });
        res.status(201).json({ job_id: jobId, status, warnings: report.warnings, deliveries });
    } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        await db().from('report_jobs').update({ status: 'failed', finished_at: new Date().toISOString(), last_error: message.slice(0, 500) }).eq('id', jobId);
        logAudit({ user: actor(req), action: 'REPORT_GENERATED', resource: 'report_job', resource_id: jobId, org_id: org, ip: req.ip ?? 'unknown', result: 'failed', severity: 'warning', details: message.slice(0, 200) });
        res.status(502).json({ error: message });
    }
});

// ── History & download ────────────────────────────────────────────────────────────────────────
router.get('/history', requirePermission('reports:read'), async (req: AuthRequest, res) => {
    const org = requestOrg(req);
    const { data: jobs, error } = await db().from('report_jobs').select('*').eq('org_id', org).order('requested_at', { ascending: false }).limit(100);
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    const jobIds = (jobs ?? []).map((j) => j.id as string);
    const { data: deliveries } = jobIds.length ? await db().from('report_deliveries').select('id, report_job_id, status, recipient_email, error').in('report_job_id', jobIds) : { data: [] as { id: string; report_job_id: string; status: string; recipient_email: string; error: string | null }[] };
    const byJob = new Map<string, typeof deliveries>();
    for (const d of deliveries ?? []) byJob.set(d.report_job_id as string, [...(byJob.get(d.report_job_id as string) ?? []), d] as never);
    res.json({ jobs: (jobs ?? []).map((j) => ({ ...j, deliveries: byJob.get(j.id as string) ?? [] })) });
});

router.get('/:jobId/download', requirePermission('reports:read'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.jobId)) { res.status(404).json({ error: 'Report not found' }); return; }
    const format = req.query.format === 'csv' ? 'csv' : 'pdf';
    const org = requestOrg(req);
    const { data: job } = await db().from('report_jobs').select('id, org_id').eq('id', req.params.jobId).eq('org_id', org).maybeSingle();
    if (!job) { res.status(404).json({ error: 'Report not found' }); return; }
    const artifact = await getArtifact(req.params.jobId, format);
    if (!artifact) { res.status(404).json({ error: 'This report has expired or was never generated with a downloadable artifact' }); return; }
    logAudit({ user: actor(req), action: 'REPORT_DOWNLOADED', resource: 'report_job', resource_id: req.params.jobId, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: format });
    res.setHeader('Content-Type', artifact.content_type);
    res.setHeader('Content-Disposition', `attachment; filename="${artifact.filename}"`);
    res.send(artifact.bytes);
});

router.post('/deliveries/:id/retry', requirePermission('reports:manage'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Delivery not found' }); return; }
    const r = await retryDelivery(req.params.id, requestOrg(req), actor(req));
    if (!r.ok) { res.status(400).json({ error: r.error }); return; }
    res.json({ ok: true });
});

// ── Operations (staff, platform-wide) ─────────────────────────────────────────────────────────
// Deliberately not org-scoped — a per-org 403 for everyone else would make queue depth and stuck
// jobs invisible to the people who need to see them. Same precedent as
// routes/securityAssessment.ts's admin /overview: requireRole, never requirePermission, and never
// executive (which routes/securityAssessment.ts had to be corrected to exclude in R3.3C for the
// exact same reason — see that route's own comment).
router.get('/ops/health', requireRole('super_admin', 'soc_manager'), async (_req, res) => {
    const [queued, running, stuckRes, failedRecent] = await Promise.all([
        db().from('report_jobs').select('id', { count: 'exact', head: true }).eq('status', 'queued'),
        db().from('report_jobs').select('id', { count: 'exact', head: true }).eq('status', 'running'),
        db().from('report_jobs').select('id, org_id, report_type, claimed_at, worker_id').eq('status', 'running').lt('claimed_at', new Date(Date.now() - 30 * 60_000).toISOString()).limit(50),
        db().from('report_jobs').select('id, org_id, report_type, last_error, finished_at').eq('status', 'failed').gte('finished_at', new Date(Date.now() - 7 * 86_400_000).toISOString()).order('finished_at', { ascending: false }).limit(50),
    ]);
    res.json({
        scheduler: lastReportSchedulerRun,
        queue: { queued: queued.count ?? 0, running: running.count ?? 0 },
        stuck_jobs: stuckRes.data ?? [],
        recent_failures: failedRecent.data ?? [],
    });
});

export default router;
