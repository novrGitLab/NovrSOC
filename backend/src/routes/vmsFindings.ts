// /api/vms/findings and /api/vms/remediation — VMS Release 2 (phase P5). Behind requireAuth; each
// route resolves the caller's organisation.
//
//   GET   /findings?status&priority&source&kev&q&overdue&asset_id   vms:read
//   GET   /findings/summary                                         vms:read   by severity / priority / status, KEV, overdue
//   GET   /findings/:id                                             vms:read   with evidence, history, CVE intelligence, asset, tasks
//   PATCH /findings/:id { status?, note?, owner?, due_at? }         vms:manage status changes follow MANUAL_TRANSITIONS
//   POST  /findings/:id/notes { note }                              vms:manage
//   POST  /findings/:id/verify                                      vms:scan   queue a verification rescan of the same check
//   POST  /findings/:id/case                                        cases:write open a case for it, or return the linked one
//   POST  /findings/:id/tasks { title, details?, owner?, due_at? }  vms:manage
//   PATCH /tasks/:id { status?, owner?, due_at? }                   vms:manage
//   GET   /remediation                                              vms:read   open work by priority and deadline
//   GET   /wazuh/vulnerabilities?asset_id&severity                     vms:read   the Wazuh Vulnerabilities page (P16): open
//                                          Wazuh findings of this organisation, by severity, with the sync's freshness
//
// Lists and the detail carry cross-source correlations (services/vmsCorrelation.ts, P16): findings
// naming the same CVE on the same asset (confirmed) or on a Wazuh endpoint and the scanned address
// its agent reports (inferred). Derived on read; nothing is merged.
//
// Verified and reopened are set only by scan evidence (services/vmsFindings.ts), never here.

import { Router } from 'express';
import { z } from 'zod';
import type { AuthRequest } from '../middleware/auth';
import { requirePermission, requestOrg, hasPermission } from '../lib/permissions';
import { getSupabase } from '../services/geoEnrichment';
import { dbErrorMessage, isUuid, createCase, addTimeline } from '../services/cases';
import { logAudit } from '../lib/audit';
import { FINDING_STATUSES, setFindingStatus, type FindingStatus } from '../services/vmsFindings';
import { correlateFindings, type CorrFinding } from '../services/vmsCorrelation';
import { wazuhFreshness } from '../services/wazuhVulnSync';
import { requestVerification } from '../services/vmsVerification';

const router = Router();
const P5_MISSING = 'Findings are not set up yet (run sql/2026-10-14_p5_vms_findings.sql)';
const missing = (e: { message?: string } | null) => !!e && /(vms_find|vms_remed|cve_intel)/.test(e.message ?? '') && /does not exist|Could not find/i.test(e.message ?? '');
const fail = (res: import('express').Response, e: { message?: string }) => res.status(missing(e) ? 503 : 502).json({ error: missing(e) ? P5_MISSING : dbErrorMessage(e) });
const actor = (req: AuthRequest) => req.user?.email ?? 'unknown';
const OPEN: FindingStatus[] = ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened'];
const LIST_COLUMNS = 'id, asset_id, asset_value, port, protocol, source_class, detected_by, rule_id, title, finding_type, cve_ids, scanner_severity, scanner_cvss, risk_score, priority, status, owner, due_at, first_seen, last_seen, verified_at, case_id';

/** Adds { correlated: n, correlated_confirmed: n } to each row; a failure leaves the rows as they are and says so. */
async function withCorrelationCounts<T extends { id: string }>(org: string, rows: T[]): Promise<{ rows: (T & { correlated?: number; correlated_confirmed?: number })[]; correlation_error: string | null }> {
    try {
        const m = await correlateFindings(org, rows as unknown as CorrFinding[]);
        return { rows: rows.map((r) => { const c = m.get(r.id) ?? []; return { ...r, correlated: c.length, correlated_confirmed: c.filter((x) => x.basis === 'confirmed').length }; }), correlation_error: null };
    } catch (err) {
        console.error('[vms] correlation failed:', err instanceof Error ? err.message : err);
        return { rows, correlation_error: 'Correlations could not be computed; findings are shown without them' };
    }
}

async function addEvent(org: string, findingId: string, by: string, action: string, from: string | null, to: string | null, details?: string) {
    await getSupabase()!.from('vms_finding_events').insert({ org_id: org, finding_id: findingId, actor: by, action, from_value: from, to_value: to, details: details?.slice(0, 2000) ?? null });
}

router.get('/findings', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const q = req.query;
    const text = typeof q.q === 'string' && q.q.trim() ? q.q.trim() : null;
    if (text && !/^[\w .:-]{1,100}$/.test(text)) { res.status(400).json({ error: 'q may hold letters, digits, spaces and . : _ -' }); return; }
    let query = getSupabase()!.from('vms_findings').select(LIST_COLUMNS).eq('org_id', requestOrg(req));
    const status = typeof q.status === 'string' ? q.status : 'open_all';
    if (status === 'open_all') query = query.in('status', OPEN);
    else if (status !== 'all') {
        const list = status.split(',').filter((s) => (FINDING_STATUSES as readonly string[]).includes(s));
        if (!list.length) { res.status(400).json({ error: `status must be open_all, all, or from ${FINDING_STATUSES.join(', ')}` }); return; }
        query = query.in('status', list);
    }
    if (typeof q.priority === 'string' && /^(P[1-4])(,P[1-4])*$/.test(q.priority)) query = query.in('priority', q.priority.split(','));
    if (q.source === 'active_scan' || q.source === 'wazuh') query = query.eq('source_class', q.source);
    if (typeof q.asset_id === 'string' && isUuid(q.asset_id)) query = query.eq('asset_id', q.asset_id);
    if (q.overdue === 'true') query = query.lt('due_at', new Date().toISOString()).in('status', OPEN);
    if (text) query = query.or(/^CVE-\d{4}-\d+$/i.test(text) ? `cve_ids.cs.{${text.toUpperCase()}}` : `title.ilike."*${text}*",asset_value.ilike."*${text}*",rule_id.eq."${text}"`);
    const { data, error } = await query.order('risk_score', { ascending: false, nullsFirst: false }).order('first_seen', { ascending: true }).limit(1000);
    if (error) { fail(res, error); return; }
    let rows = data ?? [];
    if (q.kev === 'true') {
        const cves = [...new Set(rows.flatMap((r) => r.cve_ids ?? []))];
        const { data: kev } = cves.length ? await getSupabase()!.from('cve_intel').select('cve_id').in('cve_id', cves).eq('kev', true) : { data: [] };
        const kevSet = new Set((kev ?? []).map((k) => k.cve_id));
        rows = rows.filter((r) => (r.cve_ids ?? []).some((c: string) => kevSet.has(c)));
    }
    const c = await withCorrelationCounts(requestOrg(req), rows);
    res.json({ findings: c.rows, correlation_error: c.correlation_error });
});

router.get('/findings/summary', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const supabase = getSupabase()!;
    const { data, error } = await supabase.from('vms_findings').select('scanner_severity, priority, status, cve_ids, due_at, source_class').eq('org_id', requestOrg(req)).limit(20000);
    if (error) { fail(res, error); return; }
    const rows = data ?? [];
    const open = rows.filter((r) => OPEN.includes(r.status));
    const tally = (xs: Record<string, unknown>[], k: string) => xs.reduce<Record<string, number>>((m, r) => { const v = String(r[k] ?? 'none'); m[v] = (m[v] ?? 0) + 1; return m; }, {});
    const cves = [...new Set(open.flatMap((r) => r.cve_ids ?? []))];
    const { data: kev } = cves.length ? await supabase.from('cve_intel').select('cve_id').in('cve_id', cves).eq('kev', true) : { data: [] };
    const kevSet = new Set((kev ?? []).map((k) => k.cve_id));
    const now = Date.now();
    res.json({
        open: open.length,
        by_severity: tally(open, 'scanner_severity'),
        by_priority: tally(open, 'priority'),
        by_status: tally(rows, 'status'),
        by_source: tally(open, 'source_class'),
        known_exploited_open: open.filter((r) => (r.cve_ids ?? []).some((c: string) => kevSet.has(c))).length,
        overdue: open.filter((r) => r.due_at && Date.parse(r.due_at) < now).length,
    });
});

router.get('/findings/:id', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Finding not found' }); return; }
    const supabase = getSupabase()!;
    const org = requestOrg(req);
    const { data: f, error } = await supabase.from('vms_findings').select('*').eq('id', req.params.id).eq('org_id', org).maybeSingle();
    if (error) { fail(res, error); return; }
    if (!f) { res.status(404).json({ error: 'Finding not found' }); return; }
    const [evidence, events, intel, asset, tasks] = await Promise.all([
        supabase.from('vms_finding_evidence').select('*').eq('finding_id', f.id).order('observed_at', { ascending: false }).limit(50),
        supabase.from('vms_finding_events').select('*').eq('finding_id', f.id).order('at', { ascending: true }).limit(300),
        f.cve_ids?.length ? supabase.from('cve_intel').select('*').in('cve_id', f.cve_ids) : Promise.resolve({ data: [] }),
        f.asset_id ? supabase.from('vms_assets').select('id, value, asset_type, exposure, criticality, owner, ips').eq('id', f.asset_id).eq('org_id', org).maybeSingle() : Promise.resolve({ data: null }),
        supabase.from('vms_remediation_tasks').select('*').eq('finding_id', f.id).order('created_at'),
    ]);
    let correlated: unknown[] = [];
    let correlation_error: string | null = null;
    try { correlated = (await correlateFindings(org, [f as CorrFinding])).get(f.id) ?? []; } catch { correlation_error = 'Correlations could not be computed'; }
    // The scanner's own CVSS (P22): score from the finding, version and vector from the newest
    // detection that reported them. Separate from risk_score, NovrSOC's contextual score.
    const cvssEv = (evidence.data ?? []).find((e) => { const x = e.evidence as Record<string, unknown> | null; return !!(x && (x.cvss_version || x.cvss_vector)); });
    const cx = (cvssEv?.evidence ?? {}) as Record<string, unknown>;
    const scanner_cvss = f.scanner_cvss === null && !cvssEv ? null : {
        score: f.scanner_cvss === null ? null : Number(f.scanner_cvss), version: (cx.cvss_version as string | undefined) ?? null, vector: (cx.cvss_vector as string | undefined) ?? null,
        source: cvssEv?.source ?? (f.detected_by ?? [])[0] ?? null, observed_at: cvssEv?.observed_at ?? null,
    };
    res.json({ finding: f, scanner_cvss, evidence: evidence.data ?? [], events: events.data ?? [], cve_intel: intel.data ?? [], asset: asset.data ?? null, tasks: tasks.data ?? [], correlated, correlation_error });
});

const Patch = z.object({
    status: z.enum(FINDING_STATUSES).optional(),
    note: z.string().trim().max(2000).optional(),
    owner: z.string().trim().max(200).nullable().optional(),
    due_at: z.string().refine((v) => !Number.isNaN(Date.parse(v)), 'date').nullable().optional(),
}).strict();
router.patch('/findings/:id', requirePermission('vms:manage'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Finding not found' }); return; }
    const p = Patch.safeParse(req.body);
    if (!p.success || (p.data.status === undefined && p.data.owner === undefined && p.data.due_at === undefined)) { res.status(400).json({ error: 'Body may hold status, note, owner, due_at' }); return; }
    const org = requestOrg(req);
    const supabase = getSupabase()!;
    const { data: before } = await supabase.from('vms_findings').select('id, owner, due_at').eq('id', req.params.id).eq('org_id', org).maybeSingle();
    if (!before) { res.status(404).json({ error: 'Finding not found' }); return; }
    if (p.data.status) {
        const r = await setFindingStatus(org, before.id, actor(req), p.data.status, p.data.note ?? null);
        if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
    }
    const upd: Record<string, unknown> = {};
    if (p.data.owner !== undefined) upd.owner = p.data.owner || null;
    if (p.data.due_at !== undefined) { upd.due_at = p.data.due_at ? new Date(p.data.due_at).toISOString() : null; upd.due_manual = p.data.due_at !== null; }
    if (Object.keys(upd).length) {
        await supabase.from('vms_findings').update({ ...upd, updated_at: new Date().toISOString() }).eq('id', before.id).eq('org_id', org);
        if ('owner' in upd) await addEvent(org, before.id, actor(req), 'owner', before.owner, upd.owner as string | null);
        if ('due_at' in upd) await addEvent(org, before.id, actor(req), 'due', before.due_at, upd.due_at as string | null);
    }
    logAudit({ user: actor(req), action: 'VMS_FINDING_UPDATED', resource: 'vms_finding', resource_id: before.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: JSON.stringify(p.data).slice(0, 200) });
    const { data } = await supabase.from('vms_findings').select('*').eq('id', before.id).maybeSingle();
    res.json({ finding: data });
});

router.post('/findings/:id/notes', requirePermission('vms:manage'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Finding not found' }); return; }
    const note = typeof req.body?.note === 'string' ? req.body.note.trim() : '';
    if (!note || note.length > 4000) { res.status(400).json({ error: 'note is required (up to 4000 characters)' }); return; }
    const org = requestOrg(req);
    const { data: f } = await getSupabase()!.from('vms_findings').select('id').eq('id', req.params.id).eq('org_id', org).maybeSingle();
    if (!f) { res.status(404).json({ error: 'Finding not found' }); return; }
    await addEvent(org, f.id, actor(req), 'note', null, null, note);
    res.status(201).json({ ok: true });
});

router.post('/findings/:id/verify', requirePermission('vms:scan'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Finding not found' }); return; }
    const org = requestOrg(req);
    const supabase = getSupabase()!;
    const { data: f } = await supabase.from('vms_findings').select('*').eq('id', req.params.id).eq('org_id', org).maybeSingle();
    if (!f) { res.status(404).json({ error: 'Finding not found' }); return; }
    // Shared with 'verification' schedules (services/vmsVerification.ts, phase P27).
    const r = await requestVerification(org, actor(req), f);
    if (!r.ok) { res.status(r.status).json({ error: r.error, ...(r.retry_at ? { retry_at: r.retry_at } : {}) }); return; }
    if (!r.queued) { res.json({ queued: false, message: r.message }); return; }
    res.status(201).json({ queued: true, scan: r.job });
});

router.post('/findings/:id/case', requirePermission('cases:write'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Finding not found' }); return; }
    const org = requestOrg(req);
    const supabase = getSupabase()!;
    const { data: f } = await supabase.from('vms_findings').select('*').eq('id', req.params.id).eq('org_id', org).maybeSingle();
    if (!f) { res.status(404).json({ error: 'Finding not found' }); return; }
    const sev = f.scanner_severity === 'info' ? 'low' : f.scanner_severity;
    const r = await createCase({
        org_id: org, source: 'finding', source_id: f.id, severity: sev, title: `${f.title} on ${f.asset_value}`,
        description: `Promoted from VMS finding ${f.id} (${f.priority ?? 'unprioritised'}, risk ${f.risk_score ?? '—'}). ${f.cve_ids?.length ? `CVEs: ${f.cve_ids.join(', ')}.` : ''}`,
        agent_name: f.source_class === 'wazuh' ? f.asset_value : null, tags: ['vms-finding', ...(f.cve_ids ?? []).slice(0, 5)],
    }, actor(req));
    if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
    if (!f.case_id) {
        await supabase.from('vms_findings').update({ case_id: r.case.id }).eq('id', f.id);
        await addEvent(org, f.id, actor(req), 'case_link', null, r.case.id, `Case ${r.case.case_number}`);
    }
    if (r.created) await addTimeline(r.case.id, actor(req), `Opened from VMS finding: ${f.title}`);
    res.status(r.created ? 201 : 200).json({ created: r.created, case: { id: r.case.id, case_number: r.case.case_number } });
});

const NewTask = z.object({ title: z.string().trim().min(3).max(300), details: z.string().trim().max(4000).optional(), owner: z.string().trim().max(200).optional(), due_at: z.string().refine((v) => !Number.isNaN(Date.parse(v))).optional(), ai_artifact_id: z.string().uuid().optional() }).strict();
router.post('/findings/:id/tasks', requirePermission('vms:manage'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Finding not found' }); return; }
    const p = NewTask.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: 'Body must be { title, details?, owner?, due_at?, ai_artifact_id? }' }); return; }
    const org = requestOrg(req);
    const { data: f } = await getSupabase()!.from('vms_findings').select('id').eq('id', req.params.id).eq('org_id', org).maybeSingle();
    if (!f) { res.status(404).json({ error: 'Finding not found' }); return; }
    const { data, error } = await getSupabase()!.from('vms_remediation_tasks').insert({ org_id: org, finding_id: f.id, title: p.data.title, details: p.data.details ?? null, owner: p.data.owner ?? null, due_at: p.data.due_at ? new Date(p.data.due_at).toISOString() : null, ai_artifact_id: p.data.ai_artifact_id ?? null, created_by: actor(req) }).select('*').single();
    if (error) { fail(res, error); return; }
    await addEvent(org, f.id, actor(req), 'task', null, data.title);
    res.status(201).json({ task: data });
});

const TaskPatch = z.object({ status: z.enum(['todo', 'doing', 'done', 'cancelled']).optional(), owner: z.string().trim().max(200).nullable().optional(), due_at: z.string().refine((v) => !Number.isNaN(Date.parse(v))).nullable().optional() }).strict();
router.patch('/tasks/:id', requirePermission('vms:manage'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Task not found' }); return; }
    const p = TaskPatch.safeParse(req.body);
    if (!p.success || !Object.keys(p.data).length) { res.status(400).json({ error: 'Body may hold status, owner, due_at' }); return; }
    const upd: Record<string, unknown> = { ...p.data };
    if (p.data.due_at) upd.due_at = new Date(p.data.due_at).toISOString();
    if (p.data.status === 'done') upd.completed_at = new Date().toISOString();
    const { data, error } = await getSupabase()!.from('vms_remediation_tasks').update(upd).eq('id', req.params.id).eq('org_id', requestOrg(req)).select('*').maybeSingle();
    if (error) { fail(res, error); return; }
    if (!data) { res.status(404).json({ error: 'Task not found' }); return; }
    // Finishing every task does not close the finding: only a rescan (or Wazuh) can verify it.
    res.json({ task: data });
});

router.get('/remediation', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const org = requestOrg(req);
    const supabase = getSupabase()!;
    const { data, error } = await supabase.from('vms_findings').select(LIST_COLUMNS).eq('org_id', org).in('status', OPEN)
        .order('priority', { ascending: true }).order('due_at', { ascending: true, nullsFirst: false }).limit(500);
    if (error) { fail(res, error); return; }
    const ids = (data ?? []).map((f) => f.id);
    const { data: tasks } = ids.length ? await supabase.from('vms_remediation_tasks').select('*').in('finding_id', ids).neq('status', 'cancelled') : { data: [] };
    const now = Date.now();
    res.json({
        items: (data ?? []).map((f) => ({ ...f, overdue: !!f.due_at && Date.parse(f.due_at) < now, tasks: (tasks ?? []).filter((t) => t.finding_id === f.id) })),
        can_manage: hasPermission(req.user?.role, 'vms:manage'),
    });
});

// ── Wazuh Vulnerabilities page (P16) ───────────────────────────────────────────────────────
// The page reads the shared findings the hourly sync stores (source_class 'wazuh'), scoped to the
// caller's organisation, instead of querying the indexer itself. Freshness comes with the data:
// before a complete sync there is no summary at all (never "0 vulnerabilities"), and an
// incomplete latest sync is named, with the time the data is from.
export const WAZUH_STALE_HOURS = 3;
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
router.get('/wazuh/vulnerabilities', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const org = requestOrg(req);
    const supabase = getSupabase()!;
    // One endpoint, by its asset id (agent names keep Wazuh's case in findings but not in assets).
    const assetId = typeof req.query.asset_id === 'string' && req.query.asset_id ? req.query.asset_id : null;
    if (assetId && !isUuid(assetId)) { res.status(400).json({ error: 'asset_id must be an endpoint asset id' }); return; }
    const severity = typeof req.query.severity === 'string' && (SEVERITIES as readonly string[]).includes(req.query.severity) ? req.query.severity : null;
    let list = supabase.from('vms_findings').select(LIST_COLUMNS).eq('org_id', org).eq('source_class', 'wazuh').in('status', OPEN);
    let all = supabase.from('vms_findings').select('scanner_severity').eq('org_id', org).eq('source_class', 'wazuh').in('status', OPEN);
    if (assetId) { list = list.eq('asset_id', assetId); all = all.eq('asset_id', assetId); }
    if (severity) list = list.eq('scanner_severity', severity);
    const [sync, rows, sev, endpoints] = await Promise.all([
        supabase.from('vms_wazuh_sync').select('last_synced_at, last_result').eq('org_id', org).maybeSingle(),
        list.order('scanner_cvss', { ascending: false, nullsFirst: false }).order('risk_score', { ascending: false, nullsFirst: false }).limit(100),
        all.limit(20_000),
        supabase.from('vms_assets').select('id, value, wazuh_agent_id, alive, status, last_seen').eq('org_id', org).eq('asset_type', 'endpoint').order('value').limit(1000),
    ]);
    if (rows.error || sev.error) { fail(res, (rows.error ?? sev.error)!); return; }
    const f = wazuhFreshness(sync.error ? null : sync.data);
    const age = f.last_complete_at ? (Date.now() - Date.parse(f.last_complete_at)) / 3_600_000 : null;
    const state = !f.last_attempt_at ? 'not_synced' : !f.last_complete_at ? 'never_complete' : f.complete === false ? 'incomplete' : age! > WAZUH_STALE_HOURS ? 'stale' : 'fresh';
    // The package and version Wazuh last reported, from the newest Wazuh evidence of each finding.
    const ids = (rows.data ?? []).map((r) => r.id);
    const { data: ev } = ids.length ? await supabase.from('vms_finding_evidence').select('finding_id, observed_at, evidence').eq('org_id', org).eq('source', 'wazuh').in('finding_id', ids).order('observed_at', { ascending: false }).limit(2000) : { data: [] as { finding_id: string; evidence: unknown }[] };
    const pkg = new Map<string, { name: string | null; version: string | null }>();
    for (const e of ev ?? []) if (!pkg.has(e.finding_id)) { const p = (e.evidence as { package?: { name?: string; version?: string } } | null)?.package; pkg.set(e.finding_id, { name: p?.name ?? null, version: p?.version ?? null }); }
    const c = await withCorrelationCounts(org, rows.data ?? []);
    const counts: Record<string, number> = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
    for (const r of sev.data ?? []) counts[r.scanner_severity] = (counts[r.scanner_severity] ?? 0) + 1;
    const total = (sev.data ?? []).length;
    res.json({
        source: 'vms_findings (Wazuh sync)', state, freshness: f, stale_after_hours: WAZUH_STALE_HOURS,
        // No complete sync yet: there is nothing to count, which is not the same as zero.
        summary: f.last_complete_at ? { ...counts, total } : null,
        vulnerabilities: c.rows.map((r) => ({ ...r, package: pkg.get(r.id)?.name ?? null, package_version: pkg.get(r.id)?.version ?? null })),
        shown: (rows.data ?? []).length,
        endpoints: (endpoints.data ?? []).map((e) => ({ id: e.id, name: e.value, wazuh_agent_id: e.wazuh_agent_id, alive: e.alive, status: e.status, last_seen: e.last_seen })),
        correlation_error: c.correlation_error,
    });
});

export default router;
