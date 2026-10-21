// /api/client/vms — the client portal's view of its own organisation (phase P21). Read-only.
//
// Every route needs vms:client (portal_user; staff hold it too, to preview the client view). The
// organisation is the token's org_id: for a client role resolveOrg ignores X-Org-Id, so a client
// can only ever read its own records. Responses carry what the client needs about its own assets,
// vulnerabilities, remediation and reports — and nothing about the SOC's operation: no scanner
// workers or engines, scan jobs, raw tool output, authorised scope, policies, audit entries, staff
// identities or internal notes.
//
//   GET /summary          headline figures, severity distribution, top findings and assets
//   GET /assets           assets with open-finding counts and highest risk
//   GET /findings         vulnerabilities (?status=open|resolved|all, ?severity=)
//   GET /findings/:id     one vulnerability: description, fix, CVE context, tasks, status history
//   GET /tasks            remediation tasks with their vulnerability
//   GET /report?days=30   the period report (services/vmsContinuous.ts periodReport)

import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { requirePermission, requestOrg } from '../lib/permissions';
import { getSupabase } from '../services/geoEnrichment';
import { isUuid } from '../services/cases';
import { periodReport } from '../services/vmsContinuous';

const router = Router();
const OPEN = ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened'];
const RESOLVED = ['verified', 'risk_accepted', 'false_positive'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const FINDING_COLUMNS = 'id, asset_id, asset_value, port, protocol, title, cve_ids, scanner_severity, scanner_cvss, risk_score, priority, status, due_at, first_seen, last_seen, verified_at, source_class';
/** Client wording for the lifecycle; the stored status is never changed here. */
export const CLIENT_STATUS: Record<string, string> = {
    open: 'Open', reopened: 'Reopened', acknowledged: 'Confirmed', in_progress: 'Being fixed', fixed_pending_verification: 'Fix awaiting verification',
    verified: 'Resolved (verified)', risk_accepted: 'Risk accepted', false_positive: 'Not a vulnerability',
};
const DAY = 86_400_000;
const can = requirePermission('vms:client');
const db = () => getSupabase();

router.get('/summary', can, async (req: AuthRequest, res) => {
    const supabase = db();
    if (!supabase) { res.status(503).json({ error: 'Not available' }); return; }
    const org = requestOrg(req);
    const since30 = new Date(Date.now() - 30 * DAY).toISOString();
    const [assets, open, verified, tasks] = await Promise.all([
        supabase.from('vms_assets').select('id, value, asset_type, exposure, criticality').eq('org_id', org).eq('status', 'active').limit(10_000),
        supabase.from('vms_findings').select(FINDING_COLUMNS).eq('org_id', org).in('status', OPEN).limit(20_000),
        supabase.from('vms_findings').select('id', { count: 'exact', head: true }).eq('org_id', org).gte('verified_at', since30),
        supabase.from('vms_remediation_tasks').select('status, due_at').eq('org_id', org).limit(5000),
    ]);
    if (assets.error || open.error) { res.status(502).json({ error: 'Could not read your vulnerability records' }); return; }
    const rows = open.data ?? [];
    const cves = [...new Set(rows.flatMap((f) => f.cve_ids ?? []))];
    const kev = new Set<string>();
    for (let i = 0; i < cves.length; i += 200) {
        const { data } = await supabase.from('cve_intel').select('cve_id').eq('kev', true).in('cve_id', cves.slice(i, i + 200));
        for (const k of data ?? []) kev.add(k.cve_id);
    }
    const internet = new Set((assets.data ?? []).filter((a) => a.exposure === 'internet').map((a) => a.id));
    const vulns = rows.filter((f) => f.scanner_severity !== 'info');
    const scored = vulns.filter((f) => typeof f.risk_score === 'number').map((f) => Number(f.risk_score));
    const now = Date.now();
    type PerAsset = { asset_id: string; value: string; open: number; by_severity: Record<string, number>; max_risk: number };
    const per = new Map<string, PerAsset>();
    for (const f of rows) {
        if (!f.asset_id) continue;
        const e: PerAsset = per.get(f.asset_id) ?? { asset_id: f.asset_id, value: f.asset_value, open: 0, by_severity: {}, max_risk: 0 };
        e.open++; e.by_severity[f.scanner_severity] = (e.by_severity[f.scanner_severity] ?? 0) + 1; e.max_risk = Math.max(e.max_risk, Number(f.risk_score ?? 0));
        per.set(f.asset_id, e);
    }
    const W: Record<string, number> = { critical: 1000, high: 100, medium: 10, low: 1 };
    const weight = (x: { by_severity: Record<string, number> }) => Object.entries(x.by_severity).reduce((n, [s, c]) => n + (W[s] ?? 0) * c, 0);
    res.json({
        kpis: {
            assets: (assets.data ?? []).length,
            internet_facing: internet.size,
            open_vulnerabilities: vulns.length,
            critical: rows.filter((f) => f.scanner_severity === 'critical').length,
            known_exploited: rows.filter((f) => (f.cve_ids ?? []).some((c: string) => kev.has(c))).length,
            overdue: rows.filter((f) => f.due_at && Date.parse(f.due_at) < now).length,
            resolved_30_days: verified.count ?? 0,
            risk_mean: scored.length ? Math.round((scored.reduce((a, b) => a + b, 0) / scored.length) * 10) / 10 : null,
            open_tasks: (tasks.data ?? []).filter((t) => t.status === 'todo' || t.status === 'doing').length,
        },
        severity: Object.fromEntries(SEVERITIES.map((s) => [s, rows.filter((f) => f.scanner_severity === s).length])),
        by_status: Object.fromEntries(OPEN.map((s) => [s, rows.filter((f) => f.status === s).length])),
        top_findings: [...vulns].sort((a, b) => Number(b.risk_score ?? 0) - Number(a.risk_score ?? 0)).slice(0, 8)
            .map((f) => ({ id: f.id, title: f.title, asset_value: f.asset_value, severity: f.scanner_severity, priority: f.priority, risk_score: f.risk_score, due_at: f.due_at, known_exploited: (f.cve_ids ?? []).some((c: string) => kev.has(c)), internet: !!f.asset_id && internet.has(f.asset_id) })),
        top_assets: [...per.values()].sort((a, b) => weight(b) - weight(a) || b.max_risk - a.max_risk).slice(0, 8),
    });
});

router.get('/assets', can, async (req: AuthRequest, res) => {
    const supabase = db();
    if (!supabase) { res.status(503).json({ error: 'Not available' }); return; }
    const org = requestOrg(req);
    const [assets, open] = await Promise.all([
        supabase.from('vms_assets').select('id, value, asset_type, exposure, criticality, owner, hostnames, ips, first_seen, last_seen, status').eq('org_id', org).eq('status', 'active').order('last_seen', { ascending: false }).limit(5000),
        supabase.from('vms_findings').select('asset_id, scanner_severity, risk_score').eq('org_id', org).in('status', OPEN).not('asset_id', 'is', null).limit(20_000),
    ]);
    if (assets.error) { res.status(502).json({ error: 'Could not read your assets' }); return; }
    const per = new Map<string, { open: number; by_severity: Record<string, number>; max_risk: number | null }>();
    for (const f of open.data ?? []) {
        const e: { open: number; by_severity: Record<string, number>; max_risk: number | null } = per.get(f.asset_id) ?? { open: 0, by_severity: {}, max_risk: null };
        e.open++; e.by_severity[f.scanner_severity] = (e.by_severity[f.scanner_severity] ?? 0) + 1;
        if (typeof f.risk_score === 'number') e.max_risk = Math.max(e.max_risk ?? 0, f.risk_score);
        per.set(f.asset_id, e);
    }
    res.json({ assets: (assets.data ?? []).map((a) => ({ ...a, findings: per.get(a.id) ?? { open: 0, by_severity: {}, max_risk: null } })) });
});

router.get('/findings', can, async (req: AuthRequest, res) => {
    const supabase = db();
    if (!supabase) { res.status(503).json({ error: 'Not available' }); return; }
    const status = req.query.status === 'resolved' ? RESOLVED : req.query.status === 'all' ? [...OPEN, ...RESOLVED] : OPEN;
    let q = supabase.from('vms_findings').select(FINDING_COLUMNS).eq('org_id', requestOrg(req)).in('status', status);
    if (typeof req.query.severity === 'string' && SEVERITIES.includes(req.query.severity)) q = q.eq('scanner_severity', req.query.severity);
    if (typeof req.query.asset_id === 'string' && isUuid(req.query.asset_id)) q = q.eq('asset_id', req.query.asset_id);
    const { data, error } = await q.order('risk_score', { ascending: false, nullsFirst: false }).limit(2000);
    if (error) { res.status(502).json({ error: 'Could not read your vulnerabilities' }); return; }
    res.json({ findings: (data ?? []).map((f) => ({ ...f, status_label: CLIENT_STATUS[f.status] ?? f.status })) });
});

router.get('/findings/:id', can, async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Not found' }); return; }
    const supabase = db();
    if (!supabase) { res.status(503).json({ error: 'Not available' }); return; }
    const org = requestOrg(req);
    const { data: f } = await supabase.from('vms_findings').select(`${FINDING_COLUMNS}, description, remediation, references_urls`).eq('id', req.params.id).eq('org_id', org).maybeSingle();
    if (!f) { res.status(404).json({ error: 'Not found' }); return; }
    const [intel, tasks, events, cvssEv] = await Promise.all([
        f.cve_ids?.length ? supabase.from('cve_intel').select('cve_id, description, cvss_score, epss_score, kev, kev_date_added, kev_required_action').in('cve_id', f.cve_ids) : Promise.resolve({ data: [] }),
        supabase.from('vms_remediation_tasks').select('id, title, status, owner, due_at, completed_at').eq('finding_id', f.id).eq('org_id', org).neq('status', 'cancelled').order('created_at'),
        // Status changes only, without who made them or internal notes.
        supabase.from('vms_finding_events').select('at, action, from_value, to_value').eq('finding_id', f.id).eq('org_id', org).in('action', ['detected', 'status', 'verified', 'reopened']).order('at').limit(200),
        // Only the scanner's CVSS version and vector are read from the evidence; never the raw output.
        supabase.from('vms_finding_evidence').select('source, evidence').eq('finding_id', f.id).eq('org_id', org).order('observed_at', { ascending: false }).limit(20),
    ]);
    const cx = ((cvssEv.data ?? []).map((e) => e.evidence as Record<string, unknown> | null).find((x) => x && (x.cvss_version || x.cvss_vector)) ?? {}) as Record<string, unknown>;
    res.json({ finding: { ...f, status_label: CLIENT_STATUS[f.status] ?? f.status }, scanner_cvss: { score: f.scanner_cvss === null ? null : Number(f.scanner_cvss), version: (cx.cvss_version as string | undefined) ?? null, vector: (cx.cvss_vector as string | undefined) ?? null }, cve_intel: intel.data ?? [], tasks: tasks.data ?? [], history: (events.data ?? []).map((e) => ({ at: e.at, action: e.action, from: e.from_value ? CLIENT_STATUS[e.from_value] ?? e.from_value : null, to: e.to_value ? CLIENT_STATUS[e.to_value] ?? e.to_value : null })) });
});

router.get('/tasks', can, async (req: AuthRequest, res) => {
    const supabase = db();
    if (!supabase) { res.status(503).json({ error: 'Not available' }); return; }
    const org = requestOrg(req);
    const { data: tasks, error } = await supabase.from('vms_remediation_tasks').select('id, finding_id, title, status, owner, due_at, completed_at, created_at').eq('org_id', org).neq('status', 'cancelled').order('created_at', { ascending: false }).limit(2000);
    if (error) { res.status(/vms_remediation_tasks/.test(error.message) ? 503 : 502).json({ error: 'Could not read remediation tasks' }); return; }
    const ids = [...new Set((tasks ?? []).map((t) => t.finding_id))];
    const findings = new Map<string, Record<string, unknown>>();
    for (let i = 0; i < ids.length; i += 200) {
        const { data } = await supabase.from('vms_findings').select('id, title, asset_value, scanner_severity, priority, status').eq('org_id', org).in('id', ids.slice(i, i + 200));
        for (const x of data ?? []) findings.set(x.id, { ...x, status_label: CLIENT_STATUS[x.status] ?? x.status });
    }
    const now = Date.now();
    res.json({ tasks: (tasks ?? []).map((t) => ({ ...t, overdue: (t.status === 'todo' || t.status === 'doing') && !!t.due_at && Date.parse(t.due_at) < now, finding: findings.get(t.finding_id) ?? null })) });
});

router.get('/report', can, async (req: AuthRequest, res) => {
    const days = Math.min(Math.max(Math.round(Number(req.query.days) || 30), 7), 365);
    try { res.json(await periodReport(requestOrg(req), days)); } catch { res.status(502).json({ error: 'Could not build the report' }); }
});

export default router;
