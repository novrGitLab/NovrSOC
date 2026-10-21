// /api/vms — read-only aggregations for the redesigned VMS (phase P20). Behind requireAuth; every
// route resolves the caller's organisation (requirePermission('vms:read')) and reads only its rows.
//
//   GET /dashboard?days=30   KPIs, chart series and lists for the VMS dashboard, with definitions
//   GET /risk?days=90        risk distribution, likelihood × impact matrix, EPSS/KEV exposure, the
//                            prioritised queue (with each finding's stored risk factors) and the model
//   GET /audit?days=30       VMS audit entries (incl. staff access to this organisation's VMS data) and
//                            finding history for this organisation (read-only)
//   GET /tasks               remediation tasks with their findings, for the task workspace
//   GET /ai-plans            AI artifacts on this organisation's findings (drafts, not verified advice)
//
// Nothing here writes. Every figure is counted from stored records; where a series needs history
// that was not recorded (risk score before the P20 snapshot columns), it is empty — never estimated.

import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { requirePermission, requestOrg } from '../lib/permissions';
import { getSupabase } from '../services/geoEnrichment';
import { loadScannerStatus } from '../services/vmsWorkers';
import { WEIGHTS, DUE_DAYS } from '../lib/riskScore';
import { engineStatus } from './vmsOperations';

const router = Router();
const OPEN = ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const DAY = 86_400_000;
const isoDay = (t: number | string) => new Date(t).toISOString().slice(0, 10);
const clampDays = (v: unknown, d: number, max = 365) => Math.min(Math.max(Math.round(Number(v) || d), 7), max);
const tally = <T>(rows: T[], key: (r: T) => string | null | undefined) => rows.reduce<Record<string, number>>((m, r) => { const k = key(r); if (k) m[k] = (m[k] ?? 0) + 1; return m; }, {});
/** Every day from `since` to today, so a chart shows zero days as zero rather than skipping them. */
const dayRange = (since: number, now: number) => { const out: string[] = []; for (let t = since; t <= now; t += DAY) out.push(isoDay(t)); return out; };
const NO_ASSESSMENT = new Set(['unreachable', 'insufficient_evidence', 'no_route']);

type Finding = { id: string; title: string; asset_id: string | null; asset_value: string; scanner_severity: string; scanner_cvss: number | null; priority: string | null; risk_score: number | null; status: string; first_seen: string; last_seen: string; due_at: string | null; cve_ids: string[] | null; owner?: string | null; risk_factors?: Record<string, unknown> | null; evidence_class?: string | null; source_class?: string | null; detected_by?: string[] | null };

// ── Dashboard ──────────────────────────────────────────────────────────────────────────────────
router.get('/dashboard', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const org = requestOrg(req);
    const days = clampDays(req.query.days, 30);
    const now = Date.now();
    const since = new Date(now - (days - 1) * DAY);
    since.setUTCHours(0, 0, 0, 0);
    const sinceIso = since.toISOString();
    const [assetsR, openR, statusR, newR, verifiedR, tasksR, jobsR, activeR, snapsR, assetEvR, findEvR, scanner] = await Promise.all([
        supabase.from('vms_assets').select('id, value, asset_type, exposure, criticality, status').eq('org_id', org).eq('status', 'active').limit(10_000),
        supabase.from('vms_findings').select('id, title, asset_id, asset_value, scanner_severity, scanner_cvss, priority, risk_score, status, first_seen, last_seen, due_at, cve_ids, owner').eq('org_id', org).in('status', OPEN).limit(20_000),
        supabase.from('vms_findings').select('status').eq('org_id', org).limit(50_000),
        supabase.from('vms_findings').select('first_seen, scanner_severity').eq('org_id', org).gte('first_seen', sinceIso).limit(20_000),
        supabase.from('vms_findings').select('verified_at').eq('org_id', org).gte('verified_at', sinceIso).limit(20_000),
        supabase.from('vms_remediation_tasks').select('id, title, status, owner, due_at, finding_id, created_at, completed_at').eq('org_id', org).limit(5000),
        supabase.from('vms_scan_jobs').select('id, kind, status, summary, requested_at, finished_at').eq('org_id', org).gte('requested_at', sinceIso).limit(5000),
        supabase.from('vms_scan_jobs').select('id, kind, status, targets, progress, requested_at, started_at, heartbeat_at, worker_id, purpose').eq('org_id', org).in('status', ['queued', 'running']).order('requested_at').limit(20),
        supabase.from('vms_risk_snapshots').select('*').eq('org_id', org).gte('day', isoDay(since.getTime())).order('day').limit(400),
        supabase.from('vms_asset_events').select('id, at, event, details, asset_id, vms_assets(value)').eq('org_id', org).order('at', { ascending: false }).limit(12),
        supabase.from('vms_finding_events').select('id, at, actor, action, from_value, to_value, details, finding_id').eq('org_id', org).order('at', { ascending: false }).limit(12),
        loadScannerStatus(),
    ]);
    if (openR.error || assetsR.error) { res.status(502).json({ error: 'Could not read VMS records' }); return; }
    const assets = assetsR.data ?? [];
    const assetById = new Map(assets.map((a) => [a.id, a]));
    const open = (openR.data ?? []) as Finding[];
    const nonInfo = open.filter((f) => f.scanner_severity !== 'info');
    const internet = (f: Finding) => !!f.asset_id && assetById.get(f.asset_id)?.exposure === 'internet';
    const criticalExposures = open.filter((f) => (f.scanner_severity === 'critical' || f.scanner_severity === 'high') && internet(f));
    const scored = nonInfo.filter((f) => typeof f.risk_score === 'number').map((f) => Number(f.risk_score));
    const tasks = tasksR.data ?? [];
    const overdueTasks = tasks.filter((t) => (t.status === 'todo' || t.status === 'doing') && t.due_at && Date.parse(t.due_at) < now);
    const overdueFindings = open.filter((f) => f.due_at && Date.parse(f.due_at) < now);
    const verifiedInWindow = (verifiedR.data ?? []).length;
    const engines = engineStatus(scanner.workers);

    // Series
    const range = dayRange(since.getTime(), now);
    const newByDay = Object.fromEntries(range.map((d) => [d, Object.fromEntries(SEVERITIES.map((s) => [s, 0]))])) as Record<string, Record<string, number>>;
    for (const f of newR.data ?? []) { const d = isoDay(f.first_seen); if (newByDay[d]) newByDay[d][f.scanner_severity] = (newByDay[d][f.scanner_severity] ?? 0) + 1; }
    const scanByDay = Object.fromEntries(range.map((d) => [d, { assessed: 0, inconclusive: 0, failed: 0, cancelled: 0, in_progress: 0 }])) as Record<string, Record<string, number>>;
    for (const j of jobsR.data ?? []) {
        const d = scanByDay[isoDay(j.requested_at)];
        if (!d) continue;
        const outcome = String((j.summary as { outcome?: string } | null)?.outcome ?? '');
        const k = j.status === 'succeeded' ? (NO_ASSESSMENT.has(outcome) ? 'inconclusive' : 'assessed') : j.status === 'failed' ? 'failed' : j.status === 'cancelled' ? 'cancelled' : 'in_progress';
        d[k]++;
    }
    const snaps = snapsR.data ?? [];

    // Highest-risk assets: severity-weighted open findings, then the highest risk score.
    const W: Record<string, number> = { critical: 1000, high: 100, medium: 10, low: 1 };
    const per = new Map<string, { asset_id: string; value: string; open: number; by_severity: Record<string, number>; weight: number; max_risk: number }>();
    for (const f of open) {
        if (!f.asset_id) continue;
        const e = per.get(f.asset_id) ?? { asset_id: f.asset_id, value: f.asset_value, open: 0, by_severity: {}, weight: 0, max_risk: 0 };
        e.open++; e.by_severity[f.scanner_severity] = (e.by_severity[f.scanner_severity] ?? 0) + 1; e.weight += W[f.scanner_severity] ?? 0; e.max_risk = Math.max(e.max_risk, Number(f.risk_score ?? 0));
        per.set(f.asset_id, e);
    }
    const findingTitle = new Map(open.map((f) => [f.id, f]));
    res.json({
        period: { days, from: sinceIso, to: new Date(now).toISOString() },
        kpis: {
            total_assets: assets.length,
            internet_facing_assets: assets.filter((a) => a.exposure === 'internet').length,
            open_findings: open.length,
            open_vulnerabilities: nonInfo.length,
            critical_open: open.filter((f) => f.scanner_severity === 'critical').length,
            critical_exposures: criticalExposures.length,
            overdue_tasks: overdueTasks.length,
            overdue_findings: overdueFindings.length,
            active_scans: (activeR.data ?? []).length,
            new_findings: (newR.data ?? []).length,
            verified_in_period: verifiedInWindow,
            remediation_rate: verifiedInWindow + nonInfo.length ? Math.round((verifiedInWindow / (verifiedInWindow + nonInfo.length)) * 100) : null,
            risk_mean: scored.length ? Math.round((scored.reduce((a, b) => a + b, 0) / scored.length) * 10) / 10 : null,
            risk_max: scored.length ? Math.max(...scored) : null,
            engines_available: engines.filter((e) => e.state === 'available').length,
            engines_total: engines.length,
        },
        definitions: {
            open_vulnerabilities: 'Open findings excluding informational ones',
            critical_exposures: 'Open critical or high findings on internet-facing assets',
            remediation_rate: 'Findings verified fixed in the period, as a share of those verified plus the non-informational findings still open',
            risk_mean: 'Mean risk score (0–100, lib/riskScore.ts) of open non-informational findings',
            overdue_tasks: 'Remediation tasks not done whose due date has passed',
        },
        charts: {
            severity: Object.fromEntries(SEVERITIES.map((s) => [s, open.filter((f) => f.scanner_severity === s).length])),
            status: tally(statusR.data ?? [], (r) => r.status),
            assets_by_criticality: tally(assets, (a) => a.criticality),
            assets_by_exposure: tally(assets, (a) => a.exposure),
            assets_by_type: tally(assets, (a) => a.asset_type),
            new_findings: range.map((d) => ({ day: d, ...newByDay[d] })),
            scan_activity: range.map((d) => ({ day: d, ...scanByDay[d] })),
            // Only days whose snapshot recorded the value (P20 onwards); never interpolated.
            risk: snaps.filter((s) => s.risk_mean !== null && s.risk_mean !== undefined).map((s) => ({ day: s.day, risk_mean: Number(s.risk_mean), risk_max: s.risk_max })),
            exposure: snaps.map((s) => ({ day: s.day, critical_exposures: s.critical_exposures ?? null, internet_open: s.internet_open, kev_open: s.kev_open })),
            tasks: tally(tasks, (t) => t.status),
        },
        lists: {
            recent_critical: open.filter((f) => f.scanner_severity === 'critical' || f.scanner_severity === 'high').sort((a, b) => Date.parse(b.first_seen) - Date.parse(a.first_seen)).slice(0, 8)
                .map((f) => ({ id: f.id, title: f.title, asset_id: f.asset_id, asset_value: f.asset_value, severity: f.scanner_severity, priority: f.priority, risk_score: f.risk_score, first_seen: f.first_seen, internet: internet(f) })),
            highest_risk_assets: [...per.values()].sort((a, b) => b.weight - a.weight || b.max_risk - a.max_risk).slice(0, 8)
                .map(({ weight: _w, ...x }) => ({ ...x, exposure: assetById.get(x.asset_id)?.exposure ?? null, criticality: assetById.get(x.asset_id)?.criticality ?? null, asset_type: assetById.get(x.asset_id)?.asset_type ?? null })),
            active_scans: activeR.data ?? [],
            overdue_tasks: overdueTasks.sort((a, b) => Date.parse(a.due_at!) - Date.parse(b.due_at!)).slice(0, 8)
                .map((t) => ({ ...t, finding: findingTitle.get(t.finding_id) ? { id: t.finding_id, title: findingTitle.get(t.finding_id)!.title, asset_value: findingTitle.get(t.finding_id)!.asset_value, priority: findingTitle.get(t.finding_id)!.priority } : null })),
            activity: [
                ...(assetEvR.data ?? []).map((e) => ({ at: e.at, kind: 'asset' as const, event: e.event, subject: (e.vms_assets as { value?: string } | null)?.value ?? null, subject_id: e.asset_id, details: e.details })),
                ...(findEvR.data ?? []).map((e) => ({ at: e.at, kind: 'finding' as const, event: e.action, subject: findingTitle.get(e.finding_id)?.title ?? null, subject_id: e.finding_id, details: { actor: e.actor, from: e.from_value, to: e.to_value, note: e.details } })),
            ].sort((a, b) => Date.parse(b.at) - Date.parse(a.at)).slice(0, 15),
        },
        engines,
        worker_presence: { state: scanner.state, online_workers: scanner.online_workers, last_seen_at: scanner.last_seen_at },
    });
});

// ── Risk & prioritisation ──────────────────────────────────────────────────────────────────────
export function likelihoodOf(kev: boolean, epss: number | null): 'kev' | 'epss_high' | 'epss_low' | 'unknown' {
    if (kev) return 'kev';
    if (epss === null) return 'unknown';
    return epss >= 0.1 ? 'epss_high' : 'epss_low';
}
router.get('/risk', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const org = requestOrg(req);
    const days = clampDays(req.query.days, 90);
    const now = Date.now();
    const [findR, assetsR, snapsR] = await Promise.all([
        supabase.from('vms_findings').select('*').eq('org_id', org).in('status', OPEN).limit(20_000),
        supabase.from('vms_assets').select('id, exposure, criticality, asset_type').eq('org_id', org).limit(10_000),
        supabase.from('vms_risk_snapshots').select('*').eq('org_id', org).gte('day', isoDay(now - days * DAY)).order('day').limit(400),
    ]);
    if (findR.error) { res.status(502).json({ error: 'Could not read findings' }); return; }
    const open = (findR.data ?? []) as Finding[];
    const assets = new Map((assetsR.data ?? []).map((a) => [a.id, a]));
    const cves = [...new Set(open.flatMap((f) => f.cve_ids ?? []))];
    const intel = new Map<string, { kev: boolean; epss: number | null; cvss: number | null }>();
    for (let i = 0; i < cves.length; i += 200) {
        const { data } = await supabase.from('cve_intel').select('cve_id, kev, epss_score, cvss_score').in('cve_id', cves.slice(i, i + 200));
        for (const c of data ?? []) intel.set(c.cve_id, { kev: !!c.kev, epss: c.epss_score !== null ? Number(c.epss_score) : null, cvss: c.cvss_score !== null ? Number(c.cvss_score) : null });
    }
    const enriched = open.map((f) => {
        const ci = (f.cve_ids ?? []).map((c) => intel.get(c)).filter((x): x is NonNullable<typeof x> => !!x);
        const kev = ci.some((c) => c.kev);
        const epssVals = ci.map((c) => c.epss).filter((x): x is number => x !== null);
        const epss = epssVals.length ? Math.max(...epssVals) : null;
        const a = f.asset_id ? assets.get(f.asset_id) : undefined;
        return { ...f, kev, epss, exposure: a?.exposure ?? 'unknown', criticality: a?.criticality ?? null, overdue: !!f.due_at && Date.parse(f.due_at) < now, likelihood: likelihoodOf(kev, epss) };
    });
    const bands = [{ key: '80-100', min: 80, max: 100 }, { key: '60-79', min: 60, max: 79 }, { key: '35-59', min: 35, max: 59 }, { key: '0-34', min: 0, max: 34 }];
    const matrix: Record<string, Record<string, number>> = {};
    for (const l of ['kev', 'epss_high', 'epss_low', 'unknown']) matrix[l] = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
    for (const f of enriched) matrix[f.likelihood][f.scanner_severity] = (matrix[f.likelihood][f.scanner_severity] ?? 0) + 1;
    const withCve = enriched.filter((f) => (f.cve_ids ?? []).length);
    const prioRank: Record<string, number> = { P1: 0, P2: 1, P3: 2, P4: 3 };
    res.json({
        model: {
            weights: WEIGHTS, due_days: DUE_DAYS,
            thresholds: { P1: 'KEV on an internet-facing asset, or score ≥ 80', P2: 'score ≥ 60', P3: 'score ≥ 35', P4: 'otherwise (and every informational finding)' },
            components: {
                technical: 'CVSS base × 10; without CVSS the scanner severity (critical 95, high 75, medium 50, low 25, info 0)',
                exploitation: '100 if the CVE is in CISA KEV, else EPSS × 100; 0 when unknown (shown as unknown)',
                exposure: 'internet-facing 100, unknown 60, internal 30',
                criticality: 'asset criticality: critical 100, high 75, medium 50, low 25',
            },
            evidence_rule: 'Unconfirmed findings (version match or third-party claim) are capped at P3 until a scanner confirms them',
            source: 'backend/src/lib/riskScore.ts',
        },
        totals: { open: enriched.length, with_cve: withCve.length, kev: enriched.filter((f) => f.kev).length, overdue: enriched.filter((f) => f.overdue).length },
        by_priority: tally(enriched, (f) => f.priority ?? 'unscored'),
        score_bands: bands.map((b) => ({ band: b.key, count: enriched.filter((f) => f.risk_score !== null && Number(f.risk_score) >= b.min && Number(f.risk_score) <= b.max).length })),
        matrix,
        epss: {
            no_cve: enriched.length - withCve.length,
            unknown: withCve.filter((f) => f.epss === null).length,
            '<1%': withCve.filter((f) => f.epss !== null && f.epss < 0.01).length,
            '1–10%': withCve.filter((f) => f.epss !== null && f.epss >= 0.01 && f.epss < 0.1).length,
            '10–50%': withCve.filter((f) => f.epss !== null && f.epss >= 0.1 && f.epss < 0.5).length,
            '≥50%': withCve.filter((f) => f.epss !== null && f.epss >= 0.5).length,
        },
        exposure: tally(enriched, (f) => f.exposure),
        kev_findings: enriched.filter((f) => f.kev).slice(0, 50).map((f) => ({ id: f.id, title: f.title, asset_value: f.asset_value, exposure: f.exposure, priority: f.priority, cve_ids: f.cve_ids, due_at: f.due_at, overdue: f.overdue })),
        queue: [...enriched].sort((a, b) => (prioRank[a.priority ?? 'P4'] ?? 9) - (prioRank[b.priority ?? 'P4'] ?? 9) || Number(b.risk_score ?? 0) - Number(a.risk_score ?? 0)).slice(0, 100)
            .map((f) => ({ id: f.id, title: f.title, asset_id: f.asset_id, asset_value: f.asset_value, severity: f.scanner_severity, cvss: f.scanner_cvss, priority: f.priority, risk_score: f.risk_score, kev: f.kev, epss: f.epss, exposure: f.exposure, criticality: f.criticality, status: f.status, due_at: f.due_at, overdue: f.overdue, owner: f.owner ?? null, factors: f.risk_factors ?? null, evidence_class: f.evidence_class ?? null })),
        trend: (snapsR.data ?? []).map((s) => ({ day: s.day, kev_open: s.kev_open, internet_open: s.internet_open, critical_exposures: s.critical_exposures ?? null, risk_mean: s.risk_mean !== null && s.risk_mean !== undefined ? Number(s.risk_mean) : null, by_priority: s.open_by_priority })),
    });
});

// ── Audit trail ────────────────────────────────────────────────────────────────────────────────
router.get('/audit', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const org = requestOrg(req);
    const days = clampDays(req.query.days, 30);
    const since = new Date(Date.now() - days * DAY).toISOString();
    const [auditR, findR] = await Promise.all([
        // Staff access to this organisation's VMS data is logged with the organisation as resource_id.
        supabase.from('audit_log').select('id, at, actor, action, resource, resource_id, result, severity, details')
            .or(`and(org_id.eq."${org}",action.ilike.VMS_*),and(action.eq.CROSS_ORG_ACCESS,resource_id.eq."${org}",resource.ilike.*/api/vms*)`).gte('at', since).order('at', { ascending: false }).limit(500),
        supabase.from('vms_finding_events').select('id, at, actor, action, from_value, to_value, details, finding_id').eq('org_id', org).gte('at', since).order('at', { ascending: false }).limit(500),
    ]);
    const entries = [
        ...(auditR.data ?? []).map((a) => ({ id: `a:${a.id}`, at: a.at, actor: a.actor, action: a.action, resource: a.resource, resource_id: a.resource_id, result: a.result, severity: a.severity, details: a.details, source: 'platform' as const })),
        ...(findR.data ?? []).map((e) => ({ id: `f:${e.id}`, at: e.at, actor: e.actor, action: `FINDING_${String(e.action).toUpperCase()}`, resource: 'vms_finding', resource_id: e.finding_id, result: 'success', severity: 'info', details: [e.from_value && e.to_value ? `${e.from_value} → ${e.to_value}` : e.to_value, e.details].filter(Boolean).join(' · '), source: 'finding' as const })),
    ].sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
    res.json({
        period: { days, from: since },
        available: { platform: !auditR.error, finding: !findR.error },
        entries,
        note: 'Read-only. Platform entries come from the audit log; finding entries from each finding\'s history.',
    });
});

// ── Remediation tasks ──────────────────────────────────────────────────────────────────────────
router.get('/tasks', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const org = requestOrg(req);
    const { data: tasks, error } = await supabase.from('vms_remediation_tasks').select('*').eq('org_id', org).order('created_at', { ascending: false }).limit(2000);
    if (error) { res.status(/vms_remediation_tasks/.test(error.message) ? 503 : 502).json({ error: 'Could not read remediation tasks' }); return; }
    const ids = [...new Set((tasks ?? []).map((t) => t.finding_id))];
    const findings = new Map<string, Record<string, unknown>>();
    for (let i = 0; i < ids.length; i += 200) {
        const { data } = await supabase.from('vms_findings').select('id, title, asset_id, asset_value, scanner_severity, priority, risk_score, status, due_at, owner, cve_ids').eq('org_id', org).in('id', ids.slice(i, i + 200));
        for (const f of data ?? []) findings.set(f.id, f);
    }
    const now = Date.now();
    res.json({ tasks: (tasks ?? []).map((t) => ({ ...t, overdue: (t.status === 'todo' || t.status === 'doing') && !!t.due_at && Date.parse(t.due_at) < now, finding: findings.get(t.finding_id) ?? null })) });
});

// ── AI remediation plans ───────────────────────────────────────────────────────────────────────
router.get('/ai-plans', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const org = requestOrg(req);
    const { data, error } = await supabase.from('ai_artifacts').select('id, purpose, subject_type, subject_id, content, model, created_by, created_at, status, feedback, feedback_by, feedback_at')
        .eq('org_id', org).eq('subject_type', 'finding').in('purpose', ['remediation_plan', 'finding_explanation', 'rescan_interpretation']).order('created_at', { ascending: false }).limit(100);
    if (error) { res.status(/ai_artifacts/.test(error.message) ? 503 : 502).json({ error: 'AI artifacts are not available' }); return; }
    const ids = [...new Set((data ?? []).map((a) => a.subject_id))];
    const titles = new Map<string, { title: string; asset_value: string; priority: string | null }>();
    if (ids.length) {
        const { data: f } = await supabase.from('vms_findings').select('id, title, asset_value, priority').eq('org_id', org).in('id', ids.slice(0, 200));
        for (const x of f ?? []) titles.set(x.id, { title: x.title, asset_value: x.asset_value, priority: x.priority });
    }
    res.json({ plans: (data ?? []).map((a) => ({ ...a, finding: titles.get(a.subject_id) ?? null })) });
});

export default router;
