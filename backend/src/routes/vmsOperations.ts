// /api/vms — scanner operations, profiles, services and Wazuh endpoint coverage (phase P19).
// Behind requireAuth; every route resolves the caller's organisation (requirePermission).
//
//   GET  /profiles                 vms:read   scan profiles: what each runs, which engines, what it does not cover
//   GET  /operations               vms:read   engines (availability from worker reports), queue, 7-day job
//                                             outcomes by kind, durations, recent failures, active jobs
//   GET  /services                 vms:read   open services and technologies across the organisation's assets,
//                                             with the open findings on each asset/port
//   GET  /endpoints                vms:read   Wazuh endpoints: agent detail, scan eligibility, last/next scan,
//                                             open findings; and coverage counts
//   POST /eligibility/refresh      vms:scan   re-evaluates the organisation's endpoints now
//   POST /scans/:id/retry          vms:scan   queues a failed or cancelled scan again (same kind, targets, ports),
//                                             through the same scope checks as a new scan
//
// Engines are shared infrastructure: client roles get each engine's state, staff also the workers.
// Nothing is estimated: an engine is "available" only when a connected worker reports it enabled
// with its tool installed; a job that ran but could not assess its target is counted as
// inconclusive, never as a success.

import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { requirePermission, requestOrg } from '../lib/permissions';
import { getSupabase } from '../services/geoEnrichment';
import { isUuid } from '../services/cases';
import { logAudit } from '../lib/audit';
import { isStaffRole } from '../lib/resolveOrg';
import { loadScannerStatus, type WorkerView } from '../services/vmsWorkers';
import { profileCatalogue } from '../services/vmsProfiles';
import { refreshEligibility, type Eligibility } from '../services/vmsEligibility';
import { wazuhFreshness } from '../services/wazuhVulnSync';
import { queueScan } from './vms';

const router = Router();
const actor = (req: AuthRequest) => req.user?.email ?? 'unknown';
const days = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString();

async function wazuhSyncState(org: string) {
    const { data } = await getSupabase()!.from('vms_wazuh_sync').select('*').eq('org_id', org).maybeSingle();
    return wazuhFreshness(data);
}

router.get('/profiles', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const f = await wazuhSyncState(requestOrg(req));
    res.json({ profiles: profileCatalogue({ wazuh_sync: { complete: f.complete, last_complete_at: f.last_complete_at } }) });
});

// ── Engines ────────────────────────────────────────────────────────────────────────────────────
export const ENGINES = [
    { id: 'discovery', label: 'Discovery (httpx, dnsx, subfinder)', kind: 'discovery', tools: ['httpx', 'dnsx', 'subfinder'] },
    { id: 'nmap', label: 'Nmap (ports and services)', kind: 'ports', tools: ['nmap'] },
    { id: 'nuclei', label: 'Nuclei', kind: 'vuln_nuclei', tools: ['nuclei'] },
    { id: 'openvas', label: 'Greenbone / OpenVAS', kind: 'vuln_openvas', tools: ['openvas'] },
] as const;
export type EngineState = 'available' | 'offline' | 'not_enabled' | 'not_installed' | 'no_worker';

/** Pure: each engine's state from what the workers report. Never "available" without a connected worker running it with its tools. */
export function engineStatus(workers: WorkerView[]) {
    return ENGINES.map((e) => {
        const has = (w: WorkerView) => e.tools.every((t) => (w.tools ?? {})[t] === true);
        const runs = (w: WorkerView) => (w.kinds ?? []).includes(e.kind);
        const online = workers.filter((w) => w.online);
        let state: EngineState;
        let note: string;
        if (online.some((w) => runs(w) && has(w))) { state = 'available'; note = 'A connected worker runs it'; }
        else if (workers.some((w) => !w.online && runs(w) && has(w))) { state = 'offline'; note = 'The workers that run it are not connected'; }
        else if (workers.some((w) => runs(w))) { state = 'not_installed'; note = `Enabled on a worker that reports ${e.tools.join(', ')} missing`; }
        else if (workers.some((w) => has(w))) { state = 'not_enabled'; note = `Installed, but no worker has ${e.kind} in VMS_WORKER_KINDS`; }
        else { state = workers.length ? 'not_installed' : 'no_worker'; note = workers.length ? `No worker reports ${e.tools.join(', ')}` : 'No scanner worker has connected'; }
        const versions = [...new Set(workers.filter(has).map((w) => (w.tool_versions ?? {})[e.tools[0]]).filter((v): v is string => !!v))];
        return { id: e.id, label: e.label, kind: e.kind, state, note, versions };
    });
}

const NO_ASSESSMENT = new Set(['unreachable', 'insufficient_evidence', 'no_route']);

router.get('/operations', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const org = requestOrg(req);
    const cols = 'id, kind, status, targets, options, requested_at, requested_by, started_at, finished_at, error, attempts, progress, summary, purpose, assessment_id, worker_id, heartbeat_at, cancel_requested';
    const [scanner, active, recent, sync] = await Promise.all([
        loadScannerStatus(),
        supabase.from('vms_scan_jobs').select(cols).eq('org_id', org).in('status', ['queued', 'running']).order('requested_at').limit(200),
        supabase.from('vms_scan_jobs').select(cols).eq('org_id', org).gte('requested_at', days(7)).in('status', ['succeeded', 'failed', 'cancelled']).order('requested_at', { ascending: false }).limit(2000),
        wazuhSyncState(org),
    ]);
    if (active.error || recent.error) { res.status(502).json({ error: 'Could not read scan jobs' }); return; }
    type K = { queued: number; running: number; succeeded: number; inconclusive: number; failed: number; cancelled: number; durations: number[] };
    const byKind: Record<string, K> = {};
    const k = (kind: string) => (byKind[kind] ??= { queued: 0, running: 0, succeeded: 0, inconclusive: 0, failed: 0, cancelled: 0, durations: [] });
    for (const j of active.data ?? []) k(j.kind)[j.status as 'queued' | 'running']++;
    for (const j of recent.data ?? []) {
        const outcome = String((j.summary as { outcome?: string } | null)?.outcome ?? '');
        if (j.status === 'succeeded') k(j.kind)[NO_ASSESSMENT.has(outcome) ? 'inconclusive' : 'succeeded']++;
        else k(j.kind)[j.status as 'failed' | 'cancelled']++;
        if (j.status === 'succeeded' && j.started_at && j.finished_at) k(j.kind).durations.push((Date.parse(j.finished_at) - Date.parse(j.started_at)) / 1000);
    }
    const median = (xs: number[]) => { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); return Math.round(s[Math.floor(s.length / 2)]); };
    const staff = isStaffRole(req.user?.role);
    res.json({
        engines: engineStatus(scanner.workers),
        worker_presence: { state: scanner.state, source: scanner.source, online_workers: scanner.online_workers, last_seen_at: scanner.last_seen_at },
        ...(staff ? { workers: scanner.workers.map((w) => ({ worker_id: w.worker_id, online: w.online, version: w.version, kinds: w.kinds ?? [], tools: w.tools ?? {}, tool_versions: w.tool_versions ?? {}, networks: w.networks ?? [], last_seen_at: w.last_seen_at, last_job_at: w.last_job_at })) } : {}),
        queue: {
            queued: (active.data ?? []).filter((j) => j.status === 'queued').length,
            running: (active.data ?? []).filter((j) => j.status === 'running').length,
            oldest_queued_at: (active.data ?? []).find((j) => j.status === 'queued')?.requested_at ?? null,
        },
        last_7_days: Object.fromEntries(Object.entries(byKind).map(([kind, v]) => [kind, { queued: v.queued, running: v.running, succeeded: v.succeeded, inconclusive: v.inconclusive, failed: v.failed, cancelled: v.cancelled, median_duration_s: median(v.durations) }])),
        active: active.data ?? [],
        recent_failures: (recent.data ?? []).filter((j) => j.status === 'failed').slice(0, 25),
        wazuh_sync: sync,
    });
});

// ── Services and technologies ──────────────────────────────────────────────────────────────────
router.get('/services', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const org = requestOrg(req);
    const [svc, tech, assets, findings] = await Promise.all([
        supabase.from('vms_services').select('*').eq('org_id', org).eq('status', 'active').order('port').limit(5000),
        supabase.from('vms_technologies').select('*').eq('org_id', org).order('name').limit(5000),
        supabase.from('vms_assets').select('id, asset_type, value, exposure, criticality, status').eq('org_id', org).limit(10_000),
        supabase.from('vms_findings').select('id, asset_id, port, priority, scanner_severity, status').eq('org_id', org).in('status', ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened']).limit(20_000),
    ]);
    if (svc.error) { res.status(502).json({ error: 'Could not read services' }); return; }
    const assetById = new Map((assets.data ?? []).map((a) => [a.id, a]));
    const open = new Map<string, { count: number; severities: Record<string, number> }>();
    for (const f of findings.data ?? []) {
        for (const key of [`${f.asset_id}|${f.port ?? '-'}`, `${f.asset_id}|*`]) {
            const o = open.get(key) ?? { count: 0, severities: {} };
            o.count++; o.severities[f.scanner_severity] = (o.severities[f.scanner_severity] ?? 0) + 1;
            open.set(key, o);
        }
    }
    const asset = (id: string) => { const a = assetById.get(id); return a ? { id: a.id, value: a.value, asset_type: a.asset_type, exposure: a.exposure, criticality: a.criticality } : null; };
    res.json({
        services: (svc.data ?? []).map((s) => ({ ...s, asset: asset(s.asset_id), open_findings: open.get(`${s.asset_id}|${s.port}`) ?? { count: 0, severities: {} } })),
        technologies: (tech.data ?? []).map((t) => ({ ...t, asset: asset(t.asset_id), asset_open_findings: open.get(`${t.asset_id}|*`)?.count ?? 0 })),
    });
});

// ── Wazuh endpoints: eligibility and coverage ──────────────────────────────────────────────────
router.get('/endpoints', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const org = requestOrg(req);
    const { data: endpoints, error } = await supabase.from('vms_assets').select('*').eq('org_id', org).eq('asset_type', 'endpoint').order('value').limit(5000);
    if (error) { res.status(502).json({ error: 'Could not read endpoints' }); return; }
    // Evaluated now (and stored when the P19 columns exist), so a scope or worker change shows at once.
    let elig = new Map<string, Eligibility>();
    let stored = false;
    try { const r = await refreshEligibility(org); elig = r.byAsset; stored = r.stored; } catch { /* shown as not evaluated */ }
    const ids = (endpoints ?? []).map((e) => e.id);
    const [findings, assessments] = await Promise.all([
        ids.length ? supabase.from('vms_findings').select('asset_id, scanner_severity, source_class').eq('org_id', org).in('asset_id', ids).in('status', ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened']).limit(20_000) : { data: [] },
        ids.length ? supabase.from('vms_assessments').select('id, asset_id, target, profile, requested_at, cancelled_at').eq('org_id', org).in('asset_id', ids).order('requested_at', { ascending: false }).limit(5000) : { data: [] },
    ]);
    const sev = new Map<string, Record<string, number>>();
    for (const f of findings.data ?? []) { const m = sev.get(f.asset_id) ?? {}; m[f.scanner_severity] = (m[f.scanner_severity] ?? 0) + 1; sev.set(f.asset_id, m); }
    const lastAssessment = new Map<string, Record<string, unknown>>();
    for (const a of assessments.data ?? []) if (!lastAssessment.has(a.asset_id)) lastAssessment.set(a.asset_id, a);
    const since30 = Date.now() - 30 * 86_400_000;
    const rows = (endpoints ?? []).map((e) => {
        const el = elig.get(e.id) ?? null;
        const reached = !!e.last_assessed_at && Date.parse(e.last_assessed_at) >= since30 && /^reachable/.test(String((e.last_assessment as { outcome?: string } | null)?.outcome ?? ''));
        return {
            id: e.id, name: e.value, wazuh_agent_id: e.wazuh_agent_id, ips: e.ips ?? [], os: e.os ?? null, agent_status: e.agent_status ?? null,
            agent_last_keepalive: e.agent_last_keepalive ?? null, agent_groups: e.agent_groups ?? [], status: e.status, criticality: e.criticality, owner: e.owner,
            last_seen: e.last_seen, eligibility: el, last_assessment: lastAssessment.get(e.id) ?? null, last_assessed_at: e.last_assessed_at ?? null,
            assessed_recently: reached, next_scan_at: e.next_scan_at ?? null, open_findings: sev.get(e.id) ?? {},
        };
    });
    const active = rows.filter((r) => r.status === 'active');
    const count = (s: string) => active.filter((r) => r.eligibility?.status === s).length;
    res.json({
        endpoints: rows,
        eligibility_stored: stored,
        coverage: {
            active: active.length,
            eligible: count('eligible'),
            assessed_last_30_days: active.filter((r) => r.assessed_recently).length,
            awaiting_assessment: active.filter((r) => r.eligibility?.status === 'eligible' && !r.assessed_recently).length,
            not_eligible: Object.fromEntries(['not_covered', 'private_no_route', 'offline', 'no_address', 'duplicate_address'].map((s) => [s, count(s)])),
        },
    });
});

router.post('/eligibility/refresh', requirePermission('vms:scan'), async (req: AuthRequest, res) => {
    try {
        const r = await refreshEligibility(requestOrg(req));
        res.json({ counts: r.counts, stored: r.stored });
    } catch (err) {
        res.status(502).json({ error: err instanceof Error ? err.message.slice(0, 200) : 'Could not evaluate endpoints' });
    }
});

// ── Retry a failed or cancelled scan ──────────────────────────────────────────────────────────
router.post('/scans/:id/retry', requirePermission('vms:scan'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Scan not found' }); return; }
    const org = requestOrg(req);
    const { data: job } = await getSupabase()!.from('vms_scan_jobs').select('*').eq('id', req.params.id).eq('org_id', org).maybeSingle();
    if (!job) { res.status(404).json({ error: 'Scan not found' }); return; }
    if (job.status !== 'failed' && job.status !== 'cancelled') { res.status(409).json({ error: `Only a failed or cancelled scan can be retried; this one is ${job.status}` }); return; }
    // A scan that belongs to an assessment is retried with it, so the assessment's record stays whole.
    if (job.assessment_id) { res.status(409).json({ error: 'This scan is part of an assessment: retry the assessment instead', assessment_id: job.assessment_id }); return; }
    if (job.purpose === 'verification') { res.status(409).json({ error: 'Request verification again from the finding' }); return; }
    const ports = (job.options as { ports?: string } | null)?.ports;
    const r = await queueScan(org, actor(req), { scope_id: job.scope_id, kind: job.kind, targets: Array.isArray(job.targets) ? job.targets : undefined, ...(job.kind === 'ports' && ports ? { ports } : {}) });
    if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
    logAudit({ user: actor(req), action: 'VMS_SCAN_RETRIED', resource: 'vms_scan_job', resource_id: String(r.job.id), org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: `retry of ${job.id} (${job.kind})` });
    res.status(r.existing ? 200 : 201).json({ scan: r.job, existing: r.existing, retry_of: job.id });
});

export default router;
