// /api/vms/admin — the VMS administration area (phase P14). Managers only: every route needs
// vms:scope (super_admin, soc_manager) — the same permission that approves scope — and resolves
// the caller's organisation. Changes are audited. No secret or credential value is ever returned:
// integrations report configured / not configured, freshness and errors only.
//
//   GET   /admin/status                 workers (kinds, tools, versions, networks, features, health),
//                                       scheduler, Wazuh sync, CVE intelligence, AI, evidence retention,
//                                       scope summary, policies, recent VMS audit entries, deployed version
//   POST  /admin/policies               { name, asset_source, cooldown_hours?, max_per_run? }  created disabled
//   PATCH /admin/policies/:id           { name?, enabled?, cooldown_hours?, max_per_run? }
//   POST  /admin/policies/:id/run       run it once now (planning still applies every scope/worker check)
//   POST  /admin/wazuh/check            read-only check of the live Wazuh installation for this organisation
//                                       (manager version, agent and vulnerability indices, sync freshness; P15)

import { Router } from 'express';
import { z } from 'zod';
import type { AuthRequest } from '../middleware/auth';
import { requirePermission, requestOrg } from '../lib/permissions';
import { getSupabase } from '../services/geoEnrichment';
import { isUuid } from '../services/cases';
import { logAudit, readAuditLog } from '../lib/audit';
import { loadScannerStatus } from '../services/vmsWorkers';
import { aiConfigured, AI_MODEL } from '../services/ai';
import { lastVmsContinuousRun } from '../jobs/vmsContinuousJob';
import { runPolicy, isMissingP14, P14_MISSING, type Policy } from '../services/vmsPolicies';
import { checkWazuhIntegration } from '../services/wazuhCheck';
import { wazuhFreshness } from '../services/wazuhVulnSync';

const router = Router();
const actor = (req: AuthRequest) => req.user?.email ?? 'unknown';
/** The scheduler's last policy run, limited to one organisation's policies (it holds other organisations' asset names). */
export function ownPolicyRuns(last: unknown, org: string): { at: string; result: unknown } | null {
    const l = last as { at?: string; result?: unknown } | null;
    if (!l?.at) return null;
    return { at: l.at, result: Array.isArray(l.result) ? l.result.filter((r: { org?: string }) => r?.org === org) : { error: 'The last policy run failed; see the backend log' } };
}
export const deployedVersion = () => (process.env.RAILWAY_GIT_COMMIT_SHA ?? '').slice(0, 12) || null;

router.get('/admin/status', requirePermission('vms:scope'), async (req: AuthRequest, res) => {
    const supabase = getSupabase()!;
    const org = requestOrg(req);
    const nowIso = new Date().toISOString();
    const [scanner, scopes, wazuh, kev, epss, nvd, cveCount, evidence, policies, toolVersions, audit, osv] = await Promise.all([
        loadScannerStatus(),
        supabase.from('vms_scopes').select('status, expires_at, exclusions, allow_discovery, allow_port_scan, allow_vuln_scan').eq('org_id', org),
        supabase.from('vms_wazuh_sync').select('*').eq('org_id', org).maybeSingle(),
        supabase.from('cve_intel').select('kev_checked_at').not('kev_checked_at', 'is', null).order('kev_checked_at', { ascending: false }).limit(1).maybeSingle(),
        supabase.from('cve_intel').select('epss_fetched_at').not('epss_fetched_at', 'is', null).order('epss_fetched_at', { ascending: false }).limit(1).maybeSingle(),
        supabase.from('cve_intel').select('nvd_fetched_at').not('nvd_fetched_at', 'is', null).order('nvd_fetched_at', { ascending: false }).limit(1).maybeSingle(),
        supabase.from('cve_intel').select('cve_id', { count: 'exact', head: true }),
        supabase.from('vms_job_evidence').select('expires_at').eq('org_id', org).gt('expires_at', nowIso).order('expires_at', { ascending: true }).limit(5000),
        supabase.from('vms_assessment_policies').select('*').eq('org_id', org).order('created_at'),
        supabase.from('vms_workers').select('worker_id, tool_versions'),
        readAuditLog(500),
        // OSV (P16): absent until sql/2026-10-22_p16_osv.sql — then "not set up", never "never fetched".
        supabase.from('cve_intel').select('osv_fetched_at').not('osv_fetched_at', 'is', null).order('osv_fetched_at', { ascending: false }).limit(1).maybeSingle(),
    ]);
    const versions = new Map((toolVersions.error ? [] : toolVersions.data ?? []).map((w) => [w.worker_id as string, w.tool_versions as Record<string, string>]));
    const sc = scopes.data ?? [];
    const live = sc.filter((s) => s.status === 'active' && s.expires_at > nowIso);
    res.json({
        deployed_version: deployedVersion(),
        workers: { source: scanner.source, online: scanner.online_workers, window_seconds: scanner.online_window_seconds,
            list: scanner.workers.map((w) => ({ worker_id: w.worker_id, online: w.online, version: w.version, kinds: w.kinds ?? [], tools: w.tools ?? {}, tool_versions: versions.get(w.worker_id) ?? {},
                networks: w.networks ?? [], features: w.features ?? [], last_seen_at: w.last_seen_at, last_heartbeat_at: w.last_heartbeat_at, last_claim_at: w.last_claim_at, last_job_at: w.last_job_at })) },
        // The hourly run covers every organisation: show only this one's policy results.
        scheduler: { last_run_at: lastVmsContinuousRun.at, policies: ownPolicyRuns(lastVmsContinuousRun.policies, org) },
        wazuh: wazuh.error ? { available: false } : { available: true, sync: wazuh.data ?? null, freshness: wazuhFreshness(wazuh.data), note: wazuh.data ? null : 'No Wazuh sync has run for this organisation (its Wazuh groups may not be mapped)' },
        cve_intel: { tracked: cveCount.count ?? 0, kev_checked_at: kev.data?.kev_checked_at ?? null, epss_fetched_at: epss.data?.epss_fetched_at ?? null, nvd_fetched_at: nvd.data?.nvd_fetched_at ?? null,
            osv: osv.error ? { available: false, note: 'OSV is not set up (sql/2026-10-22_p16_osv.sql)' } : { available: true, fetched_at: osv.data?.osv_fetched_at ?? null } },
        ai: { configured: aiConfigured(), model: AI_MODEL() },
        evidence: evidence.error ? { available: false } : { available: true, retention_days: 30, items: (evidence.data ?? []).length, next_expiry: evidence.data?.[0]?.expires_at ?? null },
        scopes: { active: live.length, expired_or_revoked: sc.length - live.length, with_exclusions: live.filter((s) => (s.exclusions ?? []).length).length, passive_only: live.filter((s) => s.allow_discovery === false).length, vuln_allowed: live.filter((s) => s.allow_vuln_scan).length },
        policies: policies.error ? { available: false, note: isMissingP14(policies.error) ? P14_MISSING : 'unreadable' } : { available: true, list: policies.data ?? [] },
        audit: { source: audit.source, entries: audit.entries.filter((e) => e.org_id === org && /^VMS_|^CNII_|^CROSS_ORG/.test(e.action)).slice(0, 50) },
    });
});

const NewPolicy = z.object({
    name: z.string().trim().min(3).max(120),
    asset_source: z.enum(['wazuh', 'external', 'any']),
    cooldown_hours: z.number().int().min(24).max(2160).default(168),
    max_per_run: z.number().int().min(1).max(50).default(5),
}).strict();
router.post('/admin/policies', requirePermission('vms:scope'), async (req: AuthRequest, res) => {
    const p = NewPolicy.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: 'Body must be { name, asset_source: wazuh|external|any, cooldown_hours?: 24..2160, max_per_run?: 1..50 }' }); return; }
    const org = requestOrg(req);
    const { data, error } = await getSupabase()!.from('vms_assessment_policies').insert({ org_id: org, ...p.data, enabled: false, created_by: actor(req) }).select('*').single();
    if (error) { res.status(isMissingP14(error) ? 503 : 502).json({ error: isMissingP14(error) ? P14_MISSING : 'Could not create the policy' }); return; }
    logAudit({ user: actor(req), action: 'VMS_POLICY_CREATED', resource: 'vms_assessment_policy', resource_id: data.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: `${p.data.name}: ${p.data.asset_source}, every ${p.data.cooldown_hours} h, max ${p.data.max_per_run}; disabled` });
    res.status(201).json({ policy: data });
});

const PolicyPatch = z.object({ name: z.string().trim().min(3).max(120).optional(), enabled: z.boolean().optional(), cooldown_hours: z.number().int().min(24).max(2160).optional(), max_per_run: z.number().int().min(1).max(50).optional() }).strict();
router.patch('/admin/policies/:id', requirePermission('vms:scope'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Policy not found' }); return; }
    const p = PolicyPatch.safeParse(req.body);
    if (!p.success || !Object.keys(p.data).length) { res.status(400).json({ error: 'Body may hold name, enabled, cooldown_hours (24..2160), max_per_run (1..50)' }); return; }
    const org = requestOrg(req);
    const { data, error } = await getSupabase()!.from('vms_assessment_policies').update({ ...p.data, updated_by: actor(req), updated_at: new Date().toISOString() }).eq('id', req.params.id).eq('org_id', org).select('*').maybeSingle();
    if (error) { res.status(isMissingP14(error) ? 503 : 502).json({ error: isMissingP14(error) ? P14_MISSING : 'Could not update the policy' }); return; }
    if (!data) { res.status(404).json({ error: 'Policy not found' }); return; }
    logAudit({ user: actor(req), action: p.data.enabled === true ? 'VMS_POLICY_ENABLED' : p.data.enabled === false ? 'VMS_POLICY_DISABLED' : 'VMS_POLICY_CHANGED', resource: 'vms_assessment_policy', resource_id: data.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success', severity: p.data.enabled ? 'warning' : 'info', details: JSON.stringify(p.data).slice(0, 200) });
    res.json({ policy: data });
});

router.post('/admin/policies/:id/run', requirePermission('vms:scope'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Policy not found' }); return; }
    const org = requestOrg(req);
    const { data, error } = await getSupabase()!.from('vms_assessment_policies').select('*').eq('id', req.params.id).eq('org_id', org).maybeSingle();
    if (error) { res.status(isMissingP14(error) ? 503 : 502).json({ error: isMissingP14(error) ? P14_MISSING : 'Could not read the policy' }); return; }
    if (!data) { res.status(404).json({ error: 'Policy not found' }); return; }
    const r = await runPolicy(data as Policy);
    logAudit({ user: actor(req), action: 'VMS_POLICY_RUN', resource: 'vms_assessment_policy', resource_id: data.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: `queued ${r.queued}, in progress ${r.existing}, cooldown ${r.skipped_cooldown}, blocked ${r.blocked.length}` });
    res.json({ run: r });
});

// A POST although it changes nothing: it makes outbound calls to the Wazuh installation, so it is
// not something a page load or prefetch should trigger. Audited; counts only, no documents.
router.post('/admin/wazuh/check', requirePermission('vms:scope'), async (req: AuthRequest, res) => {
    const org = requestOrg(req);
    const r = await checkWazuhIntegration(org);
    logAudit({ user: actor(req), action: 'VMS_WAZUH_CHECK', resource: 'wazuh', resource_id: org, org_id: org, ip: req.ip ?? 'unknown', result: r.verdict === 'working' ? 'success' : 'failed',
        details: `${r.verdict}; manager ${r.manager.ok ? r.manager.api_version ?? 'version unknown' : 'unavailable'}; vulnerability records ${r.vulnerabilities.ok ? r.vulnerabilities.records_for_org : 'n/a'}`.slice(0, 200) });
    res.json(r);
});

export default router;
