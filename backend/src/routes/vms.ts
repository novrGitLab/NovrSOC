// /api/vms — Vulnerability Management System, Release 1: attack surface (phase P4).
// Mounted behind requireAuth; every route resolves the caller's organisation (requirePermission).
//
//   GET    /overview                     vms:read   counts, new / changed / gone in 7 days, recent scans, scanner health
//   GET    /scopes                       vms:read
//   POST   /scopes                       vms:scope  { kind, value, include_subdomains?, allow_discovery?, allow_port_scan?, allow_vuln_scan?, authorization_reference, expires_at, notes? }
//   POST   /scopes/:id/revoke            vms:scope  also cancels that scope's queued jobs
//   GET    /scans                        vms:read
//   POST   /scans                        vms:scan   { scope_id, kind: passive_osint|discovery|ports|vuln_*, targets?: string[], ports? }
//   POST   /scans/:id/cancel             vms:scan
//   GET    /assets?q&type&status&exposure  vms:read
//   GET    /assets/:id                   vms:read   with services, technologies, recent events
//   PATCH  /assets/:id                   vms:manage { owner?, criticality? }
//   GET    /events?days=7                vms:read   new / changed / gone feed
//
// Scans run only on targets inside an active, unexpired scope entry that allows the activity
// (lib/vmsScope.ts). The scanners run in infra/vms-worker; nothing here executes a tool.
// passive_osint jobs (phase P9) are run by the backend itself (jobs/cniiPassiveJob.ts): they only
// ask third parties about the target.

import { Router } from 'express';
import { z } from 'zod';
import type { AuthRequest } from '../middleware/auth';
import { randomUUID } from 'crypto';
import { requirePermission, requestOrg, hasPermission } from '../lib/permissions';
import { parseScanWindows, inScanWindow, nextScanWindow, describeScanWindows, type ScanWindows } from '../lib/scanWindows';
import { permitsActiveScanning, pendingGroup, decideGroup, DECLARATION_VERSION, sha256 } from '../services/vmsAuthorisation';
import { authorisationFor, scanTargetOf, scopesForAuthorisation } from '../services/vmsImport';
import { getSupabase } from '../services/geoEnrichment';
import { dbErrorMessage, isUuid } from '../services/cases';
import { logAudit } from '../lib/audit';
import { loadScannerStatus, jobAttention } from '../services/vmsWorkers';
import { assetGraph } from '../services/vmsGraph';
import { isStaffRole } from '../lib/resolveOrg';
import { openvasAllowed } from '../lib/openvasPolicy';
import { validateScopeValue, parseTarget, coveringScope, normalizeExclusion, type ScopeEntry, type Activity } from '../lib/vmsScope';
import { describe, RETRYABLE, type AssessmentRow } from '../services/vmsAssessments';
import { resolveAddresses, pinsSatisfied } from '../lib/dnsResolve';
import { refreshEligibility } from '../services/vmsEligibility';

/** Coverage changed: re-evaluate the organisation's Wazuh endpoints now, in the background (P19). */
const reevaluate = (org: string) => { void refreshEligibility(org).catch((err) => console.warn('[vms] eligibility refresh failed:', err instanceof Error ? err.message : err)); };

const router = Router();
const MAX_SCOPE_DAYS = 400;
const MAX_TARGETS = 256;
export const WORKER_STALE_MINUTES = 15;
const P4_MISSING = 'VMS is not set up yet (run sql/2026-10-14_p4_vms_asm.sql)';
const missing = (e: { message?: string } | null) => !!e && /vms_/.test(e.message ?? '') && /does not exist|Could not find/i.test(e.message ?? '');
const fail = (res: import('express').Response, e: { message?: string }) => res.status(missing(e) ? 503 : 502).json({ error: missing(e) ? P4_MISSING : dbErrorMessage(e) });
const actor = (req: AuthRequest) => req.user?.email ?? 'unknown';
const days = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString();

// Phase P28 (Release 2 Stage 5): the four unified-inventory categories are predicates over
// vms_assets, not separate asset types — an asset can be in more than one at once.
export type InventoryCategory = 'wazuh' | 'vulnerability' | 'cloud' | 'other';
export function assetCategories(a: { asset_type: string; wazuh_agent_id?: string | null; last_assessed_at?: string | null; cloud_ref?: string | null }, hasFindings: boolean): InventoryCategory[] {
    const isWazuh = a.asset_type === 'endpoint' && !!a.wazuh_agent_id;
    const isVulnerability = !!a.last_assessed_at || hasFindings;
    const isCloud = a.asset_type === 'cloud_resource' || !!a.cloud_ref;
    const out: InventoryCategory[] = [];
    if (isWazuh) out.push('wazuh');
    if (isVulnerability) out.push('vulnerability');
    if (isCloud) out.push('cloud');
    if (!out.length) out.push('other');
    return out;
}

/** Where an asset came from, as labels: Wazuh, manual / CSV import, or scanning. */
export function sourceLabels(sources: string[]): string[] {
    const map: Record<string, string> = { wazuh: 'Wazuh', manual: 'Manual', csv: 'CSV import' };
    return [...new Set(sources.map((s) => map[s] ?? 'Discovered'))];
}

export async function activeScopes(org: string): Promise<ScopeEntry[]> {
    const { data, error } = await getSupabase()!.from('vms_scopes').select('*').eq('org_id', org).eq('status', 'active');
    if (error) throw error;
    return (data ?? []) as ScopeEntry[];
}

// ── Overview ────────────────────────────────────────────────────────────────────────────────
router.get('/overview', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) { res.status(503).json({ error: 'Database not configured' }); return; }
    const org = requestOrg(req);
    const count = (q: PromiseLike<{ count: number | null; error: { message: string } | null }>) => q;
    const assets = () => supabase.from('vms_assets').select('id', { count: 'exact', head: true }).eq('org_id', org);
    const ev = (e: string) => supabase.from('vms_asset_events').select('id', { count: 'exact', head: true }).eq('org_id', org).eq('event', e).gte('at', days(7));
    // Coverage (P14): Wazuh-managed vs external, and what was actually assessed — never counting a
    // check that did not run as an assessment. last_assessed_at is stamped for every outcome
    // (no route and unreachable too), so "assessed" means the last outcome reached the target; a
    // check that did not run or was inconclusive is counted from the derived step status.
    // Every query is independent, so all run in one round trip; only the assessment step details
    // (describe) follow their assessment list. The time is network round trips, not query work.
    const since30 = days(30);
    const OPEN_STATUSES = ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened'];
    const SEV_W: Record<string, number> = { critical: 1000, high: 100, medium: 10, low: 1 };
    type Vuln = { asset_id: string; value: string; open: number; by_severity: Record<string, number>; weight: number; max_risk: number };
    // P19: the assets carrying the most open risk, from stored findings (severity first, then risk
    // score), then the exposure context of the top 8 — chained, but alongside the other queries.
    const ranking = Promise.resolve(supabase.from('vms_findings').select('asset_id, asset_value, scanner_severity, risk_score').eq('org_id', org).in('status', OPEN_STATUSES).limit(20_000)).then(async (openFindings) => {
        const perAsset = new Map<string, Vuln>();
        for (const f of openFindings.data ?? []) {
            if (!f.asset_id) continue;
            const e: Vuln = perAsset.get(f.asset_id) ?? { asset_id: f.asset_id, value: f.asset_value, open: 0, by_severity: {}, weight: 0, max_risk: 0 };
            e.open++; e.by_severity[String(f.scanner_severity)] = (e.by_severity[String(f.scanner_severity)] ?? 0) + 1;
            e.weight += SEV_W[f.scanner_severity] ?? 0; e.max_risk = Math.max(e.max_risk, Number(f.risk_score ?? 0));
            perAsset.set(f.asset_id, e);
        }
        const ranked = [...perAsset.values()].sort((a, b) => b.weight - a.weight || b.max_risk - a.max_risk).slice(0, 8);
        const ctx = ranked.length ? await supabase.from('vms_assets').select('id, asset_type, exposure, criticality').eq('org_id', org).in('id', ranked.map((r) => r.asset_id)) : { data: [] };
        return { error: openFindings.error, perAsset, ranked, ctx: new Map((ctx.data ?? []).map((a) => [a.id, a])) };
    });
    const assessments30 = supabase.from('vms_assessments').select('*').eq('org_id', org).gte('requested_at', since30).order('requested_at', { ascending: false }).limit(500);
    const [active, internet, gone, services, newA, changedA, goneA, newSvc, scans, scopes, scanner, endpoints, external, assessed30, assessed, ranks] = await Promise.all([
        count(assets().eq('status', 'active')), count(assets().eq('status', 'active').eq('exposure', 'internet')), count(assets().eq('status', 'gone')),
        count(supabase.from('vms_services').select('id', { count: 'exact', head: true }).eq('org_id', org).eq('status', 'active')),
        count(ev('asset_new')), count(ev('asset_changed')), count(ev('asset_gone')), count(ev('service_new')),
        supabase.from('vms_scan_jobs').select('id, kind, status, requested_at, finished_at, error, summary, progress').eq('org_id', org).order('requested_at', { ascending: false }).limit(10),
        supabase.from('vms_scopes').select('id', { count: 'exact', head: true }).eq('org_id', org).eq('status', 'active').gt('expires_at', new Date().toISOString()),
        loadScannerStatus(),
        count(assets().eq('status', 'active').eq('asset_type', 'endpoint')),
        count(assets().eq('status', 'active').in('asset_type', ['host', 'ip', 'domain'])),
        supabase.from('vms_assets').select('id, last_assessment').eq('org_id', org).eq('status', 'active').gte('last_assessed_at', since30).limit(5000),
        assessments30.then(async (r) => ({ error: r.error, described: r.error ? [] : await describe((r.data ?? []) as AssessmentRow[]) })),
        ranking,
    ]);
    if (active.error) { fail(res, active.error); return; }
    const { perAsset, ranked, ctx: ctxById } = ranks;
    const mostVulnerable = ranked.map(({ weight: _w, ...x }) => ({ ...x, asset_type: ctxById.get(x.asset_id)?.asset_type ?? null, exposure: ctxById.get(x.asset_id)?.exposure ?? null, criticality: ctxById.get(x.asset_id)?.criticality ?? null }));
    const reached = (assessed30.data ?? []).filter((a) => /^reachable/.test(String((a.last_assessment as { outcome?: string } | null)?.outcome ?? ''))).length;
    const described = assessed.described;
    res.json({
        assets: { active: active.count ?? 0, internet_facing: internet.count ?? 0, gone: gone.count ?? 0, open_services: services.count ?? 0 },
        last_7_days: { new_assets: newA.count ?? 0, changed_assets: changedA.count ?? 0, gone_assets: goneA.count ?? 0, new_services: newSvc.count ?? 0 },
        active_scopes: scopes.count ?? 0,
        coverage: {
            wazuh_endpoints: endpoints.count ?? 0,
            external_assets: external.count ?? 0,
            // null when the P12 column is missing: unknown, not zero.
            assessed_last_30_days: assessed30.error ? null : reached,
            assessments_last_30_days: assessed.error ? null : described.length,
            checks_not_run_last_30_days: assessed.error ? null : described.reduce((n, a) => n + a.steps.filter((s) => RETRYABLE.has(s.status)).length, 0),
        },
        recent_scans: scans.data ?? [],
        most_vulnerable_assets: ranks.error ? null : mostVulnerable,
        // Assets with at least one open critical or high finding (all of them, not only the ranked top 8).
        high_risk_assets: ranks.error ? null : [...perAsset.values()].filter((a) => (a.by_severity.critical ?? 0) + (a.by_severity.high ?? 0) > 0).length,
        // Scanner workers are shared infrastructure, not tenant data: client roles get the state only.
        worker: {
            state: scanner.state, source: scanner.source, last_heartbeat_at: scanner.last_seen_at, seen_recently: scanner.state === 'online',
            online_workers: scanner.online_workers, online_window_seconds: scanner.online_window_seconds,
            ...(isStaffRole(req.user?.role) ? { workers: scanner.workers.map((w) => ({ worker_id: w.worker_id, online: w.online, kinds: w.kinds ?? [], tools: w.tools ?? {}, version: w.version, last_seen_at: w.last_seen_at, last_heartbeat_at: w.last_heartbeat_at, last_claim_at: w.last_claim_at, last_job_at: w.last_job_at })) } : {}),
        },
    });
});

// ── Scope ───────────────────────────────────────────────────────────────────────────────────
// Phase P27: an entry that permits active scanning is created `pending` and authorises nothing
// until the organisation's administrator approves it (services/vmsAuthorisation.ts). Passive-only
// entries (CNII Watch monitoring registrations, AS numbers) are registered at once, as before.
router.get('/scopes', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    let q = getSupabase()!.from('vms_scopes').select('*').eq('org_id', requestOrg(req));
    if (typeof req.query.status === 'string' && ['pending', 'active', 'revoked', 'rejected'].includes(req.query.status)) q = q.eq('status', req.query.status);
    const { data, error } = await q.order('approved_at', { ascending: false, nullsFirst: true });
    if (error) { fail(res, error); return; }
    res.json({ scopes: data ?? [] });
});

const NewScope = z.object({
    kind: z.enum(['domain', 'ip', 'cidr', 'asn']),
    value: z.string().min(1).max(253),
    include_subdomains: z.boolean().default(true),
    allow_discovery: z.boolean().default(true),
    // Hosts, .subdomains, IPs or CIDRs inside the entry that must never be touched (P13).
    exclusions: z.array(z.string().max(253)).max(200).default([]),
    allow_port_scan: z.boolean().default(false),
    allow_vuln_scan: z.boolean().default(false),
    authorization_reference: z.string().trim().min(3).max(300),
    expires_at: z.string().refine((v) => !Number.isNaN(Date.parse(v)), 'expires_at must be a date'),
    notes: z.string().trim().max(2000).optional(),
    // P27: when scans may run, and how many may be queued or running at once under this entry.
    scan_windows: z.unknown().optional(),
    max_active_jobs: z.number().int().min(1).max(20).optional(),
}).strict();
type NewScopeT = z.infer<typeof NewScope>;

/** Validates and stores one request's entries: passive-only at once, active ones pending approval. */
async function createScopes(req: AuthRequest, items: NewScopeT[]): Promise<{ ok: true; scopes: Record<string, unknown>[]; groupId: string; pending: boolean } | { ok: false; status: number; error: string }> {
    const org = requestOrg(req);
    const rows: Record<string, unknown>[] = [];
    const groupId = randomUUID();
    const now = new Date().toISOString();
    const seen = new Set<string>();
    for (const item of items) {
        const v = validateScopeValue(item.kind, item.value);
        if (!v.ok) return { ok: false, status: 400, error: v.error };
        if (seen.has(`${item.kind}:${v.value}`)) return { ok: false, status: 400, error: `${v.value} is listed twice` };
        seen.add(`${item.kind}:${v.value}`);
        const exclusions: string[] = [];
        for (const raw of item.exclusions) {
            const x = normalizeExclusion(raw);
            if (!x) return { ok: false, status: 400, error: `Not a valid exclusion (host, .subdomain, IP or CIDR): ${String(raw).slice(0, 80)}` };
            exclusions.push(x);
        }
        // An AS number covers no host or address: it registers the network for passive monitoring.
        const allowDiscovery = item.kind === 'asn' ? false : item.allow_discovery;
        if (item.kind === 'asn' && (item.allow_port_scan || item.allow_vuln_scan)) return { ok: false, status: 400, error: 'An AS number is registered for passive monitoring only; add its ranges as CIDR entries to scan them' };
        const exp = Date.parse(item.expires_at);
        if (exp <= Date.now()) return { ok: false, status: 400, error: 'expires_at must be in the future' };
        if (exp > Date.now() + MAX_SCOPE_DAYS * 86_400_000) return { ok: false, status: 400, error: `Authorisation can last at most ${MAX_SCOPE_DAYS} days; renew it when it expires` };
        const w = parseScanWindows(item.scan_windows);
        if (!w.ok) return { ok: false, status: 400, error: w.error };
        const active = permitsActiveScanning({ kind: item.kind, allow_discovery: allowDiscovery, allow_port_scan: item.allow_port_scan, allow_vuln_scan: item.allow_vuln_scan });
        rows.push({
            org_id: org, kind: item.kind, value: v.value, include_subdomains: item.kind === 'domain' ? item.include_subdomains : false,
            allow_port_scan: item.allow_port_scan, allow_vuln_scan: item.allow_vuln_scan, authorization_reference: item.authorization_reference,
            // Only written when false: rows without the column (before sql/2026-10-17_p9_cnii.sql) mean true.
            ...(allowDiscovery ? {} : { allow_discovery: false }),
            ...(exclusions.length ? { exclusions: [...new Set(exclusions)] } : {}),
            notes: item.notes ?? null, expires_at: new Date(exp).toISOString(),
            ...(active
                // Pending: authorises nothing until the organisation approves it.
                ? { status: 'pending', approved_by: null, approved_at: null, requested_by: actor(req), requested_at: now, request_group_id: groupId, ...(w.value ? { scan_windows: w.value } : {}), ...(item.max_active_jobs ? { max_active_jobs: item.max_active_jobs } : {}) }
                // Passive-only: registered at once, as before P27 (written without the P27 columns, so it
                // also works before the migration).
                : { approved_by: actor(req), approved_at: now }),
        });
    }
    const pending = rows.some((r) => r.status === 'pending');
    if (pending && rows.some((r) => r.status !== 'pending')) return { ok: false, status: 400, error: 'Request passive-only and active entries separately' };
    // One open request per target: a second would leave the approver two declarations for the same systems.
    if (pending) {
        const { data: open } = await getSupabase()!.from('vms_scopes').select('kind, value').eq('org_id', org).eq('status', 'pending').in('value', rows.map((r) => r.value as string));
        const clash = (open ?? []).find((o) => rows.some((r) => r.kind === o.kind && r.value === o.value));
        if (clash) return { ok: false, status: 409, error: `${clash.value} is already waiting for approval; approve or reject that request first` };
    }
    const { data, error } = await getSupabase()!.from('vms_scopes').insert(rows).select('*');
    if (error) {
        if (/duplicate|23505/.test(error.message)) return { ok: false, status: 409, error: 'That target is already in active scope' };
        if (/status_check|requested_by|request_group_id|scan_windows|max_active_jobs/.test(error.message)) return { ok: false, status: 503, error: 'Scan authorisation requests are not set up yet (run sql/2026-11-01_p27_vms_onboarding.sql)' };
        return { ok: false, status: missing(error) ? 503 : 502, error: missing(error) ? P4_MISSING : dbErrorMessage(error) };
    }
    for (const s of data ?? []) {
        logAudit({ user: actor(req), action: pending ? 'VMS_SCOPE_REQUESTED' : 'VMS_SCOPE_REGISTERED_PASSIVE', resource: 'vms_scope', resource_id: s.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success', severity: pending ? 'info' : 'warning',
            details: `${s.kind} ${s.value} discovery=${s.allow_discovery !== false} ports=${s.allow_port_scan} vuln=${s.allow_vuln_scan} ref=${s.authorization_reference}${pending ? ` group=${groupId}` : ''}`.slice(0, 200) });
    }
    if (!pending) reevaluate(org);
    return { ok: true, scopes: data ?? [], groupId, pending };
}

router.post('/scopes', requirePermission('vms:scope'), async (req: AuthRequest, res) => {
    const p = NewScope.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: `Invalid scope: ${p.error.issues[0]?.path.join('.') || ''} ${p.error.issues[0]?.message ?? ''}`.trim() }); return; }
    const r = await createScopes(req, [p.data]);
    if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
    res.status(201).json({ scope: r.scopes[0], ...(r.pending ? { approval_required: true, request_group_id: r.groupId } : {}) });
});

// Several entries approved together (one declaration): { entries: [scope, …] }.
router.post('/scope-requests', requirePermission('vms:scope'), async (req: AuthRequest, res) => {
    const list = z.object({ entries: z.array(NewScope).min(1).max(50) }).strict().safeParse(req.body);
    if (!list.success) { res.status(400).json({ error: `Invalid request: ${list.error.issues[0]?.path.join('.') || ''} ${list.error.issues[0]?.message ?? ''}`.trim() }); return; }
    const r = await createScopes(req, list.data.entries);
    if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
    res.status(201).json({ scopes: r.scopes, approval_required: r.pending, request_group_id: r.pending ? r.groupId : null });
});

// A request as its approver sees it, with the exact declaration they would accept.
router.get('/scope-requests/:group', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.group)) { res.status(404).json({ error: 'Scope request not found' }); return; }
    const g = await pendingGroup(requestOrg(req), req.params.group);
    if (!g.ok) { res.status(g.status).json({ error: g.error }); return; }
    res.json({ entries: g.entries, organisation_name: g.orgName, declaration: g.declaration, declaration_version: DECLARATION_VERSION, declaration_sha256: sha256(g.declaration) });
});

const Approve = z.object({
    method: z.enum(['in_platform', 'offline_document']).default('in_platform'),
    authority_name: z.string().trim().min(3).max(120),
    authority_title: z.string().trim().min(2).max(120),
    organisation_name: z.string().trim().min(1).max(200),
    declaration_version: z.string(),
    declaration_accepted: z.literal(true),
    signed_document_ref: z.string().trim().max(300).optional(),
}).strict();
const decider = (req: AuthRequest) => ({ userId: req.user?.sub ?? 'unknown', email: req.user?.email ?? 'unknown', role: req.user?.role ?? 'unknown', org: req.user?.org_id ?? '', ip: req.ip ?? 'unknown', userAgent: req.get('user-agent') ?? '' });

router.post('/scope-requests/:group/approve', requirePermission('vms:authorize'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.group)) { res.status(404).json({ error: 'Scope request not found' }); return; }
    const p = Approve.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: 'Body must be { method?, authority_name, authority_title, organisation_name, declaration_version, declaration_accepted: true, signed_document_ref? }' }); return; }
    const org = requestOrg(req);
    const r = await decideGroup(org, req.params.group, decider(req), 'approved', p.data);
    if (!r.ok) {
        logAudit({ user: actor(req), action: 'VMS_SCOPE_APPROVAL_REFUSED', resource: 'vms_scope_request', resource_id: req.params.group, org_id: org, ip: req.ip ?? 'unknown', result: 'failed', severity: 'warning', details: r.error.slice(0, 200) });
        res.status(r.status).json({ error: r.error }); return;
    }
    logAudit({ user: actor(req), action: 'VMS_SCOPE_APPROVED', resource: 'vms_scope_request', resource_id: req.params.group, org_id: org, ip: req.ip ?? 'unknown', result: 'success', severity: 'warning',
        details: `${r.scopes.length} entr${r.scopes.length === 1 ? 'y' : 'ies'} by ${p.data.authority_name} (${p.data.authority_title}), ${p.data.method}, approval ${r.approvalId}${r.superseded.length ? `, superseding ${r.superseded.length}` : ''}`.slice(0, 200) });
    reevaluate(org);
    res.json({ approval_id: r.approvalId, scopes: r.scopes, superseded: r.superseded });
});

router.post('/scope-requests/:group/reject', requirePermission('vms:authorize'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.group)) { res.status(404).json({ error: 'Scope request not found' }); return; }
    const reason = typeof req.body?.reason === 'string' ? req.body.reason : '';
    const org = requestOrg(req);
    const r = await decideGroup(org, req.params.group, decider(req), 'rejected', { reason, method: req.body?.method === 'offline_document' ? 'offline_document' : 'in_platform', signed_document_ref: typeof req.body?.signed_document_ref === 'string' ? req.body.signed_document_ref : undefined });
    if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
    logAudit({ user: actor(req), action: 'VMS_SCOPE_REJECTED', resource: 'vms_scope_request', resource_id: req.params.group, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: reason.slice(0, 200) });
    res.json({ approval_id: r.approvalId, rejected: r.scopes.length });
});

// The organisation's authorisation decisions (immutable records).
router.get('/scope-approvals', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const { data, error } = await getSupabase()!.from('vms_scope_approvals').select('id, request_group_id, scope_ids, decision, method, decided_by_email, decided_by_role, authority_name, authority_title, organisation_name, signed_document_ref, declaration_version, declaration_sha256, snapshot, reason, decided_at')
        .eq('org_id', requestOrg(req)).order('decided_at', { ascending: false }).limit(200);
    if (error) { res.status(/vms_scope_approvals/.test(error.message) ? 503 : 502).json({ error: /vms_scope_approvals/.test(error.message) ? 'Scope approval is not set up yet (run sql/2026-11-01_p27_vms_onboarding.sql)' : dbErrorMessage(error) }); return; }
    res.json({ approvals: data ?? [] });
});

// Revoking is open to the managers who request scope and to the organisation that granted it.
const revokers = (req: AuthRequest, res: import('express').Response, next: import('express').NextFunction) =>
    (hasPermission(req.user?.role, 'vms:authorize') ? requirePermission('vms:authorize') : requirePermission('vms:scope'))(req, res, next);
router.post('/scopes/:id/revoke', revokers, async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Scope not found' }); return; }
    const org = requestOrg(req);
    const supabase = getSupabase()!;
    const { data, error } = await supabase.from('vms_scopes').update({ status: 'revoked', revoked_by: actor(req), revoked_at: new Date().toISOString() })
        .eq('id', req.params.id).eq('org_id', org).eq('status', 'active').select('*').maybeSingle();
    if (error) { fail(res, error); return; }
    if (!data) { res.status(404).json({ error: 'Active scope not found' }); return; }
    // Nothing more may run under it: queued jobs are cancelled, running ones asked to stop.
    await supabase.from('vms_scan_jobs').update({ status: 'cancelled', finished_at: new Date().toISOString(), error: 'Scope revoked' }).eq('scope_id', data.id).eq('status', 'queued');
    await supabase.from('vms_scan_jobs').update({ cancel_requested: true }).eq('scope_id', data.id).eq('status', 'running');
    logAudit({ user: actor(req), action: 'VMS_SCOPE_REVOKED', resource: 'vms_scope', resource_id: data.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success', severity: 'warning', details: `${data.kind} ${data.value}` });
    reevaluate(org);
    res.json({ scope: data });
});

// ── Scans ───────────────────────────────────────────────────────────────────────────────────
router.get('/scans', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const supabase = getSupabase()!;
    const org = requestOrg(req);
    const q = req.query;
    const limit = Math.min(Math.max(Math.round(Number(q.limit) || 100), 1), 500);
    let query = supabase.from('vms_scan_jobs').select('*').eq('org_id', org);
    if (typeof q.status === 'string' && ['queued', 'running', 'succeeded', 'failed', 'cancelled'].includes(q.status)) query = query.eq('status', q.status);
    if (typeof q.kind === 'string' && /^[a-z_]{1,40}$/.test(q.kind)) query = query.eq('kind', q.kind);
    const { data, error } = await query.order('requested_at', { ascending: false }).limit(limit);
    if (error) { fail(res, error); return; }
    // Queued scans that no connected worker can take (kind, or a private target with no route) say why.
    const scanner = (data ?? []).some((j) => j.status === 'queued') ? await loadScannerStatus() : null;
    // Findings each scan produced evidence for (distinct findings, this organisation only).
    const perJob = new Map<string, Set<string>>();
    const ids = (data ?? []).map((j) => j.id);
    for (let i = 0; i < ids.length; i += 200) {
        const { data: ev } = await supabase.from('vms_finding_evidence').select('job_id, finding_id').eq('org_id', org).in('job_id', ids.slice(i, i + 200)).limit(20_000);
        for (const e of ev ?? []) { const s = perJob.get(e.job_id) ?? new Set<string>(); s.add(e.finding_id); perJob.set(e.job_id, s); }
    }
    res.json({ scans: (data ?? []).map((j) => ({ ...j, attention: scanner ? jobAttention(j, scanner) : null, findings_count: perJob.get(j.id)?.size ?? 0 })) });
});

// Raw tool output kept for a scan (redacted, at most 30 days old).
router.get('/scans/:id/evidence', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Scan not found' }); return; }
    const supabase = getSupabase()!;
    const org = requestOrg(req);
    const { data: job } = await supabase.from('vms_scan_jobs').select('id').eq('id', req.params.id).eq('org_id', org).maybeSingle();
    if (!job) { res.status(404).json({ error: 'Scan not found' }); return; }
    const { data, error } = await supabase.from('vms_job_evidence').select('id, target, tool, content, truncated, bytes, sha256, created_at, expires_at')
        .eq('job_id', job.id).eq('org_id', org).gt('expires_at', new Date().toISOString()).order('created_at').limit(50);
    if (error) { res.json({ available: false, evidence: [], note: 'Raw evidence is not set up yet' }); return; }
    res.json({ available: true, evidence: data ?? [], retention_days: 30 });
});

const PORT_SPEC = /^(top-(100|1000)|(\d{1,5}(-\d{1,5})?)(,\d{1,5}(-\d{1,5})?){0,63})$/;
export const NewScan = z.object({
    scope_id: z.string().uuid(),
    kind: z.enum(['passive_osint', 'discovery', 'ports', 'vuln_nuclei', 'vuln_openvas']),
    targets: z.array(z.string().max(253)).max(MAX_TARGETS).optional(),
    ports: z.string().regex(PORT_SPEC).optional(),
}).strict();
export const activityOf = (kind: string): Activity => (kind === 'passive_osint' ? 'passive' : kind === 'ports' ? 'ports' : kind.startsWith('vuln_') ? 'vuln' : 'discovery');

/** Checks a scan request against its scope: active, unexpired, the activity authorised, every target inside. Shared with schedules. */
export async function validateScan(org: string, input: z.infer<typeof NewScan>, extraOptions: Record<string, unknown> = {}):
    Promise<{ ok: true; scope: ScopeEntry; targets: string[]; options: Record<string, unknown> } | { ok: false; status: number; error: string }> {
    const supabase = getSupabase()!;
    const { data: scope, error } = await supabase.from('vms_scopes').select('*').eq('id', input.scope_id).eq('org_id', org).maybeSingle();
    if (error) return { ok: false, status: missing(error) ? 503 : 502, error: missing(error) ? P4_MISSING : dbErrorMessage(error) };
    const entry = scope as ScopeEntry | null;
    if (!entry || entry.status !== 'active' || Date.parse(entry.expires_at) <= Date.now()) return { ok: false, status: 400, error: 'That scope is not active (revoked, expired or not found)' };
    const activity = activityOf(input.kind);
    if (entry.kind === 'asn') {
        if (activity !== 'passive') return { ok: false, status: 403, error: 'An AS number is registered for passive monitoring only' };
        return { ok: true, scope: entry, targets: [entry.value], options: { ...extraOptions } };
    }
    if (activity === 'discovery' && entry.allow_discovery === false) return { ok: false, status: 403, error: 'This scope authorises passive monitoring only' };
    if (activity === 'ports' && !entry.allow_port_scan) return { ok: false, status: 403, error: 'This scope does not authorise port scanning' };
    if (activity === 'vuln' && !entry.allow_vuln_scan) return { ok: false, status: 403, error: 'This scope does not authorise vulnerability scanning' };
    const requested = input.targets?.length ? input.targets : [entry.value];
    const targets: string[] = [];
    for (const raw of requested) {
        if (entry.kind === 'cidr' && raw === entry.value) {
            // A whole range would sweep its excluded addresses too: queue individual addresses instead.
            if ((entry.exclusions ?? []).length) return { ok: false, status: 400, error: 'This range has exclusions: queue the addresses to assess individually' };
            targets.push(raw); continue;
        }
        const t = parseTarget(raw);
        if (!t || !coveringScope(t, [entry], activity)) return { ok: false, status: 400, error: `Not in this scope: ${String(raw).slice(0, 80)}` };
        targets.push(t.value);
    }
    // A CNII authorisation of a domain is pinned to the addresses it resolved to when approved (P18):
    // while the name resolves outside them it is not scanned — a DNS change needs a new approval.
    const pins = entry.kind === 'domain' && activity !== 'passive' ? (entry.pinned_addresses ?? []) : [];
    if (pins.length) for (const t of new Set(targets)) {
        const r = await resolveAddresses(t);
        const ok = pinsSatisfied(r.addresses, pins);
        if (!ok.ok) return { ok: false, status: 409, error: `Not queued: ${t} is authorised by a CNII approval pinned to its approved addresses, and ${r.error ? `its DNS lookup failed (${r.error})` : ok.reason}. A manager must re-approve it.` };
    }
    const options = { ...(input.kind === 'ports' ? { ports: input.ports ?? 'top-1000' } : {}), ...extraOptions };
    return { ok: true, scope: entry, targets: [...new Set(targets)].sort(), options };
}

/** Queue priority (P19): higher is claimed first; equal priority is first-in, first-out. */
export const JOB_PRIORITY = { verification: 80, manual: 60, event: 50, schedule: 40, policy: 30 } as const;
export type JobTrigger = keyof typeof JOB_PRIORITY;

/** Queues a scan after checking every target against scope. Shared with the scheduler (Release 3). */
// P27 job limits (queued + running at once). Generous defaults so existing automation is not cut
// short; tighten per scope (max_active_jobs, approved with it) or platform-wide by environment.
export const ORG_ACTIVE_JOB_LIMIT = () => Math.max(1, Number(process.env.VMS_MAX_ACTIVE_JOBS_PER_ORG) || 50);
export const SCOPE_ACTIVE_JOB_LIMIT = () => Math.max(1, Number(process.env.VMS_MAX_ACTIVE_JOBS_PER_SCOPE) || 20);
/** Why another job may not be queued now (a limit is reached), or null. */
export async function activeJobLimits(org: string, entry: ScopeEntry): Promise<string | null> {
    const supabase = getSupabase()!;
    const [o, s] = await Promise.all([
        supabase.from('vms_scan_jobs').select('id', { count: 'exact', head: true }).eq('org_id', org).in('status', ['queued', 'running']),
        supabase.from('vms_scan_jobs').select('id', { count: 'exact', head: true }).eq('org_id', org).eq('scope_id', entry.id).in('status', ['queued', 'running']),
    ]);
    const orgMax = ORG_ACTIVE_JOB_LIMIT();
    const scopeMax = (entry as ScopeEntry & { max_active_jobs?: number | null }).max_active_jobs ?? SCOPE_ACTIVE_JOB_LIMIT();
    if ((o.count ?? 0) >= orgMax) return `Job limit reached: ${o.count} scans are already queued or running for this organisation (limit ${orgMax})`;
    if ((s.count ?? 0) >= scopeMax) return `Job limit reached: ${s.count} scans are already queued or running under this scope entry (limit ${scopeMax})`;
    return null;
}

export async function queueScan(org: string, by: string, input: z.infer<typeof NewScan>, extra: { schedule_id?: string; purpose?: 'assessment' | 'verification'; options?: Record<string, unknown>; assessment_id?: string; trigger?: JobTrigger } = {}):
    Promise<{ ok: true; job: Record<string, unknown>; existing: boolean } | { ok: false; status: number; error: string; retry_at?: string | null }> {
    const supabase = getSupabase()!;
    const v = await validateScan(org, input, extra.options);
    if (!v.ok) return v;
    const { scope: entry, targets: uniq, options } = v;
    // OpenVAS runs only when switched on and only against scopes approved for it (lib/openvasPolicy.ts).
    if (input.kind === 'vuln_openvas') {
        const pol = openvasAllowed(entry.id);
        if (!pol.allowed) {
            logAudit({ user: by, action: 'VMS_SCAN_REFUSED', resource: 'vms_scope', resource_id: entry.id, org_id: org, ip: 'n/a', result: 'failed', severity: 'warning', details: `vuln_openvas: ${pol.reason}` });
            return { ok: false, status: 409, error: pol.reason };
        }
    }
    // The same scan already waiting or running: return it instead of queueing a duplicate.
    const { data: open } = await supabase.from('vms_scan_jobs').select('*').eq('org_id', org).eq('scope_id', entry.id).eq('kind', input.kind).in('status', ['queued', 'running']);
    const dup = (open ?? []).find((j) => JSON.stringify(j.targets) === JSON.stringify(uniq) && JSON.stringify(j.options ?? {}) === JSON.stringify(options));
    if (dup) return { ok: true, job: dup, existing: true };
    // P27: only inside the scope's approved scan windows (passive collection is not scanning).
    const windows = (entry as ScopeEntry & { scan_windows?: ScanWindows | null }).scan_windows ?? null;
    if (activityOf(input.kind) !== 'passive' && !inScanWindow(windows)) {
        const nextAt = nextScanWindow(windows);
        return { ok: false, status: 409, error: `Outside the approved scan windows (${describeScanWindows(windows)})`, retry_at: nextAt ? new Date(nextAt).toISOString() : null };
    }
    // P27: job limits — queued + running jobs per organisation and per scope entry.
    const lim = await activeJobLimits(org, entry);
    if (lim) return { ok: false, status: 429, error: lim, retry_at: null };
    const trigger: JobTrigger = extra.purpose === 'verification' ? 'verification' : extra.trigger ?? (extra.schedule_id ? 'schedule' : 'manual');
    const row = { org_id: org, scope_id: entry.id, kind: input.kind, targets: uniq, options, requested_by: by, schedule_id: extra.schedule_id ?? null, purpose: extra.purpose ?? 'assessment', ...(extra.assessment_id ? { assessment_id: extra.assessment_id } : {}) };
    let ins = await supabase.from('vms_scan_jobs').insert({ ...row, priority: JOB_PRIORITY[trigger] }).select('*').single();
    // Before sql/2026-10-25_p19_vms_automation.sql there is no priority column: queue in arrival order.
    if (ins.error && /priority/.test(ins.error.message) && /column|schema cache/i.test(ins.error.message)) ins = await supabase.from('vms_scan_jobs').insert(row).select('*').single();
    if (ins.error) return { ok: false, status: 502, error: dbErrorMessage(ins.error) };
    logAudit({ user: by, action: 'VMS_SCAN_QUEUED', resource: 'vms_scan_job', resource_id: ins.data.id, org_id: org, ip: 'n/a', result: 'success', details: `${input.kind} ${uniq.slice(0, 5).join(', ')}${uniq.length > 5 ? ` +${uniq.length - 5}` : ''}` });
    return { ok: true, job: ins.data, existing: false };
}

router.post('/scans', requirePermission('vms:scan'), async (req: AuthRequest, res) => {
    const p = NewScan.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: 'Body must be { scope_id, kind: passive_osint|discovery|ports|vuln_nuclei|vuln_openvas, targets?: [host or IP], ports?: "top-100" | "top-1000" | "22,80,8000-8100" }' }); return; }
    const r = await queueScan(requestOrg(req), actor(req), p.data);
    if (!r.ok) { res.status(r.status).json({ error: r.error, ...(r.retry_at !== undefined ? { retry_at: r.retry_at } : {}) }); return; }
    // Queued either way; the warning says up front if no connected worker can take it.
    const warning = jobAttention(r.job as { kind: string; status: string; targets: unknown }, await loadScannerStatus());
    res.status(r.existing ? 200 : 201).json({ scan: r.job, existing: r.existing, warning });
});

router.post('/scans/:id/cancel', requirePermission('vms:scan'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Scan not found' }); return; }
    const supabase = getSupabase()!;
    const org = requestOrg(req);
    const { data: job } = await supabase.from('vms_scan_jobs').select('id, status').eq('id', req.params.id).eq('org_id', org).maybeSingle();
    if (!job) { res.status(404).json({ error: 'Scan not found' }); return; }
    if (job.status === 'queued') await supabase.from('vms_scan_jobs').update({ status: 'cancelled', finished_at: new Date().toISOString(), error: `Cancelled by ${actor(req)}` }).eq('id', job.id).eq('status', 'queued');
    else if (job.status === 'running') await supabase.from('vms_scan_jobs').update({ cancel_requested: true }).eq('id', job.id);
    else { res.status(409).json({ error: `Already ${job.status}` }); return; }
    const { data } = await supabase.from('vms_scan_jobs').select('*').eq('id', job.id).maybeSingle();
    res.json({ scan: data, message: job.status === 'running' ? 'The worker will stop this scan at its next checkpoint' : 'Cancelled' });
});

// ── Inventory ───────────────────────────────────────────────────────────────────────────────
router.get('/assets', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const q = req.query;
    const text = typeof q.q === 'string' && q.q.trim() ? q.q.trim().toLowerCase() : null;
    if (text && !/^[\w.:-]{1,100}$/.test(text)) { res.status(400).json({ error: 'q may hold letters, digits and . : _ -' }); return; }
    let query = getSupabase()!.from('vms_assets').select('*').eq('org_id', requestOrg(req));
    if (typeof q.type === 'string' && ['domain', 'host', 'ip', 'endpoint', 'asn', 'cidr'].includes(q.type)) query = query.eq('asset_type', q.type);
    if (typeof q.status === 'string' && ['active', 'gone'].includes(q.status)) query = query.eq('status', q.status);
    if (typeof q.exposure === 'string' && ['internet', 'internal', 'unknown'].includes(q.exposure)) query = query.eq('exposure', q.exposure);
    if (text) query = query.ilike('value', `*${text}*`);
    const { data, error } = await query.order('last_seen', { ascending: false }).limit(1000);
    if (error) { fail(res, error); return; }
    // Open findings per asset: count, by severity, and the highest risk score (stored values only).
    const { data: open } = await getSupabase()!.from('vms_findings').select('asset_id, scanner_severity, risk_score')
        .eq('org_id', requestOrg(req)).in('status', ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened']).not('asset_id', 'is', null).limit(20_000);
    const per = new Map<string, { open: number; by_severity: Record<string, number>; max_risk: number | null }>();
    for (const f of open ?? []) {
        const e = per.get(f.asset_id) ?? { open: 0, by_severity: {}, max_risk: null };
        e.open++; e.by_severity[f.scanner_severity] = (e.by_severity[f.scanner_severity] ?? 0) + 1;
        if (typeof f.risk_score === 'number') e.max_risk = Math.max(e.max_risk ?? 0, f.risk_score);
        per.set(f.asset_id, e);
    }
    // P27: whether each asset is inside an approved scope (and for which activities), only in a pending
    // request, or not authorised — and where it came from. Additive fields.
    const scopes = await scopesForAuthorisation(requestOrg(req));
    // P28: this organisation's CNII sector classification, if any — assets belong to it by being
    // this organisation's assets; CNII does not keep a separate per-asset store (sql/2026-10-17_p9_cnii.sql).
    const { data: cniiProfile } = await getSupabase()!.from('cnii_org_profiles').select('sector_id, designation').eq('org_id', requestOrg(req)).maybeSingle();
    let rows = (data ?? []).map((a) => ({
        ...a,
        findings: per.get(a.id) ?? { open: 0, by_severity: {}, max_risk: null },
        authorization: authorisationFor(scanTargetOf(a), scopes.active, scopes.pending),
        sources: sourceLabels(a.discovery_sources ?? []),
        categories: assetCategories(a, per.has(a.id)),
        cnii: cniiProfile ?? null,
    }));
    if (typeof q.category === 'string' && ['wazuh', 'vulnerability', 'cloud', 'other'].includes(q.category)) {
        const cat = q.category as InventoryCategory;
        rows = rows.filter((a) => a.categories.includes(cat));
    }
    res.json({ assets: rows });
});

// Relationships around an asset, from stored records only, each labelled confirmed/observed/inferred.
router.get('/assets/:id/graph', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Asset not found' }); return; }
    const g = await assetGraph(requestOrg(req), req.params.id);
    if (!g) { res.status(404).json({ error: 'Asset not found' }); return; }
    res.json(g);
});

router.get('/assets/:id', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Asset not found' }); return; }
    const supabase = getSupabase()!;
    const org = requestOrg(req);
    const { data: asset, error } = await supabase.from('vms_assets').select('*').eq('id', req.params.id).eq('org_id', org).maybeSingle();
    if (error) { fail(res, error); return; }
    if (!asset) { res.status(404).json({ error: 'Asset not found' }); return; }
    // A Wazuh endpoint and a scanned address are separate records; show each from the other (P14).
    const addrs: string[] = asset.asset_type === 'endpoint' ? (asset.ips ?? []) : asset.asset_type === 'ip' ? [asset.value] : [];
    const [services, techs, events, linked] = await Promise.all([
        supabase.from('vms_services').select('*').eq('asset_id', asset.id).order('port'),
        supabase.from('vms_technologies').select('*').eq('asset_id', asset.id).order('name'),
        supabase.from('vms_asset_events').select('*').eq('asset_id', asset.id).order('at', { ascending: false }).limit(100),
        addrs.length
            ? (asset.asset_type === 'endpoint'
                ? supabase.from('vms_assets').select('id, asset_type, value, exposure, last_seen').eq('org_id', org).eq('asset_type', 'ip').in('value', addrs)
                : supabase.from('vms_assets').select('id, asset_type, value, exposure, last_seen').eq('org_id', org).eq('asset_type', 'endpoint').overlaps('ips', addrs))
            : Promise.resolve({ data: [] }),
    ]);
    const linkedIds = (linked.data ?? []).map((l) => l.id);
    const linkedServices = linkedIds.length ? (await supabase.from('vms_services').select('*').in('asset_id', linkedIds).eq('status', 'active').order('port')).data ?? [] : [];
    // P28: has a person already confirmed or rejected "same machine?" for this inferred pair.
    const { data: links } = linkedIds.length
        ? await supabase.from('vms_asset_links').select('*').eq('org_id', org).eq('relation', 'same_machine').or(`asset_a.eq.${asset.id},asset_b.eq.${asset.id}`)
        : { data: [] };
    const linkFor = (otherId: string) => (links ?? []).find((l) => (l.asset_a === asset.id && l.asset_b === otherId) || (l.asset_a === otherId && l.asset_b === asset.id)) ?? null;
    res.json({
        asset, services: services.data ?? [], technologies: techs.data ?? [], events: events.data ?? [],
        linked: (linked.data ?? []).map((l) => {
            const confirmation = linkFor(l.id);
            return {
                ...l, relation: 'same address (inferred: an address can be shared or reassigned)', services: linkedServices.filter((s) => s.asset_id === l.id),
                same_machine: confirmation ? { basis: confirmation.basis, confirmed_by: confirmation.confirmed_by, confirmed_at: confirmation.confirmed_at } : null,
            };
        }),
    });
});

const AssetLinkBody = z.object({
    asset_a: z.string().uuid(), asset_b: z.string().uuid(),
    relation: z.enum(['same_machine', 'serves', 'resolves_to']),
    basis: z.enum(['confirmed', 'rejected']),
    note: z.string().trim().max(500).optional(),
}).strict();
// P28: a person confirming or rejecting a suggested relationship between two inventory records
// (starting with "same machine?" on the asset page). Never written automatically — the inferred
// same_address lead from vmsGraph.ts/this file's /assets/:id stays separate and derived-on-read.
router.post('/asset-links', requirePermission('vms:manage'), async (req: AuthRequest, res) => {
    const p = AssetLinkBody.safeParse(req.body);
    if (!p.success) { res.status(400).json({ error: 'Body needs asset_a, asset_b (different UUIDs), relation and basis' }); return; }
    if (p.data.asset_a === p.data.asset_b) { res.status(400).json({ error: 'asset_a and asset_b must be different assets' }); return; }
    const org = requestOrg(req);
    const supabase = getSupabase()!;
    const { data: assets, error } = await supabase.from('vms_assets').select('id').eq('org_id', org).in('id', [p.data.asset_a, p.data.asset_b]);
    if (error) { fail(res, error); return; }
    if ((assets ?? []).length !== 2) { res.status(404).json({ error: 'Both assets must exist in this organisation' }); return; }
    // A pair is unordered (confirming A~B is the same as confirming B~A) — sort so either order
    // collapses onto the same row instead of the unique index missing the reversed pair.
    const [asset_a, asset_b] = [p.data.asset_a, p.data.asset_b].sort();
    const { data: row, error: insErr } = await supabase.from('vms_asset_links')
        .upsert({ org_id: org, asset_a, asset_b, relation: p.data.relation, basis: p.data.basis, note: p.data.note ?? null, confirmed_by: actor(req), confirmed_at: new Date().toISOString() }, { onConflict: 'org_id,asset_a,asset_b,relation' })
        .select('*').maybeSingle();
    if (insErr) { fail(res, insErr); return; }
    logAudit({ user: actor(req), action: 'VMS_ASSET_LINK', resource: 'vms_asset_link', resource_id: row?.id ?? null, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: `${p.data.relation}:${p.data.basis} ${p.data.asset_a}~${p.data.asset_b}` });
    res.json({ link: row });
});

const AssetPatch = z.object({ owner: z.string().trim().max(200).nullable().optional(), criticality: z.enum(['low', 'medium', 'high', 'critical']).optional() }).strict();
router.patch('/assets/:id', requirePermission('vms:manage'), async (req: AuthRequest, res) => {
    if (!isUuid(req.params.id)) { res.status(404).json({ error: 'Asset not found' }); return; }
    const p = AssetPatch.safeParse(req.body);
    if (!p.success || !Object.keys(p.data).length) { res.status(400).json({ error: "Body may hold owner (text or null) and criticality ('low'|'medium'|'high'|'critical')" }); return; }
    const org = requestOrg(req);
    const { data, error } = await getSupabase()!.from('vms_assets').update(p.data).eq('id', req.params.id).eq('org_id', org).select('*').maybeSingle();
    if (error) { fail(res, error); return; }
    if (!data) { res.status(404).json({ error: 'Asset not found' }); return; }
    logAudit({ user: actor(req), action: 'VMS_ASSET_UPDATED', resource: 'vms_asset', resource_id: data.id, org_id: org, ip: req.ip ?? 'unknown', result: 'success', details: JSON.stringify(p.data).slice(0, 200) });
    res.json({ asset: data });
});

router.get('/events', requirePermission('vms:read'), async (req: AuthRequest, res) => {
    const n = Math.min(Math.max(Number(req.query.days) || 7, 1), 90);
    const { data, error } = await getSupabase()!.from('vms_asset_events').select('*, vms_assets(value, asset_type, exposure)').eq('org_id', requestOrg(req)).gte('at', days(n)).order('at', { ascending: false }).limit(500);
    if (error) { fail(res, error); return; }
    res.json({ events: data ?? [] });
});

export default router;
