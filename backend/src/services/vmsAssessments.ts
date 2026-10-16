// Asset-centric Full Assessment (phase P13). One assessment = every scan of the profile, planned
// for one target (an asset's host or IP) under one authorised scope entry.
//
// Planning happens before anything is dispatched, and records a decision per step:
//   queued         a scan job was queued (through routes/vms.ts queueScan: scope re-checked, deduped)
//   not_attempted  the scope entry does not allow it, the target is excluded, or no worker has a
//                  route to a private target — with the reason
//   unsupported    no connected worker runs that kind, has the tool, or enforces the scope's exclusions
// Step and assessment status are DERIVED from the jobs whenever read, so they cannot drift:
//   pending, running, completed, findings_detected, inconclusive, failed, not_attempted, unsupported
// A job that ended because it could not be attempted (worker "no route", or cancelled before it
// started) is not_attempted — never completed. A job that ran but could not assess the target
// (unreachable from the scanner, or too little evidence) is inconclusive: it says nothing about
// the target, so it is not counted as a completed check either. Retrying re-plans only steps that did not complete;
// completed steps, their findings and their evidence stay.

import { getSupabase } from './geoEnrichment';
import { queueScan } from '../routes/vms';
import { coveringScope, parseTarget, type ScopeEntry, type Activity, type Target } from '../lib/vmsScope';
import { isNonPublicIp, workerCanReach } from '../lib/netClass';
import { loadScannerStatus, type ScannerStatus } from './vmsWorkers';
import { logAudit } from '../lib/audit';

export const FULL_PROFILE = ['discovery', 'ports', 'vuln_nuclei', 'vuln_openvas'] as const;
export type ProfileKind = (typeof FULL_PROFILE)[number];
export type StepDecision = 'queued' | 'not_attempted' | 'unsupported';
export type StepStatus = 'pending' | 'running' | 'completed' | 'findings_detected' | 'inconclusive' | 'failed' | 'not_attempted' | 'unsupported';
/** Steps a retry re-plans: everything that did not give an answer about the target. */
export const RETRYABLE: ReadonlySet<StepStatus> = new Set(['inconclusive', 'failed', 'not_attempted', 'unsupported']);
/** Job outcomes (worker job_outcome) under which a finished scan assessed nothing. */
const NO_ASSESSMENT: Record<string, string> = { unreachable: 'the target did not answer this scanner', insufficient_evidence: 'the scanner got too little evidence to assess the target' };
/** An assessment saved but not yet planned (steps still empty) is treated as in progress this long. */
export const PLANNING_GRACE_MS = 10 * 60_000;
export type AssessmentStatus = 'in_progress' | 'completed' | 'partial' | 'inconclusive' | 'failed' | 'not_attempted' | 'cancelled';
export interface Step { kind: ProfileKind; decision: StepDecision; reason: string; job_id: string | null; previous_job_ids: string[] }
export const P13_MISSING = 'Assessments are not set up yet (run sql/2026-10-20_p13_vms_assessments.sql)';
export const isMissingP13 = (e: { message?: string; code?: string } | null) => !!e && (e.code === 'PGRST205' || e.code === '42P01' || e.code === 'PGRST204' || /vms_assessments|assessment_id/.test(e.message ?? '') && /does not exist|Could not find|schema cache/i.test(e.message ?? ''));

const ACTIVITY: Record<ProfileKind, Activity> = { discovery: 'discovery', ports: 'ports', vuln_nuclei: 'vuln', vuln_openvas: 'vuln' };
const TOOLS_NEEDED: Record<ProfileKind, string[]> = { discovery: ['httpx'], ports: ['nmap'], vuln_nuclei: ['nuclei'], vuln_openvas: ['openvas'] };
const LABEL: Record<ProfileKind, string> = { discovery: 'Discovery', ports: 'Ports & services', vuln_nuclei: 'Vulnerabilities (Nuclei)', vuln_openvas: 'Vulnerabilities (OpenVAS)' };
export const stepLabel = (k: string) => LABEL[k as ProfileKind] ?? k;

/** Pure: what to do with one step, before anything is queued. */
export function planStep(kind: ProfileKind, target: Target, scope: ScopeEntry, scanner: ScannerStatus): { decision: StepDecision | 'queue'; reason: string } {
    const activity = ACTIVITY[kind];
    if (activity === 'discovery' && scope.allow_discovery === false) return { decision: 'not_attempted', reason: 'The authorised scope entry allows passive monitoring only' };
    if (activity === 'ports' && !scope.allow_port_scan) return { decision: 'not_attempted', reason: 'The authorised scope entry does not allow port scanning' };
    if (activity === 'vuln' && !scope.allow_vuln_scan) return { decision: 'not_attempted', reason: 'The authorised scope entry does not allow vulnerability scanning' };
    if (!coveringScope(target, [scope], activity)) return { decision: 'not_attempted', reason: `${target.value} is excluded from, or not covered by, the authorised scope entry` };
    if (scanner.source !== 'presence') return { decision: 'queue', reason: 'Queued; worker capabilities could not be checked (worker presence is not recorded)' };
    const online = scanner.workers.filter((w) => w.online && (w.kinds ?? []).includes(kind));
    if (!online.length) return { decision: 'unsupported', reason: `No connected scanner worker runs ${stepLabel(kind)}` };
    const tooled = online.filter((w) => TOOLS_NEEDED[kind].every((t) => (w.tools ?? {})[t] !== false));
    if (!tooled.length) return { decision: 'unsupported', reason: `No connected worker that runs ${stepLabel(kind)} has ${TOOLS_NEEDED[kind].join(', ')} installed` };
    const enforcing = (scope.exclusions ?? []).length ? tooled.filter((w) => (w.features ?? []).includes('exclusions')) : tooled;
    if (!enforcing.length) return { decision: 'unsupported', reason: 'This scope entry has exclusions and no connected worker that runs it enforces them (worker 1.4.0 or later)' };
    if (target.type === 'ip' && isNonPublicIp(target.value) && !enforcing.some((w) => workerCanReach(target.value, w.networks ?? []))) {
        return { decision: 'not_attempted', reason: `${target.value} is a private address and no connected worker declares a route to its network (VMS_WORKER_NETWORKS); a worker inside that network is needed` };
    }
    return { decision: 'queue', reason: 'Queued' };
}

interface JobRow { id: string; status: string; started_at: string | null; finished_at: string | null; error: string | null; summary: Record<string, unknown> | null; progress: Record<string, unknown> | null; kind: string }

/** Pure: a step's status from its decision, its job and how many findings that job produced. */
export function stepStatus(step: Step, job: JobRow | undefined, findings: number): { status: StepStatus; detail: string } {
    if (step.decision !== 'queued') return { status: step.decision, detail: step.reason };
    if (!job) return { status: 'failed', detail: 'The scan job record is missing' };
    const outcome = typeof job.summary?.outcome === 'string' ? job.summary.outcome : null;
    switch (job.status) {
        case 'queued': return { status: 'pending', detail: String(job.progress?.message ?? 'Waiting for a worker') };
        case 'running': return { status: 'running', detail: String(job.progress?.phase ?? 'Running') };
        case 'succeeded':
            if (findings > 0) return { status: 'findings_detected', detail: `${findings} finding(s)` };
            if (outcome && NO_ASSESSMENT[outcome]) return { status: 'inconclusive', detail: `Ran, but ${NO_ASSESSMENT[outcome]} — no assurance either way` };
            return { status: 'completed', detail: outcome ? `Completed — outcome: ${outcome.replace(/_/g, ' ')}` : 'Completed — nothing found' };
        case 'failed':
            if (outcome === 'no_route') return { status: 'not_attempted', detail: job.error ?? 'No route from the worker' };
            return { status: 'failed', detail: job.error ?? 'Failed' };
        case 'cancelled':
            return job.started_at ? { status: 'failed', detail: job.error ?? 'Cancelled while running' } : { status: 'not_attempted', detail: job.error ?? 'Cancelled before it ran' };
        default: return { status: 'failed', detail: `Unknown job state ${job.status}` };
    }
}

/** Pure: the assessment's status from its steps' statuses. */
export function assessmentStatus(statuses: StepStatus[], cancelled: boolean): AssessmentStatus {
    if (statuses.some((s) => s === 'pending' || s === 'running')) return cancelled ? 'cancelled' : 'in_progress';
    if (cancelled) return 'cancelled';
    const done = statuses.filter((s) => s === 'completed' || s === 'findings_detected').length;
    if (statuses.length && done === statuses.length) return 'completed';
    if (done > 0) return 'partial';
    if (statuses.some((s) => s === 'failed')) return 'failed';
    // Something ran but could not assess the target: not the same as never attempted.
    return statuses.some((s) => s === 'inconclusive') ? 'inconclusive' : 'not_attempted';
}

export interface AssessmentRow { id: string; org_id: string; asset_id: string | null; scope_id: string; target: string; profile: string; steps: Step[]; requested_by: string; requested_at: string; retried_at: string | null; cancelled_at: string | null }

/** Steps with live status, finding counts and the job's outcome; and the overall status. */
export async function describe(rows: AssessmentRow[]) {
    const supabase = getSupabase()!;
    const jobIds = [...new Set(rows.flatMap((r) => (r.steps ?? []).flatMap((s) => [s.job_id, ...(s.previous_job_ids ?? [])]).filter((x): x is string => !!x)))];
    const jobs = new Map<string, JobRow>();
    const findingsByJob = new Map<string, Set<string>>();
    for (let i = 0; i < jobIds.length; i += 200) {
        const chunk = jobIds.slice(i, i + 200);
        const [j, ev] = await Promise.all([
            supabase.from('vms_scan_jobs').select('id, kind, status, started_at, finished_at, error, summary, progress').in('id', chunk),
            supabase.from('vms_finding_evidence').select('finding_id, job_id').in('job_id', chunk).limit(10_000),
        ]);
        for (const x of (j.data ?? []) as JobRow[]) jobs.set(x.id, x);
        for (const e of ev.data ?? []) { const s = findingsByJob.get(e.job_id) ?? new Set(); s.add(e.finding_id); findingsByJob.set(e.job_id, s); }
    }
    return rows.map((r) => {
        const steps = (r.steps ?? []).map((s) => {
            const job = s.job_id ? jobs.get(s.job_id) : undefined;
            const st = stepStatus(s, job, s.job_id ? findingsByJob.get(s.job_id)?.size ?? 0 : 0);
            return {
                ...s, label: stepLabel(s.kind), status: st.status, detail: st.detail,
                job: job ? { id: job.id, status: job.status, started_at: job.started_at, finished_at: job.finished_at, outcome: job.summary?.outcome ?? null, target_outcomes: job.summary?.target_outcomes ?? null } : null,
                finding_ids: s.job_id ? [...(findingsByJob.get(s.job_id) ?? [])] : [],
            };
        });
        // Saved but not yet planned (a concurrent request is planning it): in progress, so it is not duplicated.
        const planning = !steps.length && !r.cancelled_at && Date.now() - Date.parse(r.requested_at) < PLANNING_GRACE_MS;
        const status = planning ? 'in_progress' as const : assessmentStatus(steps.map((s) => s.status), !!r.cancelled_at);
        const counts = steps.reduce<Record<string, number>>((m, s) => ({ ...m, [s.status]: (m[s.status] ?? 0) + 1 }), {});
        const finished = steps.filter((s) => !['pending', 'running'].includes(s.status)).length;
        return { ...r, steps, status, step_counts: counts, progress: { finished, total: steps.length }, all_job_ids: [...new Set((r.steps ?? []).flatMap((s) => [s.job_id, ...(s.previous_job_ids ?? [])]).filter((x): x is string => !!x))] };
    });
}

/** Resolves what to assess: an asset's host/IP, or a target given directly. */
export async function resolveTarget(org: string, input: { asset_id?: string; target?: string }): Promise<{ ok: true; target: Target; asset_id: string | null } | { ok: false; status: number; error: string }> {
    const supabase = getSupabase()!;
    if (input.asset_id) {
        const { data: a } = await supabase.from('vms_assets').select('id, asset_type, value, ips').eq('id', input.asset_id).eq('org_id', org).maybeSingle();
        if (!a) return { ok: false, status: 404, error: 'Asset not found' };
        // A Wazuh endpoint is assessed at its recorded address; a host or IP at its own value.
        const raw = a.asset_type === 'endpoint' ? (a.ips ?? [])[0] : a.value;
        const t = raw ? parseTarget(String(raw)) : null;
        if (!t) return { ok: false, status: 400, error: a.asset_type === 'endpoint' ? 'This endpoint has no recorded IP address to assess' : `A ${a.asset_type} asset cannot be assessed directly; assess its hosts` };
        return { ok: true, target: t, asset_id: a.id };
    }
    const t = input.target ? parseTarget(input.target) : null;
    if (!t) return { ok: false, status: 400, error: 'Give an asset_id, or a target host or IP' };
    const { data: a } = await supabase.from('vms_assets').select('id').eq('org_id', org).eq('asset_type', t.type === 'host' ? 'host' : 'ip').eq('value', t.value).maybeSingle();
    return { ok: true, target: t, asset_id: a?.id ?? null };
}

async function queueStep(org: string, by: string, assessmentId: string, kind: ProfileKind, target: Target, scope: ScopeEntry, scanner: ScannerStatus, previous: string[] = []): Promise<Step> {
    const plan = planStep(kind, target, scope, scanner);
    if (plan.decision !== 'queue') return { kind, decision: plan.decision, reason: plan.reason, job_id: null, previous_job_ids: previous };
    const r = await queueScan(org, by, { scope_id: scope.id, kind, targets: [target.value], ...(kind === 'ports' ? { ports: 'top-1000' } : {}) }, { assessment_id: assessmentId });
    if (!r.ok) return { kind, decision: 'not_attempted', reason: r.error, job_id: null, previous_job_ids: previous };
    return { kind, decision: 'queued', reason: plan.reason, job_id: String(r.job.id), previous_job_ids: previous };
}

export type CreateResult = { ok: true; assessment: Awaited<ReturnType<typeof describe>>[number]; existing: boolean } | { ok: false; status: number; error: string };

// Requests for the same target in this process are serialised, so two clicks cannot both pass the
// "already in progress?" check before either has saved. (Across processes the saved-but-unplanned
// row counts as in progress: see PLANNING_GRACE_MS.)
const inFlight = new Map<string, Promise<unknown>>();
async function serialised<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = inFlight.get(key) ?? Promise.resolve();
    const run = prev.catch(() => undefined).then(fn);
    inFlight.set(key, run);
    try { return await run; } finally { if (inFlight.get(key) === run) inFlight.delete(key); }
}

/** Creates a Full Assessment, or returns the one already in progress for the same target (idempotent). */
export async function createAssessment(org: string, by: string, input: { asset_id?: string; target?: string; scope_id?: string }, ip = 'unknown', origin: { trigger?: 'manual' | 'policy' | 'schedule'; policy_id?: string } = {}): Promise<CreateResult> {
    const supabase = getSupabase()!;
    const t = await resolveTarget(org, input);
    if (!t.ok) return t;
    const { data: scopes, error: sErr } = await supabase.from('vms_scopes').select('*').eq('org_id', org).eq('status', 'active');
    if (sErr) return { ok: false, status: 502, error: 'Could not read the authorised scope' };
    const live = ((scopes ?? []) as ScopeEntry[]).filter((s) => Date.parse(s.expires_at) > Date.now());
    const scope = input.scope_id ? live.find((s) => s.id === input.scope_id) : live.find((s) => coveringScope(t.target, [s], 'passive'));
    if (!scope) return { ok: false, status: 403, error: `${t.target.value} is not inside an active authorised scope entry of this organisation` };
    if (!coveringScope(t.target, [scope], 'passive')) return { ok: false, status: 403, error: `${t.target.value} is excluded from, or not covered by, that scope entry` };
    return serialised(`${org}|${t.target.value}`, () => planAssessment(org, by, t, scope, ip, origin));
}

async function planAssessment(org: string, by: string, t: { target: Target; asset_id: string | null }, scope: ScopeEntry, ip: string, origin: { trigger?: 'manual' | 'policy' | 'schedule'; policy_id?: string }): Promise<CreateResult> {
    const supabase = getSupabase()!;
    // Idempotent: an assessment of the same target still in progress is returned, not duplicated.
    const { data: open, error: oErr } = await supabase.from('vms_assessments').select('*').eq('org_id', org).eq('target', t.target.value).eq('profile', 'full').is('cancelled_at', null).order('requested_at', { ascending: false }).limit(5);
    if (oErr) return { ok: false, status: isMissingP13(oErr) ? 503 : 502, error: isMissingP13(oErr) ? P13_MISSING : 'Could not read assessments' };
    const described = await describe((open ?? []) as AssessmentRow[]);
    const inProgress = described.find((a) => a.status === 'in_progress');
    if (inProgress) return { ok: true, assessment: inProgress, existing: true };

    const row = { org_id: org, asset_id: t.asset_id, scope_id: scope.id, target: t.target.value, profile: 'full', steps: [], requested_by: by };
    const withOrigin = origin.trigger && origin.trigger !== 'manual' ? { ...row, trigger: origin.trigger, ...(origin.policy_id ? { policy_id: origin.policy_id } : {}) } : row;
    let ins = await supabase.from('vms_assessments').insert(withOrigin).select('*').single();
    // Before the P14 SQL there is no trigger/policy_id column: record the assessment without them.
    if (ins.error && withOrigin !== row && (ins.error.code === 'PGRST204' || ins.error.code === '42703')) ins = await supabase.from('vms_assessments').insert(row).select('*').single();
    if (ins.error) return { ok: false, status: isMissingP13(ins.error) ? 503 : 502, error: isMissingP13(ins.error) ? P13_MISSING : 'Could not create the assessment' };
    const scanner = await loadScannerStatus();
    const steps: Step[] = [];
    for (const kind of FULL_PROFILE) steps.push(await queueStep(org, by, ins.data.id, kind, t.target, scope, scanner));
    const upd = await supabase.from('vms_assessments').update({ steps }).eq('id', ins.data.id).select('*').single();
    if (upd.error) return { ok: false, status: 502, error: 'The assessment was created but its plan could not be saved' };
    logAudit({ user: by, action: 'VMS_ASSESSMENT_REQUESTED', resource: 'vms_assessment', resource_id: ins.data.id, org_id: org, ip, result: 'success',
        details: `${t.target.value}: ${steps.map((s) => `${s.kind}=${s.decision}`).join(' ')}`.slice(0, 200) });
    return { ok: true, assessment: (await describe([upd.data as AssessmentRow]))[0], existing: false };
}

/** Re-plans the steps that did not complete. Completed steps, findings and evidence are kept. */
export async function retryAssessment(org: string, id: string, by: string, ip = 'unknown'): Promise<CreateResult> {
    const supabase = getSupabase()!;
    const { data: row, error } = await supabase.from('vms_assessments').select('*').eq('id', id).eq('org_id', org).maybeSingle();
    if (error) return { ok: false, status: isMissingP13(error) ? 503 : 502, error: isMissingP13(error) ? P13_MISSING : 'Could not read the assessment' };
    if (!row) return { ok: false, status: 404, error: 'Assessment not found' };
    if (row.cancelled_at) return { ok: false, status: 409, error: 'This assessment was cancelled; start a new one' };
    const [current] = await describe([row as AssessmentRow]);
    const retryable = RETRYABLE;
    if (!current.steps.some((s) => retryable.has(s.status))) return { ok: true, assessment: current, existing: true };
    const { data: scope } = await supabase.from('vms_scopes').select('*').eq('id', row.scope_id).eq('org_id', org).maybeSingle();
    const t = parseTarget(row.target);
    if (!scope || scope.status !== 'active' || Date.parse(scope.expires_at) <= Date.now() || !t) return { ok: false, status: 409, error: 'The authorised scope entry is no longer active; nothing can be retried' };
    const scanner = await loadScannerStatus();
    const steps: Step[] = [];
    for (const s of current.steps) {
        const base: Step = { kind: s.kind, decision: s.decision, reason: s.reason, job_id: s.job_id, previous_job_ids: s.previous_job_ids ?? [] };
        if (!retryable.has(s.status)) { steps.push(base); continue; }
        steps.push(await queueStep(org, by, id, s.kind, t, scope as ScopeEntry, scanner, [...base.previous_job_ids, ...(s.job_id ? [s.job_id] : [])]));
    }
    const upd = await supabase.from('vms_assessments').update({ steps, retried_at: new Date().toISOString() }).eq('id', id).select('*').single();
    if (upd.error) return { ok: false, status: 502, error: 'Could not save the retry' };
    logAudit({ user: by, action: 'VMS_ASSESSMENT_RETRIED', resource: 'vms_assessment', resource_id: id, org_id: org, ip, result: 'success', details: steps.map((s) => `${s.kind}=${s.decision}`).join(' ').slice(0, 200) });
    return { ok: true, assessment: (await describe([upd.data as AssessmentRow]))[0], existing: false };
}

/** Findings produced by an assessment's jobs, newest first, with what kind of evidence stands behind each. */
export async function assessmentFindings(org: string, findingIds: string[]) {
    if (!findingIds.length) return [];
    const { data } = await getSupabase()!.from('vms_findings').select('id, title, priority, risk_score, status, evidence_class, cve_ids, port, asset_value, first_seen, last_seen')
        .eq('org_id', org).in('id', findingIds.slice(0, 500)).order('risk_score', { ascending: false });
    return data ?? [];
}

/** A management report in Markdown: what was assessed, under which authorisation, what ran, what did not and why. */
export function managementReport(a: Awaited<ReturnType<typeof describe>>[number], scope: Partial<ScopeEntry> & { authorization_reference?: string; approved_by?: string }, findings: Record<string, unknown>[], evidence: { tool: string; target: string; sha256: string; created_at: string; truncated: boolean }[]): string {
    const L: string[] = [];
    const by = (p: string) => findings.filter((f) => f.priority === p).length;
    const unconfirmed = findings.filter((f) => f.evidence_class === 'version_match' || f.evidence_class === 'intelligence').length;
    L.push(`# Vulnerability assessment — ${a.target}`, '');
    L.push(`- **Status:** ${a.status.replace(/_/g, ' ')} (${a.progress.finished} of ${a.progress.total} steps finished)`);
    L.push(`- **Requested:** ${a.requested_at} by ${a.requested_by}${a.retried_at ? `; last retried ${a.retried_at}` : ''}`);
    L.push(`- **Authorisation:** ${scope.kind ?? ''} ${scope.value ?? ''} — reference "${scope.authorization_reference ?? 'unknown'}", approved by ${scope.approved_by ?? 'unknown'}, valid until ${scope.expires_at ?? 'unknown'}`);
    if ((scope.exclusions ?? []).length) L.push(`- **Excluded from testing:** ${(scope.exclusions ?? []).join(', ')}`);
    L.push('', '## Summary', '');
    L.push(`- Findings: ${findings.length} (P1 ${by('P1')}, P2 ${by('P2')}, P3 ${by('P3')}, P4 ${by('P4')})${unconfirmed ? `, of which ${unconfirmed} unconfirmed (version match or third-party claim)` : ''}`);
    const notRun = a.steps.filter((s) => RETRYABLE.has(s.status));
    L.push(`- Checks completed: ${a.steps.filter((s) => s.status === 'completed' || s.status === 'findings_detected').length} of ${a.steps.length}${notRun.length ? `; not completed: ${notRun.map((s) => s.label).join(', ')}` : ''}`);
    L.push('', '## Checks', '', '| Check | Status | Detail |', '|---|---|---|');
    for (const s of a.steps) L.push(`| ${s.label} | ${s.status.replace(/_/g, ' ')} | ${String(s.detail).replace(/\|/g, '/').replace(/\n/g, ' ')} |`);
    L.push('', '## Findings', '');
    if (!findings.length) L.push('No findings were recorded by the checks that ran. Checks that did not run (above) give no assurance.');
    else {
        L.push('| Priority | Finding | Evidence | Status |', '|---|---|---|---|');
        for (const f of findings) L.push(`| ${f.priority ?? '—'} | ${String(f.title).replace(/\|/g, '/')}${f.port ? ` (port ${f.port})` : ''} | ${String(f.evidence_class ?? 'scanner_check').replace(/_/g, ' ')} | ${String(f.status).replace(/_/g, ' ')} |`);
    }
    L.push('', '## Evidence', '');
    if (!evidence.length) L.push('No raw tool output is held for this assessment (it is kept 30 days).');
    else for (const e of evidence) L.push(`- ${e.tool} on ${e.target} at ${e.created_at}${e.truncated ? ' (cut to the size limit)' : ''} — SHA-256 ${e.sha256}`);
    L.push('', '## Limitations', '');
    L.push('- Results reflect what this platform\'s scanners could reach and test at the time; "unreachable from this scanner" does not mean the system is offline or secure.');
    L.push('- Unconfirmed findings (version matches, third-party claims) need confirmation by an authorised scan before remediation is prioritised on them.');
    L.push('- Checks marked not attempted or unsupported did not run, and checks marked inconclusive ran without being able to assess the target; this report gives no assurance about what they would have found.');
    return L.join('\n') + '\n';
}
