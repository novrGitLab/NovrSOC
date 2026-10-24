// Verification rescans (phase P27): one place that queues a rescan of a finding marked fixed — used
// by a person on the finding (routes/vmsFindings.ts) and by 'verification' schedules
// (services/vmsContinuous.ts). The rescan goes through queueScan like every other scan: active,
// unexpired scope permitting vulnerability testing, scan windows and job limits all apply.

import { getSupabase } from './geoEnrichment';
import { queueScan, activeScopes } from '../routes/vms';
import { coveringScope, parseTarget, type ScopeEntry } from '../lib/vmsScope';

export type VerifyResult =
    | { ok: true; queued: true; job: Record<string, unknown> }
    | { ok: true; queued: false; message: string }
    | { ok: false; status: number; error: string; retry_at?: string | null };

type Finding = { id: string; org_id?: string; status: string; source_class?: string | null; asset_value: string; detected_by?: string[] | null; rule_id: string; port?: number | null };

/** Queues a verification rescan of one finding; `onlyScope` limits it to that scope entry (schedules). */
export async function requestVerification(org: string, by: string, f: Finding, onlyScope?: ScopeEntry): Promise<VerifyResult> {
    if (f.status !== 'fixed_pending_verification') return { ok: false, status: 409, error: 'Mark the finding fixed first; verification checks that fix' };
    if (f.source_class === 'wazuh') return { ok: true, queued: false, message: 'Wazuh findings are verified by the next Wazuh vulnerability sync (hourly): it is closed only if Wazuh no longer reports it.' };
    const target = parseTarget(f.asset_value);
    const scope = target ? coveringScope(target, onlyScope ? [onlyScope] : await activeScopes(org), 'vuln') : null;
    if (!scope) return { ok: false, status: 409, error: 'This asset is no longer in active vulnerability-scan scope, so it cannot be rescanned' };
    const kind = (f.detected_by ?? []).includes('nuclei') ? 'vuln_nuclei' : 'vuln_openvas';
    const r = await queueScan(org, by, { scope_id: scope.id, kind, targets: [f.asset_value] }, {
        purpose: 'verification', options: { finding_ids: [f.id], ...(kind === 'vuln_nuclei' ? { templates: [f.rule_id] } : {}), ...(f.port ? { ports: String(f.port) } : {}) },
    });
    if (!r.ok) return r;
    const supabase = getSupabase()!;
    await supabase.from('vms_findings').update({ verification_job_id: r.job.id as string }).eq('id', f.id);
    await supabase.from('vms_finding_events').insert({ org_id: org, finding_id: f.id, actor: by, action: 'verification_queued', from_value: null, to_value: String(r.job.id), details: `${kind} on ${f.asset_value}` });
    return { ok: true, queued: true, job: r.job };
}

/**
 * A 'verification' schedule's run: findings marked fixed inside its scope entry (and its targets, if
 * it names any) that have no rescan waiting or running, at most `max` per run.
 */
export async function runVerificationSchedule(s: { id: string; org_id: string; scope_id: string; targets?: string[] | null }, max = 20):
    Promise<{ queued: number; skipped: number; blocked: string | null; retry_at?: string | null }> {
    const supabase = getSupabase()!;
    const { data: scope } = await supabase.from('vms_scopes').select('*').eq('id', s.scope_id).eq('org_id', s.org_id).maybeSingle();
    if (!scope || scope.status !== 'active' || Date.parse(scope.expires_at) <= Date.now() || !scope.allow_vuln_scan) {
        return { queued: 0, skipped: 0, blocked: 'its scope is not active or does not permit vulnerability testing' };
    }
    let q = supabase.from('vms_findings').select('id, status, source_class, asset_value, detected_by, rule_id, port, verification_job_id').eq('org_id', s.org_id).eq('status', 'fixed_pending_verification').eq('source_class', 'active_scan'); // scanner findings only: Wazuh's close by sync, passive ones are not rescanned
    if (s.targets?.length) q = q.in('asset_value', s.targets);
    const { data: findings } = await q.limit(500);
    const pendingJobs = new Set<string>();
    const jobIds = (findings ?? []).map((f) => f.verification_job_id).filter((x): x is string => !!x);
    if (jobIds.length) {
        const { data: open } = await supabase.from('vms_scan_jobs').select('id').in('id', jobIds).in('status', ['queued', 'running']);
        for (const j of open ?? []) pendingJobs.add(j.id as string);
    }
    let queued = 0, skipped = 0;
    for (const f of findings ?? []) {
        if (queued >= max) break;
        if (f.verification_job_id && pendingJobs.has(f.verification_job_id)) { skipped++; continue; }
        const r = await requestVerification(s.org_id, `schedule:${s.id}`, f as Finding, scope as ScopeEntry);
        if (r.ok && r.queued) queued++;
        else if (!r.ok && (r.status === 409 || r.status === 429) && ('retry_at' in r || r.status === 429)) return { queued, skipped, blocked: r.error, retry_at: r.retry_at ?? null };
        else skipped++;
    }
    return { queued, skipped, blocked: null };
}
