// Automatic assessment policies (phase P14). A policy picks assets of one organisation and gives
// each a Full Assessment through the same createAssessment() as a manual request — scope,
// exclusions, worker kinds, tools and private routes are all checked there, and a check that
// cannot run is recorded as not attempted / unsupported. Policies start disabled.
//
// Safety: an asset assessed by any trigger within the cooldown is skipped, so an unreachable or
// blocked asset is not re-queued every hour; at most max_per_run assets per policy per run; an
// asset outside authorised scope is reported as blocked with the reason and creates nothing.
// Blocked assets create no assessment, so they would be re-tried every run: each run therefore
// tries at most max_per_run × BLOCKED_BUDGET_FACTOR assets and reports how many it left for later.

import { getSupabase } from './geoEnrichment';
import { createAssessment } from './vmsAssessments';

export interface Policy { id: string; org_id: string; name: string; enabled: boolean; asset_source: 'wazuh' | 'external' | 'any'; profile: 'full'; cooldown_hours: number; max_per_run: number; last_run_at: string | null; last_result: unknown }
export interface PolicyRun { policy: string; org: string; queued: number; existing: number; skipped_cooldown: number; blocked: { asset: string; reason: string }[]; blocked_total?: number; not_evaluated?: number }
export const BLOCKED_BUDGET_FACTOR = 4;

const P14_MISSING = 'Assessment policies are not set up yet (run sql/2026-10-21_p14_vms_policies.sql)';
export const isMissingP14 = (e: { message?: string; code?: string } | null) => !!e && (e.code === 'PGRST205' || e.code === '42P01' || /vms_assessment_policies/.test(e.message ?? ''));
export { P14_MISSING };

/** Assets a policy covers: Wazuh endpoints, VMS hosts/IPs, or both — active ones only. */
function eligible(a: { asset_type: string; status: string }, source: Policy['asset_source']): boolean {
    if (a.status !== 'active') return false;
    if (source === 'wazuh') return a.asset_type === 'endpoint';
    if (source === 'external') return a.asset_type === 'host' || a.asset_type === 'ip';
    return ['endpoint', 'host', 'ip'].includes(a.asset_type);
}

/** One policy run. `now` is injectable for tests. */
export async function runPolicy(p: Policy, now = Date.now()): Promise<PolicyRun> {
    const supabase = getSupabase()!;
    const out: PolicyRun = { policy: p.id, org: p.org_id, queued: 0, existing: 0, skipped_cooldown: 0, blocked: [] };
    const { data: assets } = await supabase.from('vms_assets').select('id, asset_type, value, status, criticality').eq('org_id', p.org_id).eq('status', 'active').limit(5000);
    const since = new Date(now - p.cooldown_hours * 3_600_000).toISOString();
    const { data: recent } = await supabase.from('vms_assessments').select('asset_id').eq('org_id', p.org_id).gte('requested_at', since).limit(10_000);
    const cooled = new Set((recent ?? []).map((r) => r.asset_id).filter(Boolean));
    // Most critical first, so a capped run spends its budget where it matters.
    const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    const candidates = (assets ?? []).filter((a) => eligible(a, p.asset_source)).sort((a, b) => (rank[a.criticality] ?? 9) - (rank[b.criticality] ?? 9));
    let started = 0;
    let tried = 0;
    out.blocked_total = 0;
    out.not_evaluated = 0;
    for (const a of candidates) {
        if (cooled.has(a.id)) { out.skipped_cooldown++; continue; }
        if (started >= p.max_per_run || tried >= p.max_per_run * BLOCKED_BUDGET_FACTOR) { out.not_evaluated++; continue; }
        tried++;
        const r = await createAssessment(p.org_id, `policy:${p.name}`.slice(0, 120), { asset_id: a.id }, 'scheduler', { trigger: 'policy', policy_id: p.id });
        if (!r.ok) { out.blocked_total++; if (out.blocked.length < 50) out.blocked.push({ asset: a.value, reason: r.error }); continue; }
        started++;
        if (r.existing) out.existing++; else out.queued++;
    }
    await supabase.from('vms_assessment_policies').update({ last_run_at: new Date(now).toISOString(), last_result: out }).eq('id', p.id);
    return out;
}

/** Every enabled policy, once. Returns what each did; a failing policy does not stop the others. */
export async function runEnabledPolicies(now = Date.now()): Promise<PolicyRun[] | { error: string }> {
    const supabase = getSupabase();
    if (!supabase) return { error: 'Database not configured' };
    const { data, error } = await supabase.from('vms_assessment_policies').select('*').eq('enabled', true).limit(200);
    if (error) return { error: isMissingP14(error) ? P14_MISSING : error.message };
    const runs: PolicyRun[] = [];
    for (const p of (data ?? []) as Policy[]) {
        try { runs.push(await runPolicy(p, now)); } catch (err) { runs.push({ policy: p.id, org: p.org_id, queued: 0, existing: 0, skipped_cooldown: 0, blocked: [{ asset: '*', reason: err instanceof Error ? err.message : String(err) }] }); }
    }
    return runs;
}
