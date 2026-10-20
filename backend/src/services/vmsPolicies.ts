// Automatic assessment policies (phase P14). A policy picks assets of one organisation and gives
// each an assessment through the same createAssessment() as a manual request — scope,
// exclusions, worker kinds, tools and private routes are all checked there, and a check that
// cannot run is recorded as not attempted / unsupported. Policies start disabled.
//
// Safety: an asset assessed by any trigger within the cooldown is skipped, so an unreachable or
// blocked asset is not re-queued every hour; at most max_per_run assets per policy per run; an
// asset outside authorised scope is reported as blocked with the reason and creates nothing.
// Blocked assets create no assessment, so they would be re-tried every run: each run therefore
// tries at most max_per_run × BLOCKED_BUDGET_FACTOR assets and reports how many it left for later.
//
// P19 (Wazuh-managed endpoints): once an organisation's agreed coverage is in scope, its endpoints
// are assessed without a per-scan approval:
//   • each endpoint's eligibility (services/vmsEligibility.ts) is evaluated first; an endpoint that
//     is offline, unaddressed, sharing its address or outside coverage is reported, not attempted,
//     and costs no budget;
//   • event trigger: an endpoint whose eligible address differs from the target of its last
//     assessment (DHCP change, re-addressing) is assessed now, inside the cooldown (trigger 'event');
//   • the policy's profile (discovery | standard | full) decides what runs;
//   • next_scan_at is stamped on each asset the policy covers.

import { getSupabase } from './geoEnrichment';
import { createAssessment } from './vmsAssessments';
import { refreshEligibility, missingP19, type Eligibility } from './vmsEligibility';
import { isProfileId, profileActivity, type ProfileId } from './vmsProfiles';

export interface Policy { id: string; org_id: string; name: string; enabled: boolean; asset_source: 'wazuh' | 'external' | 'any'; profile: ProfileId | string; cooldown_hours: number; max_per_run: number; last_run_at: string | null; last_result: unknown }
export interface PolicyRun {
    policy: string; org: string; queued: number; existing: number; skipped_cooldown: number; blocked: { asset: string; reason: string }[];
    blocked_total?: number; not_evaluated?: number; event_triggered?: number; ineligible?: Record<string, number>; profile?: string;
}
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

type AssetRow = { id: string; asset_type: string; value: string; status: string; criticality: string; next_scan_at?: string | null };

/** One policy run. `now` is injectable for tests. */
export async function runPolicy(p: Policy, now = Date.now()): Promise<PolicyRun> {
    const supabase = getSupabase()!;
    const profile: ProfileId = isProfileId(p.profile) ? p.profile : 'full';
    const out: PolicyRun = { policy: p.id, org: p.org_id, queued: 0, existing: 0, skipped_cooldown: 0, blocked: [], profile, event_triggered: 0, ineligible: {} };
    const cooldownMs = p.cooldown_hours * 3_600_000;
    const { data: assets } = await supabase.from('vms_assets').select('*').eq('org_id', p.org_id).eq('status', 'active').limit(5000);
    // The latest assessment of each asset (target and time): cooldown, and whether its address moved.
    const { data: history } = await supabase.from('vms_assessments').select('asset_id, target, requested_at').eq('org_id', p.org_id).order('requested_at', { ascending: false }).limit(10_000);
    const last = new Map<string, { target: string; at: number }>();
    for (const h of history ?? []) if (h.asset_id && !last.has(h.asset_id)) last.set(h.asset_id, { target: String(h.target), at: Date.parse(h.requested_at) });
    // Most critical first, so a capped run spends its budget where it matters.
    const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    const candidates = ((assets ?? []) as AssetRow[]).filter((a) => eligible(a, p.asset_source)).sort((a, b) => (rank[a.criticality] ?? 9) - (rank[b.criticality] ?? 9));
    const endpointsCovered = candidates.some((a) => a.asset_type === 'endpoint');
    const elig: Map<string, Eligibility> = endpointsCovered ? (await refreshEligibility(p.org_id, now, profileActivity(profile))).byAsset : new Map();

    const nextScan = new Map<string, string | null>();
    let started = 0;
    let tried = 0;
    out.blocked_total = 0;
    out.not_evaluated = 0;
    for (const a of candidates) {
        const prev = last.get(a.id);
        let trigger: 'policy' | 'event' = 'policy';
        if (a.asset_type === 'endpoint') {
            const e = elig.get(a.id);
            if (!e || e.status !== 'eligible') {
                const status = e?.status ?? 'not_evaluated';
                out.ineligible![status] = (out.ineligible![status] ?? 0) + 1;
                nextScan.set(a.id, null);
                continue;
            }
            // The endpoint is reachable at a different address than last assessed: assess it now.
            if (prev && e.target && prev.target !== e.target) trigger = 'event';
        }
        if (trigger === 'policy' && prev && prev.at > now - cooldownMs) {
            out.skipped_cooldown++;
            nextScan.set(a.id, new Date(prev.at + cooldownMs).toISOString());
            continue;
        }
        if (started >= p.max_per_run || tried >= p.max_per_run * BLOCKED_BUDGET_FACTOR) { out.not_evaluated++; nextScan.set(a.id, new Date(now).toISOString()); continue; }
        tried++;
        const r = await createAssessment(p.org_id, `policy:${p.name}`.slice(0, 120), { asset_id: a.id }, 'scheduler', { trigger, policy_id: p.id }, profile);
        if (!r.ok) { out.blocked_total++; if (out.blocked.length < 50) out.blocked.push({ asset: a.value, reason: r.error }); nextScan.set(a.id, null); continue; }
        started++;
        if (trigger === 'event' && !r.existing) out.event_triggered!++;
        if (r.existing) out.existing++; else out.queued++;
        nextScan.set(a.id, new Date(now + cooldownMs).toISOString());
    }
    // When each covered asset is next due (only what changed is written; skipped before the P19 SQL).
    for (const a of candidates) {
        if (!nextScan.has(a.id)) continue;
        const next = nextScan.get(a.id) ?? null;
        if ((a.next_scan_at ?? null) === next) continue;
        const { error } = await supabase.from('vms_assets').update({ next_scan_at: next }).eq('id', a.id);
        if (missingP19(error)) break;
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
