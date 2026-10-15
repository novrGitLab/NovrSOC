// VMS AI purposes (phase P5): explanations, remediation plans, rescan interpretation and asset
// assessments, grounded in the organisation's own finding, evidence, CVE intelligence and asset
// records. Plans propose; they never change a finding, set a deadline or mark anything fixed —
// people create tasks from them, and only a rescan verifies a fix.

import { z } from 'zod';
import { getSupabase } from './geoEnrichment';
import { registerAiPurpose, Confidence, type BuiltContext } from './aiPurposes';
import type { SourceRef } from './ai';

function push(records: Record<string, unknown>[], refs: SourceRef[], kind: string, id: string, row: Record<string, unknown>, label?: string) {
    const ref = `${kind}:${id}`;
    records.push({ ref, kind, ...row });
    refs.push({ ref, type: kind, id, label });
}

async function buildFinding(org: string, id: string): Promise<BuiltContext | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: f } = await supabase.from('vms_findings').select('*').eq('id', id).eq('org_id', org).maybeSingle();
    if (!f) return null;
    const records: Record<string, unknown>[] = [];
    const refs: SourceRef[] = [];
    push(records, refs, 'finding', f.id, f, f.title);
    const [ev, events, intel, asset, tasks, job] = await Promise.all([
        supabase.from('vms_finding_evidence').select('id, source, job_id, observed_at, matched_at, evidence').eq('finding_id', f.id).order('observed_at', { ascending: false }).limit(5),
        supabase.from('vms_finding_events').select('id, at, actor, action, from_value, to_value, details').eq('finding_id', f.id).order('at').limit(40),
        f.cve_ids?.length ? supabase.from('cve_intel').select('*').in('cve_id', f.cve_ids) : Promise.resolve({ data: [] as Record<string, unknown>[] }),
        f.asset_id ? supabase.from('vms_assets').select('id, value, asset_type, exposure, criticality, owner, ips, http').eq('id', f.asset_id).eq('org_id', org).maybeSingle() : Promise.resolve({ data: null }),
        supabase.from('vms_remediation_tasks').select('id, title, status, owner, due_at').eq('finding_id', f.id),
        f.verification_job_id ? supabase.from('vms_scan_jobs').select('id, kind, status, purpose, options, started_at, finished_at, error, summary').eq('id', f.verification_job_id).eq('org_id', org).maybeSingle() : Promise.resolve({ data: null }),
    ]);
    for (const e of ev.data ?? []) push(records, refs, 'evidence', e.id, e);
    for (const e of events.data ?? []) push(records, refs, 'event', e.id, e);
    for (const c of (intel.data ?? []) as Record<string, unknown>[]) push(records, refs, 'cve', String(c.cve_id), c, String(c.cve_id));
    if (asset.data) {
        push(records, refs, 'asset', asset.data.id, asset.data, asset.data.value);
        const { data: svcs } = await supabase.from('vms_services').select('id, port, protocol, service, product, version, status').eq('asset_id', asset.data.id).eq('status', 'active').limit(50);
        for (const s of svcs ?? []) push(records, refs, 'service', s.id, s);
    }
    for (const t of tasks.data ?? []) push(records, refs, 'task', t.id, t);
    if (job.data) push(records, refs, 'scan', job.data.id, job.data);
    return { records, refs };
}

async function buildAsset(org: string, id: string): Promise<BuiltContext | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: a } = await supabase.from('vms_assets').select('*').eq('id', id).eq('org_id', org).maybeSingle();
    if (!a) return null;
    const records: Record<string, unknown>[] = [];
    const refs: SourceRef[] = [];
    push(records, refs, 'asset', a.id, a, a.value);
    const [svcs, techs, findings] = await Promise.all([
        supabase.from('vms_services').select('id, port, protocol, service, product, version, status').eq('asset_id', a.id).limit(100),
        supabase.from('vms_technologies').select('id, name, version').eq('asset_id', a.id).limit(100),
        supabase.from('vms_findings').select('id, title, cve_ids, scanner_severity, priority, risk_score, status, source_class').eq('asset_id', a.id).eq('org_id', org).in('status', ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened']).order('risk_score', { ascending: false }).limit(40),
    ]);
    for (const s of svcs.data ?? []) push(records, refs, 'service', s.id, s);
    for (const t of techs.data ?? []) push(records, refs, 'technology', t.id, t);
    for (const f of findings.data ?? []) push(records, refs, 'finding', f.id, f, f.title);
    return { records, refs };
}

const Step = z.object({
    order: z.number().int(),
    action: z.string(),
    type: z.enum(['patch', 'configuration', 'compensating_control', 'verification', 'investigation']),
    details: z.string(),
    owner_suggestion: z.string(),
    proposed_deadline_days: z.number().int(),
    requires_change_approval: z.boolean(),
    evidence_refs: z.array(z.string()),
});

registerAiPurpose('finding_explanation', {
    permission: 'vms:read', subjectType: 'finding', build: buildFinding,
    task: 'Explain this vulnerability in plain language for the asset owner: what it is, what an attacker could do with it on THIS asset (use its exposure, services and criticality), whether there is evidence of exploitation in the wild (only from the CVE records: KEV and EPSS), and why it has its priority. Say clearly what is unknown.',
    schema: z.object({
        plain_summary: z.string(),
        what_an_attacker_could_do: z.string(),
        impact_on_this_asset: z.string(),
        exploitation_evidence: z.object({ known_exploited: z.enum(['yes', 'no', 'unknown']), detail: z.string(), evidence_refs: z.array(z.string()) }),
        why_this_priority: z.string(),
        evidence: z.array(z.object({ ref: z.string(), observation: z.string() })),
        uncertainties: z.array(z.string()),
        confidence: Confidence,
    }),
});

registerAiPurpose('remediation_plan', {
    permission: 'vms:read', subjectType: 'finding', build: buildFinding,
    task: 'Propose a remediation plan for this finding: concrete patching or configuration steps for the software and version the evidence shows, compensating controls if a fix must wait, how to verify the fix (the platform verifies with a rescan), who should own each step (by role), and proposed deadlines consistent with the finding\'s priority. Mark steps that change production as needing change approval. These are proposals for people to accept; do not state that anything has been done.',
    schema: z.object({
        summary: z.string(),
        priority_rationale: z.string(),
        steps: z.array(Step),
        compensating_controls: z.array(z.object({ control: z.string(), rationale: z.string(), evidence_refs: z.array(z.string()) })),
        verification: z.array(z.object({ method: z.string(), expected_result: z.string() })),
        rollback_notes: z.string(),
        uncertainties: z.array(z.string()),
        confidence: Confidence,
    }),
});

registerAiPurpose('rescan_interpretation', {
    permission: 'vms:read', subjectType: 'finding', build: buildFinding,
    task: 'Interpret the verification scan for this finding from the scan record and the finding history only: did the rescan run the same check on the same target, did it finish successfully, and what does that mean for the fix? The platform has already set the status from the evidence; explain it, and say what to do next if the result is inconclusive or the finding is still present. Never claim the fix is verified unless the finding record shows status verified.',
    schema: z.object({
        conclusion: z.enum(['fixed_verified', 'still_present', 'inconclusive', 'not_rescanned']),
        explanation: z.string(),
        scan_checks: z.array(z.object({ check: z.string(), result: z.string(), evidence_refs: z.array(z.string()) })),
        next_steps: z.array(z.string()),
        uncertainties: z.array(z.string()),
    }),
});

registerAiPurpose('asset_assessment', {
    permission: 'vms:read', subjectType: 'asset', build: buildAsset,
    task: 'Assess this asset\'s exposure for its owner: what it exposes (services, technologies), its most important open findings and why, likely attack paths using only what the records show, and the three to five actions that would reduce its risk most.',
    schema: z.object({
        summary: z.string(),
        exposure: z.string(),
        top_risks: z.array(z.object({ ref: z.string(), why: z.string() })),
        attack_paths: z.array(z.object({ path: z.string(), evidence_refs: z.array(z.string()) })),
        priority_actions: z.array(z.object({ action: z.string(), rationale: z.string(), requires_approval: z.boolean(), evidence_refs: z.array(z.string()) })),
        uncertainties: z.array(z.string()),
        confidence: Confidence,
    }),
});
