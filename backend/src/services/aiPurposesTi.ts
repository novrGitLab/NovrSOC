// Threat Information System AI purposes (phase P6). Grounded only in stored feed records, this
// organisation's matches and verdicts, and feed health. The output keeps three things apart:
// facts in the platform's records, claims a source made, and the model's own assessment. No
// threat actor is named unless a source record names it; no confidence or exploitation status is
// made up — a source's own confidence is reported as that source's. Also the weekly-insights purpose (P8).

import { z } from 'zod';
import { getSupabase } from './geoEnrichment';
import { registerAiPurpose, Confidence, type BuiltContext } from './aiPurposes';
import type { SourceRef } from './ai';
import { weeklyFacts } from './weeklyInsights';

function push(records: Record<string, unknown>[], refs: SourceRef[], kind: string, id: string, row: Record<string, unknown>, label?: string) {
    const ref = `${kind}:${id}`;
    records.push({ ref, kind, ...row });
    refs.push({ ref, type: kind, id, label });
}

async function buildIndicator(org: string, id: string): Promise<BuiltContext | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: ind } = await supabase.from('ti_indicators').select('*').eq('id', id).maybeSingle();
    if (!ind) return null;
    const records: Record<string, unknown>[] = [];
    const refs: SourceRef[] = [];
    push(records, refs, 'indicator', ind.id, ind, `${ind.type} ${ind.value}`);
    const [srcs, matches, fb] = await Promise.all([
        supabase.from('ti_indicator_sources').select('id, feed_id, source_ref, confidence, first_seen, last_seen, context').eq('indicator_id', ind.id).limit(20),
        supabase.from('ti_matches').select('id, entity_type, entity_id, matched_field, first_matched_at, last_matched_at, status, case_id').eq('indicator_id', ind.id).eq('org_id', org).limit(50),
        supabase.from('ti_feedback').select('id, verdict, note, actor, at').eq('indicator_id', ind.id).eq('org_id', org).order('at', { ascending: false }).limit(20),
    ]);
    for (const s of srcs.data ?? []) push(records, refs, 'source_record', s.id, s, `${s.feed_id}#${s.source_ref}`);
    for (const m of matches.data ?? []) push(records, refs, 'match', m.id, m);
    for (const f of fb.data ?? []) push(records, refs, 'verdict', f.id, f);
    const alertIds = (matches.data ?? []).filter((m) => m.entity_type === 'alert').map((m) => m.entity_id).slice(0, 10);
    if (alertIds.length) {
        const { data: alerts } = await supabase.from('alerts').select('id, rule_id, rule_description, rule_level, agent_name, event_time, severity').eq('org_id', org).in('id', alertIds);
        for (const a of alerts ?? []) push(records, refs, 'alert', a.id, a, a.rule_description ?? undefined);
    }
    return { records, refs };
}

/** subject id: "7d" or "30d" — the period the briefing covers, ending now. */
async function buildBriefing(org: string, period: string): Promise<BuiltContext | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const days = period === '7d' ? 7 : period === '30d' ? 30 : 0;
    if (!days) return null;
    const until = new Date();
    const since = new Date(until.getTime() - days * 86_400_000);
    const records: Record<string, unknown>[] = [];
    const refs: SourceRef[] = [];
    push(records, refs, 'period', period, { from: since.toISOString(), to: until.toISOString(), organisation: org });
    const [feeds, matches, kev] = await Promise.all([
        supabase.from('ti_feeds').select('id, name, enabled, last_success_at, last_error, last_counts'),
        supabase.from('ti_matches').select('id, entity_type, entity_id, matched_field, status, first_matched_at, case_id, ti_indicators(id, type, value, malware_families, threat_types, max_confidence, source_count)').eq('org_id', org).gte('first_matched_at', since.toISOString()).order('first_matched_at', { ascending: false }).limit(60),
        supabase.from('ti_indicators').select('id, value, first_seen').eq('type', 'cve').gte('first_seen', since.toISOString()).limit(60),
    ]);
    for (const f of feeds.data ?? []) push(records, refs, 'feed', f.id, f, f.name);
    for (const m of matches.data ?? []) push(records, refs, 'match', m.id, m as unknown as Record<string, unknown>);
    const cves = (kev.data ?? []).map((k) => k.value);
    for (const k of kev.data ?? []) push(records, refs, 'kev', k.value, { cve: k.value, added_to_platform: k.first_seen }, k.value);
    if (cves.length) {
        const { data: f } = await supabase.from('vms_findings').select('id, title, cve_ids, asset_value, priority, status').eq('org_id', org).overlaps('cve_ids', cves).in('status', ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened']).limit(40);
        for (const x of f ?? []) push(records, refs, 'finding', x.id, x, x.title);
    }
    return { records, refs };
}

const Claim = z.object({ statement: z.string(), basis: z.enum(['platform_record', 'source_claim', 'ai_assessment']), evidence_refs: z.array(z.string()) });

registerAiPurpose('indicator_assessment', {
    permission: 'intel:read', subjectType: 'indicator', build: buildIndicator,
    task: 'Assess this indicator for an analyst at this organisation: what the source records say about it (attribute each claim to its source record; a source\'s confidence is that source\'s, not yours), where it was seen in this organisation and what those records show, any analyst verdicts, and what the analyst should check next. Mark every statement as platform_record, source_claim or ai_assessment. Do not name a threat actor, campaign or attribution unless a source record names it. If the evidence is thin or conflicting, say so.',
    schema: z.object({
        summary: z.string(),
        statements: z.array(Claim),
        seen_in_organisation: z.string(),
        recommended_checks: z.array(z.object({ check: z.string(), rationale: z.string(), evidence_refs: z.array(z.string()) })),
        suggested_verdict: z.enum(['confirmed_malicious', 'suspicious', 'benign', 'false_positive', 'insufficient_evidence']),
        uncertainties: z.array(z.string()),
        confidence: Confidence,
    }),
});

registerAiPurpose('threat_briefing', {
    permission: 'intel:read', subjectType: 'report', build: buildBriefing,
    task: 'Write a threat briefing for this organisation for the stated period only, from the records given: indicator matches in its environment and their status, newly added known-exploited vulnerabilities and whether the organisation has open findings for them, and feed health (a failed or stale feed means coverage gaps — say which). Mark every statement as platform_record, source_claim or ai_assessment. State the period and the limitations. If there were no matches, say so plainly; do not fill the briefing with general threat news that is not in the records.',
    schema: z.object({
        period: z.string(),
        headline: z.string(),
        statements: z.array(Claim),
        actions: z.array(z.object({ action: z.string(), priority: z.enum(['high', 'medium', 'low']), evidence_refs: z.array(z.string()) })),
        coverage_gaps: z.array(z.string()),
        limitations: z.array(z.string()),
        confidence: Confidence,
    }),
});

// ── Weekly insights (phase P8) ────────────────────────────────────────────────────────────────
// subject id: "7d" or "30d". The facts are services/weeklyInsights.ts, the same ones the page shows.
async function buildWeekly(org: string, period: string): Promise<BuiltContext | null> {
    const days = period === '7d' ? 7 : period === '30d' ? 30 : 0;
    if (!days) return null;
    const f = await weeklyFacts(org, days);
    const records: Record<string, unknown>[] = [];
    const refs: SourceRef[] = [];
    push(records, refs, 'period', period, { ...f.period, organisation: org });
    push(records, refs, 'metric', 'alerts', f.alerts, 'Alerts');
    push(records, refs, 'metric', 'cases', f.cases, 'Cases');
    push(records, refs, 'metric', 'approvals', { by_status: f.approvals }, 'Response approvals');
    if (f.vulnerabilities) push(records, refs, 'metric', 'vulnerabilities', f.vulnerabilities, 'Vulnerabilities');
    if (f.threat_intel) push(records, refs, 'metric', 'threat_intel', f.threat_intel, 'Threat intelligence');
    for (const h of f.health) push(records, refs, 'health', h.name, h, h.name);
    push(records, refs, 'limitations', 'all', { limitations: f.limitations });
    return { records, refs };
}

registerAiPurpose('weekly_insights', {
    permission: 'alerts:read', subjectType: 'report', build: buildWeekly,
    task: 'Write the weekly security-operations insights for this organisation for the stated period, compared with the previous period of the same length, using only the metric records. Cover: what changed and by how much (quote the numbers from the records; do not compute new statistics beyond simple differences), the most important items for the SOC manager, case and vulnerability backlog and deadlines, and what to focus on next week. Mark every statement as platform_record or ai_assessment. Put every limitation and unhealthy pipeline in data_gaps — if a pipeline was down, say the related numbers may be low because of missing data, not because of less activity. Do not speculate about attackers or attribution.',
    schema: z.object({
        period: z.string(),
        headline: z.string(),
        statements: z.array(z.object({ statement: z.string(), basis: z.enum(['platform_record', 'ai_assessment']), evidence_refs: z.array(z.string()) })),
        focus_next_week: z.array(z.object({ action: z.string(), owner_role: z.string(), evidence_refs: z.array(z.string()) })),
        data_gaps: z.array(z.string()),
        confidence: Confidence,
    }),
});
