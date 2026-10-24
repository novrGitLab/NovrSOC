// AI purposes (phase P3): what each AI request reads, may produce, and who may ask for it.
// Every builder loads records for ONE organisation (the caller's, resolved by requestOrg) and
// gives each record a `ref` the answer must cite. Log and alert payloads are redacted
// (lib/redact.ts) before they leave the platform. Other modules add purposes with
// registerAiPurpose() (VMS and the Threat Information System do).

import { z } from 'zod';
import { getSupabase } from './geoEnrichment';
import { redactValue } from '../lib/redact';
import type { Permission } from '../lib/permissions';
import type { SourceRef } from './ai';

export interface BuiltContext { records: Record<string, unknown>[]; refs: SourceRef[] }
export interface AiPurpose {
    permission: Permission;
    subjectType: string;
    build: (org: string, subjectId: string) => Promise<BuiltContext | null>; // null = not found in this org
    task: string;
    schema: z.ZodTypeAny;
    maxTokens?: number;
    /** 'ti' purposes may use their own AI provider (TI_AI_PROVIDER, services/ai.ts). */
    group?: 'ti';
}
const registry = new Map<string, AiPurpose>();
export function registerAiPurpose(name: string, p: AiPurpose): void { registry.set(name, p); }
export function aiPurpose(name: string): AiPurpose | undefined { return registry.get(name); }
export function aiPurposeNames(): string[] { return [...registry.keys()]; }

// ── shared schema pieces ─────────────────────────────────────────────────────────────────────
export const Confidence = z.enum(['low', 'medium', 'high']);
export const Evidence = z.object({ ref: z.string(), observation: z.string() });
export const Recommendation = z.object({
    action: z.string(),
    rationale: z.string(),
    requires_approval: z.boolean(),
    evidence_refs: z.array(z.string()),
});

/** Redacted, size-capped copy of a raw payload for the model. */
export function safeRaw(raw: unknown, truncated: boolean | null | undefined): unknown {
    if (truncated) return '(payload over 32 KB was stored as a preview; not sent)';
    const r = redactValue(raw);
    const json = JSON.stringify(r ?? null);
    return json.length > 12_000 ? `${json.slice(0, 12_000)}…(cut)` : r;
}

const ALERT_COLUMNS = 'id, wazuh_alert_id, rule_id, rule_level, rule_description, agent_id, agent_name, agent_ip, severity, mitre_ids, location, event_time, received_at, status, case_id, raw, raw_truncated';

// ── SecOps ───────────────────────────────────────────────────────────────────────────────────
async function buildAlert(org: string, id: string): Promise<BuiltContext | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: a } = await supabase.from('alerts').select(ALERT_COLUMNS).eq('id', id).eq('org_id', org).maybeSingle();
    if (!a) return null;
    const records: Record<string, unknown>[] = [{ ref: `alert:${a.id}`, kind: 'alert', ...a, raw: safeRaw(a.raw, a.raw_truncated) }];
    const refs: SourceRef[] = [{ ref: `alert:${a.id}`, type: 'alert', id: a.id, label: a.rule_description ?? undefined }];
    // How often the same rule fired on the same agent in the 24 h before this alert (a count, measured).
    if (a.rule_id && a.agent_id) {
        const since = new Date(Date.parse(a.event_time) - 24 * 3_600_000).toISOString();
        const { count } = await supabase.from('alerts').select('id', { count: 'exact', head: true }).eq('org_id', org)
            .eq('rule_id', a.rule_id).eq('agent_id', a.agent_id).gte('event_time', since).lte('event_time', a.event_time);
        records.push({ ref: `stat:same-rule-agent-24h:${a.id}`, kind: 'measured_count', description: 'Alerts with the same rule on the same agent in the 24 h up to this alert (including it)', count: count ?? null });
        refs.push({ ref: `stat:same-rule-agent-24h:${a.id}`, type: 'stat', id: a.id });
    }
    if (a.case_id) {
        const { data: c } = await supabase.from('cases').select('id, case_number, title, status, severity').eq('id', a.case_id).eq('org_id', org).maybeSingle();
        if (c) { records.push({ ref: `case:${c.id}`, kind: 'case', ...c }); refs.push({ ref: `case:${c.id}`, type: 'case', id: c.id, label: c.case_number }); }
    }
    return { records, refs };
}

async function buildCase(org: string, id: string): Promise<BuiltContext | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: c } = await supabase.from('cases').select('*').eq('id', id).eq('org_id', org).maybeSingle();
    if (!c) return null;
    const [notes, tasks, timeline, alerts, soar, approvals] = await Promise.all([
        supabase.from('case_notes').select('id, author, content, created_at').eq('case_id', id).order('created_at').limit(50),
        supabase.from('case_tasks').select('id, title, status, result, executed_at, executed_by').eq('case_id', id).order('created_at').limit(50),
        supabase.from('case_timeline').select('id, actor, action, details, created_at').eq('case_id', id).order('created_at').limit(80),
        supabase.from('alerts').select('id, wazuh_alert_id, rule_id, rule_level, rule_description, agent_name, severity, event_time, status').eq('org_id', org).eq('case_id', id).order('event_time').limit(30),
        supabase.from('soar_log').select('id, action, result, automated, executed_at').eq('case_id', id).order('executed_at').limit(50),
        supabase.from('response_approvals').select('id, action, target, status, result, requested_by, decided_by, requested_at').eq('case_id', id).eq('org_id', org).limit(20),
    ]);
    const records: Record<string, unknown>[] = [{ ref: `case:${c.id}`, kind: 'case', ...c }];
    const refs: SourceRef[] = [{ ref: `case:${c.id}`, type: 'case', id: c.id, label: c.case_number }];
    const add = (kind: string, rows: Record<string, unknown>[] | null) => {
        for (const r of rows ?? []) {
            const ref = `${kind}:${r.id}`;
            records.push({ ref, kind, ...r, ...(kind === 'note' && typeof r.content === 'string' ? { content: redactValue(r.content) } : {}) });
            refs.push({ ref, type: kind, id: String(r.id) });
        }
    };
    add('note', notes.data); add('task', tasks.data); add('timeline', timeline.data); add('alert', alerts.data);
    add('soar_action', soar.data); add('approval', approvals.error ? null : approvals.data);
    return { records, refs };
}

registerAiPurpose('alert_summary', {
    permission: 'alerts:read', subjectType: 'alert', build: buildAlert,
    task: 'Explain this alert to an analyst: what happened, why it matters, how severe it really is given the evidence, what to check next, and what response to consider. Use the measured count if present; do not estimate counts.',
    schema: z.object({
        summary: z.string(),
        what_happened: z.string(),
        why_it_matters: z.string(),
        severity_assessment: z.object({ level: z.enum(['critical', 'high', 'medium', 'low', 'informational']), rationale: z.string() }),
        evidence: z.array(Evidence),
        investigation_steps: z.array(z.object({ step: z.string(), why: z.string(), evidence_refs: z.array(z.string()) })),
        recommended_response: z.array(Recommendation),
        suspicious_content_in_records: z.array(z.string()),
        uncertainties: z.array(z.string()),
        confidence: Confidence,
    }),
});

const CaseSummary = z.object({
    summary: z.string(),
    current_state: z.string(),
    key_events: z.array(z.object({ at: z.string(), event: z.string(), ref: z.string() })),
    actions_recorded: z.array(z.object({ action: z.string(), outcome: z.string(), ref: z.string() })),
    open_questions: z.array(z.string()),
    next_steps: z.array(Recommendation),
    uncertainties: z.array(z.string()),
    confidence: Confidence,
});
registerAiPurpose('case_summary', {
    permission: 'cases:read', subjectType: 'case', build: buildCase,
    task: 'Summarise this case for the analyst working it: what is known, what has actually been done (only what the records show, with each action\'s recorded outcome), what is still open, and evidence-based next steps.',
    schema: CaseSummary,
});
registerAiPurpose('case_handover', {
    permission: 'cases:read', subjectType: 'case', build: buildCase,
    task: 'Write a shift-handover summary for the next analyst: current state, what was done and its recorded outcome, what is pending (including approvals waiting), and the first things to do. Only what the records show.',
    schema: CaseSummary,
});
registerAiPurpose('incident_report', {
    permission: 'cases:read', subjectType: 'case', build: buildCase,
    task: 'Draft an incident report for this case: an executive summary for non-technical leaders, then the technical timeline, impact as far as the records show it, actions taken (only those recorded, with their outcomes), and recommendations. Say clearly what is not known.',
    schema: z.object({
        title: z.string(),
        executive_summary: z.string(),
        impact: z.string(),
        timeline: z.array(z.object({ at: z.string(), event: z.string(), ref: z.string() })),
        actions_taken: z.array(z.object({ action: z.string(), outcome: z.string(), ref: z.string() })),
        root_cause_assessment: z.string(),
        recommendations: z.array(Recommendation),
        unknowns: z.array(z.string()),
        confidence: Confidence,
    }),
});
