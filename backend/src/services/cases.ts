// Case management — Supabase is the system of record.
//
// Two writers create cases: the Python SOAR engine on the Wazuh manager (infra/soar/soar.py,
// one case per level 7+ alert) and this backend (analyst actions: alert → case, threat hunt,
// dark web hit, playbook-initiated case). Both let the database assign case_number from
// case_number_seq, and both key on UNIQUE(source, source_id), so an analyst opening a case
// from an alert the engine already cased gets the existing case back instead of a duplicate.
//
// Schema: backend/sql/2026-09-cases-soar.sql.
import { getSupabase } from './geoEnrichment';

export const DEFAULT_ORG_ID = 'cybernovr';

export const CASE_SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
export const CASE_STATUSES = ['open', 'investigating', 'contained', 'resolved'] as const;
export type CaseSeverity = (typeof CASE_SEVERITIES)[number];
export type CaseStatus = (typeof CASE_STATUSES)[number];

export interface CaseRow {
    id: string;
    case_number: string;
    org_id: string;
    title: string;
    description: string | null;
    severity: CaseSeverity;
    status: CaseStatus;
    source: string;
    source_id: string | null;
    agent_id: string | null;
    agent_name: string | null;
    source_ip: string | null;
    dest_ip: string | null;
    rule_id: string | null;
    rule_level: number | null;
    mitre_technique: string | null;
    mitre_tactic: string | null;
    assigned_to: string | null;
    playbook_id: string | null;
    tags: string[] | null;
    created_at: string;
    updated_at: string;
    resolved_at: string | null;
    auto_closed: boolean;
    tier: number;
    containment_done: boolean;
    escalated: boolean;
}

export const isCaseSeverity = (v: unknown): v is CaseSeverity => typeof v === 'string' && (CASE_SEVERITIES as readonly string[]).includes(v);
export const isCaseStatus = (v: unknown): v is CaseStatus => typeof v === 'string' && (CASE_STATUSES as readonly string[]).includes(v);

// Case ids are UUIDs. Checked before querying so a malformed id is a 404, not a Postgres
// "invalid input syntax for type uuid" surfacing as a 500.
export const isUuid = (v: string): boolean => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);

// Same thresholds as the SOAR engine's get_severity() and threatManagement's
// getAlertSeverity(), so a case's severity never disagrees with the alert it came from.
export function tierForSeverity(severity: CaseSeverity): number {
    if (severity === 'critical') return 3;
    if (severity === 'high') return 2;
    return 1;
}

// Africa/Lagos is UTC+1 year-round (no DST), so "start of today" is plain offset arithmetic.
export function startOfTodayWAT(): Date {
    const WAT_OFFSET_MS = 60 * 60 * 1000;
    const shifted = new Date(Date.now() + WAT_OFFSET_MS);
    return new Date(Date.UTC(shifted.getUTCFullYear(), shifted.getUTCMonth(), shifted.getUTCDate()) - WAT_OFFSET_MS);
}

export function formatWAT(value: string | number | Date | null | undefined): string {
    if (!value) return 'Unknown';
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return 'Unknown';
    return `${d.toLocaleString('en-GB', { timeZone: 'Africa/Lagos' })} WAT`;
}

// Supabase errors are plain objects — String(err) prints "[object Object]".
export function dbErrorMessage(err: unknown): string {
    if (err && typeof err === 'object' && 'message' in err) return String((err as { message: unknown }).message);
    return err instanceof Error ? err.message : String(err);
}

export async function addTimeline(caseId: string, actor: string, action: string, opts: { details?: string; automated?: boolean } = {}): Promise<void> {
    const supabase = getSupabase();
    if (!supabase) return;
    const { error } = await supabase.from('case_timeline').insert({
        case_id: caseId,
        actor,
        action,
        details: opts.details ?? null,
        automated: opts.automated ?? false,
    });
    // Logged, not thrown: a missing timeline row must not fail the action it describes.
    if (error) console.error('[cases] timeline insert failed:', dbErrorMessage(error));
}

export interface NewCaseInput {
    title: string;
    description?: string | null;
    severity: CaseSeverity;
    source: string;
    source_id?: string | null;
    org_id?: string;
    agent_id?: string | null;
    agent_name?: string | null;
    source_ip?: string | null;
    rule_id?: string | null;
    rule_level?: number | null;
    mitre_technique?: string | null;
    mitre_tactic?: string | null;
    assigned_to?: string | null;
    playbook_id?: string | null;
    tags?: string[];
}

export type CreateCaseResult =
    | { ok: true; case: CaseRow; created: boolean }
    | { ok: false; error: string; status: number };

export async function createCase(input: NewCaseInput, actor: string): Promise<CreateCaseResult> {
    const supabase = getSupabase();
    if (!supabase) return { ok: false, error: 'Case store not configured (SUPABASE_URL / SUPABASE_SERVICE_KEY)', status: 503 };

    const findExisting = async (): Promise<CaseRow | null> => {
        if (!input.source_id) return null;
        const { data } = await supabase.from('cases').select('*').eq('source', input.source).eq('source_id', input.source_id).maybeSingle();
        return (data as CaseRow | null) ?? null;
    };

    const existing = await findExisting();
    if (existing) return { ok: true, case: existing, created: false };

    const { data, error } = await supabase
        .from('cases')
        .insert({
            org_id: input.org_id ?? DEFAULT_ORG_ID,
            title: input.title.slice(0, 500),
            description: input.description ?? null,
            severity: input.severity,
            status: 'open',
            source: input.source,
            source_id: input.source_id ?? null,
            agent_id: input.agent_id ?? null,
            agent_name: input.agent_name ?? null,
            source_ip: input.source_ip ?? null,
            rule_id: input.rule_id ?? null,
            rule_level: input.rule_level ?? 0,
            mitre_technique: input.mitre_technique ?? null,
            mitre_tactic: input.mitre_tactic ?? null,
            assigned_to: input.assigned_to ?? null,
            playbook_id: input.playbook_id ?? null,
            tags: input.tags ?? [],
            tier: tierForSeverity(input.severity),
        })
        .select()
        .single();

    if (error) {
        // 23505 on (source, source_id): the SOAR engine cased the same alert between our
        // lookup and insert. Return its case rather than failing the analyst's action.
        if (error.code === '23505') {
            const raced = await findExisting();
            if (raced) return { ok: true, case: raced, created: false };
        }
        console.error('[cases] insert failed:', dbErrorMessage(error));
        return { ok: false, error: `Case creation failed: ${dbErrorMessage(error)}`, status: 502 };
    }

    const row = data as CaseRow;
    await addTimeline(row.id, actor, `Case ${row.case_number} created`, { details: `Source: ${input.source}` });
    return { ok: true, case: row, created: true };
}

export interface NewTask { step_id?: string; title: string; description?: string | null }

export async function addTasks(caseId: string, tasks: NewTask[]): Promise<{ id: string; title: string; description: string | null; status: string }[]> {
    const supabase = getSupabase();
    if (!supabase || tasks.length === 0) return [];
    const { data, error } = await supabase
        .from('case_tasks')
        .insert(tasks.map((t) => ({ case_id: caseId, step_id: t.step_id ?? 'manual', title: t.title, description: t.description ?? null, status: 'pending', automated: false })))
        .select('id, title, description, status');
    if (error) {
        console.error('[cases] task insert failed:', dbErrorMessage(error));
        return [];
    }
    return data ?? [];
}
