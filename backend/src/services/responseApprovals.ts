// Response approvals (phase P3, sql/2026-10-14_p3_secops_ai.sql).
//
// Blocking an IP at the firewall and isolating a host are consequential, so they no longer run on
// a single click. Every path that used to run them (a case's Execute button, the Playbooks page,
// the threat board's Contain, and — since the F-07 redesign fix — the SOAR engine's own tier 2/3
// containment) now records a pending request here; the action runs only when a user holding
// response:approve (soc_manager, super_admin) approves it. The requester can't approve their own
// request unless RESPONSE_ALLOW_SELF_APPROVAL=true (for a team of one). A request whose source is
// 'soar' is requested by the engine itself (routes/soar.ts POST /response-requests, SOAR_ENGINE_TOKEN)
// and decided by a person exactly like any other source.
// The stored result is exactly what services/responseActions.ts reported — success only when the
// remote system accepted the action. A rejected or cancelled request runs nothing.

import { getSupabase } from './geoEnrichment';
import { blockAddress, isolateEndpoint, type LoggedResult } from './responseActions';
import { addTimeline, dbErrorMessage, type CaseRow } from './cases';
import { logAudit } from '../lib/audit';
import { orgScope, ownsAgent } from '../lib/orgScope';

/**
 * Why an approved isolation must not run, or null when it may: the agent has to belong to the
 * approval's organisation (lib/orgScope.ts) at the moment it executes — checked here, on the
 * one path every isolation takes, whatever created the request.
 */
async function isolationRefusal(org: string, agentId: string): Promise<string | null> {
    try {
        return ownsAgent(await orgScope(org), agentId) ? null : `Agent ${agentId.slice(0, 32)} does not belong to this organisation — not isolated`;
    } catch (err) {
        return `Agent ownership could not be checked (${err instanceof Error ? err.message : String(err)}) — not isolated`;
    }
}

export const CONSEQUENTIAL_ACTIONS = ['block_ip', 'isolate_agent'] as const;
export type ConsequentialAction = (typeof CONSEQUENTIAL_ACTIONS)[number];
export const isConsequential = (v: unknown): v is ConsequentialAction => typeof v === 'string' && (CONSEQUENTIAL_ACTIONS as readonly string[]).includes(v);

export interface ApprovalRow {
    id: string; org_id: string; action: ConsequentialAction; target: string; target_label: string | null; reason: string;
    case_id: string | null; task_id: string | null; threat_id: string | null; source: 'case' | 'playbook' | 'threat' | 'soar';
    status: 'pending' | 'approved' | 'rejected' | 'executed' | 'failed' | 'skipped' | 'cancelled';
    requested_by: string; requested_at: string; decided_by: string | null; decided_at: string | null;
    decision_note: string | null; result: string | null; executed_at: string | null;
}

export interface NewApproval {
    org_id: string; action: ConsequentialAction; target: string; target_label?: string | null; reason: string;
    case_id?: string | null; task_id?: string | null; threat_id?: string | null; source: ApprovalRow['source']; requested_by: string;
}

type Hook = (a: ApprovalRow, r: LoggedResult) => Promise<void>;
const successHooks = new Map<ApprovalRow['source'], Hook>();
/** Lets the owner of a source (e.g. the threat board) record what a successful action means for it. */
export function onApprovedSuccess(source: ApprovalRow['source'], hook: Hook): void { successHooks.set(source, hook); }

export type Outcome<T> = { ok: true; value: T } | { ok: false; status: number; error: string };

/** Records a request, or returns the one already open for the same action and target. */
export async function requestApproval(input: NewApproval): Promise<Outcome<{ approval: ApprovalRow; existing: boolean }>> {
    const supabase = getSupabase();
    if (!supabase) return { ok: false, status: 503, error: 'Database not configured' };
    const target = input.target.trim();
    if (!target) return { ok: false, status: 400, error: 'No target for this action' };
    const reason = input.reason.trim().slice(0, 1000);
    if (!reason) return { ok: false, status: 400, error: 'A reason is required' };
    const open = await supabase.from('response_approvals').select('*').eq('org_id', input.org_id).eq('action', input.action).eq('target', target).eq('status', 'pending').maybeSingle();
    if (open.error) return { ok: false, status: 503, error: `Approvals unavailable: ${dbErrorMessage(open.error)}` };
    if (open.data) return { ok: true, value: { approval: open.data as ApprovalRow, existing: true } };
    const { data, error } = await supabase.from('response_approvals').insert({
        org_id: input.org_id, action: input.action, target, target_label: input.target_label ?? null, reason,
        case_id: input.case_id ?? null, task_id: input.task_id ?? null, threat_id: input.threat_id ?? null,
        source: input.source, requested_by: input.requested_by,
    }).select('*').single();
    if (error) return { ok: false, status: 503, error: `Approvals unavailable: ${dbErrorMessage(error)}` };
    const approval = data as ApprovalRow;
    if (approval.case_id) await addTimeline(approval.case_id, input.requested_by, `Requested approval to ${label(approval)}`, { details: reason });
    logAudit({ user: input.requested_by, action: 'RESPONSE_APPROVAL_REQUESTED', resource: 'response_approval', resource_id: approval.id, org_id: input.org_id, ip: 'n/a', result: 'success', severity: 'warning', details: `${label(approval)}: ${reason}`.slice(0, 200) });
    return { ok: true, value: { approval, existing: false } };
}

const label = (a: Pick<ApprovalRow, 'action' | 'target' | 'target_label'>) =>
    a.action === 'block_ip' ? `block IP ${a.target}` : `isolate agent ${a.target_label ? `${a.target_label} (${a.target})` : a.target}`;

export async function listApprovals(org: string, status?: ApprovalRow['status']): Promise<Outcome<ApprovalRow[]>> {
    const supabase = getSupabase();
    if (!supabase) return { ok: false, status: 503, error: 'Database not configured' };
    let q = supabase.from('response_approvals').select('*').eq('org_id', org);
    if (status) q = q.eq('status', status);
    const { data, error } = await q.order('requested_at', { ascending: false }).limit(200);
    if (error) return { ok: false, status: 503, error: dbErrorMessage(error) };
    return { ok: true, value: (data ?? []) as ApprovalRow[] };
}

/** Approve (and run) or reject a pending request. Only a pending request can be decided, once. */
export async function decideApproval(id: string, org: string, decider: string, approve: boolean, note: string | null): Promise<Outcome<ApprovalRow>> {
    const supabase = getSupabase();
    if (!supabase) return { ok: false, status: 503, error: 'Database not configured' };
    const cur = await supabase.from('response_approvals').select('*').eq('id', id).eq('org_id', org).maybeSingle();
    if (cur.error) return { ok: false, status: 503, error: dbErrorMessage(cur.error) };
    const a = cur.data as ApprovalRow | null;
    if (!a) return { ok: false, status: 404, error: 'Approval request not found' };
    if (a.status !== 'pending') return { ok: false, status: 409, error: `Already ${a.status}` };
    if (approve && a.requested_by.toLowerCase() === decider.toLowerCase() && process.env.RESPONSE_ALLOW_SELF_APPROVAL !== 'true') {
        return { ok: false, status: 409, error: 'You cannot approve your own request; another manager must approve it' };
    }
    // Claim the decision atomically, so two approvers can't both run it.
    const now = new Date().toISOString();
    const claim = await supabase.from('response_approvals').update({ status: approve ? 'approved' : 'rejected', decided_by: decider, decided_at: now, decision_note: note?.slice(0, 1000) ?? null })
        .eq('id', id).eq('status', 'pending').select('*').maybeSingle();
    if (claim.error) return { ok: false, status: 503, error: dbErrorMessage(claim.error) };
    if (!claim.data) return { ok: false, status: 409, error: 'Decided by someone else just now' };
    let row = claim.data as ApprovalRow;
    logAudit({ user: decider, action: approve ? 'RESPONSE_APPROVED' : 'RESPONSE_REJECTED', resource: 'response_approval', resource_id: id, org_id: org, ip: 'n/a', result: 'success', severity: 'warning', details: label(row) });
    if (!approve) {
        if (row.case_id) await addTimeline(row.case_id, decider, `Rejected request to ${label(row)}`, { details: note ?? undefined });
        return { ok: true, value: row };
    }

    let caseRow: CaseRow | undefined;
    if (row.case_id) {
        const c = await supabase.from('cases').select('*').eq('id', row.case_id).eq('org_id', org).maybeSingle();
        caseRow = (c.data as CaseRow | null) ?? undefined;
    }
    const refusal = row.action === 'isolate_agent' ? await isolationRefusal(org, row.target) : null;
    const result = row.action === 'block_ip'
        ? await blockAddress(row.target, { case: caseRow, reason: row.reason })
        : refusal
        ? { outcome: 'skipped' as const, message: refusal, affected: 0, action_id: null }
        : await isolateEndpoint(row.target, { case: caseRow, reason: row.reason, agentName: row.target_label, sourceIp: caseRow?.source_ip ?? null });
    const status: ApprovalRow['status'] = result.outcome === 'success' ? 'executed' : result.outcome === 'skipped' ? 'skipped' : 'failed';
    const done = await supabase.from('response_approvals').update({ status, result: `${result.outcome.toUpperCase()}: ${result.message}`.slice(0, 1000), executed_at: new Date().toISOString() }).eq('id', id).select('*').maybeSingle();
    if (done.data) row = done.data as ApprovalRow;

    if (row.case_id) {
        const step = row.action;
        let task = supabase.from('case_tasks').update({
            status: result.outcome === 'success' ? 'completed' : 'pending',
            result: `${result.outcome.toUpperCase()}: ${result.message}`,
            executed_at: result.outcome === 'success' ? now : null,
            executed_by: result.outcome === 'success' ? decider : null,
        }).eq('case_id', row.case_id);
        task = row.task_id ? task.eq('id', row.task_id) : task.eq('step_id', step);
        await task;
        await addTimeline(row.case_id, decider, `Approved and ran: ${label(row)} — ${result.outcome}: ${result.message}`);
    }
    if (result.outcome === 'success') {
        const hook = successHooks.get(row.source);
        if (hook) await hook(row, result).catch((err) => console.error('[approvals] success hook failed:', err instanceof Error ? err.message : err));
    }
    logAudit({ user: decider, action: 'RESPONSE_EXECUTED', resource: 'response_approval', resource_id: id, org_id: org, ip: 'n/a', result: result.outcome === 'success' ? 'success' : 'failed', severity: 'warning', details: `${label(row)}: ${result.outcome} — ${result.message}`.slice(0, 200) });
    return { ok: true, value: row };
}

/** The requester (or a manager) withdraws a pending request. */
export async function cancelApproval(id: string, org: string, actor: string, canManage: boolean): Promise<Outcome<ApprovalRow>> {
    const supabase = getSupabase();
    if (!supabase) return { ok: false, status: 503, error: 'Database not configured' };
    const cur = await supabase.from('response_approvals').select('*').eq('id', id).eq('org_id', org).maybeSingle();
    const a = cur.data as ApprovalRow | null;
    if (!a) return { ok: false, status: 404, error: 'Approval request not found' };
    if (a.requested_by.toLowerCase() !== actor.toLowerCase() && !canManage) return { ok: false, status: 403, error: 'Only the requester or a manager can cancel this request' };
    const upd = await supabase.from('response_approvals').update({ status: 'cancelled', decided_by: actor, decided_at: new Date().toISOString() }).eq('id', id).eq('status', 'pending').select('*').maybeSingle();
    if (!upd.data) return { ok: false, status: 409, error: `Already ${a.status}` };
    logAudit({ user: actor, action: 'RESPONSE_APPROVAL_CANCELLED', resource: 'response_approval', resource_id: id, org_id: org, ip: 'n/a', result: 'success', details: label(a) });
    return { ok: true, value: upd.data as ApprovalRow };
}
