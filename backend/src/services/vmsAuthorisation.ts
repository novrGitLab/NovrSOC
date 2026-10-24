// VMS scan authorisation (phase P27). A scope entry that permits ACTIVE scanning (discovery, ports,
// vulnerability tests) authorises nothing until an organisation administrator approves it with an
// explicit declaration of authority. A disclaimer alone is not enough: the approver states who they
// are and their title, types the organisation's name, accepts a versioned declaration, and must not
// be the person who requested the scope. The decision is stored as an immutable record
// (vms_scope_approvals) with the exact declaration text, its SHA-256 and a snapshot of what was
// approved, and an audit event is written.
//
// Who may approve (permission vms:authorize — lib/permissions.ts):
//   • the organisation's executive (its administrator account), in the platform — client roles are
//     pinned to their own organisation, so they can approve only their own scopes;
//   • a super_admin of the same organisation, in the platform;
//   • a super_admin recording a client's SIGNED authorisation (offline_document): the signatory's
//     name and title and the signed document's reference are required.
// soc_managers request scopes; they do not approve them.
//
// Passive-only entries (no active activity: CNII Watch's monitoring registrations, AS numbers)
// are registered at once, as before — they authorise no contact with the targets beyond passive
// collection. CNII authorisations (origin 'cnii', services/cniiIntake.ts) keep their own workflow.
// Once active, a scope permits recurring scans (schedules, policies) until it expires or is revoked,
// with no per-scan approval. Changing what a scope covers needs a new request and approval.

import { createHash, randomUUID } from 'crypto';
import { getSupabase } from './geoEnrichment';
import { describeScanWindows, type ScanWindows } from '../lib/scanWindows';

export const DECLARATION_VERSION = 'vms-scan-authority-v1';

export interface ScopeRow {
    id: string; org_id: string; kind: string; value: string; include_subdomains: boolean; allow_discovery?: boolean | null; allow_port_scan: boolean; allow_vuln_scan: boolean;
    exclusions?: string[] | null; authorization_reference: string; expires_at: string; status: string; request_group_id?: string | null; requested_by?: string | null;
    scan_windows?: ScanWindows | null; max_active_jobs?: number | null; origin?: string | null; notes?: string | null;
}

/** Does an entry permit any active contact with its targets? */
export const permitsActiveScanning = (e: { kind: string; allow_discovery?: boolean | null; allow_port_scan?: boolean; allow_vuln_scan?: boolean }) =>
    e.kind !== 'asn' && (e.allow_discovery !== false || !!e.allow_port_scan || !!e.allow_vuln_scan);

const activities = (e: ScopeRow) => [e.allow_discovery !== false && e.kind !== 'asn' ? 'discovery' : null, e.allow_port_scan ? 'port scanning' : null, e.allow_vuln_scan ? 'vulnerability testing' : null].filter(Boolean).join(', ') || 'passive monitoring only';

/** The exact declaration the approver accepts, for these entries. */
export function declarationText(orgName: string, entries: ScopeRow[]): string {
    const lines = entries.map((e) => `  - ${e.kind} ${e.value}${e.kind === 'domain' && e.include_subdomains ? ' (and subdomains)' : ''}: ${activities(e)}${(e.exclusions ?? []).length ? `; excluding ${(e.exclusions ?? []).join(', ')}` : ''}`);
    const first = entries[0];
    return [
        `I declare that I have the authority to permit security testing of the systems listed below on behalf of ${orgName}, which owns or controls them or has the right to authorise their testing.`,
        `I authorise NovrSOC to run the activities listed for each target, from its scanner, until ${first ? new Date(first.expires_at).toISOString().slice(0, 10) : '—'}, within these scan windows: ${describeScanWindows(first?.scan_windows ?? null)}.`,
        ...lines,
        'I understand that active scanning sends traffic to these systems and can, rarely, affect their availability; that targets not listed here will not be scanned; and that this authorisation can be revoked at any time in NovrSOC, which stops further scans.',
        `Authorisation reference: ${first?.authorization_reference ?? '—'}.`,
    ].join('\n');
}
export const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

export interface Decider { userId: string; email: string; role: string; org: string; ip: string; userAgent: string }
export interface ApproveBody {
    method: 'in_platform' | 'offline_document';
    authority_name: string; authority_title: string; organisation_name: string;
    declaration_version: string; declaration_accepted: boolean; signed_document_ref?: string;
}
type Fail = { ok: false; status: number; error: string };

async function orgName(org: string): Promise<string | null> {
    const { data } = await getSupabase()!.from('organisations').select('slug, name').eq('slug', org).maybeSingle();
    return data ? String(data.name ?? data.slug) : null;
}

/** The pending entries of one request, with the declaration their approver would accept. */
export async function pendingGroup(org: string, groupId: string): Promise<{ ok: true; entries: ScopeRow[]; orgName: string; declaration: string } | Fail> {
    const supabase = getSupabase()!;
    const { data, error } = await supabase.from('vms_scopes').select('*').eq('org_id', org).eq('request_group_id', groupId);
    if (error) return { ok: false, status: 502, error: error.message };
    const entries = (data ?? []) as ScopeRow[];
    if (!entries.length) return { ok: false, status: 404, error: 'Scope request not found' };
    if (entries.some((e) => e.status !== 'pending')) return { ok: false, status: 409, error: 'This request has already been decided' };
    const name = (await orgName(org)) ?? org;
    return { ok: true, entries, orgName: name, declaration: declarationText(name, entries) };
}

/** Who may decide this request, and how. */
export function checkDecider(d: Decider, org: string, body: Pick<ApproveBody, 'method' | 'signed_document_ref'>, requestedBy: string | null | undefined): Fail | null {
    if (d.role === 'executive') {
        if (d.org !== org) return { ok: false, status: 403, error: 'You can approve only your own organisation\'s scopes' };
        if (body.method !== 'in_platform') return { ok: false, status: 400, error: 'Approve in the platform; an offline document is recorded by a NovrSOC super administrator' };
    } else if (d.role === 'super_admin') {
        if (body.method === 'in_platform' && d.org !== org) return { ok: false, status: 403, error: 'In-platform approval is for the organisation\'s own administrator. For a client, record its signed authorisation (offline_document).' };
        if (body.method === 'offline_document' && !(body.signed_document_ref ?? '').trim()) return { ok: false, status: 400, error: 'Give the signed document\'s reference' };
    } else {
        return { ok: false, status: 403, error: 'Only the organisation\'s administrator can approve scan authorisation' };
    }
    if (body.method === 'in_platform' && requestedBy && requestedBy.toLowerCase() === d.email.toLowerCase()) {
        return { ok: false, status: 403, error: 'The person who requested a scope cannot approve it' };
    }
    return null;
}

export async function decideGroup(org: string, groupId: string, d: Decider, decision: 'approved' | 'rejected', body: ApproveBody | { reason: string; method?: 'in_platform' | 'offline_document'; signed_document_ref?: string }):
    Promise<{ ok: true; approvalId: string; scopes: ScopeRow[]; superseded: string[] } | Fail> {
    const supabase = getSupabase()!;
    const g = await pendingGroup(org, groupId);
    if (!g.ok) return g;
    const method = body.method ?? 'in_platform';
    const deny = checkDecider(d, org, { method, signed_document_ref: (body as ApproveBody).signed_document_ref }, g.entries[0].requested_by);
    if (deny) return deny;
    const now = new Date();
    let record: Record<string, unknown>;
    if (decision === 'approved') {
        const b = body as ApproveBody;
        if (!b.declaration_accepted || b.declaration_version !== DECLARATION_VERSION) return { ok: false, status: 400, error: `Accept the current declaration (${DECLARATION_VERSION})` };
        const name = (s: string | undefined) => (s ?? '').trim();
        if (name(b.authority_name).length < 3 || name(b.authority_title).length < 2) return { ok: false, status: 400, error: 'Give the full name and job title of the person whose authority this is' };
        if (name(b.organisation_name).toLowerCase() !== g.orgName.trim().toLowerCase()) return { ok: false, status: 400, error: 'Type the organisation\'s name exactly as it is registered, to confirm whose systems these are' };
        if (g.entries.some((e) => Date.parse(e.expires_at) <= now.getTime())) return { ok: false, status: 409, error: 'This request has expired; request the scope again' };
        record = {
            authority_name: name(b.authority_name).slice(0, 120), authority_title: name(b.authority_title).slice(0, 120), organisation_name: name(b.organisation_name).slice(0, 200),
            ...(method === 'offline_document' ? { signed_document_ref: name(b.signed_document_ref).slice(0, 300) } : {}),
            declaration_version: DECLARATION_VERSION, declaration_text: g.declaration, declaration_sha256: sha256(g.declaration),
        };
    } else {
        const reason = ((body as { reason: string }).reason ?? '').trim();
        if (reason.length < 3) return { ok: false, status: 400, error: 'Say why the request is rejected' };
        record = { reason: reason.slice(0, 1000) };
    }
    const approvalId = randomUUID();
    const snapshot = { entries: g.entries.map((e) => ({ id: e.id, kind: e.kind, value: e.value, include_subdomains: e.include_subdomains, allow_discovery: e.allow_discovery !== false, allow_port_scan: e.allow_port_scan, allow_vuln_scan: e.allow_vuln_scan, exclusions: e.exclusions ?? [], expires_at: e.expires_at, scan_windows: e.scan_windows ?? null, max_active_jobs: e.max_active_jobs ?? null, authorization_reference: e.authorization_reference })) };
    // The evidence first: if it cannot be stored, nothing is approved.
    const ins = await supabase.from('vms_scope_approvals').insert({
        id: approvalId, org_id: org, request_group_id: groupId, scope_ids: g.entries.map((e) => e.id), decision, method,
        decided_by_user_id: d.userId, decided_by_email: d.email, decided_by_role: d.role, snapshot, ip: d.ip.slice(0, 80), user_agent: d.userAgent.slice(0, 300), decided_at: now.toISOString(), ...record,
    });
    if (ins.error) return { ok: false, status: /vms_scope_approvals/.test(ins.error.message) ? 503 : 502, error: /vms_scope_approvals/.test(ins.error.message) ? 'Scope approval is not set up yet (run sql/2026-11-01_p27_vms_onboarding.sql)' : ins.error.message };

    if (decision === 'rejected') {
        await supabase.from('vms_scopes').update({ status: 'rejected', rejected_by: d.email, rejected_at: now.toISOString(), rejection_reason: (record.reason as string), approval_id: approvalId }).eq('org_id', org).eq('request_group_id', groupId).eq('status', 'pending');
        return { ok: true, approvalId, scopes: g.entries, superseded: [] };
    }
    // A renewal replaces the active entry for the same target: the old one is revoked, and its
    // schedules move to the new one if it still permits them (otherwise they are disabled, with why).
    const superseded: string[] = [];
    for (const e of g.entries) {
        // Values are stored normalised (validateScopeValue), so an exact match is the same target.
        const { data: olds } = await supabase.from('vms_scopes').select('*').eq('org_id', org).eq('kind', e.kind).eq('status', 'active').eq('value', e.value);
        for (const old of (olds ?? []) as ScopeRow[]) {
            await supabase.from('vms_scopes').update({ status: 'revoked', revoked_by: `superseded by approval ${approvalId}`, revoked_at: now.toISOString() }).eq('id', old.id).eq('status', 'active');
            superseded.push(old.id);
            const { data: scheds } = await supabase.from('vms_scan_schedules').select('id, kind').eq('scope_id', old.id);
            for (const s of scheds ?? []) {
                const allowed = s.kind === 'discovery' ? e.allow_discovery !== false : s.kind === 'ports' ? e.allow_port_scan : s.kind === 'passive_osint' ? true : e.allow_vuln_scan;
                await supabase.from('vms_scan_schedules').update(allowed ? { scope_id: e.id, updated_at: now.toISOString() } : { enabled: false, last_result: `Disabled: the renewed scope no longer permits ${s.kind}`, updated_at: now.toISOString() }).eq('id', s.id);
            }
        }
    }
    const { data: updated, error } = await supabase.from('vms_scopes').update({ status: 'active', approved_by: d.email, approved_at: now.toISOString(), approval_method: method, approval_id: approvalId })
        .eq('org_id', org).eq('request_group_id', groupId).eq('status', 'pending').select('*');
    if (error) return { ok: false, status: 502, error: error.message };
    return { ok: true, approvalId, scopes: (updated ?? []) as ScopeRow[], superseded };
}
