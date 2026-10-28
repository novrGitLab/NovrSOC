// R3.3E — report recipient management: who a scheduled or manual report may be sent to, and how
// trusted that address is.
//
// kind='portal_user' must match an active platform_users row for this exact organisation — note
// platform_users.org_id is organisations.id (a UUID), not the slug every other table in this
// codebase uses for org_id (see services/orgContacts.ts's header comment, which solves the same
// resolution this file needs). kind='external_email' is any other address; Stage 3 requires these
// to be explicitly authorised before a sensitive report is actually sent to one — see
// requireAuthorisedForDelivery() below, called from the delivery path, not just at creation time,
// so revoking authorisation later actually stops future sends rather than only blocking new rows.

import { getSupabase } from './geoEnrichment';
import { logAudit } from '../lib/audit';

export type RecipientKind = 'portal_user' | 'external_email';
export interface ReportRecipient {
    id: string; org_id: string; kind: RecipientKind; email: string; display_name: string | null;
    report_types: string[]; enabled: boolean; external_authorised_by: string | null; external_authorised_at: string | null;
    added_by: string; added_at: string; updated_by: string | null; updated_at: string;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** platform_users.org_id is organisations.id, not the slug — resolved once here so every caller
 * gets this right rather than each needing to remember it (see header). */
async function orgUuid(orgSlug: string): Promise<string | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data } = await supabase.from('organisations').select('id').eq('slug', orgSlug).maybeSingle();
    return (data?.id as string | undefined) ?? null;
}

/** Whether `email` is an active platform_users member of this exact organisation — any role, not
 * only staff, since a report recipient may legitimately be that organisation's own executive. */
export async function isActivePortalUser(orgSlug: string, email: string): Promise<boolean> {
    const supabase = getSupabase();
    if (!supabase) return false;
    const uuid = await orgUuid(orgSlug);
    if (!uuid) return false;
    const { data } = await supabase.from('platform_users').select('status').eq('org_id', uuid).ilike('email', email.trim().toLowerCase()).maybeSingle();
    return !!data && (data.status ?? 'active') === 'active';
}

export type ValidationResult = { ok: true } | { ok: false; error: string };

/** Checked before INSERT and before every delivery (an account disabled after being added as a
 * recipient must stop receiving reports, not just be blocked from being re-added). */
export async function validateRecipient(org: string, kind: RecipientKind, email: string): Promise<ValidationResult> {
    const e = email.trim().toLowerCase();
    if (!EMAIL_RE.test(e)) return { ok: false, error: 'Not a valid email address' };
    if (kind === 'portal_user') {
        const active = await isActivePortalUser(org, e);
        return active ? { ok: true } : { ok: false, error: 'No active NovrSOC account for this organisation uses that email' };
    }
    return { ok: true };
}

/** external_email recipients start unauthorised; a sensitive report never reaches one until a
 * staff member explicitly authorises it. Portal recipients need no separate authorisation — their
 * email is already an active, org-scoped platform account, verified at add time and re-verified
 * on every delivery by validateRecipient() above. */
export function requiresAuthorisation(r: Pick<ReportRecipient, 'kind' | 'external_authorised_by'>): boolean {
    return r.kind === 'external_email' && !r.external_authorised_by;
}

export async function authoriseExternalRecipient(recipientId: string, org: string, actor: string): Promise<ValidationResult> {
    const supabase = getSupabase();
    if (!supabase) return { ok: false, error: 'Database not configured' };
    const { data, error } = await supabase.from('report_recipients').update({ external_authorised_by: actor, external_authorised_at: new Date().toISOString(), updated_by: actor, updated_at: new Date().toISOString() })
        .eq('id', recipientId).eq('org_id', org).eq('kind', 'external_email').select('id').maybeSingle();
    if (error) return { ok: false, error: error.message };
    if (!data) return { ok: false, error: 'Recipient not found' };
    logAudit({ user: actor, action: 'REPORT_RECIPIENT_AUTHORISED', resource: 'report_recipient', resource_id: recipientId, org_id: org, ip: 'unknown', result: 'success' });
    return { ok: true };
}

/** Every recipient eligible for one report run: enabled, subscribed to this type (an empty
 * report_types list means "every type scheduled for this org"), and — for external_email — only
 * once explicitly authorised. A portal_user recipient whose account has since been disabled is
 * silently excluded here (not an error for the run) and re-checked again at send time. */
export async function recipientsFor(org: string, reportType: string): Promise<ReportRecipient[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    const { data, error } = await supabase.from('report_recipients').select('*').eq('org_id', org).eq('enabled', true);
    if (error || !data) return [];
    const rows = (data as ReportRecipient[]).filter((r) => r.report_types.length === 0 || r.report_types.includes(reportType));
    const out: ReportRecipient[] = [];
    for (const r of rows) {
        if (requiresAuthorisation(r)) continue;
        if (r.kind === 'portal_user' && !(await isActivePortalUser(org, r.email))) continue;
        out.push(r);
    }
    return out;
}
