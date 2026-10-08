// The people an organisation may email from NovrSOC: its active SOC staff (platform_users) and its
// own client contacts (organisations.contact_email / ciso_email). Always one organisation — the
// caller's, from the token — so no route can list or mail another tenant's contacts.
//
// Token org_id is the organisation's slug; platform_users.org_id is organisations.id (see
// sql/2026-09-organisations-onboarding.sql), so the slug is resolved to the row first.

import { getSupabase } from './geoEnrichment';

export interface Analyst { name: string; email: string; role: string }
export interface ClientContact { org: string; name: string | null; email: string; kind: 'contact' | 'ciso' }
export interface OrgContacts { analysts: Analyst[]; clients: ClientContact[] }

const STAFF = ['super_admin', 'soc_manager', 'analyst'];

export async function loadOrgContacts(orgSlug: string): Promise<OrgContacts> {
    const supabase = getSupabase();
    if (!supabase) return { analysts: [], clients: [] };
    const { data: org } = await supabase
        .from('organisations')
        .select('id, name, contact_name, contact_email, ciso_name, ciso_email, is_active')
        .eq('slug', orgSlug)
        .maybeSingle();
    if (!org || org.is_active === false) return { analysts: [], clients: [] };

    const { data: users } = await supabase.from('platform_users').select('email, name, role, status').eq('org_id', org.id);
    const analysts = (users ?? [])
        .filter((u) => u.email && (u.status ?? 'active') === 'active' && STAFF.includes(u.role))
        .map((u) => ({ name: u.name || u.email, email: u.email, role: u.role }));
    const clients: ClientContact[] = [];
    if (org.contact_email) clients.push({ org: org.name, name: org.contact_name, email: org.contact_email, kind: 'contact' });
    if (org.ciso_email) clients.push({ org: org.name, name: org.ciso_name, email: org.ciso_email, kind: 'ciso' });
    return { analysts, clients };
}

/** Lower-cased addresses of everyone in loadOrgContacts(). */
export function contactAddresses(c: OrgContacts): Set<string> {
    return new Set([...c.analysts, ...c.clients].map((x) => x.email.toLowerCase()));
}
