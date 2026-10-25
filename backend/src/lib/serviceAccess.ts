// Per-organisation module entitlements (phase P29, Release 3.1's onboarding wizard Step 2).
//
// Wired into lib/permissions.ts's requirePermission(): the permission's own prefix ('vms:read'
// -> 'vms') decides which module a route belongs to, so no route needs its own call to this file
// to be covered. 'alerts:*'/'cases:*' (core SecOps) have no module of their own and are never
// gated; SOAR's automation surface (routes/soar.ts) is checked directly, since it shares
// 'alerts:read' with core SecOps and so can't be derived from a permission prefix alone.
//
// Security hardening pass (R3.1 follow-up) — deliberately NOT this codebase's usual "additive
// migration fails open" pattern. hasServiceAccess() distinguishes two different reasons an
// organisation might have zero grant rows for a service, which an earlier version of this file
// conflated:
//   "legacy" organisation   never touched by the onboarding wizard at all (no org_onboarding
//                           row) — access is preserved, but ONLY once both org_service_grants
//                           and org_onboarding are confirmed healthy and genuinely empty for it.
//   "awaiting configuration" an organisation the wizard HAS started onboarding (an org_onboarding
//                           row exists, draft or active) but hasn't explicitly granted this
//                           service yet — access is DENIED; the wizard's whole point is that a
//                           newly onboarded organisation's entitlements are explicit, not implied.
// Any database error, either table missing, or no database configured at all is an AMBIGUOUS
// state — it is answered as denied, never as "probably fine". This means the P29 SQL migration
// is a hard prerequisite for this code, not an optional one applied at leisure: every
// organisation is denied VMS/CNII/Threat-Intel/SecOps-Automation access until
// org_service_grants and org_onboarding both exist. Apply the migration before or atomically
// with deploying this code.

import { getSupabase } from '../services/geoEnrichment';

export const SERVICES = ['vms', 'cnii_watch', 'threat_intel', 'secops_automation'] as const;
export type ServiceKey = (typeof SERVICES)[number];

export const SERVICE_LABEL: Record<ServiceKey, string> = {
    vms: 'Vulnerability Management',
    cnii_watch: 'CNII Watch',
    threat_intel: 'Threat Intelligence',
    secops_automation: 'SecOps and Automation',
};

/** requirePermission()'s permission prefix -> the module it belongs to. Permissions with no
 * entry here (alerts:*, cases:*, response:*, handover:*) are core platform features, never
 * gated by a service grant. */
export const SERVICE_BY_PERMISSION_PREFIX: Record<string, ServiceKey> = {
    vms: 'vms',
    cnii: 'cnii_watch',
    intel: 'threat_intel',
};

export interface ServiceGrant { service: ServiceKey; status: 'enabled' | 'configured' | 'pending' | 'disabled'; notes: string | null; granted_by: string; granted_at: string; updated_at: string }

/** Every grant row this organisation has (possibly none). */
export async function serviceGrantsFor(org: string): Promise<ServiceGrant[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    const { data, error } = await supabase.from('org_service_grants').select('service, status, notes, granted_by, granted_at, updated_at').eq('org_id', org);
    if (error) return [];
    return (data ?? []) as ServiceGrant[];
}

/** Whether `org` may use `service` right now. Fails CLOSED on anything that isn't a clean,
 * confirmed answer: no database configured, a query error (missing table included), or an
 * organisation the wizard has started onboarding but not yet granted this service to. Legacy
 * access is preserved only for an organisation BOTH tables confirm has no record at all. */
export async function hasServiceAccess(org: string, service: ServiceKey): Promise<boolean> {
    const supabase = getSupabase();
    if (!supabase) return false;

    const grants = await supabase.from('org_service_grants').select('service, status').eq('org_id', org);
    if (grants.error) return false;
    const rows = grants.data ?? [];
    if (rows.length > 0) {
        const row = rows.find((r) => r.service === service);
        return !!row && (row.status === 'enabled' || row.status === 'configured');
    }

    // No grants at all: only a confirmed-legacy organisation (never started onboarding) keeps
    // access. One that the wizard has touched — even an untouched draft — must grant explicitly.
    const onboarding = await supabase.from('org_onboarding').select('org_id').eq('org_id', org).maybeSingle();
    if (onboarding.error) return false;
    return onboarding.data === null;
}
