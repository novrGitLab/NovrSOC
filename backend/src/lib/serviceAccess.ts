// Per-organisation module entitlements (phase P29, Release 3.1's onboarding wizard Step 2).
// org_service_grants holds explicit grants; an organisation with none at all has never been
// through the wizard's Service Provisioning step (every organisation that existed before this
// phase, including Cybernovr) and stays fully enabled — the check never changes today's
// behaviour for an organisation nobody has configured.
//
// Wired into lib/permissions.ts's requirePermission(): the permission's own prefix ('vms:read'
// -> 'vms') decides which module a route belongs to, so no route needs its own call to this file
// to be covered. 'alerts:*'/'cases:*' (core SecOps) have no module of their own and are never
// gated; SOAR's automation surface (routes/soar.ts) is checked directly, since it shares
// 'alerts:read' with core SecOps and so can't be derived from a permission prefix alone.

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

/** Whether `org` may use `service` right now. Fails open — no grant rows at all, the P29 SQL
 * not run yet, or a read error — all read as "not yet gated for this organisation", the same
 * principle applied throughout this codebase's additive migrations (old behaviour continues
 * until a feature is actually turned on for that tenant). A platform-wide DB outage therefore
 * never locks every organisation out of every module at once. */
export async function hasServiceAccess(org: string, service: ServiceKey): Promise<boolean> {
    const supabase = getSupabase();
    if (!supabase) return true;
    const { data, error } = await supabase.from('org_service_grants').select('service, status').eq('org_id', org);
    if (error) return true;
    if (!data || data.length === 0) return true;
    const row = data.find((r) => r.service === service);
    return !!row && (row.status === 'enabled' || row.status === 'configured');
}
