// Which organisation a request acts on.
//
//   Client roles (portal_user, executive) and any unknown role: always the token's org_id. Any
//   org the client sends (header, query, body) is ignored.
//   Staff roles (super_admin, soc_manager, analyst): the token's org_id, or another organisation
//   named in the X-Org-Id header. That organisation must exist in `organisations` (by slug,
//   which is what token org_ids carry) — otherwise 400. There is no "all orgs" mode.
//   No org_id on the token: 403, never a default organisation.
//
// Every staff request for an organisation other than their own is recorded: in the in-process
// audit log (lib/audit.ts, shown on the Audit Log page) and in the org_access_audit table
// (sql/2026-10-08_org_access_audit.sql) when it exists — who, role, org, route, time.
//
// requirePermission / requireOrg (lib/permissions.ts) call this and store the result; route
// code reads it with requestOrg(req).

import type { Request } from 'express';
import type { AuthRequest, UserRole } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';
import { logAudit } from './audit';

export const ORG_HEADER = 'x-org-id';
export const STAFF_ROLES: readonly UserRole[] = ['super_admin', 'soc_manager', 'analyst'];
export const CLIENT_ROLES: readonly UserRole[] = ['portal_user', 'executive'];
export const isStaffRole = (role: string | undefined) => !!role && (STAFF_ROLES as readonly string[]).includes(role);

export type OrgResolution =
    | { ok: true; orgId: string; crossOrg: boolean }
    | { ok: false; status: 400 | 403 | 503; error: string };

const resolved = new WeakMap<Request, string>();

let auditTableWarned = false;

async function recordCrossOrgAccess(req: AuthRequest, own: string, target: string): Promise<void> {
    const entry = {
        actor: req.user?.email ?? 'unknown',
        role: req.user?.role ?? null,
        home_org: own,
        target_org: target,
        method: req.method,
        route: (req.originalUrl || req.url).split('?')[0].slice(0, 300),
        accessed_at: new Date().toISOString(),
    };
    logAudit({
        user: entry.actor, action: 'CROSS_ORG_ACCESS', resource: `${entry.method} ${entry.route}`, resource_id: target,
        ip: req.ip ?? 'unknown', result: 'success', severity: 'warning',
        details: `${entry.role} from ${own} acting on ${target}`,
    });
    const supabase = getSupabase();
    if (!supabase) return;
    const { error } = await supabase.from('org_access_audit').insert(entry);
    if (error && !auditTableWarned) {
        auditTableWarned = true;
        console.warn('[resolveOrg] org_access_audit insert failed (run sql/2026-10-08_org_access_audit.sql) — cross-org access is still in the in-process audit log:', error.message);
    }
}

export async function resolveOrg(req: AuthRequest): Promise<OrgResolution> {
    const own = req.user?.org_id;
    if (!own) return { ok: false, status: 403, error: 'No organisation on this account — tenant data cannot be accessed' };

    const requested = (req.get(ORG_HEADER) ?? '').trim();
    if (!requested || requested === own || !isStaffRole(req.user?.role)) return { ok: true, orgId: own, crossOrg: false };

    const supabase = getSupabase();
    if (!supabase) return { ok: false, status: 503, error: 'Cannot verify the requested organisation — database not configured' };
    const { data, error } = await supabase.from('organisations').select('slug').eq('slug', requested).maybeSingle();
    if (error) return { ok: false, status: 503, error: 'Cannot verify the requested organisation' };
    if (!data) return { ok: false, status: 400, error: `Unknown organisation: ${requested.slice(0, 100)}` };

    await recordCrossOrgAccess(req, own, requested);
    return { ok: true, orgId: requested, crossOrg: true };
}

/** Store a resolution for this request (called by requirePermission / requireOrg). */
export function setRequestOrg(req: Request, orgId: string): void {
    resolved.set(req, orgId);
}

/**
 * The organisation this request acts on. Only call behind requirePermission or requireOrg,
 * which resolve it; there is deliberately no default organisation.
 */
export function requestOrg(req: Request): string {
    const org = resolved.get(req);
    if (!org) throw new Error('requestOrg() reached before the org was resolved — mount requirePermission or requireOrg first');
    return org;
}
