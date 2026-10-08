// Role -> permission map and requirePermission() middleware for SecOps.
//
// Applied to the SecOps routers in phase S1. Builds on the existing requireAuth
// (middleware/auth.ts), which is unchanged: requirePermission runs it first, so a missing or
// invalid token is still a 401 with the same body.
//
// Every SecOps permission covers tenant data, so a token without an org_id is refused with 403
// — never defaulted to an organisation.

import type { Response, NextFunction } from 'express';
import { requireAuth, type AuthRequest, type UserRole } from '../middleware/auth';

export const PERMISSIONS = [
    'alerts:read',
    'cases:read',
    'cases:write',
    'cases:close',
    'response:contain',
    'response:approve',
    'handover:write',
] as const;

export type Permission = (typeof PERMISSIONS)[number];

// Follows the existing role matrix (frontend/src/config/nav.ts): Security Operations is for
// super_admin, soc_manager and analyst; executive and portal_user get no SecOps access. Approving
// a response action is a manager decision, so analysts can request containment but not approve.
export const ROLE_PERMISSIONS: Readonly<Record<UserRole, readonly Permission[]>> = {
    super_admin: PERMISSIONS,
    soc_manager: PERMISSIONS,
    analyst: ['alerts:read', 'cases:read', 'cases:write', 'cases:close', 'response:contain', 'handover:write'],
    executive: [],
    portal_user: [],
};

/** Permissions held by a role string from a token. Unknown roles hold none. */
export function permissionsFor(role: string | undefined): readonly Permission[] {
    return role && Object.prototype.hasOwnProperty.call(ROLE_PERMISSIONS, role) ? ROLE_PERMISSIONS[role as UserRole] : [];
}

export function hasPermission(role: string | undefined, permission: Permission): boolean {
    return permissionsFor(role).includes(permission);
}

const NO_ORG = { error: 'No organisation on this account — tenant data cannot be accessed' };

/**
 * requireAuth + a permission check + a tenant check.
 *   401  no/invalid token (from requireAuth, unchanged)
 *   403  the role lacks the permission, or the token carries no org_id
 */
export function requirePermission(permission: Permission) {
    return (req: AuthRequest, res: Response, next: NextFunction) => {
        requireAuth(req, res, () => {
            const role = req.user?.role;
            if (!hasPermission(role, permission)) {
                res.status(403).json({ error: 'Insufficient permissions', required: permission, current: role ?? null });
                return;
            }
            if (!req.user?.org_id) {
                res.status(403).json(NO_ORG);
                return;
            }
            next();
        });
    };
}

/**
 * For routes that only need an authenticated caller with an organisation (no SecOps
 * permission). Mount after requireAuth. 403 when the token carries no org_id.
 */
export function requireOrg(req: AuthRequest, res: Response, next: NextFunction) {
    if (!req.user?.org_id) { res.status(403).json(NO_ORG); return; }
    next();
}

/**
 * The caller's organisation, from the token. Only call behind requirePermission or requireOrg,
 * which guarantee it is set; there is deliberately no default organisation.
 */
export function tokenOrg(req: AuthRequest): string {
    const org = req.user?.org_id;
    if (!org) throw new Error('tokenOrg() reached without an org_id — mount requirePermission or requireOrg first');
    return org;
}

/** NovrSOC staff roles — everyone except client-portal users. */
export const STAFF_ROLES: readonly UserRole[] = ['super_admin', 'soc_manager', 'analyst', 'executive'];
export const isStaff = (role: string | undefined) => !!role && (STAFF_ROLES as readonly string[]).includes(role);
