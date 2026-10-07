// Role -> permission map and requirePermission() middleware for SecOps.
//
// Not applied to any route yet (phase R1 defines it; routes are retrofitted later). Builds on
// the existing requireAuth (middleware/auth.ts), which is unchanged: requirePermission runs it
// first, so a missing or invalid token is still a 401 with the same body.
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
                res.status(403).json({ error: 'No organisation on this account — tenant data cannot be accessed' });
                return;
            }
            next();
        });
    };
}
