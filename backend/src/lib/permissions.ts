// Role -> permission map and requirePermission() middleware for SecOps.
//
// Applied to the SecOps routers in phase S1. Builds on the existing requireAuth
// (middleware/auth.ts), which is unchanged: requirePermission runs it first, so a missing or
// invalid token is still a 401 with the same body.
//
// Every SecOps permission covers tenant data, so the request's organisation is resolved too
// (lib/resolveOrg.ts): a token without an org_id is refused with 403 — never defaulted — and
// only staff may act on another organisation, via X-Org-Id, which is audited.

import type { Response, NextFunction } from 'express';
import { requireAuth, type AuthRequest, type UserRole } from '../middleware/auth';
import { resolveOrg, setRequestOrg } from './resolveOrg';

export { requestOrg } from './resolveOrg';

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

/** Resolve the request's organisation (lib/resolveOrg.ts) and store it, or answer with the failure. */
async function withOrg(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    const r = await resolveOrg(req);
    if (!r.ok) { res.status(r.status).json({ error: r.error }); return; }
    setRequestOrg(req, r.orgId);
    next();
}

/**
 * requireAuth + a permission check + organisation resolution (lib/resolveOrg.ts).
 *   401  no/invalid token (from requireAuth, unchanged)
 *   403  the role lacks the permission, or the token carries no org_id
 *   400  a staff X-Org-Id that names no organisation
 * Route code reads the organisation with requestOrg(req).
 */
export function requirePermission(permission: Permission) {
    return (req: AuthRequest, res: Response, next: NextFunction) => {
        requireAuth(req, res, () => {
            const role = req.user?.role;
            if (!hasPermission(role, permission)) {
                res.status(403).json({ error: 'Insufficient permissions', required: permission, current: role ?? null });
                return;
            }
            withOrg(req, res, next).catch(next);
        });
    };
}

/**
 * For routes that only need an authenticated caller with an organisation (no SecOps
 * permission). Mount after requireAuth. Same organisation resolution as requirePermission.
 */
export function requireOrg(req: AuthRequest, res: Response, next: NextFunction) {
    withOrg(req, res, next).catch(next);
}
