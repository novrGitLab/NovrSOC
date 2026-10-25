import { isJwtLive, decodeJwtPayload } from './jwt';

const TOKEN_KEY = 'admin_token';

export interface AdminUser {
    name: string;
    email: string;
    role: string;
    company: string;
}

export function getAdminToken(): string | null {
    if (typeof window === 'undefined') return null;
    return localStorage.getItem(TOKEN_KEY);
}

// Was presence-only (token exists), unlike isPortalAuthenticated's expiry check — an expired
// admin token would pass this and render the shell until the first API call 401'd. Now matches
// the portal check: an expired token is signed out immediately on the next layout mount/navigation.
export function isAdminAuthenticated(): boolean {
    const token = getAdminToken();
    return !!token && isJwtLive(token);
}

// Best-effort decode of the admin JWT payload for display purposes only (name/email/role
// in the sidebar footer) — never used for authorization, the backend is the source of truth.
export function getAdminUser(): AdminUser {
    const fallback: AdminUser = { name: 'Admin User', email: '', role: 'Administrator', company: 'Cybernovr' };
    const token = getAdminToken();
    const payload = token ? decodeJwtPayload(token) : null;
    if (!payload) return fallback;
    return {
        name: typeof payload.name === 'string' ? payload.name : fallback.name,
        email: typeof payload.email === 'string' ? payload.email : fallback.email,
        role: typeof payload.role === 'string' ? payload.role : fallback.role,
        company: typeof payload.company === 'string' ? payload.company : fallback.company,
    };
}

export function adminSignOut(): void {
    localStorage.removeItem(TOKEN_KEY);
    window.location.href = '/login';
}
