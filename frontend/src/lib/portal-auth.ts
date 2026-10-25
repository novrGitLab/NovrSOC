import { isJwtLive } from './jwt';

export interface PortalUser {
    userId: string;
    name: string;
    email: string;
    // organisations.slug (routes/portal.ts's /auth/signin sends org.slug here) — a string,
    // never a numeric id. Named orgId for parity with AdminUser-style fields, not because it is one.
    orgId: string;
    orgName: string;
    orgIndustry: string | null;
    orgPlan: string | null;
    portalRole: string;
    wazuhGroup: string | null;
}

const TOKEN_KEY = 'portal_token';
const USER_KEY = 'portal_user';

export function getPortalToken(): string | null {
    if (typeof window === 'undefined') return null;
    return localStorage.getItem(TOKEN_KEY);
}

export function isPortalAuthenticated(): boolean {
    const token = getPortalToken();
    return !!token && isJwtLive(token);
}

export function getPortalUser(): PortalUser | null {
    if (typeof window === 'undefined') return null;
    const raw = localStorage.getItem(USER_KEY);
    if (!raw) return null;
    try {
        return JSON.parse(raw) as PortalUser;
    } catch {
        return null;
    }
}

export function setPortalSession(token: string, user: PortalUser): void {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function portalSignOut(): void {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    window.location.href = '/client/login';
}
