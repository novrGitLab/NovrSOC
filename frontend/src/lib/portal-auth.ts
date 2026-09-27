export interface PortalUser {
    userId: string;
    name: string;
    email: string;
    orgId: number;
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

function decodeJwtExpiry(token: string): number | null {
    try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        return typeof payload.exp === 'number' ? payload.exp * 1000 : null;
    } catch {
        return null;
    }
}

export function isPortalAuthenticated(): boolean {
    const token = getPortalToken();
    if (!token) return false;
    const expiry = decodeJwtExpiry(token);
    if (expiry !== null && Date.now() >= expiry) return false;
    return true;
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
