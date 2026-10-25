export interface AccountOrg {
    id: number;
    name: string;
    industry: string;
    plan: string;
    contact_name: string;
    contact_email: string;
    wazuh_group: string;
    status: string;
    created_at: string;
    endpoints_limit: number;
}

export interface AccountStats {
    total_endpoints: number;
    active_incidents: number;
    total_incidents_alltime: number;
    advisories_received: number;
    vendor_assessments: number;
    scans_performed: number;
    member_count: number;
}

export interface AccountSubscription {
    plan: string;
    endpoints_used: number;
    endpoints_limit: number;
    usage_percent: number;
    renewal_date: string;
}

export interface AccountData {
    org: AccountOrg;
    stats: AccountStats;
    subscription: AccountSubscription;
}

// Which session a browser's two independent, un-namespaced tokens belong to is decided by the
// current route, not by which one happens to exist: this used to always prefer portal_token when
// both were present, so a staff member who had ever also signed into the client portal in the
// same browser would have every /admin/* call silently sent with their client (portal_user)
// token instead of their admin one — wrong role, wrong permissions, every admin call failing or
// scoped to the wrong account. /login and /client/login and other shared/public routes have no
// token requirement yet, so the old preference is kept there only as a harmless tie-break.
export function getAuthToken(): string | null {
    if (typeof window === 'undefined') return null;
    const path = window.location.pathname;
    if (path.startsWith('/client')) return localStorage.getItem('portal_token');
    if (path.startsWith('/admin')) return localStorage.getItem('admin_token');
    return localStorage.getItem('portal_token') || localStorage.getItem('admin_token');
}
