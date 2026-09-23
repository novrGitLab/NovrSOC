// Mock team roster — replace with a real Supabase-backed user table + query once one exists
// (there is currently only a single shared admin login, see backend/src/routes/auth.ts's
// DEV_ADMIN_EMAIL bypass — no per-user accounts to query yet).
//
// Shared between the Team Members admin page and the alert-assignment picker in Threat
// Management so both draw from the same list instead of two that can silently drift apart.

export type TeamRole = 'super_admin' | 'analyst' | 'viewer';

export interface TeamMember {
    id: string;
    name: string;
    email: string;
    role: TeamRole;
    status: 'active' | 'invited';
    last_seen: string;
    org: string;
    avatar: string;
}

export const MOCK_TEAM: TeamMember[] = [
    {
        id: '1', name: 'Abubakar Usman Damilare', email: 'rayne@cybernovr.com',
        role: 'super_admin', status: 'active', last_seen: '2026-08-24 09:41',
        org: 'Cybernovr', avatar: 'AU',
    },
    {
        id: '2', name: 'Karl Mensah', email: 'karl@cybernovr.com',
        role: 'analyst', status: 'active', last_seen: '2026-08-24 08:15',
        org: 'Cybernovr', avatar: 'KM',
    },
    {
        id: '3', name: 'Amina Bello', email: 'amina@cybernovr.com',
        role: 'viewer', status: 'invited', last_seen: 'Never',
        org: 'Cybernovr', avatar: 'AB',
    },
];

// Only members who can actually be handed an alert/incident — matches ThreatManagement's
// "Assign to..." picker and the case workbench's assigned-analyst concept. Viewers are
// read-only and super_admin is the org owner, not a triage seat, so neither belongs here.
export const ASSIGNABLE_ANALYSTS = MOCK_TEAM.filter((m) => m.role === 'analyst').map((m) => m.name);

export const ROLE_BADGES: Record<TeamRole, string> = {
    super_admin: 'bg-purple text-white',
    analyst: 'bg-blue text-white',
    viewer: 'bg-card-muted text-foreground-muted',
};

export const ROLE_LABELS: Record<TeamRole, string> = {
    super_admin: 'Super Admin',
    analyst: 'SOC Analyst',
    viewer: 'Viewer',
};
