'use client';

import { Sidebar } from './Sidebar';
import { ADMIN_NAV, toNavGroups } from '@/config/nav';

// Items, order, icons and role visibility come from src/config/nav.ts (the single source of
// truth for both sidebars). Role rules there follow the customer-onboarding + multitenancy role
// matrix: Threat Intelligence, Infrastructure and Security Operations are hidden from
// `executive`; Compliance and Data Continuity are hidden from `analyst`; Sec Ops Management is
// manager-only.

interface AdminSidebarProps {
    user: { name: string; email: string; role: string };
    onLogout: () => void;
    mobileOpen?: boolean;
    onClose?: () => void;
}

export function AdminSidebar({ user, onLogout, mobileOpen, onClose }: AdminSidebarProps) {
    // Recomputed per role: a BROKEN/PLANNED item is hidden from everyone but super_admin (§4.5).
    const adminNav = toNavGroups(ADMIN_NAV, user.role);
    return <Sidebar navGroups={adminNav} user={user} onLogout={onLogout} mobileOpen={mobileOpen} onClose={onClose} />;
}
