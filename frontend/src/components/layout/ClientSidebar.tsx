'use client';

import { Sidebar } from './Sidebar';
import { CLIENT_NAV, toNavGroups } from '@/config/nav';

// Items, order and icons come from src/config/nav.ts (shared with the admin sidebar).

interface ClientSidebarProps {
    user: { name: string; email: string; role: string };
    onLogout: () => void;
    mobileOpen?: boolean;
    onClose?: () => void;
}

export function ClientSidebar({ user, onLogout, mobileOpen, onClose }: ClientSidebarProps) {
    // The client portal has no super_admin tier, so every BROKEN item (nav.ts: most of the
    // portal today — sign-in depends on a backend these pages can't reach) is simply hidden,
    // rather than linking a customer to a page where every call fails.
    const clientNav = toNavGroups(CLIENT_NAV, user.role);
    return <Sidebar navGroups={clientNav} user={user} onLogout={onLogout} mobileOpen={mobileOpen} onClose={onClose} />;
}
