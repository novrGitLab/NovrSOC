'use client';

import { Sidebar } from './Sidebar';
import { CLIENT_NAV, toNavGroups } from '@/config/nav';

// Items, order and icons come from src/config/nav.ts (shared with the admin sidebar).
const clientNav = toNavGroups(CLIENT_NAV);

interface ClientSidebarProps {
    user: { name: string; email: string; role: string };
    onLogout: () => void;
}

export function ClientSidebar({ user, onLogout }: ClientSidebarProps) {
    return <Sidebar navGroups={clientNav} user={user} onLogout={onLogout} />;
}
