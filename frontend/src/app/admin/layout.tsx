'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { AdminSidebar } from '@/components/layout/AdminSidebar';
import { Header } from '@/components/layout/Header';
import { DemoBanner } from '@/components/layout/DemoBanner';
import { HelpAssistant } from '@/components/shared/HelpAssistant';
import { isAdminAuthenticated, adminSignOut, getAdminUser } from '@/lib/admin-auth';
import { PresenceHeartbeat, announceSignOut } from '@/components/layout/PresenceHeartbeat';

// Marks the user offline before clearing the session.
const signOut = () => { announceSignOut(); adminSignOut(); };

// Settings is reachable only for the roles nav.ts actually grants a settings page to
// (super_admin: Team and everything else there; soc_manager: Platform Health only).
const SETTINGS_HREF: Record<string, string> = { super_admin: '/admin/settings/team', soc_manager: '/admin/settings/health' };

export default function AdminLayout({ children }: { children: React.ReactNode }) {
    const router = useRouter();
    const [authChecked, setAuthChecked] = useState(false);
    const [user, setUser] = useState({ name: 'Admin User', email: '', role: 'Administrator', company: 'Cybernovr' });
    const [navOpen, setNavOpen] = useState(false);

    useEffect(() => {
        if (!isAdminAuthenticated()) {
            router.replace('/login');
            return;
        }
        // The session lives in localStorage, which does not exist during server rendering, so it can only be
        // read after mount (same reasoning as Sidebar.tsx); the page renders nothing until it is checked.
        // eslint-disable-next-line react-hooks/set-state-in-effect
        setUser(getAdminUser());
        setAuthChecked(true);
    }, [router]);

    if (!authChecked) return null;

    const initials = user.name.split(' ').map((n) => n[0]).join('').toUpperCase().slice(0, 2);

    return (
        <div className="flex min-h-screen bg-surface">
            <PresenceHeartbeat />
            <AdminSidebar mobileOpen={navOpen} onClose={() => setNavOpen(false)} user={user} onLogout={signOut} />

            <div className="lg:ml-[260px] flex flex-1 min-w-0 min-h-screen flex-col">
                <DemoBanner />
                <Header initials={initials} name={user.name} email={user.email} role={user.role} onSignOut={signOut} onMenu={() => setNavOpen(true)} settingsHref={SETTINGS_HREF[user.role]} />
                <main className="flex-1 min-w-0 p-4 sm:p-6 overflow-y-auto">{children}</main>
            </div>

            <HelpAssistant />
        </div>
    );
}
