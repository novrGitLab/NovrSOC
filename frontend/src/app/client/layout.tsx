'use client';

import { useEffect, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { ClientSidebar } from '@/components/layout/ClientSidebar';
import { Header } from '@/components/layout/Header';
import { HelpAssistant } from '@/components/shared/HelpAssistant';
import { isPortalAuthenticated, portalSignOut, getPortalUser } from '@/lib/portal-auth';

export default function ClientLayout({ children }: { children: React.ReactNode }) {
    const router = useRouter();
    const pathname = usePathname();
    const isLoginPage = pathname === '/client/login';
    const [authChecked, setAuthChecked] = useState(false);
    const [user, setUser] = useState({ name: 'Client User', email: '', role: 'Client' });
    const [navOpen, setNavOpen] = useState(false);

    useEffect(() => {
        // The login page renders its own full-screen layout below and is the one route
        // under /client that's reachable while signed out — it must never be gated behind
        // authChecked, or an unauthenticated visitor can never see it (this used to send
        // them into a loop redirecting to itself while rendering nothing the whole time).
        if (isLoginPage) return;
        if (!isPortalAuthenticated()) {
            router.replace('/client/login');
            return;
        }
        const portalUser = getPortalUser();
        if (portalUser) {
            // The session lives in localStorage, which does not exist during server rendering, so it can only be
            // read after mount (same reasoning as Sidebar.tsx); the page renders nothing until it is checked.
            // eslint-disable-next-line react-hooks/set-state-in-effect
            setUser({ name: portalUser.name, email: portalUser.email, role: portalUser.portalRole || 'Client' });
        }
        setAuthChecked(true);
    }, [router, isLoginPage]);

    if (isLoginPage) return <>{children}</>;
    if (!authChecked) return null;

    const initials = user.name.split(' ').map((n) => n[0]).join('').toUpperCase().slice(0, 2);

    return (
        <div className="flex min-h-screen bg-surface">
            <ClientSidebar mobileOpen={navOpen} onClose={() => setNavOpen(false)} user={user} onLogout={portalSignOut} />

            <div className="lg:ml-[260px] print:ml-0 flex flex-1 min-w-0 min-h-screen flex-col">
                <Header initials={initials} name={user.name} email={user.email} role="portal_user" onSignOut={portalSignOut} onMenu={() => setNavOpen(true)} settingsHref="/client/settings" />
                <main className="flex-1 min-w-0 p-4 sm:p-6 print:p-0 overflow-y-auto print:overflow-visible">{children}</main>
            </div>

            <HelpAssistant />
        </div>
    );
}
