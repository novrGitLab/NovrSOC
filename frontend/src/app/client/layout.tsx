'use client';

import { useEffect, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { PanelRightClose, PanelRightOpen, FileText, Settings as SettingsIcon, Zap } from 'lucide-react';
import { ClientSidebar } from '@/components/layout/ClientSidebar';
import { Header } from '@/components/layout/Header';
import { RightRail } from '@/components/dashboard/RightRail';
import { HelpAssistant } from '@/components/shared/HelpAssistant';
import { isPortalAuthenticated, portalSignOut, getPortalUser } from '@/lib/portal-auth';
import { cn } from '@/lib/utils';

const RAIL_STORAGE_KEY = 'novrsoc_rail_open';

export default function ClientLayout({ children }: { children: React.ReactNode }) {
    const router = useRouter();
    const pathname = usePathname();
    const isLoginPage = pathname === '/client/login';
    const [authChecked, setAuthChecked] = useState(false);
    const [user, setUser] = useState({ name: 'Client User', email: '', role: 'Client' });
    const [railOpen, setRailOpen] = useState(true);
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
        const stored = localStorage.getItem(RAIL_STORAGE_KEY);
        if (stored !== null) setRailOpen(stored === 'true');
    }, [router, isLoginPage]);

    const toggleRail = () => {
        setRailOpen((prev) => {
            const next = !prev;
            localStorage.setItem(RAIL_STORAGE_KEY, String(next));
            return next;
        });
    };

    if (isLoginPage) return <>{children}</>;
    if (!authChecked) return null;

    const initials = user.name.split(' ').map((n) => n[0]).join('').toUpperCase().slice(0, 2);

    return (
        <div className="flex min-h-screen bg-surface">
            <ClientSidebar mobileOpen={navOpen} onClose={() => setNavOpen(false)} user={user} onLogout={portalSignOut} />

            <div className="lg:ml-[260px] flex flex-1 min-w-0 min-h-screen">
                <div className={cn('flex-1 min-w-0 flex flex-col min-h-screen transition-all duration-300', railOpen ? 'xl:mr-[280px]' : 'xl:mr-[48px]')}>
                    <Header initials={initials} onSignOut={portalSignOut} onMenu={() => setNavOpen(true)} />
                    <main className="flex-1 min-w-0 p-4 sm:p-6 overflow-y-auto">{children}</main>
                </div>

                <div
                    className={cn(
                        'fixed top-0 right-0 h-screen bg-white border-l border-grey-100 hidden xl:flex flex-col transition-all duration-300 z-20',
                        railOpen ? 'w-[280px]' : 'w-[48px]'
                    )}
                >
                    <button
                        onClick={toggleRail}
                        className="h-14 flex items-center justify-center border-b border-grey-100 hover:bg-grey-50 transition-colors text-grey-500 hover:text-blue flex-shrink-0"
                        aria-label={railOpen ? 'Collapse right rail' : 'Expand right rail'}
                    >
                        {railOpen ? <PanelRightClose size={18} /> : <PanelRightOpen size={18} />}
                    </button>

                    {railOpen ? (
                        <div className="flex-1 overflow-y-auto p-4">
                            <RightRail portal="client" />
                        </div>
                    ) : (
                        <div className="flex flex-col items-center gap-4 pt-4">
                            <FileText size={18} className="text-grey-500" />
                            <SettingsIcon size={18} className="text-grey-500" />
                            <Zap size={18} className="text-grey-500" />
                        </div>
                    )}
                </div>
            </div>

            <HelpAssistant />
        </div>
    );
}
