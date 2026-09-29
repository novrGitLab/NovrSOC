'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { PanelRightClose, PanelRightOpen, FileText, Settings as SettingsIcon, Zap } from 'lucide-react';
import { AdminSidebar } from '@/components/layout/AdminSidebar';
import { Header } from '@/components/layout/Header';
import { RightRail } from '@/components/dashboard/RightRail';
import { HelpAssistant } from '@/components/shared/HelpAssistant';
import { isAdminAuthenticated, adminSignOut, getAdminUser } from '@/lib/admin-auth';
import { PresenceHeartbeat, announceSignOut } from '@/components/layout/PresenceHeartbeat';

// Marks the user offline before clearing the session.
const signOut = () => { announceSignOut(); adminSignOut(); };
import { cn } from '@/lib/utils';

const RAIL_STORAGE_KEY = 'novrsoc_rail_open';

export default function AdminLayout({ children }: { children: React.ReactNode }) {
    const router = useRouter();
    const [authChecked, setAuthChecked] = useState(false);
    const [user, setUser] = useState({ name: 'Admin User', email: '', role: 'Administrator', company: 'Cybernovr' });
    const [railOpen, setRailOpen] = useState(true);

    useEffect(() => {
        if (!isAdminAuthenticated()) {
            router.replace('/login');
            return;
        }
        setUser(getAdminUser());
        setAuthChecked(true);
        const stored = localStorage.getItem(RAIL_STORAGE_KEY);
        if (stored !== null) setRailOpen(stored === 'true');
    }, [router]);

    const toggleRail = () => {
        setRailOpen((prev) => {
            const next = !prev;
            localStorage.setItem(RAIL_STORAGE_KEY, String(next));
            return next;
        });
    };

    if (!authChecked) return null;

    const initials = user.name.split(' ').map((n) => n[0]).join('').toUpperCase().slice(0, 2);

    return (
        <div className="flex min-h-screen bg-surface">
            <PresenceHeartbeat />
            <AdminSidebar user={user} onLogout={signOut} />

            <div className="ml-[260px] flex flex-1 min-w-0 min-h-screen">
                <div className={cn('flex-1 min-w-0 flex flex-col min-h-screen transition-all duration-300', railOpen ? 'mr-[280px]' : 'mr-[48px]')}>
                    <Header initials={initials} onSignOut={signOut} />
                    <main className="flex-1 min-w-0 p-6 overflow-y-auto">{children}</main>
                </div>

                <div
                    className={cn(
                        'fixed top-0 right-0 h-screen bg-white border-l border-grey-100 flex flex-col transition-all duration-300 z-20',
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
                            <RightRail portal="admin" />
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
