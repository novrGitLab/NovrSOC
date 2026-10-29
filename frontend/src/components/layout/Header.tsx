'use client';

import { useEffect, useRef, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { Bell, Sun, Moon, Menu, ChevronRight } from 'lucide-react';
import { Logo } from '@/components/shared/Logo';
import { GlobalSearch } from './GlobalSearch';
import { HeaderStatus } from './HeaderStatus';
import { OrgSwitcher } from './OrgSwitcher';
import { DemoModeSwitcher } from './DemoModeSwitcher';
import { UserMenu } from './UserMenu';
import { useTheme } from '@/components/providers/ThemeProvider';
import { apiUrl, apiFetch } from '@/lib/api';
import { usePolling } from '@/lib/usePolling';
import { breadcrumbFor } from '@/lib/breadcrumbs';

interface HeaderProps {
    initials: string;
    name: string;
    email: string;
    role: string;
    onSignOut: () => void;
    /** Opens the off-canvas sidebar below the lg breakpoint. */
    onMenu?: () => void;
    /** Where this role's Settings page is, if it has one (config/nav.ts). Omit to hide the menu item. */
    settingsHref?: string;
}

interface Notification {
    id: string;
    type: 'alert' | 'case';
    severity: 'medium' | 'high';
    title: string;
    message: string;
    time: string;
    read: boolean;
}

function timeAgo(iso: string): string {
    const mins = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 60000));
    if (mins < 1) return 'Just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    return `${hrs}h ago`;
}

export function Header({ initials, name, email, role, onSignOut, onMenu, settingsHref }: HeaderProps) {
    const pathname = usePathname();
    const router = useRouter();
    const crumb = breadcrumbFor(pathname);
    const { resolvedTheme, setTheme } = useTheme();
    const isDark = resolvedTheme === 'dark';

    const [notifications, setNotifications] = useState<Notification[]>([]);
    const [open, setOpen] = useState(false);
    // No per-user read-state on the backend (sign-in is still one shared account, so there's
    // nothing per-user to key it to) — "read" is tracked client-side only, per browser, and
    // resets on reload. Opening the dropdown marks whatever's currently loaded as seen; a
    // notification that's genuinely new on the next poll still counts toward the badge.
    const [seenIds, setSeenIds] = useState<ReadonlySet<string>>(() => new Set());
    const panelRef = useRef<HTMLDivElement>(null);

    const load = () => {
        apiFetch(apiUrl('/api/notifications'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => setNotifications(Array.isArray(data?.notifications) ? data.notifications : []))
            .catch(() => {});
    };

    useEffect(() => {
        load();
    }, []);
    // Every 60 s while the tab is visible; at once when it becomes visible again after that.
    usePolling(load, 60_000);

    useEffect(() => {
        if (!open) return;
        const handleClick = (e: MouseEvent) => {
            if (panelRef.current && !panelRef.current.contains(e.target as Node)) setOpen(false);
        };
        document.addEventListener('mousedown', handleClick);
        return () => document.removeEventListener('mousedown', handleClick);
    }, [open]);

    const unreadCount = notifications.filter((n) => !seenIds.has(n.id)).length;

    const toggleOpen = () => {
        if (!open) setSeenIds((prev) => new Set([...prev, ...notifications.map((n) => n.id)]));
        setOpen(!open);
    };

    const goToIncident = (n: Notification) => {
        setOpen(false);
        // Admin and client portal both have a SecOps cases page, just under different
        // prefixes — route to whichever one this session is actually in.
        const base = pathname.startsWith('/client') ? '/client' : '/admin';
        router.push(n.type === 'case' ? `${base}/secops/cases?id=${encodeURIComponent(n.id)}` : `${base}/secops/alerts`);
    };

    return (
        <header className="h-14 bg-white border-b border-grey-100 flex items-center gap-2 sm:gap-4 px-3 sm:px-6 sticky top-0 z-30 w-full print:hidden">
            {/* Left */}
            <div className="flex items-center gap-2 min-w-0">
                {onMenu && (
                    <button onClick={onMenu} className="lg:hidden p-1.5 -ml-1 rounded-lg text-grey-500 hover:text-grey-800 hover:bg-grey-50" aria-label="Open navigation" aria-controls="app-sidebar">
                        <Menu size={20} />
                    </button>
                )}
                <span className="shrink-0"><Logo size="sm" /></span>
                {/* Section / Page — config/nav.ts and config/vmsSections.ts, the same labels the
                    sidebar shows, not just the last URL segment. */}
                <nav aria-label="Breadcrumb" className="hidden sm:flex items-center gap-1.5 text-sm min-w-0">
                    <span className="text-grey-300">/</span>
                    {crumb.section && <span className="text-grey-500 truncate max-w-[10rem]">{crumb.section}</span>}
                    {crumb.section && <ChevronRight size={12} className="text-grey-300 shrink-0" aria-hidden />}
                    <span className="text-grey-800 font-semibold truncate max-w-[14rem]" title={crumb.page}>{crumb.page}</span>
                </nav>
            </div>

            {/* Center — search. Admin only: /api/search reads cases, which portal tokens can't
                access, so the portal gets no box rather than one that always comes back empty. */}
            <div className="flex-1 hidden md:flex justify-center min-w-0">
                {!pathname.startsWith('/client') && <GlobalSearch />}
            </div>

            {/* Right */}
            <div className="flex items-center gap-2 sm:gap-3 min-w-fit ml-auto md:ml-0">
                {/* Staff-only; renders nothing for a client session or a staff account with
                    access to only one organisation (lib/orgContext.ts). */}
                <OrgSwitcher />
                <DemoModeSwitcher />
                <div className="hidden xl:block">
                    <HeaderStatus role={role} />
                </div>
                <div className="hidden lg:block w-px h-4 bg-grey-100" />
                <button
                    onClick={() => setTheme(isDark ? 'light' : 'dark')}
                    className="text-grey-500 hover:text-grey-800 transition-colors"
                    aria-label="Toggle theme"
                >
                    {isDark ? <Sun size={16} /> : <Moon size={16} />}
                </button>
                <div className="relative" ref={panelRef}>
                    <button onClick={toggleOpen} className="relative text-grey-500 hover:text-grey-800 transition-colors" aria-label="Notifications">
                        <Bell size={18} />
                        {unreadCount > 0 && (
                            <span className="absolute -top-1 -right-1 min-w-[14px] h-[14px] px-[3px] rounded-full bg-red text-white text-[9px] font-bold flex items-center justify-center">
                                {unreadCount > 9 ? '9+' : unreadCount}
                            </span>
                        )}
                    </button>
                    {open && (
                        <div className="absolute right-0 top-full mt-2 w-80 max-w-[calc(100vw-1.5rem)] max-h-96 overflow-y-auto scrollbar-thin bg-white border border-grey-100 rounded-xl shadow-lg z-40">
                            <div className="px-4 py-2.5 border-b border-grey-100 text-xs font-bold text-grey-800">Notifications</div>
                            {notifications.length === 0 ? (
                                <p className="px-4 py-6 text-center text-xs text-grey-500">Nothing to show right now.</p>
                            ) : (
                                notifications.map((n) => (
                                    <button
                                        key={n.id}
                                        onClick={() => goToIncident(n)}
                                        className="w-full text-left px-4 py-2.5 border-b border-grey-100 last:border-0 hover:bg-grey-50 transition-colors"
                                    >
                                        <div className="flex items-center gap-1.5 mb-0.5">
                                            <span className={`w-1.5 h-1.5 rounded-full ${n.severity === 'high' ? 'bg-red' : 'bg-amber'}`} />
                                            <span className="text-xs font-bold text-grey-800 truncate">{n.title}</span>
                                        </div>
                                        <p className="text-[11px] text-grey-500 truncate">{n.message}</p>
                                        <p className="text-[10px] text-grey-300 mt-0.5">{timeAgo(n.time)}</p>
                                    </button>
                                ))
                            )}
                        </div>
                    )}
                </div>
                <UserMenu initials={initials} name={name} email={email} role={role} onSignOut={onSignOut} settingsHref={settingsHref} />
            </div>
        </header>
    );
}
