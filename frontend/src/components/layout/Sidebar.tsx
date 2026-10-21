'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { ChevronRight, LogOut, type LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Logo } from '@/components/shared/Logo';

// Every role this app's nav ever branches on. Kept in sync with backend/src/middleware/auth.ts's
// UserRole — the client portal's nav never sets `roles` on any item, so this union being wider
// than what ClientSidebar uses is harmless there.
export type NavRole = 'super_admin' | 'soc_manager' | 'analyst' | 'executive' | 'portal_user';

export interface NavItem {
    label: string;
    href: string;
    icon: LucideIcon;
    // Hidden unless user.role === 'super_admin'. Only meaningful in the admin portal today —
    // the client portal's nav has no such role tier.
    adminOnly?: boolean;
    // Hidden unless user.role is 'super_admin' or 'soc_manager' — for items a manager should
    // see but a plain analyst shouldn't (e.g. Platform Health). Weaker than adminOnly, and the
    // two are mutually exclusive in practice (an adminOnly item ignores this either way, since
    // the adminOnly check below is checked first and is strictly narrower).
    managerOnly?: boolean;
    // General allow-list for the 4-tier admin role matrix (super_admin/soc_manager/analyst/
    // executive) — used where adminOnly/managerOnly's two-tier model can't express the required
    // visibility (e.g. "everyone except executive", or "analyst but not executive"). Omit to
    // show the item to every authenticated role; when present, ANDed with adminOnly/managerOnly
    // if those are also set (they aren't, on any item that sets `roles`, in practice).
    roles?: NavRole[];
    // Other route prefixes that belong to this item (its sub-pages), so it stays highlighted there.
    match?: string[];
}

/** Whether `item` is the current page: its own route, or one of its sub-page prefixes. */
export const isNavItemActive = (item: NavItem, pathname: string) =>
    pathname === item.href || !!item.match?.some((p) => pathname === p || pathname.startsWith(`${p}/`));

export interface NavGroup {
    section: string;
    items: NavItem[];
    collapsible: boolean;
    icon?: LucideIcon;
    groupLabel?: string;
}

interface SidebarProps {
    navGroups: NavGroup[];
    user: { name: string; email: string; role: string };
    onLogout: () => void;
    /** Below the lg breakpoint the sidebar is off-canvas: shown while mobileOpen, closed by onClose. */
    mobileOpen?: boolean;
    onClose?: () => void;
}

const STORAGE_KEY = 'sidebar_collapsed';

export function Sidebar({ navGroups, user, onLogout, mobileOpen = false, onClose }: SidebarProps) {
    const pathname = usePathname();

    // Drop adminOnly items for anyone who isn't a super_admin, and managerOnly items for anyone
    // who isn't a super_admin or soc_manager, then drop any group left with no items at all (a
    // group whose items were entirely filtered out would otherwise render as an empty,
    // uselessly-clickable accordion header).
    const isAdmin = user.role === 'super_admin';
    const isManagerOrAbove = isAdmin || user.role === 'soc_manager';
    const visibleGroups = navGroups
        .map((group) => ({
            ...group,
            items: group.items.filter(
                (item) =>
                    (!item.adminOnly || isAdmin) &&
                    (!item.managerOnly || isManagerOrAbove) &&
                    (!item.roles || item.roles.includes(user.role as NavRole))
            ),
        }))
        .filter((group) => group.items.length > 0);

    // Independently toggleable per section (not a single-open accordion) and persisted, so a
    // reload doesn't collapse every section the user had open. Stores which sections are
    // OPEN (not "collapsed", despite the storage key name inherited from the original ask) —
    // true where the section is open, false/absent where it's closed.
    const [openSections, setOpenSections] = useState<Record<string, boolean>>({});
    const [hydrated, setHydrated] = useState(false);

    useEffect(() => {
        let stored: Record<string, boolean> = {};
        try {
            stored = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
        } catch {
            stored = {};
        }
        // First load ever (nothing in storage): default-open whichever section contains the
        // current route, matching the old accordion's "auto-expand where you are" behavior.
        if (Object.keys(stored).length === 0) {
            for (const group of visibleGroups) {
                if (group.collapsible && group.items.some((item) => pathname.startsWith(item.href) || isNavItemActive(item, pathname))) {
                    stored = { [group.section]: true };
                    break;
                }
            }
        }
        // localStorage doesn't exist during SSR, so this can't be a lazy useState initializer
        // (the usual way to avoid a synchronous setState-in-effect) — reading a browser-only
        // API that's genuinely unavailable on the server is one of the few legitimate uses of
        // this pattern, not the "derived state" anti-pattern the rule is written to catch.
        // eslint-disable-next-line react-hooks/set-state-in-effect
        setOpenSections(stored);
        setHydrated(true);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    const toggleSection = (section: string) => {
        setOpenSections((prev) => {
            const next = { ...prev, [section]: !prev[section] };
            try {
                localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
            } catch {
                // localStorage unavailable (private mode, quota) — state still updates in-memory
            }
            return next;
        });
    };

    const initials = user.name.split(' ').map((n) => n[0]).join('').toUpperCase().slice(0, 2);

    return (
        <>
        {mobileOpen && <div className="fixed inset-0 z-40 bg-black/40 lg:hidden" onClick={onClose} aria-hidden />}
        <aside
            id="app-sidebar"
            className={cn(
                'w-[260px] h-screen bg-white border-r border-border text-foreground flex flex-col fixed left-0 top-0 z-50 transition-transform duration-200 lg:translate-x-0',
                mobileOpen ? 'translate-x-0 shadow-2xl' : '-translate-x-full',
            )}
        >
            {/* Logo */}
            <div className="flex-shrink-0 px-6 py-5 border-b border-border">
                <Logo size="md" />
            </div>

            {/* Nav */}
            <nav className="flex-1 overflow-y-auto py-4 px-3 scrollbar-thin">
                {visibleGroups.map((group, gi) => (
                    <div key={gi}>
                        {gi > 0 && group.section && <div className="border-t border-border my-3 mx-1" />}

                        {!group.collapsible &&
                            group.items.map((item) => {
                                const Icon = item.icon;
                                const isActive = isNavItemActive(item, pathname);
                                return (
                                    <Link
                                        key={item.href}
                                        href={item.href}
                                        onClick={onClose}
                                        className={cn(
                                            'flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm mb-1 transition-colors',
                                            isActive
                                                ? 'bg-purple text-white font-semibold'
                                                : 'text-foreground-muted hover:text-purple hover:bg-[#F5F0FF]'
                                        )}
                                    >
                                        <Icon size={18} />
                                        {item.label}
                                    </Link>
                                );
                            })}

                        {group.collapsible && (
                            <>
                                {/* The section label IS the accordion trigger — no separate button row */}
                                {group.section && (
                                    <button
                                        onClick={() => toggleSection(group.section)}
                                        className="w-full flex items-center justify-between px-4 py-2 mt-3 group"
                                    >
                                        <span className="text-foreground-muted text-[9px] font-bold uppercase tracking-widest">
                                            {group.section}
                                        </span>
                                        <ChevronRight
                                            size={14}
                                            className={cn('text-foreground-muted transition-transform duration-200', hydrated && openSections[group.section] && 'rotate-90')}
                                        />
                                    </button>
                                )}

                                {hydrated && openSections[group.section] && (
                                    <div className="mt-1 mb-2">
                                        {group.items.map((item) => {
                                            const Icon = item.icon;
                                            const isActive = isNavItemActive(item, pathname);
                                            return (
                                                <Link
                                                    key={item.href}
                                                    href={item.href}
                                                    onClick={onClose}
                                                    className={cn(
                                                        'flex items-center gap-3 pl-8 pr-4 py-2 rounded-lg text-sm transition-colors',
                                                        isActive ? 'text-white font-medium bg-purple' : 'text-foreground-muted hover:text-purple hover:bg-[#F5F0FF]'
                                                    )}
                                                >
                                                    <Icon size={16} />
                                                    {item.label}
                                                </Link>
                                            );
                                        })}
                                    </div>
                                )}
                            </>
                        )}
                    </div>
                ))}
            </nav>

            {/* User footer */}
            <div className="flex-shrink-0 border-t border-border px-4 py-4 flex items-center gap-3">
                <div className="w-8 h-8 rounded-full bg-purple text-white text-xs font-bold flex items-center justify-center flex-shrink-0">
                    {initials}
                </div>
                <div className="flex-1 min-w-0">
                    <div className="text-sm font-semibold text-foreground truncate">{user.name}</div>
                    <div className="text-xs text-foreground-muted truncate">{user.role}</div>
                </div>
                <button onClick={onLogout} className="text-foreground-muted hover:text-red-500 transition-colors" aria-label="Sign out">
                    <LogOut size={16} />
                </button>
            </div>
        </aside>
        </>
    );
}
