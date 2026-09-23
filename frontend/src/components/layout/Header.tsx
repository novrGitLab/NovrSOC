'use client';

import { useEffect, useRef, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { Search, Bell, Sun, Moon } from 'lucide-react';
import { Logo } from '@/components/shared/Logo';
import { useTheme } from '@/components/providers/ThemeProvider';
import { apiUrl, apiFetch } from '@/lib/api';

interface HeaderProps {
    initials: string;
    onSignOut: () => void;
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

function humanizePathname(pathname: string): string {
    if (pathname.endsWith('/dashboard')) return 'General';
    const last = pathname.split('/').filter(Boolean).pop() ?? '';
    return last
        .split('-')
        .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
        .join(' ');
}

function timeAgo(iso: string): string {
    const mins = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 60000));
    if (mins < 1) return 'Just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    return `${hrs}h ago`;
}

export function Header({ initials, onSignOut }: HeaderProps) {
    const pathname = usePathname();
    const router = useRouter();
    const pageTitle = humanizePathname(pathname);
    const { resolvedTheme, setTheme } = useTheme();
    const isDark = resolvedTheme === 'dark';

    const [notifications, setNotifications] = useState<Notification[]>([]);
    const [open, setOpen] = useState(false);
    // No per-user read-state on the backend (no per-user accounts to key it to yet — see
    // lib/mockTeam.ts's header comment) — "read" is tracked client-side only, per browser, and
    // resets on reload. Opening the dropdown marks whatever's currently loaded as seen; a
    // notification that's genuinely new on the next poll still counts toward the badge.
    const seenIds = useRef<Set<string>>(new Set());
    const panelRef = useRef<HTMLDivElement>(null);

    const load = () => {
        apiFetch(apiUrl('/api/notifications'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => setNotifications(Array.isArray(data?.notifications) ? data.notifications : []))
            .catch(() => {});
    };

    useEffect(() => {
        load();
        const interval = setInterval(load, 60000);
        return () => clearInterval(interval);
    }, []);

    useEffect(() => {
        if (!open) return;
        const handleClick = (e: MouseEvent) => {
            if (panelRef.current && !panelRef.current.contains(e.target as Node)) setOpen(false);
        };
        document.addEventListener('mousedown', handleClick);
        return () => document.removeEventListener('mousedown', handleClick);
    }, [open]);

    const unreadCount = notifications.filter((n) => !seenIds.current.has(n.id)).length;

    const toggleOpen = () => {
        setOpen((v) => {
            const next = !v;
            if (next) notifications.forEach((n) => seenIds.current.add(n.id));
            return next;
        });
    };

    const goToIncident = (n: Notification) => {
        setOpen(false);
        // Admin and client portal both have a SecOps cases page, just under different
        // prefixes — route to whichever one this session is actually in.
        const base = pathname.startsWith('/client') ? '/client' : '/admin';
        router.push(n.type === 'case' ? `${base}/secops/cases` : `${base}/secops/alerts`);
    };

    return (
        <header className="h-14 bg-white border-b border-grey-100 flex items-center gap-4 px-6 sticky top-0 z-30 w-full">
            {/* Left */}
            <div className="flex items-center gap-2 min-w-fit">
                <Logo size="sm" />
                <span className="text-grey-300">/</span>
                <span className="text-sm text-grey-500">{pageTitle}</span>
            </div>

            {/* Center — search */}
            <div className="flex-1 flex justify-center">
                <div className="relative w-full max-w-[480px]">
                    <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-grey-500" />
                    <input
                        type="text"
                        placeholder="Search incidents, alerts, assets, threats..."
                        className="w-full bg-grey-50 border border-grey-100 rounded-lg pl-9 pr-16 py-2 text-sm text-grey-800 placeholder:text-grey-500 focus:outline-none focus:border-blue focus:ring-1 focus:ring-blue/20"
                    />
                    <kbd className="absolute right-3 top-1/2 -translate-y-1/2 border border-grey-100 rounded px-1.5 py-0.5 text-xs text-grey-500 font-mono">⌘K</kbd>
                </div>
            </div>

            {/* Right */}
            <div className="flex items-center gap-3 min-w-fit">
                <div className="flex items-center gap-1.5 bg-blue text-white text-xs font-semibold px-3 py-1.5 rounded-full">
                    <span className="w-2 h-2 rounded-full bg-green animate-pulse" />
                    Telemetry Online
                </div>
                <button onClick={onSignOut} className="text-sm text-grey-500 hover:text-red transition-colors">
                    Sign Out
                </button>
                <div className="w-px h-4 bg-grey-100" />
                <div className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-green" />
                    <span className="text-sm text-grey-800">Cloud Node</span>
                </div>
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
                        <div className="absolute right-0 top-full mt-2 w-80 max-h-96 overflow-y-auto scrollbar-thin bg-white border border-grey-100 rounded-xl shadow-lg z-40">
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
                <div className="w-8 h-8 rounded-full bg-purple text-white flex items-center justify-center text-xs font-bold">
                    {initials}
                </div>
            </div>
        </header>
    );
}
