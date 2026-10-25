'use client';

// Header user/account menu (2026 redesign, Stage 1) — replaces the bare "Sign Out" text button
// with a proper menu: who is signed in, their role, and sign out. Settings link only where the
// role can actually reach a settings page (super_admin today; config/nav.ts Settings group).
import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { ChevronDown, LogOut, Settings } from 'lucide-react';

const ROLE_LABEL: Record<string, string> = {
    super_admin: 'Super Admin', soc_manager: 'SOC Manager', analyst: 'Analyst', executive: 'Executive', portal_user: 'Client',
};

export function UserMenu({ initials, name, email, role, onSignOut, settingsHref }: {
    initials: string; name: string; email: string; role: string; onSignOut: () => void; settingsHref?: string;
}) {
    const [open, setOpen] = useState(false);
    const ref = useRef<HTMLDivElement>(null);
    const router = useRouter();

    useEffect(() => {
        if (!open) return;
        const onClick = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
        const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
        document.addEventListener('mousedown', onClick);
        document.addEventListener('keydown', onKey);
        return () => { document.removeEventListener('mousedown', onClick); document.removeEventListener('keydown', onKey); };
    }, [open]);

    return (
        <div className="relative" ref={ref}>
            <button
                onClick={() => setOpen((v) => !v)}
                aria-haspopup="menu"
                aria-expanded={open}
                className="flex items-center gap-1.5 rounded-full hover:bg-grey-50 pr-1 transition-colors outline-none focus-visible:ring-2 focus-visible:ring-blue/60"
            >
                <span className="w-8 h-8 rounded-full bg-purple text-white flex items-center justify-center text-xs font-bold">{initials}</span>
                <ChevronDown size={14} className="text-grey-500 hidden sm:inline" aria-hidden />
            </button>
            {open && (
                <div role="menu" className="absolute right-0 top-full mt-2 w-56 bg-white border border-grey-100 rounded-xl shadow-lg z-40 py-1">
                    <div className="px-3.5 py-2.5 border-b border-grey-100">
                        <p className="text-xs font-bold text-grey-800 truncate">{name || 'Signed in'}</p>
                        {email && <p className="text-[11px] text-grey-500 truncate">{email}</p>}
                        <p className="text-[10px] font-semibold text-purple mt-0.5">{ROLE_LABEL[role] ?? role}</p>
                    </div>
                    {settingsHref && (
                        <button
                            role="menuitem"
                            onClick={() => { setOpen(false); router.push(settingsHref); }}
                            className="w-full flex items-center gap-2 px-3.5 py-2 text-sm text-grey-800 hover:bg-grey-50 transition-colors"
                        >
                            <Settings size={14} className="text-grey-500" aria-hidden /> Settings
                        </button>
                    )}
                    <button
                        role="menuitem"
                        onClick={() => { setOpen(false); onSignOut(); }}
                        className="w-full flex items-center gap-2 px-3.5 py-2 text-sm text-red hover:bg-red/5 transition-colors"
                    >
                        <LogOut size={14} aria-hidden /> Sign Out
                    </button>
                </div>
            )}
        </div>
    );
}
