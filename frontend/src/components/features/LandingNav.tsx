'use client';

import { useState } from 'react';
import Link from 'next/link';

// Site-wide nav for the marketing pages (home + every /platform, /vms, /ti, ... route).
// Dropdowns are plain useState + onMouseEnter/Leave for desktop, <details> for the mobile
// accordion -- no extra UI library, consistent with the rest of this file's original style.

type Child = { label: string; href: string; external?: boolean };
type Item = { label: string; href?: string; children?: Child[] };

const NAV_ITEMS: Item[] = [
    { label: 'Platform', href: '/platform' },
    {
        label: 'Capabilities',
        children: [
            { label: 'Vulnerability Management', href: '/vms' },
            { label: 'Threat Exposure Management', href: '/vms#tem' },
            { label: 'Security Operations / Open XDR', href: '/secops' },
            { label: 'Threat Intelligence & Sharing', href: '/ti' },
            { label: 'CNII Watch (IT + OT)', href: '/cnii' },
            { label: 'GRC & Reporting', href: '/grc' },
        ],
    },
    {
        label: "Who it's for",
        children: [
            { label: 'CERTs & Sectoral CSIRTs', href: '/cert-csirt' },
            { label: 'Regulators', href: '/regulators' },
            { label: 'MSSPs', href: '/solutions#mssps' },
            { label: 'Enterprises & CNII Operators', href: '/solutions#enterprises' },
        ],
    },
    { label: 'Integrations', href: '/integrations' },
    { label: 'Trust', href: '/trust' },
    {
        label: 'Company',
        children: [
            { label: 'About', href: '/about' },
            { label: 'Contact', href: '/contact' },
            { label: 'Novr Academy', href: 'https://novracademy.com', external: true },
        ],
    },
];

function Chevron({ open }: { open: boolean }) {
    return (
        <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5"
            strokeLinecap="round" strokeLinejoin="round"
            className={`transition-transform ${open ? 'rotate-180' : ''}`} aria-hidden="true">
            <path d="M2 3.5L5 6.5L8 3.5" />
        </svg>
    );
}

export function LandingNav() {
    const [menuOpen, setMenuOpen] = useState(false);
    const [openDropdown, setOpenDropdown] = useState<string | null>(null);

    return (
        <nav className="fixed top-0 w-full z-50 bg-[#070b18]/90 backdrop-blur-md border-b border-white/10">
            <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
                {/* novrsoc.jpg is the current Cybernovr wordmark (updated 2026-10-27). */}
                <Link href="/" aria-label="NovrSOC home" className="flex items-center gap-2.5 shrink-0">
                    {/* eslint-disable-next-line @next/next/no-img-element -- fixed small brand mark */}
                    <img src="/novrsoc.jpg" alt="NovrSOC by Cybernovr" className="h-8 w-auto object-contain rounded-md" />
                </Link>

                <div className="hidden lg:flex items-center gap-7">
                    {NAV_ITEMS.map((item) =>
                        item.children ? (
                            <div
                                key={item.label}
                                className="relative"
                                onMouseEnter={() => setOpenDropdown(item.label)}
                                onMouseLeave={() => setOpenDropdown(null)}
                            >
                                <button
                                    type="button"
                                    className="flex items-center gap-1 text-sm text-white/65 hover:text-white font-medium transition-colors"
                                    aria-expanded={openDropdown === item.label}
                                >
                                    {item.label}
                                    <Chevron open={openDropdown === item.label} />
                                </button>
                                {openDropdown === item.label && (
                                    <div className="absolute top-full left-0 pt-3">
                                        <div className="min-w-[260px] bg-[#0c1226] border border-white/10 rounded-xl shadow-2xl shadow-black/40 p-2 flex flex-col gap-0.5">
                                            {item.children.map((c) => (
                                                <a
                                                    key={c.href}
                                                    href={c.href}
                                                    target={c.external ? '_blank' : undefined}
                                                    rel={c.external ? 'noopener' : undefined}
                                                    className="px-3 py-2.5 rounded-lg text-sm font-semibold text-white/75 hover:bg-white/5 hover:text-sky-300 transition-colors whitespace-nowrap"
                                                >
                                                    {c.label}{c.external ? ' ↗' : ''}
                                                </a>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        ) : (
                            <Link
                                key={item.href}
                                href={item.href!}
                                className="text-sm text-white/65 hover:text-white font-medium transition-colors"
                            >
                                {item.label}
                            </Link>
                        )
                    )}
                </div>

                <div className="flex items-center gap-3">
                    <Link href="/login" className="hidden lg:block text-sm font-semibold text-white/75 hover:text-white">
                        Sign In
                    </Link>
                    <Link href="/contact"
                        className="bg-gradient-to-r from-sky-500 to-blue-600 text-white text-sm font-bold px-5 py-2.5 rounded-xl hover:from-sky-400 hover:to-blue-500 transition-all shadow-lg shadow-blue-900/40">
                        Request Demo
                    </Link>
                    <button className="lg:hidden p-2" onClick={() => setMenuOpen(!menuOpen)}
                        aria-label={menuOpen ? 'Close menu' : 'Open menu'} aria-expanded={menuOpen}>
                        <div className="w-5 h-0.5 bg-white/80 mb-1" />
                        <div className="w-5 h-0.5 bg-white/80 mb-1" />
                        <div className="w-5 h-0.5 bg-white/80" />
                    </button>
                </div>
            </div>

            {menuOpen && (
                <div className="lg:hidden border-t border-white/10 bg-[#070b18] px-6 py-4 space-y-1 max-h-[75vh] overflow-y-auto">
                    {NAV_ITEMS.map((item) =>
                        item.children ? (
                            <details key={item.label} className="group">
                                <summary className="list-none flex items-center justify-between py-3 text-sm font-bold text-white/85 cursor-pointer">
                                    {item.label}
                                    <span className="group-open:rotate-180 transition-transform">
                                        <Chevron open={false} />
                                    </span>
                                </summary>
                                <div className="pl-3 pb-2 flex flex-col gap-1">
                                    {item.children.map((c) => (
                                        <a key={c.href} href={c.href} onClick={() => setMenuOpen(false)}
                                            className="py-2 text-sm text-white/60 font-medium">
                                            {c.label}
                                        </a>
                                    ))}
                                </div>
                            </details>
                        ) : (
                            <Link key={item.href} href={item.href!} onClick={() => setMenuOpen(false)}
                                className="block py-3 text-sm font-bold text-white/85">
                                {item.label}
                            </Link>
                        )
                    )}
                    <Link href="/login" className="block text-sm font-bold text-sky-300 pt-2">Sign In →</Link>
                </div>
            )}
        </nav>
    );
}
