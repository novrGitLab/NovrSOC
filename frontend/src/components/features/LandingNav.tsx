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
            { label: 'Detection & Response', href: '/secops' },
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
            { label: 'Pricing', href: '/#pricing' },
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
        <nav className="fixed top-0 w-full z-50 bg-white/95 backdrop-blur-sm border-b border-gray-100">
            <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
                {/* novrsoc.jpg is the full wordmark -- see HomepageScanner's header comment for why
                    this stays a plain <img> with its natural aspect ratio. */}
                {/* eslint-disable-next-line @next/next/no-img-element -- fixed small brand mark */}
                <Link href="/" aria-label="NovrSOC home">
                    <img src="/novrsoc.jpg" alt="NovrSOC by Cybernovr" className="h-9 w-auto object-contain" />
                </Link>

                <div className="hidden md:flex items-center gap-7">
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
                                    className="flex items-center gap-1 text-sm text-gray-500 hover:text-purple-700 font-medium transition-colors"
                                    aria-expanded={openDropdown === item.label}
                                >
                                    {item.label}
                                    <Chevron open={openDropdown === item.label} />
                                </button>
                                {openDropdown === item.label && (
                                    <div className="absolute top-full left-0 pt-3">
                                        <div className="min-w-[250px] bg-white border border-gray-100 rounded-xl shadow-lg p-2 flex flex-col gap-0.5">
                                            {item.children.map((c) => (
                                                <a
                                                    key={c.href}
                                                    href={c.href}
                                                    target={c.external ? '_blank' : undefined}
                                                    rel={c.external ? 'noopener' : undefined}
                                                    className="px-3 py-2.5 rounded-lg text-sm font-semibold text-gray-700 hover:bg-purple-50 hover:text-purple-700 transition-colors whitespace-nowrap"
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
                                className="text-sm text-gray-500 hover:text-purple-700 font-medium transition-colors"
                            >
                                {item.label}
                            </Link>
                        )
                    )}
                </div>

                <div className="flex items-center gap-3">
                    <Link href="/login" className="hidden md:block text-sm font-semibold text-purple-700 hover:underline">
                        Sign In
                    </Link>
                    <Link href="/login"
                        className="bg-purple-700 text-white text-sm font-bold px-5 py-2.5 rounded-xl hover:bg-purple-800 transition-colors shadow-sm">
                        Request Demo
                    </Link>
                    <button className="md:hidden p-2" onClick={() => setMenuOpen(!menuOpen)}
                        aria-label={menuOpen ? 'Close menu' : 'Open menu'} aria-expanded={menuOpen}>
                        <div className="w-5 h-0.5 bg-gray-600 mb-1" />
                        <div className="w-5 h-0.5 bg-gray-600 mb-1" />
                        <div className="w-5 h-0.5 bg-gray-600" />
                    </button>
                </div>
            </div>

            {menuOpen && (
                <div className="md:hidden border-t border-gray-100 bg-white px-6 py-4 space-y-1 max-h-[75vh] overflow-y-auto">
                    {NAV_ITEMS.map((item) =>
                        item.children ? (
                            <details key={item.label} className="group">
                                <summary className="list-none flex items-center justify-between py-3 text-sm font-bold text-gray-700 cursor-pointer">
                                    {item.label}
                                    <span className="group-open:rotate-180 transition-transform">
                                        <Chevron open={false} />
                                    </span>
                                </summary>
                                <div className="pl-3 pb-2 flex flex-col gap-1">
                                    {item.children.map((c) => (
                                        <a key={c.href} href={c.href} onClick={() => setMenuOpen(false)}
                                            className="py-2 text-sm text-gray-600 font-medium">
                                            {c.label}
                                        </a>
                                    ))}
                                </div>
                            </details>
                        ) : (
                            <Link key={item.href} href={item.href!} onClick={() => setMenuOpen(false)}
                                className="block py-3 text-sm font-bold text-gray-700">
                                {item.label}
                            </Link>
                        )
                    )}
                    <Link href="/login" className="block text-sm font-bold text-purple-700 pt-2">Sign In →</Link>
                </div>
            )}
        </nav>
    );
}
