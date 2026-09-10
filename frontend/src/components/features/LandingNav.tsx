'use client';

import { useState } from 'react';
import Link from 'next/link';

// Nav for the marketing landing page. This is the ONLY interactive part of the header — it's a
// separate client component purely so app/page.tsx can stay a server component (see
// HomepageScanner's header comment for the same reasoning: the landing page is ~700 lines of
// static marketing content, and marking the whole file 'use client' to hold one boolean would
// ship all of it to the browser for nothing).

const NAV_LINKS: [string, string][] = [
    ['#features', 'Features'],
    ['#solutions', 'Solutions'],
    ['#compliance', 'Compliance'],
    ['#pricing', 'Pricing'],
];

export function LandingNav() {
    const [menuOpen, setMenuOpen] = useState(false);

    return (
        <nav className="fixed top-0 w-full z-50 bg-white/95 backdrop-blur-sm border-b border-gray-100">
            <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
                {/* novrsoc.jpg is the full wordmark — "NOVRSOC" and "by CYBERNOVR" are baked into
                    the image itself, so it gets its natural aspect ratio (h-9 w-auto) and no
                    text label beside it. Constraining it to a square would squash the wordmark,
                    and a sibling <div>NovrSOC</div> would render the brand name twice. */}
                {/* eslint-disable-next-line @next/next/no-img-element -- fixed small brand mark */}
                <img src="/novrsoc.jpg" alt="NovrSOC by Cybernovr" className="h-9 w-auto object-contain" />

                <div className="hidden md:flex items-center gap-8">
                    {NAV_LINKS.map(([href, label]) => (
                        <a key={href} href={href}
                            className="text-sm text-gray-500 hover:text-purple-700 font-medium transition-colors">
                            {label}
                        </a>
                    ))}
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
                <div className="md:hidden border-t border-gray-100 bg-white px-6 py-4 space-y-3">
                    {NAV_LINKS.map(([href, label]) => (
                        <a key={href} href={href} onClick={() => setMenuOpen(false)}
                            className="block text-sm text-gray-600 font-medium">
                            {label}
                        </a>
                    ))}
                    <Link href="/login" className="block text-sm font-bold text-purple-700">Sign In →</Link>
                </div>
            )}
        </nav>
    );
}
