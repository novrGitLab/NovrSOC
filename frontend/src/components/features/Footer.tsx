import Link from 'next/link';

const FOOTER_COLS: { title: string; links: { label: string; href: string }[] }[] = [
    {
        title: 'Platform',
        links: [
            { label: 'Vulnerability Management', href: '/vms' },
            { label: 'Threat Exposure Management', href: '/vms#tem' },
            { label: 'Security Operations / Open XDR', href: '/secops' },
            { label: 'Threat Intelligence & Sharing', href: '/ti' },
            { label: 'CNII Watch', href: '/cnii' },
            { label: 'GRC & Reporting', href: '/grc' },
        ],
    },
    {
        title: "Who it's for",
        links: [
            { label: 'CERTs & Sectoral CSIRTs', href: '/cert-csirt' },
            { label: 'Regulators', href: '/regulators' },
            { label: 'MSSPs', href: '/solutions#mssps' },
            { label: 'Enterprises & CNII Operators', href: '/solutions#enterprises' },
        ],
    },
    {
        title: 'Company',
        links: [
            { label: 'About', href: '/about' },
            { label: 'Contact', href: '/contact' },
            { label: 'Trust', href: '/trust' },
            { label: 'Integrations', href: '/integrations' },
        ],
    },
];

export function Footer() {
    return (
        <footer className="py-12 bg-[#05070f] border-t border-white/10">
            <div className="max-w-7xl mx-auto px-6">
                <div className="grid grid-cols-2 md:grid-cols-5 gap-8 mb-10">
                    <div className="col-span-2">
                        {/* eslint-disable-next-line @next/next/no-img-element -- fixed small brand mark */}
                        <img src="/novrsoc.jpg" alt="NovrSOC by Cybernovr" className="h-8 w-auto object-contain rounded mb-4" />
                        <p className="text-xs text-white/40 leading-relaxed max-w-xs">
                            Novr VTEM — a connected Vulnerability &amp; Threat Exposure Management / Open XDR platform for
                            MSSPs, CERTs, sectoral CSIRTs, regulators and CNII operators.
                        </p>
                        <div className="flex items-center gap-3 mt-4">
                            {/* The ISO 27001 badge previously here (and on the homepage) named a specific
                                certificate number and expiry date that nothing in this repository or its
                                records substantiates. Removed rather than carried forward — see /trust for
                                what is actually confirmed about how the platform is run and secured. */}
                            <div className="flex items-center gap-1.5 bg-white/5 border border-white/10 rounded-xl px-3 py-2">
                                <span className="text-base">🇳🇬</span>
                                <div className="text-[9px] text-white/60 font-bold">Lagos, Nigeria</div>
                            </div>
                        </div>
                    </div>

                    {FOOTER_COLS.map((col) => (
                        <div key={col.title}>
                            <div className="text-xs font-bold text-white/60 uppercase tracking-widest mb-4">{col.title}</div>
                            <ul className="space-y-2.5">
                                {col.links.map((link) => (
                                    <li key={link.href}>
                                        <Link href={link.href} className="text-xs text-white/40 hover:text-sky-300 transition-colors">
                                            {link.label}
                                        </Link>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    ))}

                    <div>
                        <div className="text-xs font-bold text-white/60 uppercase tracking-widest mb-4">Connect</div>
                        <ul className="space-y-2.5">
                            <li>
                                <a href="mailto:soc@cybernovr.com" className="text-xs text-white/40 hover:text-sky-300 transition-colors">
                                    soc@cybernovr.com
                                </a>
                            </li>
                            <li>
                                <Link href="/contact" className="text-xs text-white/40 hover:text-sky-300 transition-colors">
                                    Request a consultation
                                </Link>
                            </li>
                            <li>
                                <Link href="/login" className="text-xs text-white/40 hover:text-sky-300 transition-colors">
                                    Sign in
                                </Link>
                            </li>
                        </ul>
                    </div>
                </div>

                <div className="border-t border-white/10 pt-8 flex flex-col md:flex-row items-center justify-between gap-4">
                    <div className="text-xs text-white/25">
                        © {new Date().getFullYear()} NovrSOC by Cybernovr. All rights reserved.
                    </div>
                    <div className="flex gap-6 flex-wrap justify-center">
                        <Link href="/privacy" className="text-xs text-white/25 hover:text-white/60 transition-colors">Privacy Policy</Link>
                        <Link href="/terms" className="text-xs text-white/25 hover:text-white/60 transition-colors">Terms of Service</Link>
                        <Link href="/trust" className="text-xs text-white/25 hover:text-white/60 transition-colors">Security</Link>
                    </div>
                </div>
            </div>
        </footer>
    );
}
