import Link from 'next/link';

const FOOTER_COLS: { title: string; links: { label: string; href: string }[] }[] = [
    {
        title: 'Platform',
        links: [
            { label: 'Vulnerability Management', href: '/vms' },
            { label: 'Threat Exposure Management', href: '/vms#tem' },
            { label: 'Detection & Response', href: '/secops' },
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
        <footer className="py-12 bg-gray-950 border-t border-white/5">
            <div className="max-w-7xl mx-auto px-6">
                <div className="grid grid-cols-2 md:grid-cols-5 gap-8 mb-10">
                    <div className="col-span-2">
                        {/* eslint-disable-next-line @next/next/no-img-element -- fixed small brand mark */}
                        <img src="/novrsoc.jpg" alt="NovrSOC by Cybernovr" className="h-8 w-auto object-contain mb-4" />
                        <p className="text-xs text-white/40 leading-relaxed max-w-xs">
                            A connected VTEM / Open XDR platform for CERTs, sectoral CSIRTs, regulators and CNII operators.
                        </p>
                        <div className="flex items-center gap-3 mt-4">
                            {/* ISO Badge */}
                            <div className="flex items-center gap-2 bg-white/5 border border-white/10 rounded-xl px-3 py-2">
                                <div className="w-8 h-8 rounded-full border-2 border-purple-400 flex items-center justify-center bg-transparent flex-shrink-0">
                                    <div className="text-center">
                                        <div className="text-purple-400 text-[7px] font-black leading-none">ISO</div>
                                        <div className="text-purple-400 text-[8px] font-black leading-none">27001</div>
                                    </div>
                                </div>
                                <div>
                                    <div className="text-[9px] text-white/60 font-bold">ISO 27001:2022</div>
                                    <div className="text-[8px] text-white/30">Certified ISMS</div>
                                </div>
                            </div>

                            {/* Nigeria flag indicator -- TODO: add real CAC/RC registration number once confirmed */}
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
                                        <Link href={link.href} className="text-xs text-white/30 hover:text-white/70 transition-colors">
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
                                <a href="mailto:soc@cybernovr.com" className="text-xs text-white/30 hover:text-white/70 transition-colors">
                                    soc@cybernovr.com
                                </a>
                            </li>
                            <li>
                                <Link href="/contact" className="text-xs text-white/30 hover:text-white/70 transition-colors">
                                    Request a consultation
                                </Link>
                            </li>
                        </ul>
                    </div>
                </div>

                <div className="border-t border-white/5 pt-8 flex flex-col md:flex-row items-center justify-between gap-4">
                    <div className="text-xs text-white/25">
                        © {new Date().getFullYear()} NovrSOC by Cybernovr. All rights reserved.
                    </div>
                    <div className="flex gap-6 flex-wrap justify-center">
                        {['Privacy Policy', 'Terms of Service', 'Security Policy', 'Cookie Policy'].map((link) => (
                            <a key={link} href="#" className="text-xs text-white/25 hover:text-white/50 transition-colors">{link}</a>
                        ))}
                    </div>
                </div>
            </div>
        </footer>
    );
}
