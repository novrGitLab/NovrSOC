import type { Metadata } from 'next';
import { LandingNav } from '@/components/features/LandingNav';
import { Footer } from '@/components/features/Footer';
import { PageHero } from '@/components/features/PageHero';
import { RelatedLinks } from '@/components/features/RelatedLinks';
import { CTABand } from '@/components/features/CTABand';

export const metadata: Metadata = {
    title: 'Platform | NovrSOC by Cybernovr',
    description: 'NovrSOC is a Managed Security Service Provider (MSSP) platform for Vulnerability, Threat & Exposure Management (VTEM) — nine connected capabilities in one correlated view.',
};

const FEATURES = [
    {
        icon: '🛡️', tag: 'LIVE', tagColor: 'bg-purple-50 text-purple-600',
        title: 'Real-Time Threat Detection',
        desc: 'SIEM monitoring correlates every endpoint around the clock against tens of thousands of detection rules, with MITRE ATT&CK mapping on every alert and automatic case creation for anything that matters.',
        items: ['SSH brute-force detection', 'Malware behavioural analysis', 'Lateral movement tracking'],
    },
    {
        icon: '⚡', tag: 'LIVE', tagColor: 'bg-purple-50 text-purple-600',
        title: 'SOAR Automation',
        desc: 'A tiered response pipeline: low-severity alerts enrich and auto-close; mid-tier alerts trigger a recommended containment action — such as blocking the source IP — that runs under a pre-approved policy or waits for analyst approval, configurable per tenant; critical alerts escalate to the CISO.',
        items: ['Automatic case creation', 'Policy-gated or analyst-approved containment', 'CISO escalation on critical alerts'],
    },
    {
        icon: '🇳🇬', tag: 'LIVE', tagColor: 'bg-purple-50 text-purple-600',
        title: 'Nigerian Threat Intelligence',
        desc: 'A live threat heatmap across all 36 states and the FCT, built on real scanning telemetry, with ngCERT, NCC-CSIRT and CBN advisory integration.',
        items: ['Live Nigerian ASN telemetry', 'ngCERT advisory feed', 'State-level threat heatmap'],
    },
    {
        icon: '🔍', tag: 'LIVE', tagColor: 'bg-purple-50 text-purple-600',
        title: 'Multi-Source CTI Platform',
        desc: 'Enrich any IP, domain, hash or URL across nine intelligence sources at once, with cached results and STIX 2.1 export for sharing with partners and regulators.',
        items: ['9 simultaneous sources', 'STIX 2.1 export', 'IOC history and caching'],
    },
    {
        icon: '🏢', tag: 'LIVE', tagColor: 'bg-purple-50 text-purple-600',
        title: 'Brand Protection Suite',
        desc: 'Monitor domains, social media, app stores and code repositories. Detect typosquatting, impersonation and credential leaks in real time.',
        items: ['Domain lookalike detection', 'Executive breach monitoring', 'Source code leak scanning'],
    },
    {
        icon: '📧', tag: 'LIVE', tagColor: 'bg-purple-50 text-purple-600',
        title: 'Email Security',
        desc: 'DMARC, SPF and DKIM monitoring, AI-assisted phishing detection, real-time blocklist checking and full email header analysis.',
        items: ['DMARC / SPF / DKIM checks', 'AI phishing classifier', 'Real-time blocklist checking'],
    },
    {
        icon: '🤖', tag: 'AI', tagColor: 'bg-purple-100 text-purple-700',
        title: 'NovrAI Security Analyst',
        desc: 'An AI security analyst on call around the clock, grounded in your live platform data rather than generic advice.',
        items: ['Case triage guidance', 'MITRE technique mapping', 'Compliance Q&A (NDPA / CBN)'],
    },
    {
        icon: '✅', tag: 'LIVE', tagColor: 'bg-purple-50 text-purple-600',
        title: 'Nigerian Compliance',
        desc: 'Track NDPA, the CBN Cybersecurity Framework, NCC, ISO/IEC 27001 and PCI-DSS. Auto-generate evidence reports for auditors.',
        items: ['5 compliance frameworks', 'Control-level assessment', 'Auditor evidence export'],
        // TODO: flyer claims "tens of international standards" -- reconcile to one true number
    },
    {
        icon: '🏬', tag: 'BETA', tagColor: 'bg-amber-100 text-amber-700',
        title: 'MSSP Multi-Tenancy',
        desc: 'Manage multiple client organisations from one dashboard, with per-org data isolation and role-based access across admin, SOC manager, analyst and executive roles.',
        items: ['Per-org data isolation', 'Guided client onboarding', 'Role-based navigation'],
        // TODO: confirm multi-tier tenancy status -- flyer markets it as core. Remove BETA only when true.
    },
];

const CYCLE = [
    { title: 'See', desc: 'Understand assets, exposure and security signals.' },
    { title: 'Prioritise', desc: 'Bring evidence and threat context into risk decisions.' },
    { title: 'Act', desc: 'Manage remediation and governed response workflows.' },
    { title: 'Communicate', desc: 'Share role-aware operational and executive insights.' },
];

export default function PlatformPage() {
    return (
        <div className="min-h-screen bg-white font-sans">
            <LandingNav />
            <PageHero
                breadcrumb="Platform"
                eyebrow="Introducing NovrSOC"
                title="One platform. Four connected security disciplines."
                description="NovrSOC is a Managed Security Service Provider (MSSP) platform for Vulnerability, Threat & Exposure Management (VTEM) — connecting assets, findings, intelligence, cases and response workflows so your team can detect, respond and protect with confidence."
            />

            <section id="features" className="py-20">
                <div className="max-w-7xl mx-auto px-6">
                    <div className="text-center mb-14">
                        <h2 className="text-4xl md:text-5xl font-black text-gray-900 mb-4">
                            Everything your SOC needs, in one platform.
                        </h2>
                        <p className="text-gray-500 text-lg max-w-2xl mx-auto">
                            Nine connected capabilities working as one system, not nine disconnected tools.
                        </p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                        {FEATURES.map((f) => (
                            <div key={f.title}
                                className="bg-white border border-gray-100 rounded-2xl p-6 hover:border-purple-200 hover:shadow-lg transition-all">
                                <div className="flex items-start justify-between mb-4">
                                    <span className="text-3xl">{f.icon}</span>
                                    <span className={`text-[9px] font-black px-2.5 py-1 rounded-full ${f.tagColor}`}>
                                        {f.tag}
                                    </span>
                                </div>
                                <h3 className="font-black text-gray-900 mb-2 text-lg">{f.title}</h3>
                                <p className="text-sm text-gray-500 leading-relaxed mb-4">{f.desc}</p>
                                <ul className="space-y-1.5">
                                    {f.items.map((item) => (
                                        <li key={item} className="flex items-center gap-2 text-xs text-gray-600">
                                            <div className="w-1.5 h-1.5 rounded-full bg-purple-400 flex-shrink-0" />
                                            {item}
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            <section className="py-20 bg-gray-50 border-y border-gray-100">
                <div className="max-w-7xl mx-auto px-6 grid md:grid-cols-2 gap-16 items-center">
                    <div>
                        <div className="inline-flex items-center gap-2 bg-purple-100 border border-purple-200 rounded-full px-4 py-2 mb-6">
                            <span className="text-purple-700 text-xs font-bold">Built for operations</span>
                        </div>
                        <h2 className="text-3xl md:text-4xl font-black text-gray-900 mb-4">
                            Built around the full decision cycle
                        </h2>
                        <p className="text-gray-500 mb-2 leading-relaxed">
                            NovrSOC aims to connect discovery, monitoring, intelligence and response without losing context.
                        </p>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                        {CYCLE.map((c) => (
                            <div key={c.title} className="bg-white border border-gray-100 rounded-2xl p-5">
                                <h4 className="font-black text-gray-900 mb-1">{c.title}</h4>
                                <p className="text-xs text-gray-500 leading-relaxed">{c.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            <RelatedLinks
                items={[
                    { href: '/cnii', title: 'CNII Watch', desc: 'Sector-aware visibility across IT and OT for critical national infrastructure.' },
                    { href: '/vms', title: 'Vulnerability Management', desc: 'Discover, scan and prioritise exposure across your estate.' },
                    { href: '/secops', title: 'Detection & Response', desc: 'SIEM, UEBA, NDR, IDS, malware analysis and SOAR as one pipeline.' },
                ]}
            />

            <CTABand text="Explore how NovrSOC by Cybernovr can connect your security operations." />
            <Footer />
        </div>
    );
}
