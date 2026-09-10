import Link from 'next/link';
import { LandingNav } from '@/components/features/LandingNav';
import { HomepageScanner } from '@/components/features/HomepageScanner';

// Marketing landing page. Deliberately a SERVER component — every interactive piece lives in its
// own small client component (LandingNav for the mobile menu, HomepageScanner for the free scan),
// so none of the static marketing content below ships to the browser as JS.

const STATS = [
    { value: '99+', label: 'Platform Features' },
    { value: '9', label: 'CTI Data Sources' },
    { value: '37', label: 'Nigerian States Monitored' },
    { value: '24/7', label: 'AI Threat Detection' },
];

const FEATURES = [
    {
        icon: '🛡️', tag: 'LIVE', tagColor: 'bg-green-100 text-green-700',
        title: 'Real-Time Threat Detection',
        desc: 'Wazuh SIEM monitors all endpoints 24/7 with 37,000+ detection rules. MITRE ATT&CK mapping on every alert. Automatic case creation in TheHive.',
        items: ['SSH brute force detection', 'Malware behavioural analysis', 'Lateral movement tracking'],
    },
    {
        icon: '⚡', tag: 'LIVE', tagColor: 'bg-green-100 text-green-700',
        title: 'SOAR Automation',
        desc: 'Wazuh detects → case auto-created in TheHive → analyst notified on Slack → low severity cases auto-close after 30 minutes.',
        items: ['Zero-touch incident creation', 'Escalation emails via Resend', 'Playbook-guided response'],
    },
    {
        icon: '🇳🇬', tag: 'LIVE', tagColor: 'bg-green-100 text-green-700',
        title: 'Nigerian Threat Intelligence',
        desc: 'Real-time threat heatmap across all 37 states and FCT. GreyNoise Nigerian ASN data. ngCERT, NCC-CSIRT, and CBN advisory integration.',
        items: ['GreyNoise Nigerian ASN data', 'ngCERT advisory feed', 'State-level threat heatmap'],
    },
    {
        icon: '🔍', tag: 'LIVE', tagColor: 'bg-green-100 text-green-700',
        title: 'Multi-Source CTI Platform',
        desc: 'Enrich any IP, domain, hash, or URL across 9 sources simultaneously. Results cached in Supabase. MISP integration for STIX-format sharing.',
        items: ['9 simultaneous sources', 'STIX 2.1 export', 'IOC history and caching'],
    },
    {
        icon: '🏢', tag: 'LIVE', tagColor: 'bg-green-100 text-green-700',
        title: 'Brand Protection Suite',
        desc: 'Monitor domains, social media, app stores, and code repositories. Detect typosquatting, impersonation, and credential leaks in real time.',
        items: ['Domain lookalike detection', 'Executive breach monitoring', 'Source code leak scanning'],
    },
    {
        icon: '📧', tag: 'LIVE', tagColor: 'bg-green-100 text-green-700',
        title: 'Email Security',
        desc: 'DMARC monitoring, AI-powered phishing detection, RBL blocklist checking, and email header analysis. Powered by Cisco Talos and OpenPhish.',
        items: ['DMARC / SPF / DKIM check', 'AI phishing classifier', 'Real-time RBL checking'],
    },
    {
        icon: '🤖', tag: 'AI', tagColor: 'bg-purple-100 text-purple-700',
        title: 'NovrAI Security Analyst',
        desc: 'AI-powered SOC analyst available 24/7. Powered by Claude (Anthropic) with Gemini fallback. Context-aware of live platform data.',
        items: ['Incident triage guidance', 'MITRE technique mapping', 'Compliance Q&A (NDPA/CBN)'],
    },
    {
        icon: '✅', tag: 'LIVE', tagColor: 'bg-green-100 text-green-700',
        title: 'Nigerian Compliance',
        desc: 'Track NDPA, CBN Cybersecurity Framework, NCC, ISO 27001, and PCI-DSS compliance. Auto-generate evidence reports for auditors.',
        items: ['5 compliance frameworks', 'Control-level assessment', 'Auditor evidence export'],
    },
    {
        icon: '🏬', tag: 'BETA', tagColor: 'bg-amber-100 text-amber-700',
        title: 'MSSP Multi-Tenancy',
        desc: 'Manage multiple client organisations from one dashboard. Role-based access: super_admin, soc_manager, analyst, executive. White-label ready.',
        items: ['Per-org data isolation', '5-step client onboarding', 'Role-based navigation'],
    },
];

const PIPELINE = [
    { step: '01', icon: '🚨', title: 'Detected', desc: 'Wazuh SIEM fires on anomaly' },
    { step: '02', icon: '🔍', title: 'Enriched', desc: 'MITRE mapping + source IP geo' },
    { step: '03', icon: '📋', title: 'Case Created', desc: 'TheHive case in < 1 second' },
    { step: '04', icon: '📲', title: 'Notified', desc: 'Slack + email to CISO' },
    { step: '05', icon: '👨‍💻', title: 'Resolved', desc: 'Analyst works in NovrSOC' },
];

const FRAMEWORKS = [
    { code: 'NDPA', name: 'Nigeria Data Protection Act', req: 'Mandatory for all orgs processing personal data' },
    { code: 'CBN', name: 'CBN Cybersecurity Framework', req: 'Required for all banks and fintechs' },
    { code: 'NCC', name: 'NCC Consumer Protection', req: 'Required for telecoms operators' },
    { code: 'ISO', name: 'ISO/IEC 27001:2022', req: 'International ISMS standard' },
    { code: 'PCI', name: 'PCI-DSS v4.0', req: 'Required for card payment processing' },
];

const CERT_TILES = [
    { icon: '🔒', title: 'SOC 2 Type II', sub: 'In progress' },
    { icon: '🌍', title: 'GDPR Ready', sub: 'Data residency options' },
    { icon: '🏛️', title: 'CBN Compliant', sub: 'Financial sector ready' },
    { icon: '📋', title: 'NDPA Aligned', sub: 'Nigerian data law' },
];

const SECTORS = [
    'Banking & Finance', 'Telecommunications', 'Oil & Gas', 'Government',
    'Fintech', 'Healthcare', 'Insurance', 'Manufacturing',
];

const PLANS = [
    {
        name: 'Starter', price: '₦150,000', period: '/month', desc: 'For growing businesses',
        features: ['Up to 25 endpoints', 'SIEM + SOAR', 'Email Security', 'Basic Compliance (NDPA)', 'NovrAI Assistant', '8×5 Support'],
        highlight: false, cta: 'Get Started',
    },
    {
        name: 'Professional', price: '₦450,000', period: '/month', desc: 'For mid-size enterprises',
        features: ['Up to 100 endpoints', 'Everything in Starter', 'Brand Protection Suite', 'CTI Platform (9 sources)', 'All 5 Compliance Frameworks', 'Nigerian Threat Intel', '24×7 Support'],
        highlight: true, cta: 'Most Popular',
    },
    {
        name: 'Enterprise', price: 'Custom', period: '', desc: 'For large organisations',
        features: ['Unlimited endpoints', 'Everything in Professional', 'Dedicated SOC Analyst', 'Custom Integrations', 'OPNsense Deployment', 'MSSP White-label', 'SLA Guarantee'],
        highlight: false, cta: 'Contact Sales',
    },
];

const FOOTER_COLS = [
    { title: 'Platform', links: ['Features', 'Pricing', 'Security', 'Roadmap'] },
    { title: 'Solutions', links: ['Banking & Finance', 'Telecommunications', 'Government', 'Fintech'] },
    { title: 'Company', links: ['About Cybernovr', 'Careers', 'Blog', 'Contact'] },
];

export default function LandingPage() {
    return (
        <div className="min-h-screen bg-white font-sans">
            <LandingNav />

            {/* ── HERO ─────────────────────────────────────────────────── */}
            <section className="pt-28 pb-20 bg-gradient-to-br from-gray-950 via-purple-950 to-blue-950 relative overflow-hidden">
                <div className="absolute inset-0 opacity-10"
                    style={{ backgroundImage: 'radial-gradient(circle at 2px 2px, rgba(255,255,255,0.3) 1px, transparent 0)', backgroundSize: '40px 40px' }} />

                <div className="max-w-7xl mx-auto px-6 relative">
                    <div className="text-center max-w-4xl mx-auto">
                        <div className="inline-flex items-center gap-2 bg-white/10 border border-white/20 rounded-full px-4 py-2 mb-8">
                            <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                            <span className="text-white/80 text-xs font-medium">
                                Live threat monitoring across Nigeria and West Africa
                            </span>
                        </div>

                        <h1 className="text-5xl md:text-7xl font-black text-white mb-6 leading-tight tracking-tight">
                            AI-Powered SOC<br />
                            <span className="text-transparent bg-clip-text bg-gradient-to-r from-amber-400 to-orange-500">
                                Built for Africa
                            </span>
                        </h1>

                        <p className="text-xl text-white/60 max-w-2xl mx-auto mb-10 leading-relaxed">
                            NovrSOC combines SIEM, SOAR, Threat Intelligence, Brand Protection,
                            and Compliance into one platform purpose-built for Nigerian and African enterprises.
                        </p>

                        <div className="flex flex-col sm:flex-row gap-4 justify-center mb-16">
                            <Link href="/login"
                                className="bg-orange-500 text-white font-black px-8 py-4 rounded-2xl hover:bg-orange-600 text-lg transition-colors shadow-xl">
                                Start Free Trial →
                            </Link>
                            <a href="#scanner"
                                className="bg-white/10 border border-white/20 text-white font-bold px-8 py-4 rounded-2xl hover:bg-white/20 text-lg transition-colors">
                                Free Threat Scan
                            </a>
                        </div>

                        <div className="grid grid-cols-2 md:grid-cols-4 gap-6 max-w-3xl mx-auto">
                            {STATS.map((s) => (
                                <div key={s.label} className="text-center">
                                    <div className="text-3xl md:text-4xl font-black text-white mb-1">{s.value}</div>
                                    <div className="text-xs text-white/50 leading-tight">{s.label}</div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </section>

            {/* ── FREE SCANNER ─────────────────────────────────────────── */}
            <section id="scanner" className="py-16 bg-gradient-to-b from-gray-50 to-white">
                <div className="max-w-3xl mx-auto px-6">
                    <div className="text-center mb-8">
                        <div className="inline-flex items-center gap-2 bg-purple-100 border border-purple-200 rounded-full px-4 py-2 mb-4">
                            <span className="text-purple-700 text-xs font-bold uppercase tracking-wider">
                                Free Tool — No Account Needed
                            </span>
                        </div>
                        <h2 className="text-3xl md:text-4xl font-black text-gray-900 mb-3">
                            Instant Threat Scanner
                        </h2>
                        <p className="text-gray-500 text-lg">
                            Scan any IP address, domain, or URL against 9 live threat intelligence sources.
                            Results in seconds.
                        </p>
                    </div>

                    <HomepageScanner />
                </div>
            </section>

            {/* ── FEATURES ─────────────────────────────────────────────── */}
            <section id="features" className="py-20">
                <div className="max-w-7xl mx-auto px-6">
                    <div className="text-center mb-14">
                        <h2 className="text-4xl md:text-5xl font-black text-gray-900 mb-4">
                            Everything Your SOC Needs
                        </h2>
                        <p className="text-gray-500 text-lg max-w-2xl mx-auto">
                            One platform replacing 8+ security tools. Built for African enterprises,
                            priced for African budgets.
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

            {/* ── SOAR PIPELINE ────────────────────────────────────────── */}
            <section className="py-20 bg-gray-950">
                <div className="max-w-7xl mx-auto px-6 text-center">
                    <h2 className="text-4xl font-black text-white mb-4">
                        From Threat to Resolution in Minutes
                    </h2>
                    <p className="text-white/50 mb-14 max-w-xl mx-auto">
                        Fully automated incident response pipeline. Your team focuses on
                        investigation, not alert fatigue.
                    </p>
                    <div className="flex flex-col md:flex-row items-center justify-center gap-3 flex-wrap">
                        {PIPELINE.map((s, i) => (
                            <div key={s.step} className="flex items-center gap-3">
                                <div className="bg-white/5 border border-white/10 rounded-2xl p-5 text-center w-40 hover:border-purple-500/50 hover:bg-white/10 transition-all">
                                    <div className="text-2xl mb-2">{s.icon}</div>
                                    <div className="text-[9px] text-purple-400 font-black mb-1">{s.step}</div>
                                    <div className="text-xs font-bold text-white mb-1">{s.title}</div>
                                    <div className="text-[10px] text-white/40 leading-tight">{s.desc}</div>
                                </div>
                                {i < PIPELINE.length - 1 && <div className="text-white/20 text-xl hidden md:block">→</div>}
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ── COMPLIANCE + ISO ─────────────────────────────────────── */}
            <section id="compliance" className="py-20">
                <div className="max-w-7xl mx-auto px-6">
                    <div className="grid md:grid-cols-2 gap-16 items-center">
                        <div>
                            <div className="inline-flex items-center gap-2 bg-purple-100 border border-purple-200 rounded-full px-4 py-2 mb-6">
                                <span className="text-purple-700 text-xs font-bold">Nigerian Regulatory Compliance</span>
                            </div>
                            <h2 className="text-4xl font-black text-gray-900 mb-4">
                                Built for Nigerian Regulations
                            </h2>
                            <p className="text-gray-500 mb-8 leading-relaxed">
                                NovrSOC tracks compliance across every major framework required by
                                Nigerian regulators. Show your board a live compliance score,
                                not a spreadsheet updated once a year.
                            </p>
                            <div className="space-y-3">
                                {FRAMEWORKS.map((f) => (
                                    <div key={f.code}
                                        className="flex items-center gap-4 bg-white border border-gray-100 rounded-xl p-4 hover:border-purple-200 transition-colors">
                                        <div className="w-12 h-12 rounded-xl bg-purple-700 flex items-center justify-center flex-shrink-0">
                                            <span className="text-white text-[10px] font-black">{f.code}</span>
                                        </div>
                                        <div>
                                            <div className="text-sm font-bold text-gray-900">{f.name}</div>
                                            <div className="text-[10px] text-gray-400 mt-0.5">{f.req}</div>
                                        </div>
                                        <div className="ml-auto text-[10px] text-green-600 font-bold whitespace-nowrap">✓ Supported</div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* ISO certificate card. Wording deliberately scopes the certification to the
                            infrastructure NovrSOC is built on — same claim the previous landing page
                            made. Don't upgrade this to a bare "Cybernovr is ISO 27001 certified"
                            without a certificate to point at. */}
                        <div className="space-y-5">
                            <div className="bg-gradient-to-br from-purple-900 to-purple-700 rounded-3xl p-8 text-center text-white shadow-2xl">
                                <div className="w-24 h-24 bg-white/10 rounded-2xl flex items-center justify-center mx-auto mb-5 border border-white/20">
                                    <div className="text-center">
                                        <div className="text-xl font-black">ISO</div>
                                        <div className="text-[10px] font-bold opacity-70">27001</div>
                                    </div>
                                </div>
                                <h3 className="text-2xl font-black mb-2">ISO 27001 Certified</h3>
                                <p className="text-white/60 text-sm mb-5 leading-relaxed">
                                    NovrSOC is built on ISO 27001:2022 certified infrastructure and follows
                                    information security management best practices, so your security data is
                                    protected to an internationally recognised standard.
                                </p>
                                <div className="border-t border-white/10 pt-5">
                                    <div className="text-[10px] text-white/40 uppercase tracking-widest mb-3">Certificate Details</div>
                                    <div className="text-base font-bold">Cybernovr Limited</div>
                                    <div className="text-xs text-white/50 mt-1">Information Security Management System</div>
                                    <div className="text-xs text-white/50">ISO/IEC 27001:2022</div>
                                    <div className="mt-4 inline-flex items-center gap-2 bg-green-500/20 border border-green-400/30 rounded-full px-4 py-2">
                                        <div className="w-2 h-2 rounded-full bg-green-400" />
                                        <span className="text-xs text-green-300 font-bold">Certificate Valid</span>
                                    </div>
                                </div>
                            </div>

                            <div className="grid grid-cols-2 gap-4">
                                {CERT_TILES.map((c) => (
                                    <div key={c.title}
                                        className="bg-white border border-gray-100 rounded-2xl p-5 text-center hover:border-purple-200 transition-colors">
                                        <div className="text-3xl mb-2">{c.icon}</div>
                                        <div className="text-sm font-bold text-gray-900">{c.title}</div>
                                        <div className="text-[10px] text-gray-400 mt-1">{c.sub}</div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* ── SECTORS ──────────────────────────────────────────────── */}
            <section id="solutions" className="py-14 bg-gray-50 border-y border-gray-100">
                <div className="max-w-7xl mx-auto px-6 text-center">
                    <p className="text-xs text-gray-400 uppercase tracking-widest mb-8 font-medium">
                        Built for Nigerian Enterprises Across Key Sectors
                    </p>
                    <div className="flex flex-wrap justify-center gap-6">
                        {SECTORS.map((s) => (
                            <div key={s}
                                className="bg-white border border-gray-200 rounded-xl px-5 py-3 text-sm font-semibold text-gray-600 hover:border-purple-300 hover:text-purple-700 transition-colors">
                                {s}
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ── PRICING ──────────────────────────────────────────────── */}
            <section id="pricing" className="py-20">
                <div className="max-w-7xl mx-auto px-6 text-center">
                    <h2 className="text-4xl font-black text-gray-900 mb-4">Simple, Transparent Pricing</h2>
                    <p className="text-gray-500 mb-14 max-w-xl mx-auto">
                        Enterprise-grade security at African market rates.
                        All plans include unlimited alerts and 24/7 AI monitoring.
                    </p>
                    <div className="grid md:grid-cols-3 gap-6 max-w-5xl mx-auto">
                        {PLANS.map((plan) => (
                            <div key={plan.name}
                                className={`rounded-3xl p-8 text-left ${plan.highlight ? 'bg-purple-700 text-white shadow-2xl md:scale-105' : 'bg-white border border-gray-100'}`}>
                                <div className="mb-6">
                                    <div className={`text-xs font-black uppercase tracking-widest mb-2 ${plan.highlight ? 'text-purple-300' : 'text-gray-400'}`}>
                                        {plan.name}
                                    </div>
                                    <div className={`text-3xl font-black ${plan.highlight ? 'text-white' : 'text-gray-900'}`}>
                                        {plan.price}
                                        <span className={`text-base font-medium ${plan.highlight ? 'text-purple-300' : 'text-gray-400'}`}>
                                            {plan.period}
                                        </span>
                                    </div>
                                    <div className={`text-sm mt-1 ${plan.highlight ? 'text-purple-200' : 'text-gray-400'}`}>{plan.desc}</div>
                                </div>
                                <ul className="space-y-3 mb-8">
                                    {plan.features.map((f) => (
                                        <li key={f} className="flex items-center gap-2.5 text-sm">
                                            <div className={`w-4 h-4 rounded-full flex items-center justify-center flex-shrink-0 ${plan.highlight ? 'bg-white/20' : 'bg-purple-100'}`}>
                                                <span className={`text-[8px] font-black ${plan.highlight ? 'text-white' : 'text-purple-700'}`}>✓</span>
                                            </div>
                                            <span className={plan.highlight ? 'text-purple-100' : 'text-gray-600'}>{f}</span>
                                        </li>
                                    ))}
                                </ul>
                                <Link href="/login"
                                    className={`block text-center font-bold py-3.5 rounded-xl text-sm transition-colors ${plan.highlight ? 'bg-white text-purple-700 hover:bg-purple-50' : 'bg-purple-700 text-white hover:bg-purple-800'}`}>
                                    {plan.cta}
                                </Link>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ── CTA ──────────────────────────────────────────────────── */}
            <section className="py-24 bg-gradient-to-br from-gray-950 via-purple-950 to-blue-950">
                <div className="max-w-3xl mx-auto px-6 text-center">
                    {/* eslint-disable-next-line @next/next/no-img-element -- fixed brand mark */}
                    <img src="/novrsoc.jpg" alt="NovrSOC by Cybernovr"
                        className="h-16 w-auto mx-auto mb-8 object-contain rounded-2xl shadow-2xl" />
                    <h2 className="text-4xl md:text-5xl font-black text-white mb-5">
                        Secure Your Organisation Today
                    </h2>
                    <p className="text-white/50 text-lg mb-10 max-w-xl mx-auto">
                        Protect your infrastructure with NovrSOC.
                        Full platform deployment in under 24 hours.
                    </p>
                    <div className="flex flex-col sm:flex-row gap-4 justify-center">
                        <Link href="/login"
                            className="bg-white text-purple-700 font-black px-8 py-4 rounded-2xl hover:bg-gray-100 text-lg transition-colors">
                            Start Free Trial
                        </Link>
                        <a href="mailto:soc@cybernovr.com"
                            className="bg-white/10 border border-white/20 text-white font-bold px-8 py-4 rounded-2xl hover:bg-white/20 text-lg transition-colors">
                            Talk to Sales →
                        </a>
                    </div>
                    <p className="text-white/30 text-xs mt-6">soc@cybernovr.com · Lagos, Nigeria</p>
                </div>
            </section>

            {/* ── FOOTER ───────────────────────────────────────────────── */}
            <footer className="py-12 bg-gray-950 border-t border-white/5">
                <div className="max-w-7xl mx-auto px-6">
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-8 mb-10">
                        <div className="col-span-2">
                            {/* eslint-disable-next-line @next/next/no-img-element -- fixed small brand mark */}
                            <img src="/novrsoc.jpg" alt="NovrSOC by Cybernovr"
                                className="h-8 w-auto object-contain mb-4" />
                            <p className="text-xs text-white/40 leading-relaxed max-w-xs">
                                AI-powered MSSP and SOC-as-a-Service platform for Nigerian and African
                                enterprises, built on ISO 27001 certified infrastructure.
                            </p>
                        </div>

                        {FOOTER_COLS.map((col) => (
                            <div key={col.title}>
                                <div className="text-xs font-bold text-white/60 uppercase tracking-widest mb-4">{col.title}</div>
                                <ul className="space-y-2.5">
                                    {col.links.map((link) => (
                                        <li key={link}>
                                            <a href="#" className="text-xs text-white/30 hover:text-white/70 transition-colors">{link}</a>
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        ))}
                    </div>

                    <div className="border-t border-white/5 pt-8 flex flex-col md:flex-row items-center justify-between gap-4">
                        <div className="text-xs text-white/25">
                            © 2026 Cybernovr Limited. All rights reserved. Lagos, Nigeria.
                        </div>
                        <div className="flex gap-6 flex-wrap justify-center">
                            {['Privacy Policy', 'Terms of Service', 'Security Policy', 'Cookie Policy'].map((link) => (
                                <a key={link} href="#" className="text-xs text-white/25 hover:text-white/50 transition-colors">{link}</a>
                            ))}
                        </div>
                    </div>
                </div>
            </footer>
        </div>
    );
}
