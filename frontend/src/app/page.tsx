import Link from 'next/link';
import { LandingNav } from '@/components/features/LandingNav';
import { Footer } from '@/components/features/Footer';
import { HomepageScanner } from '@/components/features/HomepageScanner';

// Marketing landing page (2026 redesign). Deliberately a SERVER component — every interactive
// piece lives in its own small client component (LandingNav for the mega-menu, HomepageScanner
// for the free scan, the FAQ accordions use plain <details>), so none of the static marketing
// content below ships to the browser as JS.
//
// Every capability named below is checked against the actual codebase (backend/src) rather than
// the Cybernovr flyer alone: VMS risk scoring (lib/riskScore.ts), SOAR approval workflow
// (routes/responseApprovals.ts), Threat Intelligence relevance tiers and TLP enforcement
// (services/threatInfo.ts, services/tiPolicy.ts), and CNII's sector hierarchy and passive-
// collection model (routes/cniiNational.ts). Nothing here claims a certification, an uptime SLA
// or a customer count that isn't backed by something in the repository — see /trust for what is
// actually confirmed about how the platform runs.

const PILLARS = [
    {
        id: 'vms', eyebrow: 'Pillar 1', href: '/vms', cta: 'Explore Vulnerability Management',
        title: 'Vulnerability & Exposure Management',
        desc: 'Discover your real attack surface, scan it continuously, and know exactly what to fix first — with evidence, not just a CVSS number.',
        features: [
            'Asset discovery and inventory', 'Vulnerability scanning across infrastructure, web, API, cloud and containers',
            'Attack surface visibility', 'CVE, CVSS and CISA KEV intelligence', 'Risk-based prioritisation (P1–P4)',
            'Remediation workflows with owners and evidence', 'Scheduled and on-demand assessments',
            'Exposure trends over time', 'Executive and technical reports',
        ],
        useCase: 'A critical CVE lands on CISA\'s Known Exploited Vulnerabilities list — findings on internet-facing assets jump straight to P1, remediation due in days, not next quarter.',
        mock: 'vms' as const,
    },
    {
        id: 'secops', eyebrow: 'Pillar 2', href: '/secops', cta: 'Explore Security Operations',
        title: 'Open XDR & Security Operations',
        desc: 'Every detection becomes a correlated case with MITRE context and threat intelligence attached — response runs through an approval workflow, not a black box.',
        features: [
            'Security event ingestion and SIEM correlation', 'Alert correlation into cases', 'Incident investigation and case management',
            'MITRE ATT&CK context on every alert', 'Threat intelligence enrichment', 'SOAR workflows, tiered by severity',
            'Human-approved response actions', 'Security operations reporting',
        ],
        useCase: 'A brute-force alert correlates with a known-malicious indicator and opens a case automatically — the analyst reviews evidence and MITRE context already attached, then approves containment.',
        mock: 'secops' as const,
    },
    {
        id: 'ti', eyebrow: 'Pillar 3', href: '/ti', cta: 'Explore Threat Intelligence',
        title: 'Threat Intelligence & AI-Assisted Analysis',
        desc: 'Indicators from real feeds, correlated against your own environment, and ranked by evidence — never by an invented score.',
        features: [
            'Threat Intelligence Platform', 'IOC feeds (ThreatFox, URLhaus and more)', 'CISA KEV intelligence',
            'Intelligence correlation against your assets, findings, alerts and cases', 'TLP-aware sharing and a TAXII 2.1 exchange',
            'Relevant-intelligence prioritisation', 'Threat advisories', 'Evidence-grounded AI assistance',
        ],
        useCase: 'An indicator matches a stored alert and an open finding that\'s on CISA\'s KEV list — it\'s ranked critical relevance, with the exact evidence shown, not a bare confidence number.',
        mock: 'ti' as const,
    },
    {
        id: 'cnii', eyebrow: 'Pillar 4', href: '/cnii', cta: 'Explore CNII Watch',
        title: 'CNII Watch & Sector-Wide Security',
        desc: 'National, sector, subsector and organisation visibility for critical infrastructure — built on authorised passive collection, never active scanning of OT.',
        features: [
            'Critical infrastructure asset visibility', 'Nigeria sector intelligence', 'Authorised passive monitoring',
            'Critical asset exposure', 'Sector-level dashboards', 'Threat correlation', 'Multi-organisation monitoring',
            'CERT/CSIRT coordination', 'Executive reporting',
        ],
        useCase: 'A CERT drills from a national heatmap into one sector, then into a single organisation\'s own exposure — without ever seeing another organisation\'s underlying data.',
        mock: 'cnii' as const,
    },
];

const LIFECYCLE = [
    { step: '01', title: 'Discover', desc: 'Find assets across internal infrastructure and your internet-facing footprint.' },
    { step: '02', title: 'Ingest', desc: 'Pull in scan results, SIEM events and threat intelligence feeds.' },
    { step: '03', title: 'Correlate', desc: 'Match indicators and findings against your own assets, alerts and cases.' },
    { step: '04', title: 'Prioritise', desc: 'Rank by real evidence — exploit status, asset criticality, verified association.' },
    { step: '05', title: 'Investigate', desc: 'Work a case with MITRE context, intelligence and history in one view.' },
    { step: '06', title: 'Respond', desc: 'Run a governed action through approval, policy or escalation.' },
    { step: '07', title: 'Report', desc: 'Share executive and technical reporting from the same underlying evidence.' },
];

const INTEGRATION_CATEGORIES = [
    { icon: '🧱', title: 'Firewalls', desc: 'Containment actions route through your existing firewall.' },
    { icon: '🖥️', title: 'EDR / XDR', desc: 'Endpoint telemetry feeds the correlation layer.' },
    { icon: '📊', title: 'SIEM', desc: 'Correlate alongside, or in place of, an existing SIEM.' },
    { icon: '📡', title: 'NDR', desc: 'Network signals correlated with endpoint and identity context.' },
    { icon: '🧬', title: 'Threat intel feeds', desc: 'Bring your own feeds in alongside NovrSOC\'s own sources.' },
    { icon: '☁️', title: 'Cloud', desc: 'Cloud posture and identity signals in the same correlated view.' },
    { icon: '🔑', title: 'Identity', desc: 'Identity and access signals feed investigation context.' },
    { icon: '🎫', title: 'Ticketing / ITSM', desc: 'Cases and remediation tasks route into your existing workflow tools.' },
    { icon: '🏭', title: 'OT / ICS', desc: 'Passive, non-intrusive visibility for operational technology.' },
];

const DIFFERENTIATORS = [
    { title: 'Unified security visibility', desc: 'Vulnerability, threat and operational data in one correlated view, not nine disconnected tools.' },
    { title: 'Vendor-agnostic architecture', desc: 'Built to sit on top of the firewalls, EDR, SIEM and feeds you already run.' },
    { title: 'Multi-tenant operations', desc: 'Serve multiple client organisations with per-org data isolation and role-based access.' },
    { title: 'Intelligence-driven prioritisation', desc: 'Rank by evidence — exploit status, asset criticality, verified association — never a guess.' },
    { title: 'Human-governed automation', desc: 'Response actions run through an approval workflow; nothing destructive fires without sign-off.' },
    { title: 'Cost-conscious operational efficiency', desc: 'One platform where teams previously stitched several tools together by hand.' },
];

const FAQS = [
    { q: 'What is VTEM?', a: 'Vulnerability & Threat Exposure Management: continuously discovering your assets, scanning them, and prioritising what to fix by real evidence — exploit status, asset criticality and verified threat association — rather than raw severity alone.' },
    { q: 'What is Open XDR?', a: 'An architecture that correlates detections across the security tools you already run — SIEM, EDR, network, identity — into a single case, rather than requiring you to replace them with one vendor\'s stack.' },
    { q: 'Does Novr VTEM replace an existing SIEM?', a: 'It can run alongside an existing SIEM, correlating its alerts with vulnerability and threat context, or serve as the primary correlation layer — the right fit depends on your environment, which is exactly what a demo conversation is for.' },
    { q: 'How does vulnerability scanning work?', a: 'Scheduled, on-demand and unauthenticated scans run within approved scopes, identifying findings against CVE, NVD and CWE and scoring them by CVSS, CISA KEV status, exploit availability and asset criticality.' },
    { q: 'Can existing security tools integrate?', a: 'Yes — Novr VTEM is vendor-agnostic by design. See the integration categories above, or the full Integrations page for the open APIs available today.' },
    { q: 'How does multi-tenancy work?', a: 'Each client organisation\'s data is isolated and scoped by role — super admin, SOC manager, analyst and executive each see only what their role and organisation permit, which is what makes the platform usable for MSSPs, CERTs and CSIRTs managing many constituents.' },
    { q: 'What is CNII Watch?', a: 'Sector-aware visibility across organisations, assets, exposure and risk — in IT and OT — built for critical national infrastructure oversight, from authorised passive collection rather than active scanning of operational technology.' },
    { q: 'Is the platform suitable for CERTs and CSIRTs?', a: 'Yes — constituency-wide monitoring, intelligence distribution with acknowledgement tracking, and anonymised benchmarking are built for exactly that operating model. See Who it\'s for → CERTs & Sectoral CSIRTs.' },
    { q: 'How is AI used?', a: 'As an assistant grounded in your own platform data — case summaries, MITRE mapping, threat intelligence context — with every statement tied to the record it came from. It supports analyst decisions; it does not take autonomous containment action.' },
    { q: 'How do customers request access?', a: 'Request a demo, and we\'ll walk through the platform against your own environment before any commitment.' },
];

export default function LandingPage() {
    return (
        <div className="min-h-screen bg-white font-sans">
            <LandingNav />

            {/* ── A/B: HERO ────────────────────────────────────────────── */}
            <section className="pt-32 pb-20 bg-[#05070f] relative overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-br from-[#0a1230] via-[#070b18] to-[#05070f]" />
                <div className="absolute -top-40 left-1/4 w-[40rem] h-[40rem] bg-blue-600/25 rounded-full blur-[140px]" />
                <div className="absolute top-20 right-0 w-[30rem] h-[30rem] bg-sky-500/10 rounded-full blur-[120px]" />
                <div className="absolute inset-0 opacity-[0.06]"
                    style={{ backgroundImage: 'radial-gradient(circle at 2px 2px, rgba(255,255,255,0.4) 1px, transparent 0)', backgroundSize: '40px 40px' }} />

                <div className="max-w-7xl mx-auto px-6 relative">
                    <div className="grid lg:grid-cols-[1.1fr_0.9fr] gap-14 items-center">
                        <div>
                            <div className="inline-flex items-center gap-2 bg-white/5 border border-sky-400/20 rounded-full px-4 py-2 mb-7">
                                <div className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-pulse" />
                                <span className="text-sky-300 text-xs font-bold uppercase tracking-wider">Novr VTEM · Open XDR for Managed Security Services</span>
                            </div>

                            <h1 className="text-4xl md:text-6xl font-black text-white mb-6 leading-[1.08] tracking-tight">
                                One Platform.<br />Complete Security Visibility.
                            </h1>

                            <p className="text-lg text-white/60 max-w-xl mb-9 leading-relaxed">
                                Novr VTEM unifies vulnerability management, threat intelligence, security monitoring,
                                investigation and response across IT and OT environments — through one integrated,
                                vendor-agnostic security platform.
                            </p>

                            <div className="flex flex-col sm:flex-row gap-4 mb-14">
                                <Link href="/contact"
                                    className="bg-gradient-to-r from-sky-500 to-blue-600 text-white font-black px-7 py-4 rounded-2xl hover:from-sky-400 hover:to-blue-500 text-base transition-all shadow-xl shadow-blue-900/40 text-center">
                                    Request a Demo →
                                </Link>
                                <Link href="/platform"
                                    className="bg-white/5 border border-white/15 text-white font-bold px-7 py-4 rounded-2xl hover:bg-white/10 text-base transition-colors text-center">
                                    Explore the Platform
                                </Link>
                            </div>

                            <div className="grid grid-cols-4 gap-6 max-w-lg">
                                {[['4', 'Connected disciplines'], ['IT + OT', 'Coverage'], ['Multi-tenant', 'Architecture'], ['Evidence-led', 'Prioritisation']].map(([v, l]) => (
                                    <div key={l}>
                                        <div className="text-lg md:text-xl font-black text-white mb-0.5">{v}</div>
                                        <div className="text-[10px] text-white/40 leading-tight uppercase tracking-wide">{l}</div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Representative platform view — a constructed mockup in the product's own
                            visual language, not a literal screenshot or live data. */}
                        <div className="relative">
                            <div className="bg-[#0c1226] border border-white/10 rounded-2xl shadow-2xl shadow-black/50 overflow-hidden">
                                <div className="flex items-center gap-1.5 px-4 py-3 border-b border-white/10 bg-white/[0.02]">
                                    <div className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
                                    <div className="w-2.5 h-2.5 rounded-full bg-amber-500/60" />
                                    <div className="w-2.5 h-2.5 rounded-full bg-green-500/60" />
                                    <span className="ml-3 text-[10px] text-white/30 font-mono">Security Command Center — representative view</span>
                                </div>
                                <div className="p-5 space-y-4">
                                    <div className="grid grid-cols-3 gap-3">
                                        {[['Open P1/P2', '—', 'text-red-400'], ['Verified TI matches', '—', 'text-amber-400'], ['Pending approvals', '—', 'text-sky-400']].map(([l, v, c]) => (
                                            <div key={l as string} className="bg-white/[0.03] border border-white/10 rounded-xl p-3">
                                                <div className={`text-xl font-black ${c}`}>{v}</div>
                                                <div className="text-[9px] text-white/40 mt-1 leading-tight">{l}</div>
                                            </div>
                                        ))}
                                    </div>
                                    <div className="bg-white/[0.03] border border-white/10 rounded-xl p-3 space-y-2">
                                        <div className="text-[9px] text-white/40 uppercase tracking-wider font-bold mb-1">Relevant intelligence</div>
                                        {[['Critical', 'bg-red-500/15 text-red-300 border-red-500/30'], ['High', 'bg-orange-500/15 text-orange-300 border-orange-500/30'], ['Medium', 'bg-sky-500/15 text-sky-300 border-sky-500/30']].map(([tier, cls]) => (
                                            <div key={tier as string} className="flex items-center justify-between text-xs">
                                                <span className={`px-2 py-0.5 rounded-full border text-[9px] font-bold uppercase ${cls}`}>{tier}</span>
                                                <span className="text-white/30 font-mono text-[10px]">evidence-ranked match</span>
                                            </div>
                                        ))}
                                    </div>
                                    <div className="bg-white/[0.03] border border-white/10 rounded-xl p-3">
                                        <div className="text-[9px] text-white/40 uppercase tracking-wider font-bold mb-2">Alert → Case → Response</div>
                                        <div className="flex items-center gap-1">
                                            {['Detected', 'Enriched', 'Case', 'Approved', 'Resolved'].map((s, i) => (
                                                <div key={s} className="flex items-center gap-1 flex-1">
                                                    <div className="text-[8px] text-white/50 text-center flex-1 bg-white/5 rounded py-1.5">{s}</div>
                                                    {i < 4 && <span className="text-white/15 text-[8px]">→</span>}
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* ── FREE SCANNER ─────────────────────────────────────────── */}
            <section id="scanner" className="py-16 bg-gradient-to-b from-gray-50 to-white">
                <div className="max-w-3xl mx-auto px-6">
                    <div className="text-center mb-8">
                        <div className="inline-flex items-center gap-2 bg-blue-100 border border-blue-200 rounded-full px-4 py-2 mb-4">
                            <span className="text-blue-700 text-xs font-bold uppercase tracking-wider">
                                Free Tool — No Account Needed
                            </span>
                        </div>
                        <h2 className="text-3xl md:text-4xl font-black text-gray-900 mb-3">
                            Instant Threat Scanner
                        </h2>
                        <p className="text-gray-500 text-lg">
                            Scan any IP address, domain, or URL against live threat intelligence sources. Results in seconds.
                        </p>
                    </div>
                    <HomepageScanner />
                </div>
            </section>

            {/* ── C: PLATFORM OVERVIEW ─────────────────────────────────── */}
            <section className="py-20 bg-white">
                <div className="max-w-5xl mx-auto px-6 text-center">
                    <h2 className="text-3xl md:text-5xl font-black text-gray-900 mb-5">
                        From Exposure to Response. <span className="text-blue-600">All in One Platform.</span>
                    </h2>
                    <p className="text-gray-500 text-lg max-w-2xl mx-auto mb-12 leading-relaxed">
                        Novr VTEM connects asset discovery, vulnerability data, threat intelligence, detections and
                        response into one correlated model — instead of four separate tools your team stitches together by hand.
                    </p>
                    <div className="flex flex-wrap items-center justify-center gap-3">
                        {['Vulnerability & Exposure', 'Open XDR / SecOps', 'Threat Intelligence', 'CNII Watch'].map((p, i) => (
                            <div key={p} className="flex items-center gap-3">
                                <div className="bg-gray-50 border border-gray-200 rounded-2xl px-5 py-4 text-sm font-bold text-gray-700">{p}</div>
                                {i < 3 && <span className="text-gray-300 text-lg hidden sm:block">↔</span>}
                            </div>
                        ))}
                    </div>
                    <p className="text-xs text-gray-400 mt-6">One shared data model — an asset, a finding or an indicator in one pillar is visible, in context, in every other.</p>
                </div>
            </section>

            {/* ── D: FOUR CORE PILLARS ─────────────────────────────────── */}
            <section id="pillars" className="py-8">
                {PILLARS.map((p, i) => (
                    <div key={p.id} id={p.id} className={`py-16 scroll-mt-20 ${i % 2 === 1 ? 'bg-gray-50 border-y border-gray-100' : ''}`}>
                        <div className="max-w-7xl mx-auto px-6">
                            <div className={`grid lg:grid-cols-2 gap-12 items-center ${i % 2 === 1 ? 'lg:[&>*:first-child]:order-2' : ''}`}>
                                <div>
                                    <div className="inline-flex items-center gap-2 bg-blue-100 border border-blue-200 rounded-full px-4 py-1.5 mb-5">
                                        <span className="text-blue-700 text-[11px] font-black uppercase tracking-wider">{p.eyebrow}</span>
                                    </div>
                                    <h3 className="text-2xl md:text-3xl font-black text-gray-900 mb-4">{p.title}</h3>
                                    <p className="text-gray-500 mb-6 leading-relaxed">{p.desc}</p>
                                    <ul className="grid sm:grid-cols-2 gap-2.5 mb-7">
                                        {p.features.map((f) => (
                                            <li key={f} className="flex items-start gap-2 text-xs text-gray-600">
                                                <div className="w-1.5 h-1.5 rounded-full bg-blue-400 flex-shrink-0 mt-1.5" />
                                                {f}
                                            </li>
                                        ))}
                                    </ul>
                                    <p className="text-xs text-gray-400 italic mb-6 border-l-2 border-blue-200 pl-3">{p.useCase}</p>
                                    <Link href={p.href} className="inline-flex items-center gap-1.5 bg-blue-600 text-white font-bold px-6 py-3 rounded-xl hover:bg-blue-700 transition-colors text-sm">
                                        {p.cta} →
                                    </Link>
                                </div>

                                <PillarMock kind={p.mock} />
                            </div>
                        </div>
                    </div>
                ))}
            </section>

            {/* ── E: HOW NOVR VTEM WORKS ───────────────────────────────── */}
            <section className="py-20 bg-[#05070f] relative overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-br from-[#0a1230] via-[#070b18] to-[#05070f]" />
                <div className="max-w-7xl mx-auto px-6 relative">
                    <div className="text-center mb-14">
                        <h2 className="text-3xl md:text-4xl font-black text-white mb-4">How Novr VTEM Works</h2>
                        <p className="text-white/50 max-w-xl mx-auto">Seven stages, one correlated pipeline — not seven disconnected tools.</p>
                    </div>
                    <div className="flex flex-col md:flex-row items-stretch justify-center gap-3 flex-wrap">
                        {LIFECYCLE.map((s, i) => (
                            <div key={s.step} className="flex items-center gap-3">
                                <div className="bg-white/5 border border-white/10 rounded-2xl p-5 text-center w-44 hover:border-sky-500/40 hover:bg-white/10 transition-all">
                                    <div className="text-[9px] text-sky-400 font-black mb-1.5">{s.step}</div>
                                    <div className="text-sm font-bold text-white mb-1.5">{s.title}</div>
                                    <div className="text-[10px] text-white/40 leading-tight">{s.desc}</div>
                                </div>
                                {i < LIFECYCLE.length - 1 && <div className="text-white/15 text-xl hidden md:block">→</div>}
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ── F: INTEGRATIONS ──────────────────────────────────────── */}
            <section className="py-20">
                <div className="max-w-7xl mx-auto px-6">
                    <div className="text-center mb-14">
                        <h2 className="text-3xl md:text-4xl font-black text-gray-900 mb-4">Connect Your Existing Security Stack.</h2>
                        <p className="text-gray-500 max-w-2xl mx-auto">
                            Novr VTEM is vendor-agnostic by design — it correlates and acts on data from the tools you already
                            operate, rather than asking you to replace them.
                        </p>
                    </div>
                    <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5 mb-10">
                        {INTEGRATION_CATEGORIES.map((c) => (
                            <div key={c.title} className="bg-white border border-gray-100 rounded-2xl p-6 hover:border-blue-200 hover:shadow-lg transition-all">
                                <span className="text-3xl mb-3 block">{c.icon}</span>
                                <h3 className="font-black text-gray-900 mb-2">{c.title}</h3>
                                <p className="text-sm text-gray-500 leading-relaxed">{c.desc}</p>
                            </div>
                        ))}
                    </div>
                    <div className="text-center">
                        <Link href="/integrations" className="inline-flex items-center gap-1.5 text-blue-700 font-bold hover:underline">
                            See the full integrations directory →
                        </Link>
                    </div>
                </div>
            </section>

            {/* ── G: API & AUTOMATION ──────────────────────────────────── */}
            <section className="py-20 bg-gray-950">
                <div className="max-w-6xl mx-auto px-6">
                    <div className="grid lg:grid-cols-2 gap-12 items-center">
                        <div>
                            <h2 className="text-3xl md:text-4xl font-black text-white mb-4">Built to Integrate. Designed to Automate.</h2>
                            <p className="text-white/50 mb-7 leading-relaxed">
                                A free, rate-limited public scan endpoint is live today, and a TAXII 2.1 exchange shares
                                threat intelligence with credentialed partners under TLP-aware access control. A broader
                                self-serve developer API is planned.
                            </p>
                            <ul className="space-y-3">
                                {[
                                    ['Public scan endpoint', 'Live — the scanner above calls it directly, rate-limited per IP.'],
                                    ['TAXII 2.1 intelligence exchange', 'Live — credentialed partners pull STIX 2.1 objects up to an agreed TLP ceiling.'],
                                    ['Workflow automation', 'SOAR actions run through an approval workflow today, inside the platform.'],
                                    ['Self-serve developer API', 'Planned — not yet publicly available.'],
                                ].map(([t, d]) => (
                                    <li key={t} className="flex items-start gap-3">
                                        <div className="w-1.5 h-1.5 rounded-full bg-sky-400 mt-2 flex-shrink-0" />
                                        <div><span className="text-white font-bold text-sm">{t}</span><span className="text-white/40 text-sm"> — {d}</span></div>
                                    </li>
                                ))}
                            </ul>
                        </div>
                        <div className="bg-[#0c1226] border border-white/10 rounded-2xl overflow-hidden shadow-2xl">
                            <div className="flex items-center gap-1.5 px-4 py-3 border-b border-white/10 bg-white/[0.02]">
                                <div className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
                                <div className="w-2.5 h-2.5 rounded-full bg-amber-500/60" />
                                <div className="w-2.5 h-2.5 rounded-full bg-green-500/60" />
                                <span className="ml-3 text-[10px] text-white/30 font-mono">curl — public scan endpoint</span>
                            </div>
                            <pre className="p-5 text-[11px] font-mono text-sky-200 overflow-x-auto leading-relaxed">{`curl -X POST https://api.novrsoc.com/api/public/scan \\
  -H "Content-Type: application/json" \\
  -d '{"target": "185.220.101.47"}'

{
  "target": "185.220.101.47",
  "ioc_type": "ip",
  "verdict": "suspicious",
  "risk_score": 62,
  "sources_checked": 9,
  "detections": 3
}`}</pre>
                        </div>
                    </div>
                </div>
            </section>

            {/* ── H: MSSPs, CERTs, CSIRTs ───────────────────────────────── */}
            <section className="py-20">
                <div className="max-w-7xl mx-auto px-6">
                    <div className="grid lg:grid-cols-2 gap-14 items-center">
                        <div>
                            <div className="inline-flex items-center gap-2 bg-blue-100 border border-blue-200 rounded-full px-4 py-2 mb-6">
                                <span className="text-blue-700 text-xs font-bold">Built for operators, not just one team</span>
                            </div>
                            <h2 className="text-3xl md:text-4xl font-black text-gray-900 mb-5">Built for MSSPs, CERTs and CSIRTs.</h2>
                            <div className="space-y-5">
                                {[
                                    ['Multi-tier multi-tenancy', 'Serve multiple client organisations from one dashboard, each logically isolated.'],
                                    ['Role-based access', 'Super admin, SOC manager, analyst and executive roles each see only what they should.'],
                                    ['Sector-level visibility', 'Roll exposure up to a sector view, with drill-down to the organisation behind any hotspot.'],
                                    ['Centralised operations with delegated access', 'Run monitoring and response centrally while clients keep their own view.'],
                                    ['Coordinated incident response', 'Push intelligence and advisories to a constituency, with acknowledgement tracking.'],
                                ].map(([t, d]) => (
                                    <div key={t as string} className="flex gap-3">
                                        <div className="w-5 h-5 rounded-full bg-blue-100 text-blue-700 flex items-center justify-center text-[10px] font-black flex-shrink-0 mt-0.5">✓</div>
                                        <div>
                                            <p className="font-bold text-gray-900 text-sm">{t}</p>
                                            <p className="text-xs text-gray-500">{d}</p>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                        <div className="bg-gray-50 border border-gray-200 rounded-2xl p-8">
                            <p className="text-[10px] text-gray-400 uppercase tracking-widest font-bold mb-5 text-center">Organisation hierarchy</p>
                            <div className="space-y-2.5">
                                {[
                                    ['National', 0], ['Sector', 1], ['Subsector', 2], ['Organisation', 3], ['Asset', 4],
                                ].map(([label, depth]) => (
                                    <div key={label as string} style={{ marginLeft: `${Number(depth) * 20}px` }}
                                        className="bg-white border border-gray-200 rounded-lg px-4 py-2.5 text-xs font-bold text-gray-700 shadow-sm">
                                        {label}
                                    </div>
                                ))}
                            </div>
                            <p className="text-[10px] text-gray-400 mt-5 text-center leading-relaxed">A CERT or regulator sees the hierarchy down to the organisation level; an organisation sees only its own data.</p>
                        </div>
                    </div>
                </div>
            </section>

            {/* ── I: CRITICAL INFRASTRUCTURE / IT+OT ───────────────────── */}
            <section className="py-20 bg-gray-50 border-y border-gray-100">
                <div className="max-w-4xl mx-auto px-6 text-center">
                    <div className="inline-flex items-center gap-2 bg-blue-100 border border-blue-200 rounded-full px-4 py-2 mb-6">
                        <span className="text-blue-700 text-xs font-bold">CNII Watch</span>
                    </div>
                    <h2 className="text-3xl md:text-4xl font-black text-gray-900 mb-5">Critical Infrastructure, IT and OT.</h2>
                    <p className="text-gray-500 leading-relaxed max-w-2xl mx-auto mb-6">
                        Novr VTEM brings sector-aware visibility and evidence-based risk analysis to critical national
                        infrastructure operators, across both IT and operational technology. Visibility into OT and
                        ICS assets comes from authorised, passive, non-intrusive collection alongside IT — never
                        active scanning of industrial control systems, and never a claim of official CNII designation
                        or regulatory certification.
                    </p>
                    <Link href="/cnii" className="inline-flex items-center gap-1.5 text-blue-700 font-bold hover:underline">
                        Read how CNII Watch actually works →
                    </Link>
                </div>
            </section>

            {/* ── J: GOVERNANCE & REPORTING ─────────────────────────────── */}
            <section className="py-20">
                <div className="max-w-7xl mx-auto px-6">
                    <div className="text-center mb-14">
                        <h2 className="text-3xl md:text-4xl font-black text-gray-900 mb-4">Governance &amp; Reporting</h2>
                        <p className="text-gray-500 max-w-2xl mx-auto">Executive and technical reporting from the same evidence your analysts already work with — not a separate spreadsheet.</p>
                    </div>
                    <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-5">
                        {[
                            ['Executive dashboards', 'A live view of risk, exposure and compliance posture for leadership.'],
                            ['Technical reports', 'Full detail — CVE, CVSS, provenance, verification — for your analysts.'],
                            ['Exposure trends', 'Track whether open risk is actually going down over time.'],
                            ['Remediation tracking', 'Owners, tasks, evidence and overdue findings, end to end.'],
                            ['Audit trails', 'Scans, access and configuration changes logged for later review.'],
                            ['Compliance context mapping', 'Findings mapped to NDPA, CBN, NCC, ISO 27001 and NIST CSF controls.'],
                            ['Nigerian regulatory context', 'NDPA, the CBN Cybersecurity Framework and NCC Consumer Protection.'],
                            ['ISO & NIST framework context', 'A technical mapping to help you prepare — never a certification or compliance determination on its own.'],
                        ].map(([t, d]) => (
                            <div key={t} className="bg-white border border-gray-100 rounded-2xl p-5">
                                <h4 className="font-black text-gray-900 mb-1.5 text-sm">{t}</h4>
                                <p className="text-xs text-gray-500 leading-relaxed">{d}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ── K: WHY NOVR VTEM ─────────────────────────────────────── */}
            <section className="py-20 bg-gray-950">
                <div className="max-w-7xl mx-auto px-6">
                    <div className="text-center mb-14">
                        <h2 className="text-3xl md:text-4xl font-black text-white mb-4">Why Novr VTEM</h2>
                    </div>
                    <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5">
                        {DIFFERENTIATORS.map((d, i) => (
                            <div key={d.title} className="bg-white/5 border border-white/10 rounded-2xl p-6 hover:border-sky-500/40 transition-colors">
                                <div className="text-sky-400 text-xs font-black mb-3">{String(i + 1).padStart(2, '0')}</div>
                                <h4 className="font-black text-white mb-2">{d.title}</h4>
                                <p className="text-sm text-white/40 leading-relaxed">{d.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ── L: DEPLOYMENT & ARCHITECTURE ─────────────────────────── */}
            <section className="py-20">
                <div className="max-w-5xl mx-auto px-6">
                    <div className="text-center mb-14">
                        <h2 className="text-3xl md:text-4xl font-black text-gray-900 mb-4">Deployment &amp; Architecture</h2>
                        <p className="text-gray-500 max-w-2xl mx-auto">What deploying Novr VTEM actually means — see <Link href="/trust" className="text-blue-700 font-semibold hover:underline">Trust &amp; Deployment</Link> for the full detail.</p>
                    </div>
                    <div className="grid sm:grid-cols-2 gap-5">
                        {[
                            ['Platform architecture', 'Delivered as a cloud-native SaaS platform, with a data layer logically separated per tenant.'],
                            ['Data ingestion', 'Scan results, SIEM events and threat feeds flow into one correlated data model.'],
                            ['Security controls', 'Role-based access control; each organisation\'s data is scoped by role and tenant.'],
                            ['Integration boundaries', 'External integrations (scanning workers, SIEM ingest, intelligence feeds) authenticate with their own scoped credentials.'],
                            ['Deployment considerations', 'Hosting region, data residency and specific SLA terms are confirmed during procurement, not asserted here without a contract behind them.'],
                            ['Availability & scalability', 'Architecture and capacity are discussed directly as part of a deployment conversation.'],
                        ].map(([t, d]) => (
                            <div key={t} className="bg-gray-50 border border-gray-100 rounded-2xl p-5">
                                <h4 className="font-black text-gray-900 mb-1.5 text-sm">{t}</h4>
                                <p className="text-xs text-gray-500 leading-relaxed">{d}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ── M: FAQ ────────────────────────────────────────────────── */}
            <section className="py-20 bg-gray-50 border-y border-gray-100">
                <div className="max-w-3xl mx-auto px-6">
                    <h2 className="text-3xl md:text-4xl font-black text-gray-900 mb-10 text-center">Frequently Asked Questions</h2>
                    <div className="space-y-3">
                        {FAQS.map((f) => (
                            <details key={f.q} className="group bg-white border border-gray-100 rounded-2xl p-5 open:border-blue-200">
                                <summary className="list-none flex items-center justify-between gap-4 cursor-pointer font-bold text-gray-900 text-sm">
                                    {f.q}
                                    <span className="text-blue-600 group-open:rotate-45 transition-transform text-xl leading-none flex-shrink-0">+</span>
                                </summary>
                                <p className="text-sm text-gray-500 leading-relaxed mt-3">{f.a}</p>
                            </details>
                        ))}
                    </div>
                </div>
            </section>

            {/* ── N: FINAL CTA ──────────────────────────────────────────── */}
            <section className="py-24 bg-[#05070f] relative overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-br from-[#0a1230] via-[#070b18] to-[#05070f]" />
                <div className="absolute top-0 left-1/3 w-[34rem] h-[34rem] bg-blue-600/20 rounded-full blur-[140px]" />
                <div className="max-w-3xl mx-auto px-6 text-center relative">
                    {/* eslint-disable-next-line @next/next/no-img-element -- fixed brand mark */}
                    <img src="/novrsoc.jpg" alt="NovrSOC by Cybernovr" className="h-16 w-auto mx-auto mb-8 object-contain rounded-2xl shadow-2xl" />
                    <h2 className="text-4xl md:text-5xl font-black text-white mb-5">
                        Strengthen Your Security Operations with Novr VTEM.
                    </h2>
                    <p className="text-white/50 text-lg mb-10 max-w-xl mx-auto">
                        See the platform against your own environment, before any commitment.
                    </p>
                    <div className="flex flex-col sm:flex-row gap-4 justify-center">
                        <Link href="/contact"
                            className="bg-gradient-to-r from-sky-500 to-blue-600 text-white font-black px-8 py-4 rounded-2xl hover:from-sky-400 hover:to-blue-500 transition-all text-lg shadow-xl shadow-blue-900/40">
                            Request a Demo
                        </Link>
                        <a href="mailto:soc@cybernovr.com"
                            className="bg-white/5 border border-white/15 text-white font-bold px-8 py-4 rounded-2xl hover:bg-white/10 text-lg transition-colors">
                            Contact Cybernovr →
                        </a>
                    </div>
                    <p className="text-white/30 text-xs mt-6">soc@cybernovr.com · Lagos, Nigeria</p>
                </div>
            </section>

            <Footer />
        </div>
    );
}

// Small, product-language mockups for each pillar — constructed in the real app's own visual
// language (severity/priority tags, TLP badges, coverage states), never a literal screenshot and
// never fabricated figures: every label is a real field name or state the backend actually uses.
function MockShell({ caption, children }: { caption: string; children: React.ReactNode }) {
    return (
        <div className="bg-[#0c1226] border border-white/10 rounded-2xl shadow-2xl shadow-black/40 overflow-hidden">
            <div className="flex items-center gap-1.5 px-4 py-3 border-b border-white/10 bg-white/[0.02]">
                <div className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
                <div className="w-2.5 h-2.5 rounded-full bg-amber-500/60" />
                <div className="w-2.5 h-2.5 rounded-full bg-green-500/60" />
                <span className="ml-3 text-[10px] text-white/30 font-mono">{caption}</span>
            </div>
            <div className="p-5">{children}</div>
        </div>
    );
}

function PillarMock({ kind }: { kind: 'vms' | 'secops' | 'ti' | 'cnii' }) {
    if (kind === 'vms') {
        return (
            <MockShell caption="Risk queue — representative view">
                <div className="space-y-2">
                    {[['P1', 'CVE-2024-XXXX — KEV listed', 'bg-red-500/15 text-red-300 border-red-500/30'],
                        ['P1', 'Internet-facing, CVSS 9.1', 'bg-red-500/15 text-red-300 border-red-500/30'],
                        ['P2', 'Internal asset, CVSS 7.4', 'bg-orange-500/15 text-orange-300 border-orange-500/30'],
                        ['P3', 'Low exposure, unconfirmed', 'bg-sky-500/15 text-sky-300 border-sky-500/30']].map(([tag, label, cls]) => (
                        <div key={label as string} className="flex items-center gap-3 bg-white/[0.03] border border-white/10 rounded-lg px-3 py-2.5">
                            <span className={`text-[9px] font-black px-2 py-0.5 rounded-full border ${cls}`}>{tag}</span>
                            <span className="text-[11px] text-white/60 flex-1 truncate">{label}</span>
                        </div>
                    ))}
                </div>
                <p className="text-[9px] text-white/25 mt-3">Priority from CVSS, CISA KEV status, exploit availability and asset criticality — never severity alone.</p>
            </MockShell>
        );
    }
    if (kind === 'secops') {
        return (
            <MockShell caption="Alert → Case → Response — representative view">
                <div className="space-y-2">
                    {['Detected — SIEM correlation', 'Enriched — MITRE ATT&CK + threat intel', 'Case opened — automatically', 'Response — pending approval'].map((s, i) => (
                        <div key={s} className="flex items-center gap-3 bg-white/[0.03] border border-white/10 rounded-lg px-3 py-2.5">
                            <span className="text-[9px] text-sky-400 font-black">{String(i + 1).padStart(2, '0')}</span>
                            <span className="text-[11px] text-white/60 flex-1">{s}</span>
                        </div>
                    ))}
                </div>
                <p className="text-[9px] text-white/25 mt-3">Every automated action is logged as succeeded, skipped or failed — never silently assumed.</p>
            </MockShell>
        );
    }
    if (kind === 'ti') {
        return (
            <MockShell caption="Relevant intelligence — representative view">
                <div className="space-y-2">
                    {[['Critical', 'Verified + KEV + critical asset', 'bg-red-500/15 text-red-300 border-red-500/30'],
                        ['High', 'KEV match, exposed asset', 'bg-orange-500/15 text-orange-300 border-orange-500/30'],
                        ['Medium', 'Fresh match, no verification', 'bg-sky-500/15 text-sky-300 border-sky-500/30']].map(([tier, reason, cls]) => (
                        <div key={tier as string} className="bg-white/[0.03] border border-white/10 rounded-lg px-3 py-2.5">
                            <span className={`text-[9px] font-black px-2 py-0.5 rounded-full border ${cls}`}>{tier}</span>
                            <p className="text-[10px] text-white/50 mt-1.5">{reason}</p>
                        </div>
                    ))}
                </div>
                <p className="text-[9px] text-white/25 mt-3">A match is an association, not proof of compromise — only an analyst-promoted or case-linked match is shown as verified.</p>
            </MockShell>
        );
    }
    return (
        <MockShell caption="Monitoring coverage — representative view">
            <div className="space-y-2">
                {[['Connected · fresh', 'Recent authorised passive collection', 'bg-green-500/15 text-green-300 border-green-500/30'],
                    ['Connected · stale', 'No fresh collection in the expected window', 'bg-amber-500/15 text-amber-300 border-amber-500/30'],
                    ['Not connected', 'No passive collection configured', 'bg-white/10 text-white/40 border-white/15']].map(([state, desc, cls]) => (
                    <div key={state as string} className="flex items-center gap-3 bg-white/[0.03] border border-white/10 rounded-lg px-3 py-2.5">
                        <span className={`text-[9px] font-black px-2 py-0.5 rounded-full border whitespace-nowrap ${cls}`}>{state}</span>
                        <span className="text-[10px] text-white/50">{desc}</span>
                    </div>
                ))}
            </div>
            <p className="text-[9px] text-white/25 mt-3">Unknown monitoring is shown as unknown — never collapsed into &quot;healthy&quot;.</p>
        </MockShell>
    );
}
