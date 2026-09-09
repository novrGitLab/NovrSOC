import Link from 'next/link';
import { HomepageScanner } from '@/components/features/HomepageScanner';

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-white font-sans">

      {/* ── NAVBAR ─────────────────────────────────────────────────── */}
      <nav className="sticky top-0 z-50 bg-white border-b border-[#EEF0F6]">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">

          {/* Logo — novrsoc.jpg is the full wordmark ("NOVRSOC" + "by CYBERNOVR" baked into
              the image), so no separate text label next to it */}
          {/* eslint-disable-next-line @next/next/no-img-element -- fixed small brand mark */}
          <img src="/novrsoc.jpg" alt="NovrSOC by Cybernovr" className="h-9 w-auto object-contain" />

          {/* Nav links */}
          <div className="hidden md:flex items-center gap-8 text-sm text-[#7A8099]">
            {['Features', 'Compliance', 'Pricing', 'About'].map(link => (
              <a key={link} href={`#${link.toLowerCase()}`}
                className="hover:text-[#520385] transition-colors">
                {link}
              </a>
            ))}
          </div>

          {/* Auth buttons */}
          <div className="flex items-center gap-3">
            <Link href="/login"
              className="text-sm text-[#7A8099] hover:text-[#520385] transition-colors font-medium px-3 py-2">
              Login
            </Link>
            <Link href="/login"
              className="text-sm font-bold bg-[#FF5500] text-white px-5 py-2.5 rounded-lg hover:bg-[#E54D00] transition-colors uppercase tracking-wide">
              Request Demo
            </Link>
          </div>
        </div>
      </nav>

      {/* ── HERO ───────────────────────────────────────────────────── */}
      <section className="bg-[#520385] min-h-[calc(100vh-64px)] flex items-center">
        <div className="max-w-6xl mx-auto px-6 py-20 w-full">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">

            {/* Left — Text */}
            <div>
              {/* Eyebrow badge */}
              <div className="inline-flex items-center gap-2 bg-white/10 border border-white/20 rounded-full px-4 py-1.5 mb-8">
                <span className="w-1.5 h-1.5 rounded-full bg-[#FF5500]" />
                <span className="text-white/80 text-xs font-medium tracking-wide">
                  SOC-as-a-Service · Nigeria & Africa
                </span>
              </div>

              {/* H1 */}
              <h1 className="text-5xl lg:text-6xl font-black text-white leading-[1.05] mb-6 tracking-tight">
                Your Entire<br />
                Security<br />
                Operation. One<br />
                Platform.
              </h1>

              {/* Subtext */}
              <p className="text-white/60 text-base leading-relaxed mb-10 max-w-sm">
                Advanced threat detection, incident response, and continuous
                compliance monitoring tailored for the African threat landscape.
                Geared for high-stakes cybersecurity operations.
              </p>

              {/* CTAs */}
              <div className="flex items-center gap-4 flex-wrap">
                <Link href="/login"
                  className="flex items-center gap-2 bg-[#FF5500] text-white font-bold px-6 py-3.5 rounded-lg hover:bg-[#E54D00] transition-all hover:scale-[1.02] text-sm uppercase tracking-wider">
                  Get Started
                  <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                    <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </Link>
                <Link href="/login"
                  className="flex items-center gap-2 border border-white/30 text-white font-medium px-6 py-3.5 rounded-lg hover:bg-white/10 transition-all text-sm">
                  See Live Demo
                </Link>
              </div>
            </div>

            {/* Right — Dashboard Mockup */}
            <div className="relative">
              {/* Outer card */}
              <div className="bg-[#1C1F2E] rounded-2xl overflow-hidden border border-white/10 shadow-2xl"
                style={{ transform: 'perspective(1000px) rotateY(-2deg) rotateX(1deg)' }}>

                {/* Window chrome bar */}
                <div className="flex items-center gap-2 px-4 py-3 bg-[#13151E] border-b border-white/5">
                  <div className="w-3 h-3 rounded-full bg-[#CC2B2B]/70" />
                  <div className="w-3 h-3 rounded-full bg-[#FF5500]/70" />
                  <div className="w-3 h-3 rounded-full bg-green-500/70" />
                  <div className="ml-auto text-[10px] text-white/20 font-mono">
                    NovrSOC / v4.7.5 / 2 agents
                  </div>
                </div>

                {/* Dashboard content */}
                <div className="p-5">
                  {/* Two KPI cards top row */}
                  <div className="grid grid-cols-2 gap-3 mb-4">
                    <div className="bg-[#13151E] rounded-xl p-4 border border-white/5">
                      <div className="text-white/40 text-[10px] uppercase tracking-wider mb-1">
                        Active Threats
                      </div>
                      <div className="text-white font-black text-3xl font-mono">47</div>
                      <div className="text-[#CC2B2B] text-[10px] mt-1">▲ 3 new in last hour</div>
                    </div>
                    <div className="bg-[#13151E] rounded-xl p-4 border border-white/5">
                      <div className="text-white/40 text-[10px] uppercase tracking-wider mb-1">
                        Compliance Score
                      </div>
                      <div className="text-white font-black text-3xl font-mono">98.2%</div>
                      <div className="text-green-400 text-[10px] mt-1">▲ NDPR · CBN · ISO</div>
                    </div>
                  </div>

                  {/* Nigeria map area */}
                  <div className="bg-[#13151E] rounded-xl border border-white/5 overflow-hidden mb-3">
                    {/* Mini browser bar */}
                    <div className="flex items-center gap-2 px-3 py-2 border-b border-white/5">
                      <div className="w-2 h-2 rounded-full bg-[#520385]" />
                      <span className="text-[9px] text-white/30 font-mono">NovrSOC — Nigeria Threat Map</span>
                    </div>
                    {/* Map placeholder — dark with glowing state dots */}
                    <div className="relative h-48 bg-[#0D0F16] flex items-center justify-center overflow-hidden">
                      {/* Nigeria outline SVG — simplified */}
                      <svg viewBox="0 0 300 280" className="w-full h-full opacity-40 absolute inset-0"
                        xmlns="http://www.w3.org/2000/svg">
                        {/* Simplified Nigeria shape */}
                        <path
                          d="M60 40 L80 20 L140 15 L200 20 L250 40 L270 80 L265 130 L250 170 L230 210 L200 240 L170 260 L150 270 L130 265 L100 240 L80 220 L60 200 L40 170 L30 130 L35 80 Z"
                          fill="none"
                          stroke="#520385"
                          strokeWidth="2"
                        />
                        {/* State grid lines */}
                        <line x1="60" y1="140" x2="270" y2="140" stroke="#520385" strokeWidth="0.5" strokeDasharray="4,4" opacity="0.5"/>
                        <line x1="150" y1="20" x2="150" y2="265" stroke="#520385" strokeWidth="0.5" strokeDasharray="4,4" opacity="0.5"/>
                        <line x1="100" y1="20" x2="90" y2="265" stroke="#520385" strokeWidth="0.5" strokeDasharray="2,6" opacity="0.3"/>
                        <line x1="200" y1="20" x2="210" y2="240" stroke="#520385" strokeWidth="0.5" strokeDasharray="2,6" opacity="0.3"/>
                      </svg>

                      {/* Threat dots on map */}
                      {/* Lagos - south west */}
                      <div className="absolute bottom-[22%] left-[24%]">
                        <div className="w-3 h-3 rounded-full bg-[#FF5500] animate-ping absolute opacity-75" />
                        <div className="w-3 h-3 rounded-full bg-[#FF5500] relative" />
                      </div>
                      {/* Abuja - center */}
                      <div className="absolute top-[42%] left-[44%]">
                        <div className="w-2.5 h-2.5 rounded-full bg-[#F59E0B] animate-ping absolute opacity-75" />
                        <div className="w-2.5 h-2.5 rounded-full bg-[#F59E0B] relative" />
                      </div>
                      {/* Borno - north east, critical */}
                      <div className="absolute top-[18%] right-[20%]">
                        <div className="w-3 h-3 rounded-full bg-[#CC2B2B] animate-ping absolute opacity-75" />
                        <div className="w-3 h-3 rounded-full bg-[#CC2B2B] relative" />
                      </div>
                      {/* Kano - north */}
                      <div className="absolute top-[28%] left-[40%]">
                        <div className="w-2 h-2 rounded-full bg-[#2B3BCC] relative" />
                      </div>
                      {/* Rivers - south */}
                      <div className="absolute bottom-[30%] left-[38%]">
                        <div className="w-2 h-2 rounded-full bg-[#FF5500] animate-ping absolute opacity-60" />
                        <div className="w-2 h-2 rounded-full bg-[#FF5500] relative" />
                      </div>

                      {/* Lagos label */}
                      <div className="absolute bottom-[18%] left-[14%] text-[8px] text-[#FF5500] font-mono font-bold">
                        Lagos · HIGH
                      </div>
                      {/* Borno label */}
                      <div className="absolute top-[12%] right-[8%] text-[8px] text-[#CC2B2B] font-mono font-bold">
                        Borno · CRIT
                      </div>
                    </div>
                  </div>

                  {/* Live alert bar */}
                  <div className="bg-[#CC2B2B]/10 border border-[#CC2B2B]/30 rounded-xl px-4 py-3 flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full bg-[#CC2B2B] animate-pulse flex-shrink-0" />
                    <span className="text-[#CC2B2B] text-[11px] font-mono font-bold truncate">
                      Ryuk C2 Detected [IP: 91.215.153.180] — Elevating to TIER 2
                    </span>
                  </div>
                </div>
              </div>

              {/* Floating glow behind card */}
              <div className="absolute inset-0 bg-[#FF5500]/10 blur-3xl -z-10 rounded-full" />
            </div>
          </div>
        </div>
      </section>

      {/* ── FREE WEBSITE SECURITY SCANNER ─────────────────────────────── */}
      <section className="py-16 bg-[#F8F9FC]">
        <div className="max-w-3xl mx-auto px-6 text-center">
          <div className="inline-flex items-center gap-2 bg-[#F5F0FF] border border-[#520385]/20
                          rounded-full px-4 py-2 mb-6">
            <span className="text-[#520385] text-xs font-bold uppercase tracking-wider">
              Free Tool
            </span>
          </div>
          <h2 className="text-3xl font-black text-[#1C1F2E] mb-3">
            Website Security Scanner
          </h2>
          <p className="text-[#7A8099] mb-8">
            Scan any website, IP address, or domain for threats, malware, and security issues —
            powered by 9 threat intelligence sources running behind the scenes.
          </p>
          <HomepageScanner />
        </div>
      </section>

      {/* ── SOCIAL PROOF BAR ───────────────────────────────────────── */}
      <section className="bg-white border-b border-[#EEF0F6] py-6">
        <div className="max-w-6xl mx-auto px-6">
          <div className="flex items-center justify-center gap-2 flex-wrap">
            <span className="text-[#7A8099] text-xs mr-4">Trusted by security teams across Nigeria</span>
            {['MTN Nigeria', 'GTBank', 'Dangote Group', 'Airtel Nigeria', 'MainOne'].map((name, i) => (
              <span key={name} className="flex items-center gap-2">
                {i > 0 && <span className="text-[#EEF0F6]">·</span>}
                <span className="text-[#1C1F2E] text-sm font-semibold">{name}</span>
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ── FEATURES STRIP ─────────────────────────────────────────── */}
      <section id="features" className="bg-white py-24">
        <div className="max-w-6xl mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-black text-[#1C1F2E] mb-4 tracking-tight">
              One platform. Six security domains.
            </h2>
            <p className="text-[#7A8099] text-base max-w-xl mx-auto">
              From brand protection to incident response — every layer of your
              organisation's security posture, managed from one dashboard.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {[
              {
                icon: '🛡',
                title: 'Brand Protection',
                desc: 'Monitor domains, social media, dark web, and app stores for brand impersonation.',
                tags: ['Domain Suite', 'Social Suite', 'Executive Monitoring'],
              },
              {
                icon: '🔍',
                title: 'Threat Intelligence',
                desc: 'Real-time IOC lookup, CVE monitoring, URL scanning, and vendor risk scoring.',
                tags: ['CTI Platform', 'Threat Advisory', 'Vendor Assessments'],
              },
              {
                icon: '🌐',
                title: 'Infrastructure',
                desc: 'Live endpoint inventory, DNS health monitoring, and middleware performance.',
                tags: ['Digital Assets', 'DNS Suite', 'WebLogic'],
              },
              {
                icon: '✉️',
                title: 'Email Security',
                desc: 'DMARC enforcement, gateway monitoring, and AI-powered phishing detection.',
                tags: ['DMARC SaaS', 'Messaging Suite', 'PHISHID'],
              },
              {
                icon: '⚡',
                title: 'SecOps & Response',
                desc: 'Real-time alert queue, incident lifecycle management, and multi-channel alerts.',
                tags: ['Threat Management', 'Incident Response', 'Alert Communication'],
              },
              {
                icon: '💾',
                title: 'Data Continuity',
                desc: 'Backup integrity verification, SLA tracking, and recovery credit automation.',
                tags: ['Data Loss Recovery', 'Recovery Credit'],
              },
            ].map(feature => (
              <div key={feature.title}
                className="bg-white border border-[#EEF0F6] rounded-xl p-6 hover:border-[#520385]/40 hover:shadow-sm transition-all group cursor-pointer">
                <div className="text-2xl mb-4">{feature.icon}</div>
                <h3 className="font-bold text-[#1C1F2E] text-base mb-2 group-hover:text-[#520385] transition-colors">
                  {feature.title}
                </h3>
                <p className="text-[#7A8099] text-sm leading-relaxed mb-4">{feature.desc}</p>
                <div className="flex flex-wrap gap-1.5">
                  {feature.tags.map(tag => (
                    <span key={tag}
                      className="text-[10px] font-medium bg-[#F5F0FF] text-[#520385] px-2.5 py-1 rounded-full">
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── NIGERIA CALLOUT ────────────────────────────────────────── */}
      <section className="bg-[#520385] py-24">
        <div className="max-w-6xl mx-auto px-6">
          <div className="text-center mb-14">
            <h2 className="text-4xl font-black text-white mb-4 tracking-tight">
              Built specifically for Nigeria
            </h2>
            <p className="text-white/60 text-base max-w-lg mx-auto">
              Not a global product retrofitted for Africa. Built from the ground up
              for the Nigerian threat landscape, regulatory environment, and infrastructure.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[
              {
                title: 'Nigeria Threat Map',
                desc: 'State-by-state threat intelligence map. Click any of Nigeria\'s 37 states to see active threats, monitored IPs, and live Wazuh alerts from that region.',
              },
              {
                title: 'Nigerian ASN Intelligence',
                desc: 'Enriched threat data for all Nigerian ISPs — MTN, Airtel, Glo, 9mobile. Know exactly which local networks your threats are originating from.',
              },
              {
                title: 'Local Compliance',
                desc: 'Built-in monitoring for NDPR, CBN Cybersecurity Framework, and Nigerian banking regulations. Automatic score tracking and exportable evidence reports.',
              },
            ].map(item => (
              <div key={item.title}
                className="bg-white/5 border border-white/10 rounded-xl p-6 hover:bg-white/10 transition-colors">
                <div className="w-8 h-8 bg-[#FF5500] rounded-lg mb-4 flex items-center justify-center">
                  <div className="w-3 h-3 bg-white rounded-sm" />
                </div>
                <h3 className="font-bold text-white text-base mb-3">{item.title}</h3>
                <p className="text-white/50 text-sm leading-relaxed">{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── COMPLIANCE ─────────────────────────────────────────────── */}
      <section id="compliance" className="py-24 bg-white">
        <div className="max-w-6xl mx-auto px-6">
          <div className="grid md:grid-cols-2 gap-12 items-center">
            <div>
              <div className="inline-flex items-center gap-2 bg-[#F5F0FF]
                              border border-[#520385]/20 rounded-full px-4 py-2 mb-6">
                <span className="text-[#520385] text-xs font-bold">
                  Nigerian Compliance
                </span>
              </div>
              <h2 className="text-4xl font-black text-[#1C1F2E] mb-4 tracking-tight">
                Built for Nigerian<br />Regulatory Requirements
              </h2>
              <p className="text-[#7A8099] mb-8">
                NovrSOC tracks compliance across every major framework relevant to Nigerian
                enterprises. Show your board a live compliance score, not a spreadsheet.
              </p>
              <div className="space-y-3">
                {[
                  { name: 'NDPA', desc: 'Nigeria Data Protection Act' },
                  { name: 'CBN', desc: 'CBN Cybersecurity Framework' },
                  { name: 'NCC', desc: 'NCC Consumer Protection' },
                  { name: 'ISO 27001', desc: 'Information Security Management' },
                  { name: 'PCI-DSS', desc: 'Payment Card Industry Standard' },
                ].map(f => (
                  <div key={f.name}
                    className="flex items-center gap-3 bg-[#F8F9FC] border
                               border-[#EEF0F6] rounded-xl p-3">
                    <div className="w-8 h-8 rounded-lg bg-[#520385] flex items-center
                                    justify-center flex-shrink-0">
                      <span className="text-white text-[9px] font-black">{f.name.slice(0, 3)}</span>
                    </div>
                    <div>
                      <div className="text-sm font-bold text-[#1C1F2E]">{f.name}</div>
                      <div className="text-[10px] text-[#7A8099]">{f.desc}</div>
                    </div>
                    <div className="ml-auto text-[10px] text-green-600 font-bold">
                      Supported ✓
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* ISO Certificate card */}
            <div className="space-y-4">
              <div className="bg-white border-2 border-[#520385]/20 rounded-3xl p-8
                              text-center shadow-lg">
                <div className="w-20 h-20 bg-[#520385] rounded-2xl flex items-center
                                justify-center mx-auto mb-4">
                  <span className="text-white text-2xl font-black">ISO</span>
                </div>
                <h3 className="text-xl font-black text-[#1C1F2E] mb-2">
                  ISO 27001 Certified
                </h3>
                <p className="text-sm text-[#7A8099] mb-4">
                  NovrSOC is built on ISO 27001 certified infrastructure and follows information
                  security management best practices.
                </p>
                <div className="border-t border-[#EEF0F6] pt-4">
                  <div className="text-[10px] text-[#7A8099] uppercase tracking-wider mb-2">
                    Certificate Details
                  </div>
                  <div className="text-sm font-bold text-[#1C1F2E]">Cybernovr Limited</div>
                  <div className="text-xs text-[#7A8099]">
                    Information Security Management System
                  </div>
                  <div className="mt-3 inline-flex items-center gap-2 bg-green-50
                                  border border-green-200 rounded-full px-3 py-1">
                    <div className="w-1.5 h-1.5 rounded-full bg-green-500" />
                    <span className="text-[10px] text-green-700 font-bold">
                      Certificate Valid
                    </span>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                {[
                  { icon: '🔒', title: 'SOC 2 Type II', desc: 'In progress' },
                  { icon: '🌍', title: 'GDPR Ready', desc: 'Data residency options' },
                  { icon: '🏛️', title: 'CBN Compliant', desc: 'Financial sector ready' },
                  { icon: '📋', title: 'NDPA Aligned', desc: 'Nigerian data law' },
                ].map(c => (
                  <div key={c.title}
                    className="bg-[#F8F9FC] border border-[#EEF0F6] rounded-2xl p-4 text-center">
                    <div className="text-2xl mb-2">{c.icon}</div>
                    <div className="text-xs font-bold text-[#1C1F2E]">{c.title}</div>
                    <div className="text-[10px] text-[#7A8099] mt-1">{c.desc}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── SOAR PIPELINE VISUAL ──────────────────────────────────────── */}
      <section className="py-20 bg-[#F8F9FC]">
        <div className="max-w-6xl mx-auto px-6 text-center">
          <h2 className="text-4xl font-black text-[#1C1F2E] mb-4 tracking-tight">
            Automated Response in Seconds
          </h2>
          <p className="text-[#7A8099] mb-12 max-w-xl mx-auto">
            From threat detection to case creation — fully automated. Your team focuses on
            investigation, not alert fatigue.
          </p>
          <div className="flex flex-col md:flex-row items-center justify-center gap-3">
            {[
              { step: '01', title: 'Threat Detected', icon: '🚨', desc: 'Wazuh SIEM detects anomaly across any endpoint' },
              { step: '02', title: 'Alert Enriched', icon: '🔍', desc: 'MITRE mapping, source IP geo, CVE correlation' },
              { step: '03', title: 'Case Auto-Created', icon: '📋', desc: 'TheHive case created with full context instantly' },
              { step: '04', title: 'Team Notified', icon: '📲', desc: 'Slack alert sent with case link and severity' },
              { step: '05', title: 'Analyst Responds', icon: '🧑‍💻', desc: 'Full investigation inside the NovrSOC dashboard' },
            ].map((s, i, arr) => (
              <div key={s.step} className="flex flex-col md:flex-row items-center">
                <div className="bg-white border border-[#EEF0F6] rounded-2xl p-5
                                text-center w-44 hover:border-[#520385]/30 hover:shadow-md
                                transition-all">
                  <div className="text-2xl mb-2">{s.icon}</div>
                  <div className="text-[9px] text-[#520385] font-black mb-1">{s.step}</div>
                  <div className="text-xs font-bold text-[#1C1F2E] mb-1">{s.title}</div>
                  <div className="text-[10px] text-[#7A8099]">{s.desc}</div>
                </div>
                {i < arr.length - 1 && (
                  <div className="text-[#EEF0F6] text-2xl mx-1 rotate-90 md:rotate-0">→</div>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── STATS BAR ──────────────────────────────────────────────── */}
      <section className="bg-white border-y border-[#EEF0F6] py-12">
        <div className="max-w-6xl mx-auto px-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
            {[
              { value: '22+', label: 'Security Features' },
              { value: '16',  label: 'Live API Sources' },
              { value: '37',  label: 'Nigerian States Monitored' },
              { value: '<2s', label: 'Threat Classification Time' },
            ].map(stat => (
              <div key={stat.label}>
                <div className="font-black text-4xl text-[#520385] mb-1">{stat.value}</div>
                <div className="text-[#7A8099] text-sm">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── PRICING ────────────────────────────────────────────────── */}
      <section id="pricing" className="bg-[#F8F9FC] py-24">
        <div className="max-w-6xl mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-black text-[#1C1F2E] mb-4 tracking-tight">
              Simple, transparent pricing
            </h2>
            <p className="text-[#7A8099] text-base">All plans include all 22 features. Scale as you grow.</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-4xl mx-auto">
            {[
              {
                name: 'Starter',
                price: '$299',
                desc: 'For growing businesses',
                features: ['Up to 10 endpoints', '2 domains monitored', 'Email + Slack alerts', 'Standard support'],
                highlight: false,
              },
              {
                name: 'Professional',
                price: '$799',
                desc: 'For established enterprises',
                features: ['Up to 50 endpoints', '10 domains monitored', 'All alert channels', 'Priority support', 'Quarterly compliance reports'],
                highlight: true,
              },
              {
                name: 'Enterprise',
                price: 'Custom',
                desc: 'For large organisations',
                features: ['Unlimited endpoints', 'Unlimited domains', 'Dedicated SOC analyst', 'Custom SLA', 'NDPR/CBN package'],
                highlight: false,
              },
            ].map(plan => (
              <div key={plan.name}
                className={`rounded-xl p-7 border ${
                  plan.highlight
                    ? 'bg-[#520385] border-[#520385] relative'
                    : 'bg-white border-[#EEF0F6]'
                }`}>
                {plan.highlight && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-[#FF5500] text-white text-[10px] font-bold px-3 py-1 rounded-full uppercase tracking-wider">
                    Most Popular
                  </div>
                )}
                <div className={`text-sm font-semibold mb-1 ${plan.highlight ? 'text-white/60' : 'text-[#7A8099]'}`}>
                  {plan.name}
                </div>
                <div className={`font-black text-4xl mb-1 ${plan.highlight ? 'text-white' : 'text-[#1C1F2E]'}`}>
                  {plan.price}
                  {plan.price !== 'Custom' && <span className={`text-base font-normal ${plan.highlight ? 'text-white/50' : 'text-[#7A8099]'}`}>/mo</span>}
                </div>
                <div className={`text-xs mb-6 ${plan.highlight ? 'text-white/50' : 'text-[#7A8099]'}`}>
                  {plan.desc}
                </div>
                <ul className="space-y-2.5 mb-8">
                  {plan.features.map(f => (
                    <li key={f} className="flex items-center gap-2.5">
                      <span className={`text-xs font-bold ${plan.highlight ? 'text-[#FF5500]' : 'text-[#520385]'}`}>✓</span>
                      <span className={`text-sm ${plan.highlight ? 'text-white/80' : 'text-[#1C1F2E]'}`}>{f}</span>
                    </li>
                  ))}
                </ul>
                <Link href="/login"
                  className={`block text-center text-sm font-bold py-3 rounded-lg transition-all ${
                    plan.highlight
                      ? 'bg-[#FF5500] text-white hover:bg-[#E54D00]'
                      : 'border border-[#520385] text-[#520385] hover:bg-[#F5F0FF]'
                  }`}>
                  {plan.price === 'Custom' ? 'Contact Sales' : 'Get Started'}
                </Link>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── FINAL CTA ──────────────────────────────────────────────── */}
      <section className="bg-[#1C1F2E] py-24">
        <div className="max-w-6xl mx-auto px-6 text-center">
          <h2 className="text-4xl font-black text-white mb-4 tracking-tight">
            Ready to secure your organisation?
          </h2>
          <p className="text-white/50 text-base mb-10 max-w-md mx-auto">
            Join security teams across Nigeria using NovrSOC to protect their
            brands, infrastructure, and data.
          </p>
          <div className="flex items-center justify-center gap-4 flex-wrap">
            <Link href="/login"
              className="bg-[#FF5500] text-white font-bold px-8 py-3.5 rounded-lg hover:bg-[#E54D00] transition-all hover:scale-[1.02] text-sm uppercase tracking-wider">
              Start Free Trial
            </Link>
            <Link href="/login"
              className="border border-white/20 text-white font-medium px-8 py-3.5 rounded-lg hover:bg-white/10 transition-all text-sm">
              Talk to an Expert
            </Link>
          </div>
          <p className="text-white/20 text-xs mt-6">
            No credit card required · 14-day free trial · Cancel anytime
          </p>
        </div>
      </section>

      {/* ── FOOTER ─────────────────────────────────────────────────── */}
      <footer className="bg-white border-t border-[#EEF0F6] py-16">
        <div className="max-w-6xl mx-auto px-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-10 mb-12">

            {/* Brand */}
            <div>
              {/* eslint-disable-next-line @next/next/no-img-element -- fixed small brand mark */}
              <img src="/novrsoc.jpg" alt="NovrSOC by Cybernovr" className="h-8 w-auto object-contain mb-3" />
              <p className="text-[#7A8099] text-sm leading-relaxed">
                Powered by Cybernovr · Lagos, Nigeria
              </p>
            </div>

            {/* Product */}
            <div>
              <h4 className="font-bold text-[#1C1F2E] text-sm mb-4">Product</h4>
              <ul className="space-y-3">
                {['Platform', 'Features', 'Integrations', 'Solutions'].map(item => (
                  <li key={item}>
                    <a href="#" className="text-[#7A8099] text-sm hover:text-[#520385] transition-colors">
                      {item}
                    </a>
                  </li>
                ))}
              </ul>
            </div>

            {/* Company */}
            <div>
              <h4 className="font-bold text-[#1C1F2E] text-sm mb-4">Company</h4>
              <ul className="space-y-3">
                {['About Us', 'Careers', 'Press'].map(item => (
                  <li key={item}>
                    <a href="#" className="text-[#7A8099] text-sm hover:text-[#520385] transition-colors">
                      {item}
                    </a>
                  </li>
                ))}
              </ul>
            </div>

            {/* Legal */}
            <div>
              <h4 className="font-bold text-[#1C1F2E] text-sm mb-4">Legal</h4>
              <ul className="space-y-3">
                {['Legal', 'Privacy Policy', 'Terms of Service', 'Security'].map(item => (
                  <li key={item}>
                    <a href="#" className="text-[#7A8099] text-sm hover:text-[#520385] transition-colors">
                      {item}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Bottom bar */}
          <div className="border-t border-[#EEF0F6] pt-6 flex items-center justify-between flex-wrap gap-4">
            <p className="text-[#7A8099] text-xs">© 2026 Cybernovr. All rights reserved.</p>
            <p className="text-[#7A8099] text-xs">NovrSOC · Enterprise SOC-as-a-Service for Africa</p>
          </div>
        </div>
      </footer>

    </div>
  );
}
