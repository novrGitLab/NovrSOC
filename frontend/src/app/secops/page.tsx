import type { Metadata } from 'next';
import { LandingNav } from '@/components/features/LandingNav';
import { Footer } from '@/components/features/Footer';
import { PageHero } from '@/components/features/PageHero';
import { DetailItem } from '@/components/features/DetailList';
import { RelatedLinks } from '@/components/features/RelatedLinks';
import { CTABand } from '@/components/features/CTABand';

export const metadata: Metadata = {
    title: 'Detection & Response | NovrSOC by Cybernovr',
    description: 'Unify monitoring, investigation, case management and governed automation for faster, more consistent security operations.',
};

const SURFACE = [
    { icon: '📡', title: 'SIEM', desc: 'Centralised log collection and correlation against detection rules, with MITRE ATT&CK mapping on every alert.' },
    { icon: '👤', title: 'UEBA', desc: 'User and entity behaviour analytics surface anomalies that signature-based detection alone would miss.' },
    { icon: '🌐', title: 'NDR', desc: 'Network detection and response correlated alongside endpoint and identity signals, not reviewed in isolation.' },
    { icon: '🚨', title: 'IDS', desc: 'Intrusion detection feeding the same case pipeline as every other detection source.' },
    { icon: '🦠', title: 'Malware analysis', desc: 'Automated analysis of suspicious files and behaviour, attached directly to the case it belongs to.' },
    { icon: '⚡', title: 'SOAR', desc: 'Tiered, policy-gated automated response — see the pipeline below.' },
];

const PIPELINE = [
    { step: '01', title: 'Detected', desc: 'SIEM correlates the signal against detection rules' },
    { step: '02', title: 'Enriched', desc: 'MITRE ATT&CK mapping and source context added automatically' },
    { step: '03', title: 'Case created', desc: 'Opened automatically, with no analyst time spent on triage' },
    { step: '04', title: 'Notified', desc: 'Relevant analysts and stakeholders alerted immediately' },
    { step: '05', title: 'Resolved', desc: 'Analyst investigates and closes with a governed, audited action' },
];

export default function SecOpsPage() {
    return (
        <div className="min-h-screen bg-white font-sans">
            <LandingNav />
            <PageHero
                breadcrumb="Detection & Response"
                eyebrow="NovrSOC / Detection & Response"
                title="From alert to action. With oversight."
                description="Unify monitoring, investigation, case management and governed automation for faster, more consistent security operations."
            />

            <section className="py-20">
                <div className="max-w-4xl mx-auto px-6">
                    <h2 className="text-2xl font-black text-gray-900 mb-6">Built for clarity across the security lifecycle</h2>
                    <DetailItem title="Unified alert operations">
                        SIEM monitoring correlates every endpoint against tens of thousands of detection rules, with MITRE ATT&CK mapping on each alert and automatic case creation for anything that matters.
                    </DetailItem>
                    <DetailItem title="Tiered automated response">
                        Low-severity alerts enrich and auto-close with no analyst time spent; mid-tier alerts trigger a recommended containment action — such as blocking the source IP — that runs under a pre-approved policy or waits for analyst approval, configurable per tenant; critical alerts escalate to the CISO.
                    </DetailItem>
                    <DetailItem title="Automation with guardrails">
                        Reduce repetitive triage while preserving accountability and audit trails — every automated action is logged as succeeded, skipped or failed.
                    </DetailItem>
                    <DetailItem title="AI-assisted understanding">
                        NovrAI summarises evidence, maps alerts to MITRE ATT&CK technique and proposes next steps, grounded in your live platform data rather than generic advice.
                    </DetailItem>
                    <DetailItem title="ML-driven correlation">
                        Machine-learning correlation merges disparate alerts from across sources into a single incident, instead of leaving analysts to connect them by hand.
                    </DetailItem>
                    <DetailItem title="Natural-language investigation">
                        Ask a case a question in plain language and get an answer grounded in its actual evidence, not a canned response.
                    </DetailItem>
                </div>
            </section>

            <section className="py-20 bg-gray-50 border-y border-gray-100">
                <div className="max-w-7xl mx-auto px-6">
                    <div className="text-center mb-14">
                        <h2 className="text-3xl md:text-4xl font-black text-gray-900 mb-4">
                            One correlated pipeline, not six separate tools.
                        </h2>
                        <p className="text-gray-500 max-w-2xl mx-auto">
                            SIEM, UEBA, NDR, IDS, malware analysis and SOAR, feeding the same cases and the same correlation layer.
                        </p>
                    </div>
                    <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5">
                        {SURFACE.map((s) => (
                            <div key={s.title} className="bg-white border border-gray-100 rounded-2xl p-6">
                                <span className="text-3xl mb-3 block">{s.icon}</span>
                                <h3 className="font-black text-gray-900 mb-2">{s.title}</h3>
                                <p className="text-sm text-gray-500 leading-relaxed">{s.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            <section className="py-20 bg-gray-950">
                <div className="max-w-7xl mx-auto px-6 text-center">
                    <h2 className="text-3xl md:text-4xl font-black text-white mb-4">
                        From Threat to Resolution in Minutes
                    </h2>
                    <p className="text-white/50 mb-14 max-w-xl mx-auto">
                        Fully automated incident response pipeline. Your team focuses on investigation, not alert fatigue.
                    </p>
                    <div className="flex flex-col md:flex-row items-center justify-center gap-3 flex-wrap">
                        {PIPELINE.map((s, i) => (
                            <div key={s.step} className="flex items-center gap-3">
                                <div className="bg-white/5 border border-white/10 rounded-2xl p-5 text-center w-40 hover:border-purple-500/50 hover:bg-white/10 transition-all">
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

            <RelatedLinks
                items={[
                    { href: '/cnii', title: 'CNII Watch', desc: 'See risk through a national, sector, subsector and organisation lens.' },
                    { href: '/vms', title: 'Vulnerability Management', desc: 'Connect asset discovery, risk scoring, scanning and remediation tracking.' },
                    { href: '/ti', title: 'Threat Intelligence', desc: 'Correlate indicators, advisories and local intelligence with your environment.' },
                ]}
            />

            <CTABand text="Explore how NovrSOC by Cybernovr can connect your security operations." />
            <Footer />
        </div>
    );
}
