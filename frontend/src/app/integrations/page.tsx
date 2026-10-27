import type { Metadata } from 'next';
import { LandingNav } from '@/components/features/LandingNav';
import { Footer } from '@/components/features/Footer';
import { PageHero } from '@/components/features/PageHero';
import { DetailItem } from '@/components/features/DetailList';
import { CTABand } from '@/components/features/CTABand';

export const metadata: Metadata = {
    title: 'Integrations | NovrSOC by Cybernovr',
    description: 'NovrSOC is built to sit on top of the security and IT stack you already run, not replace it. Integration categories and open APIs.',
};

const CATEGORIES = [
    { icon: '🧱', title: 'Firewalls', desc: 'Containment actions such as source-IP blocking route through your existing firewall.' },
    { icon: '🖥️', title: 'EDR / XDR', desc: 'Endpoint telemetry and behavioural detections feed the correlation layer.' },
    { icon: '📊', title: 'SIEM', desc: 'Correlate alongside, or in place of, an existing SIEM deployment.' },
    { icon: '📡', title: 'NDR', desc: 'Network detection signals correlated with endpoint and identity context.' },
    { icon: '🧬', title: 'Threat intel feeds', desc: "Bring your own feeds into the multi-source CTI platform alongside NovrSOC's own sources." },
    { icon: '☁️', title: 'Cloud', desc: 'Cloud posture and identity signals included in the same correlated view.' },
    { icon: '🔑', title: 'Identity', desc: 'Identity and access signals feed UEBA and investigation context.' },
    { icon: '🎫', title: 'Ticketing / ITSM', desc: 'Cases and remediation tasks route into the workflow tools your teams already use.' },
    { icon: '🏭', title: 'OT / ICS', desc: 'Passive, non-intrusive visibility designed for operational technology environments.' },
];

export default function IntegrationsPage() {
    return (
        <div className="min-h-screen bg-white font-sans">
            <LandingNav />
            <PageHero
                breadcrumb="Integrations"
                eyebrow="NovrSOC / Integrations"
                title="Built to sit on top of what you run."
                description="NovrSOC is vendor-agnostic by design — it correlates and acts on data from the tools you already operate, rather than asking you to replace them."
            />

            <section className="py-20">
                <div className="max-w-7xl mx-auto px-6">
                    <div className="mb-10">
                        <h2 className="text-2xl font-black text-gray-900 mb-2">Integration categories</h2>
                        <p className="text-gray-500 max-w-2xl">
                            Per-product integration status is being finalised; categories below reflect where NovrSOC is
                            designed to connect.
                            {/* TODO: replace with a per-vendor table (Native / API / Roadmap) once statuses are confirmed */}
                        </p>
                    </div>
                    <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5">
                        {CATEGORIES.map((c) => (
                            <div key={c.title} className="bg-white border border-gray-100 rounded-2xl p-6">
                                <span className="text-3xl mb-3 block">{c.icon}</span>
                                <h3 className="font-black text-gray-900 mb-2">{c.title}</h3>
                                <p className="text-sm text-gray-500 leading-relaxed">{c.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            <section className="py-20 bg-gray-50 border-y border-gray-100">
                <div className="max-w-4xl mx-auto px-6">
                    <h2 className="text-2xl font-black text-gray-900 mb-6">Open APIs</h2>
                    <DetailItem title="CTI API">
                        Query and enrich indicators programmatically against the same multi-source intelligence the platform uses.
                    </DetailItem>
                    <DetailItem title="SIEM API">
                        Pull correlated alerts and cases into your own tooling.
                    </DetailItem>
                    <DetailItem title="Workflow automation API">
                        Trigger and extend response actions from your own automation.
                    </DetailItem>
                </div>
            </section>

            <CTABand text="Ask us about connecting a specific tool in your stack." />
            <Footer />
        </div>
    );
}
