import type { Metadata } from 'next';
import Link from 'next/link';
import { LandingNav } from '@/components/features/LandingNav';
import { Footer } from '@/components/features/Footer';
import { PageHero } from '@/components/features/PageHero';
import { DetailItem } from '@/components/features/DetailList';
import { RelatedLinks } from '@/components/features/RelatedLinks';
import { CTABand } from '@/components/features/CTABand';

export const metadata: Metadata = {
    title: 'GRC & Reporting | NovrSOC by Cybernovr',
    description: 'Governance, risk and compliance reporting connected directly to live findings — risk-based remediation, incident reporting, CISO dashboards and regulator templates.',
};

export default function GRCPage() {
    return (
        <div className="min-h-screen bg-white font-sans">
            <LandingNav />
            <PageHero
                breadcrumb="GRC & Reporting"
                eyebrow="NovrSOC / GRC & Reporting"
                title="From a live finding to a governed outcome."
                description="NovrSOC connects what it detects to how it gets governed — risk-based remediation, incident reporting and compliance monitoring, feeding CISO dashboards and regulator templates directly from platform data."
            />

            <section className="py-20">
                <div className="max-w-4xl mx-auto px-6">
                    <h2 className="text-2xl font-black text-gray-900 mb-2">Connected, not copied</h2>
                    <p className="text-gray-500 mb-8 leading-relaxed">
                        Findings, cases and exposure data flow directly into governance workflows — including NovrGRC,
                        Cybernovr&apos;s dedicated risk and compliance product — rather than being re-entered by hand.
                        {/* TODO: confirm exact NovrSOC/NovrGRC integration mechanism and add the NovrGRC product link */}
                    </p>
                    <DetailItem title="Risk-based remediation">
                        Prioritise remediation by business risk, not just technical severity, and track it through to closure.
                    </DetailItem>
                    <DetailItem title="Incident reporting">
                        Turn a case into a regulator-ready incident report without re-keying the underlying facts.
                    </DetailItem>
                    <DetailItem title="Compliance monitoring">
                        Map findings and controls to NDPA, the CBN Cybersecurity Framework, NCC, ISO/IEC 27001 and PCI-DSS as they change, not once a year.
                    </DetailItem>
                    <DetailItem title="CISO dashboards">
                        A single live view of risk, exposure and compliance posture for leadership, without a manual roll-up.
                    </DetailItem>
                    <DetailItem title="Regulator templates">
                        Export in the formats your regulator already expects — see <Link href="/regulators" className="text-purple-700 font-semibold hover:underline">Regulators</Link>.
                    </DetailItem>
                </div>
            </section>

            <RelatedLinks
                items={[
                    { href: '/vms', title: 'Vulnerability Management', desc: 'Every finding carries the context GRC and remediation workflows need.' },
                    { href: '/regulators', title: 'Regulators', desc: 'See how the same evidence becomes regulator-ready reporting.' },
                    { href: '/cert-csirt', title: 'CERTs & Sectoral CSIRTs', desc: 'GRC and reporting for an entire constituency, not just one organisation.' },
                ]}
            />

            <CTABand text="Explore how NovrSOC by Cybernovr can connect your security operations." />
            <Footer />
        </div>
    );
}
