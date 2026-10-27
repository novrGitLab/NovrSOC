import type { Metadata } from 'next';
import { LandingNav } from '@/components/features/LandingNav';
import { Footer } from '@/components/features/Footer';
import { PageHero } from '@/components/features/PageHero';
import { DetailItem } from '@/components/features/DetailList';
import { RelatedLinks } from '@/components/features/RelatedLinks';
import { CTABand } from '@/components/features/CTABand';

export const metadata: Metadata = {
    title: 'CERTs & Sectoral CSIRTs | NovrSOC by Cybernovr',
    description: 'A platform built for national and sectoral CERTs and CSIRTs to monitor their constituency, distribute intelligence and track response — without growing headcount.',
};

export default function CertCsirtPage() {
    return (
        <div className="min-h-screen bg-white font-sans">
            <LandingNav />
            <PageHero
                breadcrumb="CERTs & Sectoral CSIRTs"
                eyebrow="NovrSOC / CERTs & Sectoral CSIRTs"
                title="Oversight for your entire constituency."
                description="Monitor every organisation you're responsible for, distribute intelligence and track who's acted on it — without growing headcount to match."
            />

            <section className="py-20">
                <div className="max-w-4xl mx-auto px-6">
                    <h2 className="text-2xl font-black text-gray-900 mb-2">Six ways NovrSOC supports a CERT or CSIRT</h2>
                    <p className="text-gray-500 mb-8">Capabilities designed around the actual job: seeing your constituency, reaching it, and proving you did.</p>
                    <DetailItem title="Constituency monitoring at scale">
                        See exposure, threats and compliance posture across every organisation in your constituency from one aggregated view.
                    </DetailItem>
                    <DetailItem title="Sector-wide heatmaps with drill-down">
                        Start at the sector level, then drill into an individual provider&apos;s own data when something needs attention.
                    </DetailItem>
                    <DetailItem title="Threat intel distribution">
                        Push IOCs, advisories and incident notices to your constituency, with acknowledgement tracking and escalation when nothing comes back.
                    </DetailItem>
                    <DetailItem title="Anonymised benchmarking">
                        Compare patch cadence and exposure density across providers without exposing any one organisation&apos;s raw data.
                    </DetailItem>
                    <DetailItem title="Managed services with your existing team">
                        Deliver monitoring and response to your constituency without a proportional increase in analyst headcount.
                    </DetailItem>
                    <DetailItem title="CNII Watch">
                        Extend the same oversight model to critical national infrastructure, in IT and OT.
                    </DetailItem>
                    {/* TODO: add a pilot or reference CERT/CSIRT deployment once one exists */}
                </div>
            </section>

            <RelatedLinks
                heading="Related capabilities"
                items={[
                    { href: '/grc', title: 'GRC & Reporting', desc: 'Board-ready reporting mapped to the frameworks your constituency answers to.' },
                    { href: '/cnii', title: 'CNII Watch', desc: 'Sector-aware visibility across IT and OT for critical national infrastructure.' },
                    { href: '/ti', title: 'Threat Intelligence', desc: 'Correlate indicators, advisories and local intelligence with your constituency.' },
                ]}
            />

            <CTABand text="Explore how NovrSOC by Cybernovr can support your constituency." />
            <Footer />
        </div>
    );
}
