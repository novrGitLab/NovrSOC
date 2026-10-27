import type { Metadata } from 'next';
import { LandingNav } from '@/components/features/LandingNav';
import { Footer } from '@/components/features/Footer';
import { PageHero } from '@/components/features/PageHero';
import { DetailItem } from '@/components/features/DetailList';
import { RelatedLinks } from '@/components/features/RelatedLinks';
import { CTABand } from '@/components/features/CTABand';

export const metadata: Metadata = {
    title: 'Regulators | NovrSOC by Cybernovr',
    description: 'Real-time, regulator-ready compliance-exception reporting across the organisations you supervise, mapped to the frameworks you enforce.',
};

export default function RegulatorsPage() {
    return (
        <div className="min-h-screen bg-white font-sans">
            <LandingNav />
            <PageHero
                breadcrumb="Regulators"
                eyebrow="NovrSOC / Regulators"
                title="Compliance oversight, not spreadsheets."
                description="Real-time, regulator-ready reporting on the organisations under your supervision, mapped to the frameworks you enforce."
                ctaHref="/grc"
                ctaLabel="Explore GRC & Reporting"
            />

            <section className="py-20">
                <div className="max-w-4xl mx-auto px-6">
                    <h2 className="text-2xl font-black text-gray-900 mb-2">From self-reported to continuously verified</h2>
                    <p className="text-gray-500 mb-8">Oversight built around the artefacts a regulator actually needs to produce.</p>
                    <DetailItem title="Compliance-exception reporting">
                        See exceptions against NCS-CRF, NDPA, NCC and CBN as they happen, not at the next audit cycle.
                    </DetailItem>
                    <DetailItem title="Regulator-ready templates">
                        Generate submission-ready reports in the format your office already expects.
                    </DetailItem>
                    <DetailItem title="Board-level reporting">
                        Summarise resilience posture for boards and oversight committees without translating it yourself.
                    </DetailItem>
                    <DetailItem title="Real-time resilience maturity">
                        Track resilience maturity per provider or per sector, updated continuously rather than self-reported.
                    </DetailItem>
                </div>
            </section>

            <RelatedLinks
                items={[
                    { href: '/grc', title: 'GRC & Reporting', desc: 'How NovrSOC connects findings to frameworks, and frameworks to reports.' },
                    { href: '/cnii', title: 'CNII Watch', desc: 'Sector-aware visibility across IT and OT for critical national infrastructure.' },
                    { href: '/cert-csirt', title: "Who it's for: CERTs & CSIRTs", desc: 'The operational counterpart to regulatory oversight — see how it connects.' },
                ]}
            />

            <CTABand text="Explore how NovrSOC by Cybernovr can support your supervisory mandate." />
            <Footer />
        </div>
    );
}
