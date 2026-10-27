import type { Metadata } from 'next';
import { LandingNav } from '@/components/features/LandingNav';
import { Footer } from '@/components/features/Footer';
import { PageHero } from '@/components/features/PageHero';
import { DetailItem } from '@/components/features/DetailList';
import { RelatedLinks } from '@/components/features/RelatedLinks';
import { CTABand } from '@/components/features/CTABand';

export const metadata: Metadata = {
    title: 'CNII Watch | NovrSOC by Cybernovr',
    description: 'Sector-aware visibility across organisations, assets, exposure and risk — in IT and OT — designed for critical national information infrastructure oversight.',
};

export default function CNIIPage() {
    return (
        <div className="min-h-screen bg-white font-sans">
            <LandingNav />
            <PageHero
                breadcrumb="CNII Watch"
                eyebrow="NovrSOC / CNII Watch"
                title="Know what matters most to critical infrastructure."
                description="Sector-aware visibility across organisations, assets, exposure and risk — in IT and OT — designed for critical national information infrastructure oversight."
            />

            <section className="py-20">
                <div className="max-w-4xl mx-auto px-6">
                    <h2 className="text-2xl font-black text-gray-900 mb-6">Built for clarity across the security lifecycle</h2>
                    <DetailItem title="Sector-to-asset context">
                        Navigate from national overview to sector, subsector, organisation and associated assets.
                    </DetailItem>
                    <DetailItem title="Risk-informed oversight">
                        Connect authorised asset observations, vulnerabilities and threat signals.
                    </DetailItem>
                    <DetailItem title="Evidence-based mapping">
                        Clearly distinguish verified state-level data from country-only intelligence, backed by live telemetry across all 36 states and the FCT.
                    </DetailItem>
                    <DetailItem title="Audience-aware reporting">
                        Support operational and executive perspectives without overstating certainty.
                    </DetailItem>
                    <DetailItem title="CNII vulnerability mapping">
                        Map vulnerability and threat findings directly to critical national infrastructure, with ngCERT, NCC-CSIRT and CBN advisories layered into the picture.
                    </DetailItem>
                    <DetailItem title="IT and OT/ICS visibility">
                        Passive, non-intrusive scanning covers operational technology and industrial control system assets alongside IT, without the risk active scanning poses to OT environments.
                    </DetailItem>
                </div>
            </section>

            <RelatedLinks
                items={[
                    { href: '/vms', title: 'Vulnerability Management', desc: 'Connect asset discovery, risk scoring, scanning and remediation tracking.' },
                    { href: '/ti', title: 'Threat Intelligence', desc: 'Correlate indicators, advisories and local intelligence with your environment.' },
                    { href: '/secops', title: 'Detection & Response', desc: 'Turn alerts into cases and governed response workflows, supported by AI.' },
                ]}
            />

            <CTABand text="Explore how NovrSOC by Cybernovr can connect your security operations." />
            <Footer />
        </div>
    );
}
