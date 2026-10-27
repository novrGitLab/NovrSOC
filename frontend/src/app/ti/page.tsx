import type { Metadata } from 'next';
import { LandingNav } from '@/components/features/LandingNav';
import { Footer } from '@/components/features/Footer';
import { PageHero } from '@/components/features/PageHero';
import { DetailItem } from '@/components/features/DetailList';
import { RelatedLinks } from '@/components/features/RelatedLinks';
import { CTABand } from '@/components/features/CTABand';

export const metadata: Metadata = {
    title: 'Threat Intelligence & Sharing | NovrSOC by Cybernovr',
    description: 'Bring indicators, advisories, observed threats and Nigeria-focused context into one evidence-led intelligence workspace.',
};

export default function TIPage() {
    return (
        <div className="min-h-screen bg-white font-sans">
            <LandingNav />
            <PageHero
                breadcrumb="Threat Intelligence & Sharing"
                eyebrow="NovrSOC / Threat Intelligence"
                title="Intelligence that informs the next decision."
                description="Bring indicators, advisories, observed threats and Nigeria-focused context into one evidence-led intelligence workspace."
            />

            <section className="py-20">
                <div className="max-w-4xl mx-auto px-6">
                    <h2 className="text-2xl font-black text-gray-900 mb-6">Built for clarity across the security lifecycle</h2>
                    <DetailItem title="Indicator and advisory intelligence">
                        Enrich IPs, domains, hashes and URLs across nine intelligence sources at once, with IOC history, caching and STIX 2.1 export for sharing with partners and regulators.
                    </DetailItem>
                    <DetailItem title="Nigeria-focused visibility">
                        Explore relevant intelligence without confusing hosting geography with attack origin, with ngCERT and NCC-CSIRT advisories integrated directly into the feed.
                    </DetailItem>
                    <DetailItem title="Organisation context">
                        Correlate indicators and detections to the appropriate environment, with AI-assisted analysis surfacing what actually needs attention.
                    </DetailItem>
                    <DetailItem title="Analyst-ready investigation">
                        Keep provenance, confidence, sharing restrictions and investigation trails visible.
                    </DetailItem>
                    <DetailItem title="Sector-wide sharing">
                        Distribute IOCs, advisories and incident notices across a constituency, with acknowledgement tracking and escalation when nothing comes back.
                    </DetailItem>
                    <DetailItem title="Brand protection">
                        Monitor domains, social media, app stores and code repositories for typosquatting, impersonation and credential leaks tied to your organisation.
                    </DetailItem>
                    <DetailItem title="Email threat intelligence">
                        DMARC, SPF and DKIM monitoring with AI-assisted phishing detection and real-time blocklist checking.
                    </DetailItem>
                </div>
            </section>

            <RelatedLinks
                items={[
                    { href: '/cnii', title: 'CNII Watch', desc: 'See risk through a national, sector, subsector and organisation lens.' },
                    { href: '/vms', title: 'Vulnerability Management', desc: 'Connect asset discovery, risk scoring, scanning and remediation tracking.' },
                    { href: '/secops', title: 'Detection & Response', desc: 'Turn alerts into cases and governed response workflows, supported by AI.' },
                ]}
            />

            <CTABand text="Explore how NovrSOC by Cybernovr can connect your security operations." />
            <Footer />
        </div>
    );
}
