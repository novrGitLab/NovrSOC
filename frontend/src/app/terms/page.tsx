import type { Metadata } from 'next';
import { LandingNav } from '@/components/features/LandingNav';
import { Footer } from '@/components/features/Footer';
import { PageHero } from '@/components/features/PageHero';
import { DetailItem } from '@/components/features/DetailList';
import { CTABand } from '@/components/features/CTABand';

export const metadata: Metadata = {
    title: 'Terms of Service | NovrSOC by Cybernovr',
    description: 'The terms that govern using this website and the NovrSOC platform.',
};

// Kept short and honest, same rationale as /privacy: a summary of what's already true, not a
// fabricated binding legal document. Full commercial terms are agreed directly during procurement.
export default function TermsPage() {
    return (
        <div className="min-h-screen bg-white font-sans">
            <LandingNav />
            <PageHero
                breadcrumb="Terms of Service"
                eyebrow="Legal"
                title="Terms of Service"
                description="The terms that govern using this website and the NovrSOC platform."
                ctaHref="/contact"
                ctaLabel="Request the full terms"
            />

            <section className="py-20">
                <div className="max-w-3xl mx-auto px-6">
                    <p className="text-gray-500 mb-8 leading-relaxed">
                        Full commercial terms for the NovrSOC platform are agreed directly as part of procurement. This
                        page covers using this public website.
                    </p>
                    <DetailItem title="This website">
                        The free scanner and contact form are provided for evaluation purposes, without warranty, and
                        may change or be withdrawn at any time. The scanner is rate-limited per visitor.
                    </DetailItem>
                    <DetailItem title="The NovrSOC platform">
                        Access to the platform itself is governed by a separate agreement with Cybernovr, confirmed
                        during procurement — not by this page.
                    </DetailItem>
                    <DetailItem title="Intellectual property">
                        The NovrSOC name, the Cybernovr brand and the content of this site belong to Cybernovr unless
                        stated otherwise.
                    </DetailItem>
                    <DetailItem title="Contact">
                        Questions about these terms, or a request for full commercial terms: <a href="mailto:soc@cybernovr.com" className="text-purple font-semibold hover:underline">soc@cybernovr.com</a>.
                    </DetailItem>
                </div>
            </section>

            <CTABand text="Ask us anything before you commit to anything." />
            <Footer />
        </div>
    );
}
