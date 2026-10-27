import type { Metadata } from 'next';
import { LandingNav } from '@/components/features/LandingNav';
import { Footer } from '@/components/features/Footer';
import { PageHero } from '@/components/features/PageHero';
import { DetailItem } from '@/components/features/DetailList';
import { CTABand } from '@/components/features/CTABand';

export const metadata: Metadata = {
    title: 'Privacy Policy | NovrSOC by Cybernovr',
    description: 'How Cybernovr handles personal data on this website and within the NovrSOC platform.',
};

// Kept short and honest: a short practice statement, not a long fabricated legal document. A
// full, counsel-reviewed privacy policy is available on request — see /trust for what is
// separately confirmed about platform-level data handling and security.
export default function PrivacyPage() {
    return (
        <div className="min-h-screen bg-white font-sans">
            <LandingNav />
            <PageHero
                breadcrumb="Privacy Policy"
                eyebrow="Legal"
                title="Privacy Policy"
                description="How Cybernovr handles personal data on this website and within the NovrSOC platform."
                ctaHref="/contact"
                ctaLabel="Request the full policy"
            />

            <section className="py-20">
                <div className="max-w-3xl mx-auto px-6">
                    <p className="text-gray-500 mb-8 leading-relaxed">
                        A full, counsel-reviewed Privacy Policy is available on request from our team. This page
                        summarises the practices that already apply today.
                    </p>
                    <DetailItem title="This website">
                        The scanner and contact form on this site do not require an account. The contact form opens
                        your own email client with a prefilled message — it does not submit or store anything on this
                        website. The scanner sends only the value you enter to be checked against threat intelligence
                        sources; it is not retained against your identity.
                    </DetailItem>
                    <DetailItem title="The NovrSOC platform">
                        Each client organisation&apos;s data is logically separated and scoped by role — see{' '}
                        <a href="/trust" className="text-blue-700 font-semibold hover:underline">Trust &amp; Deployment</a> for
                        tenant isolation, access control and audit trail detail.
                    </DetailItem>
                    <DetailItem title="Nigerian data protection">
                        The platform tracks NDPA obligations as a product capability for the organisations it monitors.
                        Cybernovr&apos;s own data-handling posture as a controller/processor under NDPA is confirmed
                        directly on request.
                    </DetailItem>
                    <DetailItem title="Contact">
                        Questions about this policy, or a request for the full document: <a href="mailto:soc@cybernovr.com" className="text-blue-700 font-semibold hover:underline">soc@cybernovr.com</a>.
                    </DetailItem>
                </div>
            </section>

            <CTABand text="Ask us anything about how your data is handled." />
            <Footer />
        </div>
    );
}
