import type { Metadata } from 'next';
import { LandingNav } from '@/components/features/LandingNav';
import { Footer } from '@/components/features/Footer';
import { PageHero } from '@/components/features/PageHero';
import { DetailItem } from '@/components/features/DetailList';
import { CTABand } from '@/components/features/CTABand';

export const metadata: Metadata = {
    title: 'Trust & Deployment | NovrSOC by Cybernovr',
    description: 'How NovrSOC is deployed, isolated, secured and governed — deployment model, tenant isolation, access control, audit trails and responsible disclosure.',
};

export default function TrustPage() {
    return (
        <div className="min-h-screen bg-white font-sans">
            <LandingNav />
            <PageHero
                breadcrumb="Trust & Deployment"
                eyebrow="NovrSOC / Trust & Deployment"
                title="How NovrSOC is run, isolated and secured."
                description="What deploying NovrSOC actually means for your own security and compliance posture."
            />

            <section className="py-20">
                <div className="max-w-4xl mx-auto px-6">
                    <h2 className="text-2xl font-black text-gray-900 mb-6">Deployment &amp; security</h2>
                    <DetailItem title="Deployment model">
                        NovrSOC is delivered as a cloud-native SaaS platform.
                    </DetailItem>
                    <DetailItem title="Data residency & hosting location">
                        Hosting region and provider details are confirmed on request during procurement.
                        {/* TODO: publish the confirmed hosting region/provider here */}
                    </DetailItem>
                    <DetailItem title="NDPA alignment">
                        The platform tracks NDPA obligations for the organisations you monitor as a product capability.
                        {/* TODO: confirm Cybernovr's own data-handling posture under NDPA, separately from this product feature */}
                    </DetailItem>
                    <DetailItem title="Tenant isolation">
                        Each tenant&apos;s data is logically separated, with access scoped by organisation.
                    </DetailItem>
                    <DetailItem title="Access control">
                        Role-based access control, scoped by organisation and role, with Google sign-in support today.
                        Broader SSO (SAML) and multi-factor authentication are on the roadmap, not yet implemented.
                    </DetailItem>
                    <DetailItem title="Audit trails">
                        Scans, access and configuration changes are logged for later review.
                        {/* TODO: confirm audit log retention period and export format */}
                    </DetailItem>
                    <DetailItem title="Encryption">
                        Data is encrypted in transit and at rest.
                        {/* TODO: confirm specific algorithms/key management for public disclosure */}
                    </DetailItem>
                    <DetailItem title="Availability">
                        Availability commitments are confirmed as part of procurement, not published as a standing number here
                        without a contract behind it.
                    </DetailItem>
                </div>
            </section>

            <section className="py-20 bg-gray-50 border-y border-gray-100">
                <div className="max-w-4xl mx-auto px-6">
                    <h2 className="text-2xl font-black text-gray-900 mb-2">Found a security issue?</h2>
                    <p className="text-gray-500 mb-6">Report it to our security team directly — we&apos;ll acknowledge and investigate.</p>
                    <div className="text-xs text-purple-700 font-bold tracking-wider mb-1">SECURITY DISCLOSURES</div>
                    <a href="mailto:soc@cybernovr.com" className="text-gray-900 font-semibold hover:text-purple-700">soc@cybernovr.com ↗</a>
                </div>
            </section>

            <CTABand text="Ask us anything about how NovrSOC is run." />
            <Footer />
        </div>
    );
}
