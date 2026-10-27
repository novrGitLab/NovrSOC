import type { Metadata } from 'next';
import { LandingNav } from '@/components/features/LandingNav';
import { Footer } from '@/components/features/Footer';
import { PageHero } from '@/components/features/PageHero';
import { DetailItem } from '@/components/features/DetailList';
import { CTABand } from '@/components/features/CTABand';

export const metadata: Metadata = {
    title: 'About | NovrSOC by Cybernovr',
    description: 'We build connected cybersecurity capabilities that help organisations understand exposure and act on risk.',
};

export default function AboutPage() {
    return (
        <div className="min-h-screen bg-white font-sans">
            <LandingNav />
            <PageHero
                breadcrumb="About"
                eyebrow="About Cybernovr"
                title="Security engineering with operational purpose."
                description="We build connected cybersecurity capabilities that help organisations understand exposure and act on risk."
            />

            <section className="py-20">
                <div className="max-w-4xl mx-auto px-6">
                    <h2 className="text-2xl font-black text-gray-900 mb-2">Technology is only useful when it helps people act.</h2>
                    <p className="text-gray-500 mb-8">Our approach focuses on connecting evidence, prioritising meaningful risk and enabling accountable security decisions.</p>
                    <DetailItem title="Security operations">Workflows designed around detection, investigation and response.</DetailItem>
                    <DetailItem title="Exposure management">Clear visibility into assets and vulnerabilities.</DetailItem>
                    <DetailItem title="Threat context">Intelligence that supports practical decisions.</DetailItem>
                    <DetailItem title="Human oversight">Automation with appropriate governance and accountability.</DetailItem>
                </div>
            </section>

            <section className="py-20 bg-gray-50 border-y border-gray-100">
                <div className="max-w-7xl mx-auto px-6">
                    <div className="inline-flex items-center gap-2 bg-purple-100 border border-purple-200 rounded-full px-4 py-2 mb-6">
                        <span className="text-purple-700 text-xs font-bold">Our ecosystem</span>
                    </div>
                    <h2 className="text-3xl font-black text-gray-900 mb-10">Security operations and security learning.</h2>
                    <div className="grid md:grid-cols-2 gap-5">
                        <a href="/platform"
                            className="bg-white border border-gray-100 rounded-2xl p-7 hover:border-purple-200 hover:shadow-lg transition-all block">
                            <h3 className="font-black text-gray-900 mb-2 text-lg">NovrSOC</h3>
                            <p className="text-sm text-gray-500 mb-3">Connected cybersecurity operations and intelligence.</p>
                            <span className="text-sm font-bold text-purple-700">Explore platform →</span>
                        </a>
                        <a href="https://novracademy.com" target="_blank" rel="noopener"
                            className="bg-white border border-gray-100 rounded-2xl p-7 hover:border-purple-200 hover:shadow-lg transition-all block">
                            <h3 className="font-black text-gray-900 mb-2 text-lg">Novr Academy</h3>
                            <p className="text-sm text-gray-500 mb-3">Cybersecurity training, learning and awareness.</p>
                            <span className="text-sm font-bold text-purple-700">Visit Novr Academy ↗</span>
                        </a>
                    </div>
                </div>
            </section>

            <section className="py-20">
                <div className="max-w-4xl mx-auto px-6">
                    <div className="inline-flex items-center gap-2 bg-blue-100 border border-blue-200 rounded-full px-4 py-2 mb-6">
                        <span className="text-blue-700 text-xs font-bold">Trust & assurance</span>
                    </div>
                    <h2 className="text-3xl font-black text-gray-900 mb-4">Built around Nigerian regulatory context.</h2>
                    <p className="text-gray-500 leading-relaxed">
                        NovrSOC tracks Nigerian regulatory frameworks — NDPA, the CBN Cybersecurity Framework and NCC
                        Consumer Protection — as a platform capability. See <a href="/trust" className="text-blue-700 font-semibold hover:underline">Trust &amp; Deployment</a> for
                        what is confirmed today about how the platform itself is run, isolated and secured.
                        {/* The earlier "ISO/IEC 27001:2022-certified infrastructure" claim here named a
                            specific certification nothing in this repository or its records substantiates
                            — removed rather than carried forward (see Footer.tsx and page.tsx for the
                            same correction). */}
                    </p>
                </div>
            </section>

            <CTABand text="Explore how NovrSOC by Cybernovr can connect your security operations." />
            <Footer />
        </div>
    );
}
