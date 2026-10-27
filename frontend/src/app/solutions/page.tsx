import type { Metadata } from 'next';
import { LandingNav } from '@/components/features/LandingNav';
import { Footer } from '@/components/features/Footer';
import { PageHero } from '@/components/features/PageHero';
import { CTABand } from '@/components/features/CTABand';

export const metadata: Metadata = {
    title: 'Solutions | NovrSOC by Cybernovr',
    description: 'A flexible approach for enterprises, managed security teams and critical infrastructure operators.',
};

const PERSONAS = [
    { id: 'enterprises', title: 'Enterprises', desc: 'Unify exposure and incident context across teams and environments.' },
    { id: '', title: 'Critical infrastructure', desc: 'Bring sector-aware visibility and evidence-based risk analysis to essential services.' },
    { id: 'mssps', title: 'Managed security teams', desc: 'Work across authorised client organisations from one dashboard, with per-org data isolation, role-based access and a guided onboarding flow — white-label ready.' },
    { id: '', title: 'Public sector', desc: 'Support oversight, asset accountability and meaningful reporting.' },
];

const SECTORS = [
    'Banking & Finance', 'Telecommunications', 'Oil & Gas', 'Government',
    'Fintech', 'Healthcare', 'Insurance', 'Education', 'Energy', 'Manufacturing',
];

export default function SolutionsPage() {
    return (
        <div className="min-h-screen bg-white font-sans">
            <LandingNav />
            <PageHero
                breadcrumb="Solutions"
                eyebrow="Solutions"
                title="Built for the environments you protect."
                description="A flexible approach for enterprises, managed security teams and critical infrastructure operators."
            />

            <section className="py-20 bg-gray-50 border-y border-gray-100">
                <div className="max-w-7xl mx-auto px-6">
                    <h2 className="text-3xl md:text-4xl font-black text-gray-900 mb-10">
                        Different environments. One focus: meaningful security.
                    </h2>
                    <div className="grid md:grid-cols-2 gap-5">
                        {PERSONAS.map((p) => (
                            <div key={p.title} id={p.id || undefined}
                                className="bg-white border border-gray-100 rounded-2xl p-7 scroll-mt-24">
                                <h3 className="font-black text-gray-900 mb-2 text-lg">{p.title}</h3>
                                <p className="text-sm text-gray-500 leading-relaxed">{p.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            <section className="py-14 text-center">
                <div className="max-w-7xl mx-auto px-6">
                    <p className="text-xs text-gray-400 uppercase tracking-widest mb-8 font-medium">
                        Industries we serve
                    </p>
                    <div className="flex flex-wrap justify-center gap-3">
                        {SECTORS.map((s) => (
                            <span key={s}
                                className="bg-white border border-gray-200 rounded-full px-5 py-2.5 text-sm font-semibold text-gray-600">
                                {s}
                            </span>
                        ))}
                    </div>
                </div>
            </section>

            <CTABand text="Explore how NovrSOC by Cybernovr can connect your security operations." />
            <Footer />
        </div>
    );
}
