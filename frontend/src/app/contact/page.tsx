import type { Metadata } from 'next';
import { LandingNav } from '@/components/features/LandingNav';
import { Footer } from '@/components/features/Footer';
import { ContactForm } from '@/components/features/ContactForm';

export const metadata: Metadata = {
    title: 'Contact | NovrSOC by Cybernovr',
    description: "Tell us what you need to protect. We'll help you explore the right starting point.",
};

export default function ContactPage() {
    return (
        <div className="min-h-screen bg-white font-sans">
            <LandingNav />

            <section className="pt-36 pb-16 bg-gradient-to-br from-gray-950 via-purple-950 to-purple-900">
                <div className="max-w-4xl mx-auto px-6">
                    <div className="inline-flex items-center gap-2 bg-white/10 border border-white/20 rounded-full px-4 py-2 mb-6">
                        <span className="text-white/80 text-xs font-bold uppercase tracking-wider">Let&apos;s connect</span>
                    </div>
                    <h1 className="text-4xl md:text-6xl font-black text-white mb-5 leading-tight tracking-tight">
                        Let&apos;s talk about your security priorities.
                    </h1>
                    <p className="text-lg text-white/60 max-w-2xl leading-relaxed">
                        Share what you&apos;re working on. We&apos;ll help identify the right conversation.
                    </p>
                </div>
            </section>

            <section className="py-20">
                <div className="max-w-5xl mx-auto px-6 grid md:grid-cols-2 gap-14">
                    <div>
                        <h2 className="text-2xl font-black text-gray-900 mb-3">Start with a conversation.</h2>
                        <p className="text-gray-500 mb-8 leading-relaxed">
                            For platform demos, product questions and partnership discussions, send us a message.
                        </p>
                        <div className="space-y-6">
                            <div>
                                <div className="text-xs text-purple-700 font-bold tracking-wider mb-1">GENERAL ENQUIRIES</div>
                                <a href="mailto:soc@cybernovr.com" className="text-gray-900 font-semibold hover:text-purple-700">soc@cybernovr.com ↗</a>
                            </div>
                            <div>
                                <div className="text-xs text-purple-700 font-bold tracking-wider mb-1">PRODUCTS</div>
                                <a href="/platform" className="block text-gray-900 font-semibold hover:text-purple-700 mb-1">NovrSOC Platform ↗</a>
                                <a href="https://novracademy.com" target="_blank" rel="noopener" className="block text-gray-900 font-semibold hover:text-purple-700">Novr Academy ↗</a>
                            </div>
                            <div>
                                <div className="text-xs text-purple-700 font-bold tracking-wider mb-1">CALGARY OFFICE</div>
                                <p className="text-sm text-gray-600">108, 4625 Varsity Drive NW, Calgary, AB T3A 0Z9, Canada</p>
                            </div>
                            <div>
                                <div className="text-xs text-purple-700 font-bold tracking-wider mb-1">LAGOS OFFICE</div>
                                <p className="text-sm text-gray-600">17 Sunday Adigun Street, Alausa Ikeja, Lagos, Nigeria</p>
                            </div>
                            <div>
                                <div className="text-xs text-purple-700 font-bold tracking-wider mb-1">PHONE</div>
                                <a href="tel:+2348161759819" className="block text-gray-900 font-semibold hover:text-purple-700">+234 0816 175 9819</a>
                                <a href="tel:+2348098120000" className="block text-gray-900 font-semibold hover:text-purple-700">0809 812 0000</a>
                            </div>
                        </div>
                    </div>

                    <ContactForm />
                </div>
            </section>

            <Footer />
        </div>
    );
}
