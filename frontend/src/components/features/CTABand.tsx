import Link from 'next/link';

export function CTABand({ text }: { text?: string }) {
    return (
        <section className="py-20 bg-[#05070f] relative overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-br from-[#1a0a2e] via-[#0f0a1a] to-[#05070f]" />
            <div className="absolute top-0 right-1/4 w-[30rem] h-[30rem] bg-purple/20 rounded-full blur-[120px]" />
            <div className="max-w-3xl mx-auto px-6 text-center relative">
                <h2 className="text-3xl md:text-4xl font-black text-white mb-4">
                    Strengthen your security operations with Novr VTEM.
                </h2>
                <p className="text-white/50 mb-8">
                    {text ?? 'Explore how NovrSOC by Cybernovr can connect your security operations.'}
                </p>
                <div className="flex flex-col sm:flex-row gap-4 justify-center">
                    <Link href="/contact"
                        className="bg-purple text-white font-black px-8 py-4 rounded-2xl hover:bg-purple-hover transition-colors shadow-xl shadow-black/30">
                        Request a demo
                    </Link>
                    <a href="mailto:soc@cybernovr.com"
                        className="bg-white/5 border border-white/15 text-white font-bold px-8 py-4 rounded-2xl hover:bg-white/10 transition-colors">
                        Contact Cybernovr →
                    </a>
                </div>
            </div>
        </section>
    );
}
