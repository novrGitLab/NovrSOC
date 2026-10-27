import Link from 'next/link';

export function CTABand({ text }: { text?: string }) {
    return (
        <section className="py-20 bg-[#05070f] relative overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-br from-[#0a1230] via-[#070b18] to-[#05070f]" />
            <div className="absolute top-0 right-1/4 w-[30rem] h-[30rem] bg-blue-600/15 rounded-full blur-[120px]" />
            <div className="max-w-3xl mx-auto px-6 text-center relative">
                <h2 className="text-3xl md:text-4xl font-black text-white mb-4">
                    Strengthen your security operations with Novr VTEM.
                </h2>
                <p className="text-white/50 mb-8">
                    {text ?? 'Explore how NovrSOC by Cybernovr can connect your security operations.'}
                </p>
                <div className="flex flex-col sm:flex-row gap-4 justify-center">
                    <Link href="/contact"
                        className="bg-gradient-to-r from-sky-500 to-blue-600 text-white font-black px-8 py-4 rounded-2xl hover:from-sky-400 hover:to-blue-500 transition-all shadow-xl shadow-blue-900/40">
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
