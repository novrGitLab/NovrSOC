import Link from 'next/link';

export function CTABand({ text }: { text?: string }) {
    return (
        <section className="py-20 bg-gradient-to-br from-gray-950 via-purple-950 to-blue-950">
            <div className="max-w-3xl mx-auto px-6 text-center">
                <h2 className="text-3xl md:text-4xl font-black text-white mb-4">
                    Better visibility. Better decisions. Stronger security.
                </h2>
                <p className="text-white/50 mb-8">
                    {text ?? 'Explore how NovrSOC by Cybernovr can connect your security operations.'}
                </p>
                <div className="flex flex-col sm:flex-row gap-4 justify-center">
                    <Link href="/contact"
                        className="bg-white text-purple-700 font-black px-8 py-4 rounded-2xl hover:bg-gray-100 transition-colors">
                        Request a demo
                    </Link>
                </div>
            </div>
        </section>
    );
}
