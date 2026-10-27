import Link from 'next/link';

export function PageHero({
    breadcrumb,
    eyebrow,
    title,
    description,
    ctaHref = '/contact',
    ctaLabel = 'Talk to our team',
}: {
    breadcrumb: string;
    eyebrow: string;
    title: string;
    description: string;
    ctaHref?: string;
    ctaLabel?: string;
}) {
    return (
        <section className="pt-36 pb-16 bg-gradient-to-br from-gray-950 via-purple-950 to-blue-950 relative overflow-hidden">
            <div className="absolute inset-0 opacity-10"
                style={{ backgroundImage: 'radial-gradient(circle at 2px 2px, rgba(255,255,255,0.3) 1px, transparent 0)', backgroundSize: '40px 40px' }} />
            <div className="max-w-4xl mx-auto px-6 relative">
                <div className="flex items-center gap-2 text-xs text-white/40 mb-6">
                    <Link href="/" className="hover:text-white/70">Home</Link>
                    <span>/</span>
                    <span>{breadcrumb}</span>
                </div>
                <div className="inline-flex items-center gap-2 bg-white/10 border border-white/20 rounded-full px-4 py-2 mb-6">
                    <span className="text-white/80 text-xs font-bold uppercase tracking-wider">{eyebrow}</span>
                </div>
                <h1 className="text-4xl md:text-6xl font-black text-white mb-5 leading-tight tracking-tight">
                    {title}
                </h1>
                <p className="text-lg text-white/60 max-w-2xl leading-relaxed mb-8">
                    {description}
                </p>
                <Link href={ctaHref}
                    className="inline-block bg-orange-500 text-white font-black px-7 py-3.5 rounded-2xl hover:bg-orange-600 transition-colors shadow-xl">
                    {ctaLabel} →
                </Link>
            </div>
        </section>
    );
}
