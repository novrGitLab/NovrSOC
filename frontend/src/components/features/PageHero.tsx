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
        <section className="pt-36 pb-16 bg-[#05070f] relative overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-br from-[#1a0a2e] via-[#0f0a1a] to-[#05070f]" />
            <div className="absolute -top-32 left-1/3 w-[36rem] h-[36rem] bg-purple/25 rounded-full blur-[120px]" />
            <div className="absolute inset-0 opacity-[0.07]"
                style={{ backgroundImage: 'radial-gradient(circle at 2px 2px, rgba(255,255,255,0.4) 1px, transparent 0)', backgroundSize: '40px 40px' }} />
            <div className="max-w-4xl mx-auto px-6 relative">
                <div className="flex items-center gap-2 text-xs text-white/40 mb-6">
                    <Link href="/" className="hover:text-white/70">Home</Link>
                    <span>/</span>
                    <span>{breadcrumb}</span>
                </div>
                <div className="inline-flex items-center gap-2 bg-white/5 border border-purple-400/20 rounded-full px-4 py-2 mb-6">
                    <div className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                    <span className="text-purple-300 text-xs font-bold uppercase tracking-wider">{eyebrow}</span>
                </div>
                <h1 className="text-4xl md:text-6xl font-black text-white mb-5 leading-tight tracking-tight">
                    {title}
                </h1>
                <p className="text-lg text-white/60 max-w-2xl leading-relaxed mb-8">
                    {description}
                </p>
                <Link href={ctaHref}
                    className="inline-block bg-purple text-white font-black px-7 py-3.5 rounded-2xl hover:bg-purple-hover transition-colors shadow-xl shadow-black/30">
                    {ctaLabel} →
                </Link>
            </div>
        </section>
    );
}
