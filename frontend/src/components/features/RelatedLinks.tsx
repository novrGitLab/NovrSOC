import Link from 'next/link';

export function RelatedLinks({
    heading = 'Related capabilities',
    items,
}: {
    heading?: string;
    items: { href: string; title: string; desc: string }[];
}) {
    return (
        <section className="py-20 bg-gray-50 border-y border-gray-100">
            <div className="max-w-7xl mx-auto px-6">
                <h2 className="text-2xl font-black text-gray-900 mb-8">{heading}</h2>
                <div className="grid md:grid-cols-3 gap-5">
                    {items.map((item) => (
                        <Link key={item.href} href={item.href}
                            className="bg-white border border-gray-100 rounded-2xl p-6 hover:border-purple-200 hover:shadow-lg transition-all block">
                            <h3 className="font-black text-gray-900 mb-2">{item.title}</h3>
                            <p className="text-sm text-gray-500 leading-relaxed mb-3">{item.desc}</p>
                            <span className="text-sm font-bold text-purple">Explore →</span>
                        </Link>
                    ))}
                </div>
            </div>
        </section>
    );
}
