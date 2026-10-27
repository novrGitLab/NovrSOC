import type { MetadataRoute } from 'next';

// Public marketing routes only — authenticated /admin and /client routes are intentionally left
// out of the sitemap, since they require sign-in and carry no public SEO value.
//
// The first domain guessed here (novrsoc-frontend.onrender.com, from render.yaml's service name)
// does not exist — confirmed by curl (404): that Render service was defined but never actually
// deployed. docs/runbooks/deploy-p1-p8.md:51 documents the real one (FRONTEND_URL's value), and a
// live curl confirms it: https://novr-soc.vercel.app serves this site today. Update this (and
// layout.tsx's metadataBase) if a custom domain is ever configured instead.
const SITE = 'https://novr-soc.vercel.app';

const ROUTES: { path: string; priority: number; changeFrequency: MetadataRoute.Sitemap[number]['changeFrequency'] }[] = [
    { path: '/', priority: 1, changeFrequency: 'weekly' },
    { path: '/platform', priority: 0.9, changeFrequency: 'monthly' },
    { path: '/vms', priority: 0.9, changeFrequency: 'monthly' },
    { path: '/secops', priority: 0.9, changeFrequency: 'monthly' },
    { path: '/ti', priority: 0.9, changeFrequency: 'monthly' },
    { path: '/cnii', priority: 0.9, changeFrequency: 'monthly' },
    { path: '/grc', priority: 0.7, changeFrequency: 'monthly' },
    { path: '/integrations', priority: 0.7, changeFrequency: 'monthly' },
    { path: '/solutions', priority: 0.7, changeFrequency: 'monthly' },
    { path: '/cert-csirt', priority: 0.6, changeFrequency: 'monthly' },
    { path: '/regulators', priority: 0.6, changeFrequency: 'monthly' },
    { path: '/trust', priority: 0.6, changeFrequency: 'monthly' },
    { path: '/about', priority: 0.5, changeFrequency: 'monthly' },
    { path: '/contact', priority: 0.6, changeFrequency: 'yearly' },
    { path: '/privacy', priority: 0.2, changeFrequency: 'yearly' },
    { path: '/terms', priority: 0.2, changeFrequency: 'yearly' },
];

export default function sitemap(): MetadataRoute.Sitemap {
    const lastModified = new Date();
    return ROUTES.map((r) => ({ url: `${SITE}${r.path}`, lastModified, changeFrequency: r.changeFrequency, priority: r.priority }));
}
