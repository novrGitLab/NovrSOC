import type { MetadataRoute } from 'next';

// Public marketing routes only — authenticated /admin and /client routes are intentionally left
// out of the sitemap, since they require sign-in and carry no public SEO value.
//
// render.yaml defines no custom domain for novrsoc-frontend, so this is that service's real
// Render URL, not a guessed vanity domain — update it here (and in layout.tsx's metadataBase)
// if a custom domain is ever configured.
const SITE = 'https://novrsoc-frontend.onrender.com';

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
