import type { MetadataRoute } from 'next';

export default function robots(): MetadataRoute.Robots {
    return {
        rules: [
            { userAgent: '*', allow: '/', disallow: ['/admin', '/client', '/api', '/login', '/set-password'] },
        ],
        sitemap: 'https://novrsoc-frontend.onrender.com/sitemap.xml',
    };
}
