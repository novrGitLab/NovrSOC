import { redirect } from 'next/navigation';

// BROKEN at the portal level (Release 2 Stage 6): SocialSuite calls /api/brand/socials, not a
// client-scoped route, so every request fails for portal_user. Redirects with a notice instead
// of rendering a page where everything fails. The admin page at /admin/brand/social is unaffected.
export default function Page() {
    redirect('/client/dashboard?unavailable=' + encodeURIComponent('Social Suite'));
}
