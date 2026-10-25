import { redirect } from 'next/navigation';

// BROKEN at the portal level (Release 2 Stage 6): BrandSuite calls /api/brand/assets and
// /api/brand/search, not client-scoped routes, so every request fails for portal_user. Redirects
// with a notice instead of rendering a page where everything fails. /admin/brand/brand is unaffected.
export default function Page() {
    redirect('/client/dashboard?unavailable=' + encodeURIComponent('Brand Suite'));
}
