import { redirect } from 'next/navigation';

// BROKEN at the portal level (Release 2 Stage 6): DomainSuite calls /api/brand/domains, not a
// client-scoped route, so every request fails for portal_user. Redirects with a notice instead
// of rendering a page where everything fails. The admin page at /admin/brand/domain is unaffected.
export default function Page() {
    redirect('/client/dashboard?unavailable=' + encodeURIComponent('Domain Suite'));
}
