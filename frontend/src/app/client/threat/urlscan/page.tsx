import { redirect } from 'next/navigation';

// BROKEN at the portal level (Release 2 Stage 6): UrlScanSuite calls /api/urlscan/*, not a
// client-scoped route, so every request fails for portal_user. Redirects with a notice instead
// of rendering a page where everything fails. /admin/threat/urlscan is unaffected.
export default function Page() {
    redirect('/client/dashboard?unavailable=' + encodeURIComponent('URL Scan Suite'));
}
