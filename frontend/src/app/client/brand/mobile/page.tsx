import { redirect } from 'next/navigation';

// BROKEN at the portal level (Release 2 Stage 6): MobileAppSuite calls /api/brand/apps, not a
// client-scoped route, so every request fails for portal_user. Redirects with a notice instead
// of rendering a page where everything fails. /admin/brand/mobile is unaffected.
export default function Page() {
    redirect('/client/dashboard?unavailable=' + encodeURIComponent('Mobile App Suite'));
}
