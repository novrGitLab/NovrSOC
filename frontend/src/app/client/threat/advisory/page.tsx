import { redirect } from 'next/navigation';

// BROKEN at the portal level (Release 2 Stage 6): ThreatAdvisory calls /api/threat/advisory/*,
// not a client-scoped route, so every request fails for portal_user. Redirects with a notice
// instead of rendering a page where everything fails. /admin/threat/advisory is unaffected.
export default function Page() {
    redirect('/client/dashboard?unavailable=' + encodeURIComponent('Threat Advisory'));
}
