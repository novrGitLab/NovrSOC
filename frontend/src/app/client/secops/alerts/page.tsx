import { redirect } from 'next/navigation';

// BROKEN at the portal level (Release 2 Stage 6): AlertCommunication calls /api/communications
// and /api/cases, not client-scoped routes, so every request fails for portal_user. Redirects
// with a notice instead of rendering a page where everything fails.
export default function Page() {
    redirect('/client/dashboard?unavailable=' + encodeURIComponent('Alert Communication'));
}
