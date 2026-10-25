import { redirect } from 'next/navigation';

// BROKEN at the portal level (Release 2 Stage 6): DataLossRecovery calls /api/recovery/health,
// not a client-scoped route, so every request fails for portal_user. Redirects with a notice
// instead of rendering a page where everything fails.
export default function Page() {
    redirect('/client/dashboard?unavailable=' + encodeURIComponent('Data Loss Recovery'));
}
