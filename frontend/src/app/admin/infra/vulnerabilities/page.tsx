import { permanentRedirect } from 'next/navigation';

// Moved to /admin/secops/vulnerabilities — kept so old links and bookmarks still land.
export default function Page() {
    permanentRedirect('/admin/secops/vulnerabilities');
}
