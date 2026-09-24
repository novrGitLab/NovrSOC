import { permanentRedirect } from 'next/navigation';

// Moved to /admin/network/topology — kept so old links and bookmarks still land.
export default function Page() {
    permanentRedirect('/admin/network/topology');
}
