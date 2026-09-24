import { permanentRedirect } from 'next/navigation';

// Moved to /admin/network/shadow — kept so old links and bookmarks still land.
export default function Page() {
    permanentRedirect('/admin/network/shadow');
}
