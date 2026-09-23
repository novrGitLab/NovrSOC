import { permanentRedirect } from 'next/navigation';

// Incidents were renamed to Cases. Kept so old links and bookmarks still land somewhere.
export default function Page() {
    permanentRedirect('/client/secops/cases');
}
