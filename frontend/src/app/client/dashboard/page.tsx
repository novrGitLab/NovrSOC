import { Suspense } from 'react';
import { PortalDashboard } from '@/components/dashboards/PortalDashboard';
import { UnavailableNotice } from '@/components/shared/UnavailableNotice';

// Suspense boundary: UnavailableNotice reads ?unavailable= with useSearchParams, which needs one to prerender.
export default function Page() {
    return (
        <>
            <Suspense fallback={null}><UnavailableNotice /></Suspense>
            <PortalDashboard />
        </>
    );
}
