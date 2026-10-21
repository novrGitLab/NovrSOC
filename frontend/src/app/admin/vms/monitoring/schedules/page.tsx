import { Suspense } from 'react';
import { VmsSchedulesPage } from '@/components/features/vms/VmsMonitorOps';

export default function Page() {
    return (
        <Suspense>
            <VmsSchedulesPage />
        </Suspense>
    );
}
