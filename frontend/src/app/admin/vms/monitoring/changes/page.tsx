import { Suspense } from 'react';
import { VmsChanges } from '@/components/features/vms/VmsMonitorOps';

export default function Page() {
    return (
        <Suspense>
            <VmsChanges />
        </Suspense>
    );
}
