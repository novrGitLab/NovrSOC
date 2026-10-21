import { Suspense } from 'react';
import { VmsReport } from '@/components/features/vms/VmsReport';

export default function Page() {
    return (
        <Suspense>
            <VmsReport />
        </Suspense>
    );
}
