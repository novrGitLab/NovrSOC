import { Suspense } from 'react';
import { VmsWorkerHealth } from '@/components/features/vms/VmsMonitorOps';

export default function Page() {
    return (
        <Suspense>
            <VmsWorkerHealth />
        </Suspense>
    );
}
