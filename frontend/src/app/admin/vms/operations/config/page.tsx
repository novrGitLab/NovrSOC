import { Suspense } from 'react';
import { VmsScanConfig } from '@/components/features/vms/VmsMonitorOps';

export default function Page() {
    return (
        <Suspense>
            <VmsScanConfig />
        </Suspense>
    );
}
