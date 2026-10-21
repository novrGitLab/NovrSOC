import { Suspense } from 'react';
import { VmsScannerIntegrations } from '@/components/features/vms/VmsMonitorOps';

export default function Page() {
    return (
        <Suspense>
            <VmsScannerIntegrations />
        </Suspense>
    );
}
