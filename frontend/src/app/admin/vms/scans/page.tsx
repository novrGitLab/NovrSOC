import { Suspense } from 'react';
import { VmsScanManagement } from '@/components/features/vms/VmsScanning';

export default function Page() {
    return (
        <Suspense>
            <VmsScanManagement />
        </Suspense>
    );
}
