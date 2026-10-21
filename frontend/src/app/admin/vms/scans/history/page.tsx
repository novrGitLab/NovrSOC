import { Suspense } from 'react';
import { VmsScanHistory } from '@/components/features/vms/VmsScanning';

export default function Page() {
    return (
        <Suspense>
            <VmsScanHistory />
        </Suspense>
    );
}
