import { Suspense } from 'react';
import { VmsDiscovery } from '@/components/features/vms/VmsAssetMgmt';

export default function Page() {
    return (
        <Suspense>
            <VmsDiscovery />
        </Suspense>
    );
}
