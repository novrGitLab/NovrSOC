import { Suspense } from 'react';
import { VmsAssetInventory } from '@/components/features/vms/VmsAssetMgmt';

export default function Page() {
    return (
        <Suspense>
            <VmsAssetInventory />
        </Suspense>
    );
}
