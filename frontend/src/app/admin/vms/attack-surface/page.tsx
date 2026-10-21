import { Suspense } from 'react';
import { VmsAttackSurface } from '@/components/features/vms/VmsAssetMgmt';

export default function Page() {
    return (
        <Suspense>
            <VmsAttackSurface />
        </Suspense>
    );
}
