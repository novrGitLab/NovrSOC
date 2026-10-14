import { Suspense } from 'react';
import { VmsAssets } from '@/components/features/vms/VmsAssets';

export default function Page() {
    return (
        <Suspense>
            <VmsAssets />
        </Suspense>
    );
}
