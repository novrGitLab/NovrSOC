import { Suspense } from 'react';
import { VmsExposure } from '@/components/features/vms/VmsRisk';

export default function Page() {
    return (
        <Suspense>
            <VmsExposure />
        </Suspense>
    );
}
