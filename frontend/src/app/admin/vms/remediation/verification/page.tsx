import { Suspense } from 'react';
import { VmsVerification } from '@/components/features/vms/VmsRemediationPlus';

export default function Page() {
    return (
        <Suspense>
            <VmsVerification />
        </Suspense>
    );
}
