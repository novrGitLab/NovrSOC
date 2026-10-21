import { Suspense } from 'react';
import { VmsAiPlans } from '@/components/features/vms/VmsRemediationPlus';

export default function Page() {
    return (
        <Suspense>
            <VmsAiPlans />
        </Suspense>
    );
}
