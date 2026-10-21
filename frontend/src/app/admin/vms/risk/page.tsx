import { Suspense } from 'react';
import { VmsRiskOverview } from '@/components/features/vms/VmsRisk';

export default function Page() {
    return (
        <Suspense>
            <VmsRiskOverview />
        </Suspense>
    );
}
