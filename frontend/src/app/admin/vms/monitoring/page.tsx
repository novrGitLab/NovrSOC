import { Suspense } from 'react';
import { VmsMonitoringRules } from '@/components/features/vms/VmsMonitorOps';

export default function Page() {
    return (
        <Suspense>
            <VmsMonitoringRules />
        </Suspense>
    );
}
