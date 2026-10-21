import { Suspense } from 'react';
import { VmsAudit } from '@/components/features/vms/VmsAudit';

export default function Page() {
    return (
        <Suspense>
            <VmsAudit />
        </Suspense>
    );
}
