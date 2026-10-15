import { Suspense } from 'react';
import { VmsFindings } from '@/components/features/vms/VmsFindings';

export default function Page() {
    return (
        <Suspense>
            <VmsFindings />
        </Suspense>
    );
}
