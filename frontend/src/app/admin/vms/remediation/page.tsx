import { Suspense } from 'react';
import { VmsRemediation } from '@/components/features/vms/VmsRemediation';

export default function Page() {
    return (
        <Suspense>
            <VmsRemediation />
        </Suspense>
    );
}
