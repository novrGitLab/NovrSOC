import { Suspense } from 'react';
import { VmsServices } from '@/components/features/vms/VmsServices';

export default function Page() {
    return (
        <Suspense>
            <VmsServices />
        </Suspense>
    );
}
