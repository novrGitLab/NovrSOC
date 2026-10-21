import { Suspense } from 'react';
import { ClientVmsOverview } from '@/components/features/vms/ClientVms';

export default function Page() {
    return (
        <Suspense>
            <ClientVmsOverview />
        </Suspense>
    );
}
