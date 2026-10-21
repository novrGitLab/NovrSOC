import { Suspense } from 'react';
import { ClientVmsAssets } from '@/components/features/vms/ClientVms';

export default function Page() {
    return (
        <Suspense>
            <ClientVmsAssets />
        </Suspense>
    );
}
