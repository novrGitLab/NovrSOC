import { Suspense } from 'react';
import { ClientVmsRemediation } from '@/components/features/vms/ClientVms';

export default function Page() {
    return (
        <Suspense>
            <ClientVmsRemediation />
        </Suspense>
    );
}
