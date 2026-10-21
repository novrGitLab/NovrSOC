import { Suspense } from 'react';
import { ClientVmsFindings } from '@/components/features/vms/ClientVms';

export default function Page() {
    return (
        <Suspense>
            <ClientVmsFindings />
        </Suspense>
    );
}
