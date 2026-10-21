import { Suspense } from 'react';
import { ClientVmsReports } from '@/components/features/vms/ClientVms';

export default function Page() {
    return (
        <Suspense>
            <ClientVmsReports />
        </Suspense>
    );
}
