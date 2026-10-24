import { Suspense } from 'react';
import { VmsImportPage } from '@/components/features/vms/VmsOnboarding';

export default function Page() {
    return (
        <Suspense>
            <VmsImportPage />
        </Suspense>
    );
}
