import { Suspense } from 'react';
import { VmsAuthorisationPage } from '@/components/features/vms/VmsOnboarding';

export default function Page() {
    return (
        <Suspense>
            <VmsAuthorisationPage />
        </Suspense>
    );
}
