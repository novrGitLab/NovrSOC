import { Suspense } from 'react';
import { VmsAssessments } from '@/components/features/vms/VmsAssessments';

export default function Page() {
    return (
        <Suspense>
            <VmsAssessments />
        </Suspense>
    );
}
