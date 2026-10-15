import { Suspense } from 'react';
import { TiIndicators } from '@/components/features/ti/TiIndicators';

export default function Page() {
    return (
        <Suspense>
            <TiIndicators />
        </Suspense>
    );
}
