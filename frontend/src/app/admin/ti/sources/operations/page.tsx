import { Suspense } from 'react';
import { TiSourcesOperations } from '@/components/features/ti/TiSourcesOperations';

export default function Page() {
    return <Suspense fallback={null}><TiSourcesOperations /></Suspense>;
}
