import { Suspense } from 'react';
import { TiOverview } from '@/components/features/ti/TiOverview';

export default function Page() {
    return <Suspense fallback={null}><TiOverview /></Suspense>;
}
