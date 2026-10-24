import { Suspense } from 'react';
import { TiSources } from '@/components/features/ti/TiSources';

export default function Page() {
    return <Suspense fallback={null}><TiSources /></Suspense>;
}
