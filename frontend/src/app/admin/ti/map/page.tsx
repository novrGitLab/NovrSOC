import { Suspense } from 'react';
import { TiMap } from '@/components/features/ti/TiMap';

export default function Page() {
    return <Suspense fallback={null}><TiMap /></Suspense>;
}
