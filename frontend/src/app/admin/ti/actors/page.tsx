import { Suspense } from 'react';
import { TiActors } from '@/components/features/ti/TiActors';

export default function Page() {
    return <Suspense fallback={null}><TiActors /></Suspense>;
}
