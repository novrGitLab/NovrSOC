import { Suspense } from 'react';
import { TiAnalyst } from '@/components/features/ti/TiAnalyst';

export default function Page() {
    return <Suspense fallback={null}><TiAnalyst /></Suspense>;
}
