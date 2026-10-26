import { Suspense } from 'react';
import { TiReport } from '@/components/features/ti/TiReport';

export default function Page() {
    return <Suspense fallback={null}><TiReport /></Suspense>;
}
