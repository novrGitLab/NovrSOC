import { Suspense } from 'react';
import { TiMatches } from '@/components/features/ti/TiMatches';

export default function Page() {
    return <Suspense fallback={null}><TiMatches /></Suspense>;
}
