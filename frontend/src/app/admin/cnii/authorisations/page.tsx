import { Suspense } from 'react';
import { CniiAuthorisations } from '@/components/features/cnii/CniiAuthorisations';

export default function Page() {
    return <Suspense fallback={null}><CniiAuthorisations /></Suspense>;
}
