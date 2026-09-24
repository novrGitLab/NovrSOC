import { Suspense } from 'react';
import { CaseWorkbench } from '@/components/features/CaseWorkbench';

// Suspense boundary: CaseWorkbench reads ?id= with useSearchParams, which needs one to prerender.
export default function Page() {
    return (
        <Suspense fallback={null}>
            <CaseWorkbench />
        </Suspense>
    );
}
