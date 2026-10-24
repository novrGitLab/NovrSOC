import { Suspense } from 'react';
import { TiVulnerabilities } from '@/components/features/ti/TiVulnerabilities';

export default function Page() {
    return <Suspense fallback={null}><TiVulnerabilities /></Suspense>;
}
