import { Suspense } from 'react';
import { SecurityReportCard } from '@/components/features/SecurityReportCard';

// Suspense: the report card reads ?org= with useSearchParams.
export default function Page() {
    return (
        <Suspense fallback={null}>
            <SecurityReportCard mode="client" />
        </Suspense>
    );
}
