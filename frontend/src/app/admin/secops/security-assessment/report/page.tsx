import { Suspense } from 'react';
import Link from 'next/link';
import { SecurityReportCard } from '@/components/features/SecurityReportCard';

// Staff preview of a client's report card — the same component the client portal renders.
export default function Page() {
    return (
        <div className="space-y-3">
            <Link href="/admin/secops/security-assessment" className="text-xs font-bold text-purple hover:underline">← All clients</Link>
            <Suspense fallback={null}>
                <SecurityReportCard mode="staff" />
            </Suspense>
        </div>
    );
}
