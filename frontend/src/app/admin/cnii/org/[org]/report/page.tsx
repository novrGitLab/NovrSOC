'use client';

import { useParams } from 'next/navigation';
import Link from 'next/link';
import { CniiReport } from '@/components/features/cnii/CniiReport';
import { Card } from '@/components/features/vms/ui';
import { EmptyState } from '@/components/features/vms/kit';

// Mirrors /org/[org]/page.tsx's own branching: "me" is the executive's own-organisation shortcut
// (cnii:read, a different, simpler payload) and has no report of this shape yet; every other slug
// is the staff national drill-down (cnii:sector), which is what this report is built on.
export default function Page() {
    const { org } = useParams<{ org: string }>();
    const slug = decodeURIComponent(org);
    if (slug === 'me') {
        return (
            <Card>
                <EmptyState title="A report is not yet available for your own organisation here" body="This report is built for the staff sector view. Your own organisation's profile and inventory are on its own page." action={<Link href="/admin/cnii/org/me" className="text-xs font-semibold underline">Open your organisation →</Link>} />
            </Card>
        );
    }
    return <CniiReport org={slug} />;
}
