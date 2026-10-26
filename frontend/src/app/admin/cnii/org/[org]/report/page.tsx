'use client';

import { useParams } from 'next/navigation';
import { CniiReport } from '@/components/features/cnii/CniiReport';
import { CniiMyOrgReport } from '@/components/features/cnii/CniiMyOrgReport';

// Mirrors /org/[org]/page.tsx's own branching: "me" is the executive's own-organisation shortcut
// (cnii:read, never cnii:sector — CniiMyOrgReport never reaches national or cross-organisation
// data); every other slug is the staff national drill-down (cnii:sector).
export default function Page() {
    const { org } = useParams<{ org: string }>();
    const slug = decodeURIComponent(org);
    return slug === 'me' ? <CniiMyOrgReport /> : <CniiReport org={slug} />;
}
