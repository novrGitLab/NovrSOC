'use client';

import { useParams } from 'next/navigation';
import { CniiOrg } from '@/components/features/cnii/CniiOrg';

export default function Page() {
    const { org } = useParams<{ org: string }>();
    return <CniiOrg org={decodeURIComponent(org)} />;
}
