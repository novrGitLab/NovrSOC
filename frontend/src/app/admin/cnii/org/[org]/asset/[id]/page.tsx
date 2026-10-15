'use client';

import { useParams } from 'next/navigation';
import { CniiAsset } from '@/components/features/cnii/CniiAsset';

export default function Page() {
    const { org, id } = useParams<{ org: string; id: string }>();
    return <CniiAsset org={decodeURIComponent(org)} id={id} />;
}
