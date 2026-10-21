'use client';

import { useParams } from 'next/navigation';
import { CniiAsset } from '@/components/features/cnii/CniiAsset';
import { CniiNationalAsset } from '@/components/features/cnii/CniiNational';

export default function Page() {
    const { org, id } = useParams<{ org: string; id: string }>();
    const slug = decodeURIComponent(org);
    return slug === 'me' ? <CniiAsset org="me" id={id} /> : <CniiNationalAsset org={slug} id={id} />;
}
