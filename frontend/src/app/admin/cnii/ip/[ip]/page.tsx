'use client';

import { useParams } from 'next/navigation';
import { CniiLookup } from '@/components/features/cnii/CniiLookup';

export default function Page() {
    const { ip } = useParams<{ ip: string }>();
    return <CniiLookup ip={decodeURIComponent(ip)} />;
}
