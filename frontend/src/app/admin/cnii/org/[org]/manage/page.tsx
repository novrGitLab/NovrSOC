'use client';

import { useParams } from 'next/navigation';
import { CniiOrg } from '@/components/features/cnii/CniiOrg';

// Profile, classification and inventory of one organisation (the pre-P23 organisation page).
export default function Page() {
    const { org } = useParams<{ org: string }>();
    return <CniiOrg org={decodeURIComponent(org)} />;
}
