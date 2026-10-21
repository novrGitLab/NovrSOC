'use client';

import { useParams } from 'next/navigation';
import { CniiOrg } from '@/components/features/cnii/CniiOrg';
import { CniiNationalOrg } from '@/components/features/cnii/CniiNational';

// /org/me is the executive's own organisation (profile view); any other organisation opens its
// national intelligence page (staff; the backend checks who may view it).
export default function Page() {
    const { org } = useParams<{ org: string }>();
    const slug = decodeURIComponent(org);
    return slug === 'me' ? <CniiOrg org="me" /> : <CniiNationalOrg org={slug} />;
}
