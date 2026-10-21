'use client';

import { useParams } from 'next/navigation';
import { CniiNationalSector } from '@/components/features/cnii/CniiNational';

export default function Page() {
    const { sector } = useParams<{ sector: string }>();
    return <CniiNationalSector sectorId={sector} />;
}
