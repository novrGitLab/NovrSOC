'use client';

import { useParams } from 'next/navigation';
import { CniiSector } from '@/components/features/cnii/CniiSector';

export default function Page() {
    const { sector } = useParams<{ sector: string }>();
    return <CniiSector sectorId={sector} />;
}
