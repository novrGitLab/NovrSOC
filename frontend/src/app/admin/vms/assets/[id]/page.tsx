import { VmsAssetPage } from '@/components/features/vms/VmsAssetMgmt';

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
    const { id } = await params;
    return <VmsAssetPage id={id} />;
}
