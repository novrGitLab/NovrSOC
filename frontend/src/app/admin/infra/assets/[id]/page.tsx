import { AssetDetail } from '@/components/features/AssetDetail';

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
    const { id } = await params;
    return <AssetDetail agentId={id} />;
}
