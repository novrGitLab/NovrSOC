import { DmarcDomainDetail } from '@/components/features/email-security/DmarcDomainDetail';

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
    const { id } = await params;
    return <DmarcDomainDetail id={id} />;
}
