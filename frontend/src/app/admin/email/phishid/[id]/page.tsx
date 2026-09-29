import { PhishInvestigation } from '@/components/features/email-security/PhishInvestigation';

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
    const { id } = await params;
    return <PhishInvestigation id={id} />;
}
