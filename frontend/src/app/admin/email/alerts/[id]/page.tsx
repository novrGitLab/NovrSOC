import { EmailAlertDetail } from '@/components/features/email-security/EmailAlertDetail';

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
    const { id } = await params;
    return <EmailAlertDetail id={id} />;
}
