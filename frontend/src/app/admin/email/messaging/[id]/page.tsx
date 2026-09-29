import { EmailEventDetail } from '@/components/features/email-security/EmailEventDetail';

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
    const { id } = await params;
    return <EmailEventDetail id={id} />;
}
