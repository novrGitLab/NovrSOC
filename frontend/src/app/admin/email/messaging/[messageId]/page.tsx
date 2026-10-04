import { EmailEventDetail } from '@/components/features/email-security/EmailEventDetail';

// /admin/email/messaging/[messageId] — the NovrSOC event id of one message.
export default async function Page({ params }: { params: Promise<{ messageId: string }> }) {
    const { messageId } = await params;
    return <EmailEventDetail id={messageId} />;
}
