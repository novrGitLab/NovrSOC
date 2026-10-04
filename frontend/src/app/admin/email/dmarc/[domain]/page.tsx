import { DmarcDomainRoute } from '@/components/features/email-security/DmarcDomainDetail';

// /admin/email/dmarc/[domain] — a domain name (ids from older links still work).
export default async function Page({ params }: { params: Promise<{ domain: string }> }) {
    const { domain } = await params;
    return <DmarcDomainRoute param={domain} />;
}
