import { PhishInvestigationRoute } from '@/components/features/email-security/PhishInvestigation';

// /admin/email/phishid/investigate/[domain] — a domain name (ids from older links still work).
export default async function Page({ params }: { params: Promise<{ domain: string }> }) {
    const { domain } = await params;
    return <PhishInvestigationRoute param={domain} />;
}
