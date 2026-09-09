import { RegulatoryAdvisories, type RegulatoryAdvisory } from '@/components/features/RegulatoryAdvisories';

// Illustrative summaries of the kinds of cybersecurity guidance the Central Bank of Nigeria
// issues to deposit money banks, PSPs and mobile money operators. These are NOT scraped
// circulars — CBN publishes no machine-readable feed — so each links to CBN's real circulars
// index. The page itself states this prominently; see RegulatoryAdvisories.tsx.
const CBN_ADVISORIES: RegulatoryAdvisory[] = [
    {
        id: 'REF-CBN-001',
        title: 'Cybersecurity framework expectations for Nigerian banks',
        date: '2026-01-15',
        severity: 'policy',
        category: 'Compliance',
        sector: 'Banking & Finance',
        summary: 'Framework-level expectations for deposit money banks: multi-factor authentication on privileged and customer-facing access, continuous security monitoring, a named CISO function, and prompt incident reporting to the regulator.',
        url: 'https://www.cbn.gov.ng/documents/circulars.asp',
        tags: ['banking', 'compliance', 'mfa', 'incident-reporting'],
    },
    {
        id: 'REF-CBN-002',
        title: 'Controls against fraudulent electronic transactions',
        date: '2026-03-22',
        severity: 'high',
        category: 'Fraud Prevention',
        sector: 'Banking & Finance',
        summary: 'Expectations around real-time transaction monitoring, automated holds on anomalous transfers, and defined customer remediation timelines where funds are lost to fraud.',
        url: 'https://www.cbn.gov.ng/documents/circulars.asp',
        tags: ['fraud', 'electronic-banking', 'monitoring', 'banking'],
    },
    {
        id: 'REF-CBN-003',
        title: 'Security requirements for mobile money operators',
        date: '2026-05-10',
        severity: 'high',
        category: 'Mobile Banking',
        sector: 'Fintech',
        summary: 'Security expectations for mobile money operators covering end-to-end encryption of transaction data, SIM-swap verification before high-risk actions, and tiered KYC thresholds.',
        url: 'https://www.cbn.gov.ng/documents/circulars.asp',
        tags: ['mobile-money', 'kyc', 'encryption', 'fintech'],
    },
    {
        id: 'REF-CBN-004',
        title: 'Open banking API security standards',
        date: '2026-07-01',
        severity: 'medium',
        category: 'Open Banking',
        sector: 'Fintech',
        summary: 'Security baseline for open banking interfaces: OAuth 2.0 authorisation flows, per-consumer rate limiting, consent management, and independent penetration testing of exposed endpoints.',
        url: 'https://www.cbn.gov.ng/documents/circulars.asp',
        tags: ['open-banking', 'api', 'oauth', 'fintech'],
    },
    {
        id: 'REF-CBN-005',
        title: 'Cryptocurrency-related fraud exposure',
        date: '2026-08-14',
        severity: 'high',
        category: 'Cryptocurrency',
        sector: 'Banking & Finance',
        summary: 'Guidance on rising cryptocurrency investment scams, including transaction monitoring for crypto-adjacent flows and suspicious activity reporting obligations.',
        url: 'https://www.cbn.gov.ng/documents/circulars.asp',
        tags: ['cryptocurrency', 'fraud', 'scam', 'banking'],
    },
];

const SECTORS = ['All Sectors', 'Banking & Finance', 'Fintech'];

export default function Page() {
    return (
        <RegulatoryAdvisories
            title="CBN Advisories"
            subtitle="Nigerian Threat Intel · Central Bank of Nigeria cybersecurity guidance"
            issuer="CBN"
            issuerUrl="https://www.cbn.gov.ng/documents/circulars.asp"
            advisories={CBN_ADVISORIES}
            sectors={SECTORS}
        />
    );
}
