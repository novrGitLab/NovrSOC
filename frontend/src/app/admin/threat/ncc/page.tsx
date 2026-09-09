import { RegulatoryAdvisories, type RegulatoryAdvisory } from '@/components/features/RegulatoryAdvisories';

// Illustrative summaries of the classes of advisory NCC-CSIRT issues to Nigerian telecom
// operators and subscribers. NOT scraped bulletins — NCC publishes no machine-readable feed.
//
// Note there are deliberately no CVE identifiers here. The original spec for this page included
// a specific CVE against ISP router firmware; that identifier does not correspond to a real
// published vulnerability, and a fabricated CVE is exactly the kind of detail that gets copied
// out of a dashboard into a customer report and cited as fact. Threat classes are described
// without inventing identifiers for them.
const NCC_ADVISORIES: RegulatoryAdvisory[] = [
    {
        id: 'REF-NCC-001',
        title: 'Authentication weaknesses in consumer ISP router firmware',
        date: '2026-02-10',
        severity: 'critical',
        category: 'Infrastructure',
        sector: 'Telecommunications',
        summary: 'Advisory class covering authentication bypass weaknesses in CPE router firmware distributed by ISPs, where remote management interfaces are exposed to the internet by default. Verify affected models and firmware levels against the vendor advisory before acting.',
        url: 'https://www.ncc.gov.ng/technical-regulation/csirt',
        tags: ['router', 'vulnerability', 'isp', 'telecom'],
    },
    {
        id: 'REF-NCC-002',
        title: 'SS7 signalling exploitation against mobile subscribers',
        date: '2026-03-05',
        severity: 'high',
        category: 'Telecom Security',
        sector: 'Telecommunications',
        summary: 'Exploitation of weaknesses in SS7 inter-carrier signalling to intercept calls and SMS, defeating SMS-delivered second factors. Primary mitigation is migrating high-value accounts off SMS-based 2FA.',
        url: 'https://www.ncc.gov.ng/technical-regulation/csirt',
        tags: ['ss7', 'telecom', 'interception', '2fa-bypass'],
    },
    {
        id: 'REF-NCC-003',
        title: 'Phishing campaigns impersonating regulator portals',
        date: '2026-04-18',
        severity: 'high',
        category: 'Phishing',
        sector: 'Government',
        summary: 'Lookalike domains closely resembling official regulator hostnames used to harvest credentials from telecom subscribers and staff. Domain monitoring and registrar takedown are the practical controls.',
        url: 'https://www.ncc.gov.ng/technical-regulation/csirt',
        tags: ['phishing', 'credential-theft', 'telecom', 'typosquatting'],
    },
    {
        id: 'REF-NCC-004',
        title: 'Ransomware targeting telecom billing infrastructure',
        date: '2026-06-22',
        severity: 'critical',
        category: 'Ransomware',
        sector: 'Telecommunications',
        summary: 'Ransomware operators gaining entry through exposed RDP and unpatched VPN concentrators, then moving laterally to billing and provisioning systems where downtime is most costly.',
        url: 'https://www.ncc.gov.ng/technical-regulation/csirt',
        tags: ['ransomware', 'telecom', 'rdp', 'vpn'],
    },
    {
        id: 'REF-NCC-005',
        title: 'IMSI catcher activity in commercial districts',
        date: '2026-08-30',
        severity: 'high',
        category: 'Surveillance',
        sector: 'Telecommunications',
        summary: 'Reports of IMSI catcher devices operating near business districts, capable of intercepting mobile communications. Relevant to executive protection programmes; mitigation is encrypted messaging and device hygiene for high-risk staff.',
        url: 'https://www.ncc.gov.ng/technical-regulation/csirt',
        tags: ['imsi', 'surveillance', 'executive', 'telecom'],
    },
];

const SECTORS = ['All Sectors', 'Telecommunications', 'Government'];

export default function Page() {
    return (
        <RegulatoryAdvisories
            title="NCC Advisories"
            subtitle="Nigerian Threat Intel · Nigerian Communications Commission CSIRT guidance"
            issuer="NCC-CSIRT"
            issuerUrl="https://www.ncc.gov.ng/technical-regulation/csirt"
            advisories={NCC_ADVISORIES}
            sectors={SECTORS}
        />
    );
}
