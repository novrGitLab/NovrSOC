// Threat actor reference library.
//
// There is no threat_actors table in this database — neither `nigeria_intel.threat_actors` nor
// `global_intel.threat_actors` exists (verified live 2026-09-09; those schemas don't exist at
// all, and the full public table list contains nothing actor-shaped). So this is served from
// code rather than read from Supabase.
//
// Unlike the Nigeria map baseline, this is NOT invented data. Every group below is publicly
// documented by a named vendor or by MITRE, and the attributes here (aliases, origin,
// motivation, targeted sectors, ATT&CK technique ids) reflect that public reporting. The
// `reference` field on each entry says who published it, so an analyst can go read the source
// rather than taking this page's word for it. Nothing here is presented as NovrSOC's own
// telemetry, and `last_active` is deliberately coarse — a precise "last seen" would imply
// tracking this platform doesn't do.

export interface ThreatActor {
    id: string;
    name: string;
    aliases: string[];
    origin: string;
    origin_code: string;
    motivation: 'financial' | 'espionage' | 'hacktivism' | 'destructive';
    targeted_sectors: string[];
    targeted_regions: string[];
    mitre_techniques: Array<{ id: string; name: string }>;
    confidence: 'high' | 'medium' | 'low';
    last_active: string;
    description: string;
    reference: string;
    reference_url: string;
}

// Groups whose documented targeting centres on Nigeria / West Africa.
export const NIGERIAN_ACTORS: ThreatActor[] = [
    {
        id: 'silverterrier',
        name: 'SilverTerrier',
        aliases: ['Nigerian BEC actors'],
        origin: 'Nigeria',
        origin_code: 'NG',
        motivation: 'financial',
        targeted_sectors: ['Banking & Finance', 'Manufacturing', 'Government', 'Education'],
        targeted_regions: ['Global', 'Nigeria', 'United States', 'Europe'],
        mitre_techniques: [
            { id: 'T1566', name: 'Phishing' },
            { id: 'T1566.001', name: 'Spearphishing Attachment' },
            { id: 'T1114', name: 'Email Collection' },
            { id: 'T1056.001', name: 'Keylogging' },
        ],
        confidence: 'high',
        last_active: 'Ongoing',
        description:
            'Umbrella name used by Palo Alto Networks Unit 42 for Nigerian business email compromise actors. Characterised by commodity infostealers and RATs delivered via phishing, followed by email thread hijacking and fraudulent payment redirection rather than data theft for its own sake.',
        reference: 'Palo Alto Networks Unit 42',
        reference_url: 'https://unit42.paloaltonetworks.com/',
    },
    {
        id: 'opera1er',
        name: 'OPERA1ER',
        aliases: ['DESKTOP-GROUP', 'Common Raven', 'NX$M$'],
        origin: 'French-speaking West Africa',
        origin_code: 'NG',
        motivation: 'financial',
        targeted_sectors: ['Banking & Finance', 'Telecommunications', 'Financial Services'],
        targeted_regions: ['West Africa', 'Nigeria', 'Côte d’Ivoire', 'Senegal', 'Bangladesh', 'Argentina'],
        mitre_techniques: [
            { id: 'T1566.001', name: 'Spearphishing Attachment' },
            { id: 'T1219', name: 'Remote Access Software' },
            { id: 'T1078', name: 'Valid Accounts' },
            { id: 'T1005', name: 'Data from Local System' },
        ],
        confidence: 'high',
        last_active: 'Reported through 2023',
        description:
            'French-speaking group documented by Group-IB and Orange CERT-CC, responsible for a long series of thefts from banks and telecoms, largely across West Africa. Notable for living-off-the-land tooling and long dwell times between initial access and cash-out via operator accounts.',
        reference: 'Group-IB / Orange CERT-CC',
        reference_url: 'https://www.group-ib.com/resources/research-hub/opera1er-apt/',
    },
    {
        id: 'tmt',
        name: 'TMT',
        aliases: ['Gold Galleon (related activity)'],
        origin: 'Nigeria',
        origin_code: 'NG',
        motivation: 'financial',
        targeted_sectors: ['Shipping & Maritime', 'Manufacturing', 'Banking & Finance'],
        targeted_regions: ['Global', 'Nigeria'],
        mitre_techniques: [
            { id: 'T1566', name: 'Phishing' },
            { id: 'T1552.001', name: 'Credentials In Files' },
            { id: 'T1114.002', name: 'Remote Email Collection' },
        ],
        confidence: 'medium',
        last_active: 'Reported 2020 onward',
        description:
            'Nigerian BEC cluster documented by Trend Micro, using off-the-shelf keyloggers and credential stealers against maritime and manufacturing supply chains to intercept and alter invoice payments.',
        reference: 'Trend Micro',
        reference_url: 'https://www.trendmicro.com/en_us/research.html',
    },
];

// Groups with no particular Nigeria focus, but whose documented sector targeting (finance,
// telecoms, government) makes them relevant to Nigerian defenders.
export const GLOBAL_ACTORS: ThreatActor[] = [
    {
        id: 'lockbit',
        name: 'LockBit',
        aliases: ['LockBit 3.0', 'LockBit Black', 'Bitwise Spider'],
        origin: 'Russia (suspected)',
        origin_code: 'RU',
        motivation: 'financial',
        targeted_sectors: ['Banking & Finance', 'Healthcare', 'Manufacturing', 'Government'],
        targeted_regions: ['Global'],
        mitre_techniques: [
            { id: 'T1486', name: 'Data Encrypted for Impact' },
            { id: 'T1490', name: 'Inhibit System Recovery' },
            { id: 'T1567', name: 'Exfiltration Over Web Service' },
            { id: 'T1078', name: 'Valid Accounts' },
        ],
        confidence: 'high',
        last_active: 'Disrupted Feb 2024 (Operation Cronos); residual activity reported',
        description:
            'Ransomware-as-a-service operation, for several years the highest-volume ransomware brand by victim count. Double extortion: exfiltrate, then encrypt. Affiliate model means intrusion tradecraft varies widely between incidents.',
        reference: 'CISA advisory AA23-165A',
        reference_url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a',
    },
    {
        id: 'fin7',
        name: 'FIN7',
        aliases: ['Carbanak Group', 'Carbon Spider', 'Sangria Tempest'],
        origin: 'Russia / Ukraine (suspected)',
        origin_code: 'RU',
        motivation: 'financial',
        targeted_sectors: ['Retail', 'Hospitality', 'Banking & Finance'],
        targeted_regions: ['Global'],
        mitre_techniques: [
            { id: 'T1566.001', name: 'Spearphishing Attachment' },
            { id: 'T1204.002', name: 'Malicious File' },
            { id: 'T1059.005', name: 'Visual Basic' },
            { id: 'T1486', name: 'Data Encrypted for Impact' },
        ],
        confidence: 'high',
        last_active: 'Ongoing',
        description:
            'Long-running financially motivated group, historically focused on payment card theft and latterly on ransomware. Known for unusually well-developed social engineering, including physical mail lures and fake security-company personas used to recruit unwitting operators.',
        reference: 'MITRE ATT&CK G0046',
        reference_url: 'https://attack.mitre.org/groups/G0046/',
    },
    {
        id: 'lazarus',
        name: 'Lazarus Group',
        aliases: ['Hidden Cobra', 'Diamond Sleet', 'APT38 (financial subgroup)'],
        origin: 'North Korea',
        origin_code: 'KP',
        motivation: 'financial',
        targeted_sectors: ['Banking & Finance', 'Cryptocurrency', 'Defence'],
        targeted_regions: ['Global', 'Africa', 'Asia'],
        mitre_techniques: [
            { id: 'T1566.003', name: 'Spearphishing via Service' },
            { id: 'T1195.002', name: 'Compromise Software Supply Chain' },
            { id: 'T1071.001', name: 'Web Protocols' },
            { id: 'T1657', name: 'Financial Theft' },
        ],
        confidence: 'high',
        last_active: 'Ongoing',
        description:
            'State-sponsored North Korean group. Its APT38 financial arm is documented targeting SWIFT-connected banks and cryptocurrency exchanges, making it directly relevant to any institution on international payment rails.',
        reference: 'MITRE ATT&CK G0032',
        reference_url: 'https://attack.mitre.org/groups/G0032/',
    },
    {
        id: 'apt29',
        name: 'APT29',
        aliases: ['Cozy Bear', 'Midnight Blizzard', 'Nobelium'],
        origin: 'Russia',
        origin_code: 'RU',
        motivation: 'espionage',
        targeted_sectors: ['Government', 'Diplomatic', 'Technology', 'Think Tanks'],
        targeted_regions: ['Global'],
        mitre_techniques: [
            { id: 'T1195.002', name: 'Compromise Software Supply Chain' },
            { id: 'T1550.001', name: 'Application Access Token' },
            { id: 'T1078.004', name: 'Cloud Accounts' },
            { id: 'T1114.002', name: 'Remote Email Collection' },
        ],
        confidence: 'high',
        last_active: 'Ongoing',
        description:
            'Russian state-sponsored espionage group associated with the SVR. Notable for supply chain compromise and for patient, low-noise abuse of cloud identity and OAuth tokens rather than malware-heavy intrusions.',
        reference: 'MITRE ATT&CK G0016',
        reference_url: 'https://attack.mitre.org/groups/G0016/',
    },
];
