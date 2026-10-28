import type { DemoOrgId, DemoOrgProfile } from './types';

export const DEMO_ORGS: Record<DemoOrgId, DemoOrgProfile> = {
    lapo: {
        id: 'lapo', name: 'LAPO', sector: 'Banking, Finance & Insurance', sectorId: 'finance', location: 'Lagos, Nigeria',
        description: 'A microfinance bank serving retail and SME customers across Lagos and the South-West.',
        employeeCount: 1850, assetCount: 64,
    },
    tazemi: {
        id: 'tazemi', name: 'Tazemi', sector: 'ICT & Communications', sectorId: 'ict', location: 'Lagos, Nigeria',
        description: 'A regional telecommunications operator providing mobile data and enterprise connectivity.',
        employeeCount: 2400, assetCount: 118,
    },
    ikea: {
        id: 'ikea', name: 'IKEA', sector: 'Power & Energy', sectorId: 'power', location: 'Lagos, Nigeria',
        description: 'A power distribution and critical-infrastructure operator for a Lagos-area franchise zone.',
        employeeCount: 3100, assetCount: 97,
    },
};

export const DEMO_ORG_IDS: DemoOrgId[] = ['lapo', 'tazemi', 'ikea'];

/** The compliance frameworks each sector is expected to be assessed against, same mapping
 * backend/src and lib/cnii-sectors.ts already use — not invented for the demo. */
export const DEMO_ORG_FRAMEWORKS: Record<DemoOrgId, string[]> = {
    lapo: ['NDPR', 'CBN Cybersecurity Framework', 'PCI-DSS', 'ISO 27001'],
    tazemi: ['NDPR', 'NCC Framework', 'ISO 27001'],
    ikea: ['NDPR', 'NERC CIP'],
};
