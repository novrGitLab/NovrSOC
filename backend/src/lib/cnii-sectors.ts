// The 13 Nigeria CNII sectors as the backend needs them: ids, sub-entities (for classification)
// and compliance frameworks (attached to vulnerabilities). Mirrors frontend/src/lib/cnii-sectors.ts,
// which also carries labels, colours and copy — keep ids, subfields and compliance in step.

export interface CniiSectorData {
    id: string;
    subfields: string[];
    compliance: string[];
}

export const CNII_SECTORS: CniiSectorData[] = [
    { id: 'power', compliance: ['NDPR', 'NERC CIP'], subfields: ['Oil & Gas', 'Power Generation & Distribution'] },
    { id: 'water', compliance: ['NDPR'], subfields: ['Dams & Water Stations'] },
    { id: 'ict', compliance: ['NDPR', 'NCC Framework', 'ISO 27001'], subfields: ['Communications Companies', 'ISPs / Exchange Points (NiRA)', 'NCC', 'Galaxy Backbone', 'NIMC', 'NigCOMSAT'] },
    { id: 'finance', compliance: ['NDPR', 'CBN Cybersecurity Framework', 'PCI-DSS', 'ISO 27001'], subfields: ['Inter-Bank Payment Systems', 'Electronic Transactions / CBN', 'Federal Civil Service Payroll (IPPIS)', 'Financial Trading', 'NHIS'] },
    { id: 'health', compliance: ['NDPR', 'ISO 27001'], subfields: ['Hospitals', 'NCDC', 'NAFDAC', 'NIMR', 'NPHCDA'] },
    { id: 'publicadmin', compliance: ['NDPR', 'ISO 27001'], subfields: ['MDAs', 'Nigeria Immigration Service', 'FIRS', 'Nigerian Correctional Service', 'INEC'] },
    { id: 'education', compliance: ['NDPR'], subfields: ['JAMB', 'WAEC', 'NECO', 'TETFund', 'UBEC'] },
    { id: 'defence', compliance: ['NDPR', 'ISO 27001', 'NIST SP 800-53'], subfields: ['Nigerian Army', 'Nigerian Navy', 'NAF', 'DSA', 'ONSA', 'DIA', 'DSS', 'NIA', 'NCCSALW', 'NPF', 'NSCDC', 'NCS', 'NDLEA', 'EFCC', 'NFIU', 'DICON / NDA / NDC'] },
    { id: 'transport', compliance: ['NDPR', 'ICAO Annex 17'], subfields: ['FAAN', 'NCAA', 'NAMA', 'NCAT', 'NiMet', 'AIB', 'NRC', 'NPA', 'NIMASA'] },
    { id: 'food', compliance: ['NDPR'], subfields: ['NIRSAL'] },
    { id: 'safety', compliance: ['NDPR'], subfields: ['NEMA', 'FRSC'] },
    { id: 'industrial', compliance: ['NDPR', 'ISO 27001'], subfields: ['Textile Industry', 'Automobile Sector', 'Other Critical Industrial Sectors'] },
    { id: 'mines', compliance: ['NDPR'], subfields: ['Solid Minerals', 'Ajaokuta Steel Company', 'Major Mines & Steel Entities'] },
];

export const SECTOR_BY_ID: Record<string, CniiSectorData> = Object.fromEntries(CNII_SECTORS.map((s) => [s.id, s]));
