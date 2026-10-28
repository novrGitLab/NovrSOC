export type DemoOrgId = 'lapo' | 'tazemi' | 'ikea';

export interface DemoOrgProfile {
    id: DemoOrgId;
    name: string;
    sector: string;
    sectorId: string; // matches lib/cnii-sectors.ts ids where relevant
    location: string;
    description: string;
    employeeCount: number;
    assetCount: number;
}

export interface DemoState {
    enabled: boolean;
    org: DemoOrgId;
}
