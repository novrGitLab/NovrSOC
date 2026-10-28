import { DEMO_ORGS, DEMO_ORG_IDS } from '../orgs';
import { DEMO_SCENARIOS } from '../scenario';

const SECTOR_IDS = ['power', 'water', 'ict', 'finance', 'health', 'publicadmin', 'education', 'defence', 'transport', 'food', 'safety', 'industrial', 'mines'];

export function demoCniiSectors() {
    const bySector = new Map(DEMO_ORG_IDS.map((id) => [DEMO_ORGS[id].sectorId, id]));
    return {
        sectors: SECTOR_IDS.map((id) => {
            const orgId = bySector.get(id);
            if (!orgId) return { id, organisations: 0, unmonitored: 0, confirmed_p1_p2: 0, unconfirmed_open: 0, designated: 0, assets: 0, kev_open: 0 };
            const org = DEMO_ORGS[orgId];
            const scenarioFinding = DEMO_SCENARIOS[orgId];
            return { id, organisations: 1, unmonitored: 0, confirmed_p1_p2: id === 'power' ? 1 : 0, unconfirmed_open: id === 'finance' ? 1 : 0, designated: 1, assets: org.assetCount, kev_open: scenarioFinding ? 1 : 0 };
        }),
    };
}

export function demoCniiOrganisations() {
    return {
        organisations: DEMO_ORG_IDS.map((id) => {
            const org = DEMO_ORGS[id];
            return { slug: `demo-${id}`, name: `${org.name} [DEMO]`, industry: org.sector, profile: { sector_id: org.sectorId, designation: 'designated', org_id: `demo-${id}` } };
        }),
    };
}

export function demoCniiLegacy() {
    return { available: true, rows: [] };
}
