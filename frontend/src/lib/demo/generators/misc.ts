import { DEMO_ORGS, DEMO_ORG_IDS, DEMO_ORG_FRAMEWORKS } from '../orgs';
import type { DemoOrgId } from '../types';
import { seeded } from '../rng';

export function demoPlatformHealth() {
    return { overall: 'operational', services: [
        { name: 'Database', status: 'up' }, { name: 'Wazuh Manager', status: 'up' }, { name: 'Alert ingestion', status: 'up' },
        { name: 'Threat feeds', status: 'up' }, { name: 'VMS scanner', status: 'up' },
    ] };
}

export function demoCompliance(org: DemoOrgId) {
    const frameworks = DEMO_ORG_FRAMEWORKS[org];
    return seeded(`compliance:${org}`, (r) => frameworks.map((f) => ({ shortName: f.includes('ISO') ? 'ISO 27001' : f.includes('CBN') ? 'CBN' : f.includes('NERC') ? 'NERC' : f.includes('NCC') ? 'NCC' : f.includes('PCI') ? 'PCI-DSS' : 'NDPA', score: r.int(55, 90), assessed: 1 })));
}

export function demoNovrAiStatus() { return { configured: true, provider: 'demo-simulated' }; }

export function demoWazuhAgents() { return { total: 0, active: 0 }; }
export function demoWazuhStatus() { return { connected: true, version: 'demo' }; }
export function demoWazuhMitreStats() { return { tactics: [] }; }

export function demoWazuhTrend(org: DemoOrgId, range: string) {
    const days = range === '24h' ? 12 : range === '6h' ? 6 : range === '1h' ? 4 : 7;
    const unit = range === '24h' ? 'h' : range === '6h' || range === '1h' ? 'h' : 'd';
    return seeded(`trend:${org}:${range}`, (r) => Array.from({ length: days }, (_, i) => {
        const alerts = r.int(2, 18);
        const critical = i === 0 ? 1 : r.int(0, 1);
        return { label: unit === 'h' ? `${i * 2}:00` : new Date(Date.now() - (days - i) * 86_400_000).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }), alerts, incidents: Math.min(alerts, r.int(0, 3)), critical };
    }));
}

/** The dashboard's "onboarded clients" widget — in Demo Mode, these ARE the three demo
 * organisations, so the dashboard's client roster reinforces the same three-org narrative
 * everywhere rather than showing an unrelated, empty, or real client list. */
export function demoCustomers() {
    return { customers: DEMO_ORG_IDS.map((id) => {
        const org = DEMO_ORGS[id];
        return { id: `demo-${id}`, slug: `demo-${id}`, name: `${org.name} [SAMPLE]`, industry: org.sector, status: 'active', agentsTotal: org.assetCount, activeIncidents: 1, wazuhGroup: `demo-${id}`, setupComplete: true };
    }) };
}
