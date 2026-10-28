import type { DemoOrgId } from './types';

/** The one connected "golden thread" per organisation, named once here so every domain generator
 * (findings, cases, TI matches, reports, AI investigation) references the SAME entity instead of
 * each inventing its own — this is what makes the demo "internally consistent" rather than a pile
 * of unrelated random rows. */
export interface DemoScenario {
    title: string;
    narrative: string;
    assetId: string; assetName: string; assetValue: string;
    cveId: string;
    indicatorValue: string;
    findingId: string; findingTitle: string;
    caseId: string; caseNumber: string; caseTitle: string;
    srcIp: string; dstIp: string; srcPort: number; dstPort: number; protocol: 'TCP' | 'UDP';
}

export const DEMO_SCENARIOS: Record<DemoOrgId, DemoScenario> = {
    lapo: {
        title: 'Suspicious authentication → correlated alert → incident investigation → executive summary',
        narrative: 'Repeated failed sign-ins against the customer banking portal, correlated with a known credential-stuffing indicator, opened as a case and escalated to the executive summary.',
        assetId: 'demo-lapo-asset-portal', assetName: 'customer-portal-01', assetValue: 'portal.lapo-demo.test',
        cveId: 'CVE-2025-21412',
        indicatorValue: '203.0.113.77',
        findingId: 'demo-lapo-finding-authbrute', findingTitle: 'Repeated failed authentication against customer portal (credential stuffing pattern)',
        caseId: 'demo-lapo-case-1', caseNumber: 'CASE-LAPO-0142', caseTitle: 'Suspected credential stuffing against customer banking portal',
        srcIp: '203.0.113.77', dstIp: '198.18.4.12', srcPort: 51422, dstPort: 443, protocol: 'TCP',
    },
    tazemi: {
        title: 'Firewall activity → network threat intelligence → Nigeria heatmap → CNII exposure',
        narrative: 'A firewall-logged connection attempt from an address with a source-reported Nigeria-targeting tag, visible on the Nigeria Threat Heatmap, alongside an unmonitored exposed asset in CNII Watch.',
        assetId: 'demo-tazemi-asset-core', assetName: 'core-router-edge-03', assetValue: 'edge03.tazemi-demo.test',
        cveId: 'CVE-2024-3400',
        indicatorValue: '198.51.100.23',
        findingId: 'demo-tazemi-finding-exposed', findingTitle: 'Management interface reachable from the internet on core edge router',
        caseId: 'demo-tazemi-case-1', caseNumber: 'CASE-TAZEMI-0087', caseTitle: 'Unusual inbound connections to core network edge from a flagged source',
        srcIp: '198.51.100.23', dstIp: '198.18.8.4', srcPort: 443, dstPort: 22, protocol: 'TCP',
    },
    ikea: {
        title: 'Critical asset vulnerability → remediation workflow → verification → risk improvement',
        narrative: 'A critical, known-exploited vulnerability on a grid-control gateway, worked through a remediation task, confirmed fixed by a verification scan, with the organisation’s risk score improving as a result.',
        assetId: 'demo-ikea-asset-scada', assetName: 'grid-gateway-07', assetValue: 'gw07.ikea-demo.test',
        cveId: 'CVE-2023-29199',
        indicatorValue: '192.0.2.145',
        findingId: 'demo-ikea-finding-scada', findingTitle: 'Known-exploited vulnerability on grid-control gateway (unpatched remote management service)',
        caseId: 'demo-ikea-case-1', caseNumber: 'CASE-IKEA-0053', caseTitle: 'Critical finding on grid-control gateway escalated for emergency patching',
        srcIp: '192.0.2.145', dstIp: '198.18.12.9', srcPort: 443, dstPort: 8443, protocol: 'TCP',
    },
};
