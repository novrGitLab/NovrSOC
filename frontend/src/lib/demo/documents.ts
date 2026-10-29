// The 5 downloadable sample documents per organisation (management-demo sprint). Built entirely
// from the same seeded demo generators used by the live screens — never a backend call — and
// rendered client-side with the SAME exportDataAsPDF() utility CaseWorkbench.tsx already uses
// for real case reports, per the brief's "reuse the existing... PDF-generation conventions
// without calling production report-generation APIs." Every document is clearly SAMPLE/SIMULATED
// in its own title and in a leading methodology/limitations section.
import type { DemoOrgId } from './types';
import { DEMO_ORGS, DEMO_ORG_FRAMEWORKS } from './orgs';
import { DEMO_SCENARIOS } from './scenario';
import { demoFindings, demoFindingsSummary } from './generators/vms';
import { demoTiOverview, demoTiRelevant } from './generators/ti';
import { demoCases, demoCaseDetail } from './generators/secops';
import { demoCniiSectors } from './generators/cnii';
import { demoCompliance } from './generators/misc';

export type DemoDocType = 'exec_summary' | 'vuln_assessment' | 'ti_briefing' | 'incident_report' | 'cnii_report';

export const DEMO_DOCUMENT_TYPES: { type: DemoDocType; label: string }[] = [
    { type: 'exec_summary', label: 'Executive Security Summary' },
    { type: 'vuln_assessment', label: 'Vulnerability Assessment Report' },
    { type: 'ti_briefing', label: 'Threat Intelligence Briefing' },
    { type: 'incident_report', label: 'Incident Investigation Report' },
    { type: 'cnii_report', label: 'CNII Security and Compliance Report' },
];

interface DemoDocument { title: string; filename: string; sections: { heading: string; rows: { label: string; value: string }[] }[] }

const PERIOD = () => {
    const end = new Date();
    const start = new Date(Date.now() - 30 * 86_400_000);
    const fmt = (d: Date) => d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
    return `${fmt(start)} – ${fmt(end)}`;
};

const methodologyRows = () => [
    { label: 'Methodology', value: 'Automated scanning, SIEM correlation, and threat-intelligence matching against the organisation\'s declared asset inventory.' },
    { label: 'Limitations', value: 'SAMPLE DOCUMENT — all findings, indicators, and case detail in this report are simulated for demonstration and do not describe a real security event.' },
];

function execSummary(org: DemoOrgId): DemoDocument {
    const o = DEMO_ORGS[org];
    const s = DEMO_SCENARIOS[org];
    const sum = demoFindingsSummary(org);
    const cases = demoCases(org);
    return {
        title: `[SAMPLE] ${o.name} — Executive Security Summary`,
        filename: `sample-${org}-executive-summary`,
        sections: [
            { heading: 'Organisation', rows: [
                { label: 'Organisation', value: `${o.name} [SAMPLE]` },
                { label: 'Sector', value: o.sector },
                { label: 'Location', value: o.location },
                { label: 'Reporting Period', value: PERIOD() },
            ] },
            { heading: 'Executive Summary', rows: [
                { label: 'Open Findings', value: String(sum.open) },
                { label: 'Overdue Remediations', value: String(sum.overdue) },
                { label: 'Active Cases', value: String(cases.summary.active) },
                { label: 'Critical Cases', value: String(cases.summary.critical) },
                { label: 'Headline Issue', value: `${s.title}` },
            ] },
            { heading: 'Findings', rows: [
                { label: 'Critical/P1 Open', value: String(sum.by_priority.P1 ?? 0) },
                { label: 'Known-Exploited (Open)', value: String(sum.known_exploited_open) },
            ] },
            { heading: 'Recommendations', rows: [
                { label: 'Priority 1', value: `Remediate ${s.findingTitle} on ${s.assetName} and verify with a rescan.` },
                { label: 'Priority 2', value: 'Review the correlated case for containment and close out investigation notes.' },
            ] },
            { heading: 'Methodology & Limitations', rows: methodologyRows() },
        ],
    };
}

function vulnAssessment(org: DemoOrgId): DemoDocument {
    const o = DEMO_ORGS[org];
    const findings = demoFindings(org).slice(0, 6);
    const sum = demoFindingsSummary(org);
    return {
        title: `[SAMPLE] ${o.name} — Vulnerability Assessment Report`,
        filename: `sample-${org}-vulnerability-assessment`,
        sections: [
            { heading: 'Organisation', rows: [
                { label: 'Organisation', value: `${o.name} [SAMPLE]` }, { label: 'Assets in Scope', value: String(o.assetCount) }, { label: 'Reporting Period', value: PERIOD() },
            ] },
            { heading: 'Executive Summary', rows: [
                { label: 'Open Findings', value: String(sum.open) },
                { label: 'Critical (P1)', value: String(sum.by_priority.P1 ?? 0) },
                { label: 'High (P2)', value: String(sum.by_priority.P2 ?? 0) },
                { label: 'Overdue', value: String(sum.overdue) },
            ] },
            { heading: 'Findings (sample)', rows: findings.map((f, i) => ({ label: `Finding ${i + 1}`, value: `[${f.priority}] ${f.title} — ${f.asset_value} (${f.status})` })) },
            { heading: 'Evidence', rows: [
                { label: 'Detection Source', value: findings[0]?.detected_by.join(', ') ?? 'active_scan' },
                { label: 'CVE', value: findings[0]?.cve_ids.join(', ') || 'n/a' },
            ] },
            { heading: 'Recommendations', rows: [
                { label: 'Immediate', value: 'Patch all P1 findings and restrict exposed management interfaces to internal networks.' },
                { label: 'Follow-up', value: 'Schedule a verification scan once remediation is applied.' },
            ] },
            { heading: 'Methodology & Limitations', rows: methodologyRows() },
        ],
    };
}

function tiBriefing(org: DemoOrgId): DemoDocument {
    const o = DEMO_ORGS[org];
    const s = DEMO_SCENARIOS[org];
    const overview = demoTiOverview(org);
    const relevant = demoTiRelevant(org);
    return {
        title: `[SAMPLE] ${o.name} — Threat Intelligence Briefing`,
        filename: `sample-${org}-ti-briefing`,
        sections: [
            { heading: 'Organisation', rows: [{ label: 'Organisation', value: `${o.name} [SAMPLE]` }, { label: 'Reporting Period', value: PERIOD() }] },
            { heading: 'Executive Summary', rows: [
                { label: 'Active Indicators', value: String(overview.indicators.active) },
                { label: 'New (24h)', value: String(overview.indicators.new_last_24h) },
                { label: 'Matches Against This Organisation', value: String(overview.matches.total) },
                { label: 'Critical-Tier Matches', value: String(relevant.by_tier.critical) },
            ] },
            { heading: 'Findings', rows: [
                { label: 'Primary Indicator', value: s.indicatorValue },
                { label: 'Matched Field', value: 'source_ip' },
                { label: 'Reason', value: relevant.items[0]?.reasons[0] ?? 'n/a' },
            ] },
            { heading: 'Evidence', rows: [
                { label: 'Feeds Consulted', value: overview.feeds.map((f) => f.name).join(', ') },
            ] },
            { heading: 'Recommendations', rows: [
                { label: 'Immediate', value: `Block ${s.indicatorValue} at the perimeter and review any correlated authentication events.` },
            ] },
            { heading: 'Methodology & Limitations', rows: methodologyRows() },
        ],
    };
}

function incidentReport(org: DemoOrgId): DemoDocument {
    const o = DEMO_ORGS[org];
    const s = DEMO_SCENARIOS[org];
    const detail = demoCaseDetail(org, s.caseId);
    return {
        title: `[SAMPLE] ${o.name} — Incident Investigation Report`,
        filename: `sample-${org}-incident-report`,
        sections: [
            { heading: 'Organisation', rows: [{ label: 'Organisation', value: `${o.name} [SAMPLE]` }, { label: 'Case Number', value: s.caseNumber }, { label: 'Reporting Period', value: PERIOD() }] },
            { heading: 'Executive Summary', rows: [
                { label: 'Title', value: s.caseTitle },
                { label: 'Severity', value: detail?.case.severity ?? 'critical' },
                { label: 'Status', value: detail?.case.status ?? 'investigating' },
                { label: 'Assigned To', value: detail?.case.assigned_to ?? 'SOC Analyst (Sample)' },
            ] },
            { heading: 'Findings', rows: [{ label: 'Narrative', value: s.narrative }] },
            { heading: 'Evidence', rows: [
                { label: 'Source', value: `${s.srcIp}:${s.srcPort}` }, { label: 'Destination', value: `${s.dstIp}:${s.dstPort}` }, { label: 'Protocol', value: s.protocol },
                { label: 'IOC', value: detail?.iocs[0]?.value ?? s.indicatorValue },
            ] },
            { heading: 'Timeline', rows: (detail?.timeline ?? []).map((t, i) => ({ label: `Event ${i + 1}`, value: `${t.action} — ${t.details}` })) },
            { heading: 'Recommendations', rows: [
                { label: 'Containment', value: `Block ${s.srcIp} and reset credentials for any affected accounts.` },
                { label: 'Follow-up', value: 'Close out with a lessons-learned note once contained.' },
            ] },
            { heading: 'Methodology & Limitations', rows: methodologyRows() },
        ],
    };
}

function cniiReport(org: DemoOrgId): DemoDocument {
    const o = DEMO_ORGS[org];
    const frameworks = DEMO_ORG_FRAMEWORKS[org];
    const compliance = demoCompliance(org);
    const sectors = demoCniiSectors().sectors.find((x) => x.id === o.sectorId);
    return {
        title: `[SAMPLE] ${o.name} — CNII Security and Compliance Report`,
        filename: `sample-${org}-cnii-compliance`,
        sections: [
            { heading: 'Organisation', rows: [
                { label: 'Organisation', value: `${o.name} [SAMPLE]` }, { label: 'CNII Sector', value: o.sector }, { label: 'Designation', value: 'Designated critical infrastructure (demo)' }, { label: 'Reporting Period', value: PERIOD() },
            ] },
            { heading: 'Executive Summary', rows: [
                { label: 'Assets in Sector Scope', value: String(sectors?.assets ?? o.assetCount) },
                { label: 'Confirmed P1/P2 Exposure', value: String(sectors?.confirmed_p1_p2 ?? 0) },
                { label: 'Known-Exploited Open', value: String(sectors?.kev_open ?? 0) },
            ] },
            { heading: 'Compliance Status', rows: compliance.map((c) => ({ label: c.shortName, value: `${c.score}/100` })) },
            { heading: 'Findings', rows: [{ label: 'Frameworks Assessed', value: frameworks.join(', ') }] },
            { heading: 'Recommendations', rows: [
                { label: 'Priority', value: 'Close the lowest-scoring framework gap first and re-assess next cycle.' },
            ] },
            { heading: 'Methodology & Limitations', rows: methodologyRows() },
        ],
    };
}

export function demoDocument(org: DemoOrgId, docType: DemoDocType): DemoDocument {
    switch (docType) {
        case 'exec_summary': return execSummary(org);
        case 'vuln_assessment': return vulnAssessment(org);
        case 'ti_briefing': return tiBriefing(org);
        case 'incident_report': return incidentReport(org);
        case 'cnii_report': return cniiReport(org);
    }
}
