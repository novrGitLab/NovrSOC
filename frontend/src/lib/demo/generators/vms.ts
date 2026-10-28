import type { DemoOrgId } from '../types';
import { seeded } from '../rng';
import { DEMO_SCENARIOS } from '../scenario';

export interface DemoFinding {
    id: string; asset_id: string | null; asset_value: string; port: number | null; protocol: string | null;
    source_class: 'active_scan' | 'wazuh'; detected_by: string[]; rule_id: string; title: string; finding_type: string;
    cve_ids: string[]; scanner_severity: string; scanner_cvss: number | null; risk_score: number | null;
    priority: 'P1' | 'P2' | 'P3' | 'P4' | null; status: string; owner: string | null; due_at: string | null;
    first_seen: string; last_seen: string; verified_at: string | null; case_id: string | null;
    description?: string | null; remediation?: string | null; overdue?: boolean;
}

const TITLES = [
    'Outdated TLS configuration permits weak cipher negotiation', 'Exposed administrative interface without MFA',
    'Unpatched remote code execution vulnerability', 'Default credentials active on management service',
    'Missing security headers on public-facing application', 'SQL injection in legacy reporting endpoint',
    'Outdated SSH daemon with known vulnerabilities', 'Unrestricted file upload on customer-facing form',
    'Expired TLS certificate on internal service', 'Verbose error messages disclose internal paths',
];
const OWNERS = ['SOC Analyst (Demo)', 'IT Operations (Demo)', 'Platform Team (Demo)'];
const ago = (days: number) => new Date(Date.now() - days * 86_400_000).toISOString();
const ahead = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

export function demoFindings(org: DemoOrgId): DemoFinding[] {
    const s = DEMO_SCENARIOS[org];
    return seeded(`findings:${org}`, (r) => {
        const out: DemoFinding[] = [{
            id: s.findingId, asset_id: s.assetId, asset_value: s.assetValue, port: s.dstPort, protocol: s.protocol.toLowerCase(),
            source_class: 'active_scan', detected_by: ['nuclei'], rule_id: 'demo-critical-001', title: s.findingTitle,
            finding_type: 'vulnerability', cve_ids: [s.cveId], scanner_severity: 'critical', scanner_cvss: 9.1, risk_score: 92,
            priority: 'P1', status: org === 'ikea' ? 'fixed_pending_verification' : 'open', owner: OWNERS[0],
            due_at: ago(1), first_seen: ago(9), last_seen: ago(0), verified_at: org === 'ikea' ? null : null, case_id: s.caseId,
            description: `[DEMO] ${s.narrative}`, remediation: 'Apply the vendor patch and restrict management access to the internal network only.', overdue: true,
        }];
        for (let i = 0; i < 9; i++) {
            const priority = r.pick(['P1', 'P2', 'P2', 'P3', 'P3', 'P4'] as const);
            const sev = priority === 'P1' ? 'critical' : priority === 'P2' ? 'high' : priority === 'P3' ? 'medium' : 'low';
            const status = r.pick(['open', 'open', 'acknowledged', 'in_progress', 'verified', 'risk_accepted'] as const);
            out.push({
                id: `demo-${org}-finding-${i}`, asset_id: `demo-${org}-asset-${i % 5}`, asset_value: `host-${i % 5}.${org}-demo.test`,
                port: r.pick([22, 443, 3389, 8080, 3306]), protocol: 'tcp', source_class: r.bool(0.6) ? 'active_scan' : 'wazuh',
                detected_by: [r.pick(['nuclei', 'openvas', 'wazuh-vuln'])], rule_id: `demo-${1000 + i}`, title: r.pick(TITLES),
                finding_type: 'vulnerability', cve_ids: r.bool(0.5) ? [`CVE-202${r.int(2, 5)}-${r.int(1000, 9999)}`] : [],
                scanner_severity: sev, scanner_cvss: sev === 'critical' ? 9 + r.next() : sev === 'high' ? 7 + r.next() * 2 : sev === 'medium' ? 4 + r.next() * 3 : r.next() * 4,
                risk_score: r.int(10, 95), priority, status, owner: r.bool(0.6) ? r.pick(OWNERS) : null,
                due_at: status === 'open' ? ahead(r.int(-3, 14)) : null, first_seen: ago(r.int(5, 60)), last_seen: ago(r.int(0, 4)),
                verified_at: status === 'verified' ? ago(r.int(0, 5)) : null, case_id: null,
                overdue: status === 'open' && r.bool(0.3),
            });
        }
        return out;
    });
}

export function demoFindingsSummary(org: DemoOrgId) {
    const findings = demoFindings(org);
    const open = findings.filter((f) => ['open', 'acknowledged', 'in_progress'].includes(f.status));
    const by = <K extends string>(rows: DemoFinding[], key: (f: DemoFinding) => K) => rows.reduce<Record<string, number>>((acc, f) => { const k = key(f); acc[k] = (acc[k] ?? 0) + 1; return acc; }, {});
    return {
        open: open.length,
        by_severity: by(open, (f) => f.scanner_severity),
        by_priority: by(open, (f) => f.priority ?? 'P4'),
        known_exploited_open: open.filter((f) => f.cve_ids.length > 0 && f.priority === 'P1').length,
        overdue: open.filter((f) => f.overdue).length,
        by_source: by(open, (f) => f.source_class),
    };
}

export function demoRemediationQueue(org: DemoOrgId) {
    return { items: demoFindings(org).filter((f) => (f.priority === 'P1' || f.priority === 'P2') && f.status !== 'verified').map((f) => ({ ...f, overdue: !!f.overdue })) };
}

export function demoAiPlans(org: DemoOrgId) {
    const s = DEMO_SCENARIOS[org];
    return {
        plans: [{
            id: `demo-${org}-plan-1`, purpose: 'remediation_plan' as const, subject_id: s.findingId, model: 'demo-simulated',
            created_by: 'AI Remediation Assistant (Demo)', created_at: ago(2), status: 'accepted' as const, feedback: 'Reviewed by SOC manager — useful', feedback_by: 'SOC Manager (Demo)',
            content: {
                summary: `[DEMO] Proposed remediation for ${s.findingTitle}.`,
                steps: [
                    { order: 1, action: 'Apply vendor security patch', details: `Patches ${s.cveId} on ${s.assetName}.`, owner_suggestion: 'Platform Team (Demo)', proposed_deadline_days: 3 },
                    { order: 2, action: 'Restrict management interface to internal network', details: 'Remove internet-facing access; require VPN.', owner_suggestion: 'Network Team (Demo)', proposed_deadline_days: 5 },
                    { order: 3, action: 'Run verification scan', details: 'Confirm the fix with an authorised rescan.', owner_suggestion: 'SOC Analyst (Demo)', proposed_deadline_days: 7 },
                ],
            },
            finding: { title: s.findingTitle, asset_value: s.assetValue, priority: 'P1' as const },
        }],
    };
}

export function demoScans(org: DemoOrgId) {
    const s = DEMO_SCENARIOS[org];
    return seeded(`scans:${org}`, (r) => ({
        scans: Array.from({ length: 6 }, (_, i) => ({
            id: `demo-${org}-scan-${i}`, scope_id: `demo-${org}-scope-1`, kind: r.pick(['vuln_nuclei', 'discovery', 'ports'] as const),
            targets: [i === 0 ? s.assetValue : `host-${i % 5}.${org}-demo.test`], options: {},
            status: i === 0 ? 'succeeded' as const : r.pick(['succeeded', 'succeeded', 'failed'] as const),
            requested_by: 'SOC Analyst (Demo)', requested_at: ago(i), started_at: ago(i), finished_at: ago(i - 0.01),
            progress: {}, error: null, summary: { outcome: 'reachable_and_assessed' }, worker_id: 'demo-worker', heartbeat_at: null, cancel_requested: false, purpose: i === 0 && org === 'ikea' ? 'verification' : 'scheduled',
        })),
    }));
}
