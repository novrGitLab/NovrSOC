import type { DemoOrgId } from '../types';
import { seeded } from '../rng';
import { DEMO_SCENARIOS } from '../scenario';

const ago = (days: number) => new Date(Date.now() - days * 86_400_000).toISOString();
const agoH = (hours: number) => new Date(Date.now() - hours * 3_600_000).toISOString();
const SEVS = ['critical', 'high', 'medium', 'low'] as const;
const STATUSES = ['open', 'investigating', 'contained', 'resolved'] as const;

export function demoCases(org: DemoOrgId, statusFilter?: string) {
    const s = DEMO_SCENARIOS[org];
    const all = seeded(`cases:${org}`, (r) => {
        const featured = {
            id: s.caseId, case_number: s.caseNumber, title: `[DEMO] ${s.caseTitle}`, description: `[DEMO] ${s.narrative}`,
            severity: 'critical' as const, status: 'investigating' as const, source: 'manual', agent_id: null, agent_name: null,
            source_ip: s.srcIp, rule_id: 'demo-5710', rule_level: 12, mitre_technique: 'T1110', mitre_tactic: 'Credential Access',
            assigned_to: 'SOC Analyst (Demo)', created_at: ago(1), updated_at: agoH(2), resolved_at: null, due_at: ago(-1),
            tier: 2, auto_closed: false, containment_done: false, escalated: true, tags: ['demo'],
        };
        const rest = Array.from({ length: 11 }, (_, i) => {
            const status = r.pick(STATUSES);
            return {
                id: `demo-${org}-case-${i + 2}`, case_number: `CASE-${org.toUpperCase()}-${String(1 + i).padStart(4, '0')}`,
                title: `[DEMO] ${r.pick(['Suspicious login from unrecognised location', 'Malware signature detected on endpoint', 'Unusual outbound data transfer', 'Multiple failed VPN authentication attempts', 'Port scan detected against perimeter firewall'])}`,
                description: '[DEMO] Synthetic case for demonstration.', severity: r.pick(SEVS), status, source: r.pick(['manual', 'wazuh']),
                agent_id: r.bool(0.5) ? `00${i}` : null, agent_name: r.bool(0.5) ? `host-${i}.${org}-demo.test` : null, source_ip: `198.51.100.${r.int(10, 250)}`,
                rule_id: `demo-${5000 + i}`, rule_level: r.int(6, 14), mitre_technique: null, mitre_tactic: null,
                assigned_to: r.bool(0.6) ? 'SOC Analyst (Demo)' : null, created_at: ago(r.int(1, 30)), updated_at: ago(r.int(0, 5)),
                resolved_at: status === 'resolved' ? ago(r.int(0, 3)) : null, due_at: null, tier: r.int(1, 3), auto_closed: false,
                containment_done: status === 'contained', escalated: r.bool(0.2), tags: [],
            };
        });
        return [featured, ...rest];
    });
    const cases = statusFilter && statusFilter !== 'all' ? all.filter((c) => c.status === statusFilter) : all;
    const unresolved = all.filter((c) => c.status !== 'resolved');
    const by = (pred: (c: typeof all[number]) => boolean) => all.filter(pred).length;
    return {
        cases, total: cases.length,
        summary: {
            open: by((c) => c.status === 'open'), investigating: by((c) => c.status === 'investigating'), contained: by((c) => c.status === 'contained'),
            active: unresolved.length, critical: by((c) => c.severity === 'critical' && c.status !== 'resolved'), resolved: by((c) => c.status === 'resolved'),
            resolvedToday: by((c) => c.status === 'resolved' && Date.parse(c.resolved_at ?? '0') > Date.now() - 86_400_000),
            severity: { critical: by((c) => c.severity === 'critical' && c.status !== 'resolved'), high: by((c) => c.severity === 'high' && c.status !== 'resolved'), medium: by((c) => c.severity === 'medium' && c.status !== 'resolved'), low: by((c) => c.severity === 'low' && c.status !== 'resolved') },
        },
    };
}

export function demoCaseDetail(org: DemoOrgId, caseId: string) {
    const s = DEMO_SCENARIOS[org];
    const match = demoCases(org).cases.find((c) => c.id === caseId);
    if (!match) return null;
    const isFeatured = caseId === s.caseId;
    return {
        case: match,
        notes: isFeatured ? [{ id: 'n1', author: 'SOC Analyst (Demo)', type: 'Update' as const, content: `[DEMO] Confirmed ${s.indicatorValue} matches a known indicator; escalating.`, created_at: agoH(3) }] : [],
        tasks: isFeatured ? [{ id: 't1', step_id: 'isolate_agent', title: 'Block source address at the perimeter', description: 'Demo containment step', status: 'pending' }] : [],
        timeline: [
            { id: 'tl1', actor: 'system', action: 'Case created', details: '[DEMO] Opened from correlated detection', automated: true, created_at: ago(1) },
            ...(isFeatured ? [{ id: 'tl2', actor: 'SOC Analyst (Demo)', action: 'Investigation started', details: '[DEMO] Reviewing authentication logs and TI match', automated: false, created_at: agoH(4) }] : []),
        ],
        iocs: isFeatured ? [{ id: 'ioc1', type: 'ip', value: s.indicatorValue, verdict: 'malicious', risk_score: 88 }] : [],
        linked: [],
        threat_intelligence: isFeatured ? [{ indicator_type: 'ip', indicator_value: s.indicatorValue, confidence: 80, malware_families: ['Demo-Stealer'], threat_types: ['credential-theft'], verified: true, status: 'new', case_id: s.caseId, tlp: 'amber', indicator_active: true }] : [],
    };
}

export function demoResponseApprovals(org: DemoOrgId) {
    return seeded(`approvals:${org}`, (r) => ({ approvals: Array.from({ length: r.int(0, 2) }, (_, i) => ({ id: `demo-${org}-approval-${i}`, action: 'block_ip', target: `198.51.100.${r.int(10, 200)}`, target_label: null, reason: '[DEMO] Suspicious activity', case_id: null, threat_id: null, source: 'demo', status: 'pending', requested_by: 'SOC Analyst (Demo)', requested_at: ago(1), decided_by: null, decided_at: null, decision_note: null, result: null })) }));
}

export function demoSoarStats(org: DemoOrgId) {
    return seeded(`soar:${org}`, (r) => ({ cases_created_today: r.int(1, 5), auto_resolved_today: r.int(0, 3), open_cases: r.int(3, 10), escalated_open: r.int(0, 2), engine_active: true }));
}

export function demoAlertsFeed(org: DemoOrgId, limit = 10) {
    const s = DEMO_SCENARIOS[org];
    return seeded(`alerts-feed:${org}`, (r) => ({
        alerts: Array.from({ length: limit }, (_, i) => i === 0 ? {
            id: `demo-${org}-alert-0`, severity: 'critical', rule_description: `[DEMO] ${s.findingTitle}`, agent_name: s.assetName, agent_ip: s.dstIp, event_time: agoH(1),
        } : {
            id: `demo-${org}-alert-${i}`, severity: r.pick(SEVS), rule_description: `[DEMO] ${r.pick(['Failed login attempt', 'Firewall block', 'Port scan detected', 'File integrity change', 'Unusual process execution'])}`,
            agent_name: `host-${i}.${org}-demo.test`, agent_ip: `198.51.100.${r.int(10, 250)}`, event_time: agoH(r.int(1, 48)),
        }),
    }));
}

export function demoAlertStats(org: DemoOrgId) {
    return seeded(`alert-stats:${org}`, (r) => ({
        range: '7d', since: ago(7), total: r.int(40, 120),
        by_severity: { critical: r.int(1, 5), high: r.int(5, 15), medium: r.int(10, 30), low: r.int(20, 60) },
        by_status: { new: r.int(5, 20), acknowledged: r.int(5, 15), closed: r.int(20, 60) },
        last_received_at: agoH(1), last_event_time: agoH(1), stale_after_minutes: 60,
    }));
}

export function demoPlaybooks() {
    return [{ id: 'demo-playbook-1', name: '[DEMO] Credential Stuffing Response', description: 'Simulated playbook', tier: 2, steps: 3 }];
}

export function demoCommunicationsRecipients(org: DemoOrgId) {
    return { recipients: [{ name: 'SOC Shift Lead (Demo)', email: `shift-lead@${org}-demo.test` }, { name: 'CISO (Demo)', email: `ciso@${org}-demo.test` }] };
}
