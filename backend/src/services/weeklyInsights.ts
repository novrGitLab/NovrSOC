// Weekly insights (phase P8): one organisation's security operations for a stated period compared
// with the period before, counted from stored records — alerts, cases, response approvals,
// vulnerability management and threat-intelligence matches — plus the platform's own health
// checks, so that gaps in the data are stated next to the numbers. The same facts are shown to
// people (GET /api/insights/weekly) and given to the AI model (purpose weekly_insights); the model adds
// interpretation, never numbers of its own.

import { getSupabase } from './geoEnrichment';
import { pipelineChecks } from './pipelineHealth';
import { OPEN_STATUSES } from './vmsContinuous';

const DAY = 86_400_000;
type Count = { count: number | null; error: { message: string } | null };

export interface WeeklyFacts {
    org: string;
    period: { from: string; to: string; days: number; previous_from: string };
    alerts: { total: number; previous_total: number; by_severity: Record<string, number>; previous_by_severity: Record<string, number>; top_rules: { rule_id: string | null; description: string | null; count: number }[]; top_agents: { agent: string; count: number }[]; sampled: boolean };
    cases: { opened: number; previous_opened: number; resolved: number; open_now: number; overdue_now: number; by_severity_opened: Record<string, number> };
    approvals: Record<string, number>;
    vulnerabilities: { open_now: number; open_by_priority: Record<string, number>; new_p1_p2: number; verified: number; reopened: number; overdue_now: number } | null;
    threat_intel: { new_matches: number; promoted: number } | null;
    health: { name: string; status: string; detail: string }[];
    limitations: string[];
}

const tally = <T,>(rows: T[], key: (r: T) => string | null | undefined) => rows.reduce<Record<string, number>>((a, r) => { const k = key(r) ?? 'unknown'; a[k] = (a[k] ?? 0) + 1; return a; }, {});
const top = (m: Record<string, number>, n: number) => Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, n);
const ALERT_SAMPLE = 20_000;

export async function weeklyFacts(org: string, days = 7, now = new Date()): Promise<WeeklyFacts> {
    const supabase = getSupabase()!;
    const to = now.toISOString();
    const from = new Date(now.getTime() - days * DAY).toISOString();
    const prevFrom = new Date(now.getTime() - 2 * days * DAY).toISOString();
    const limitations: string[] = [];
    const n = (r: Count) => r.count ?? 0;

    // Alerts
    const [cur, prev] = await Promise.all([
        supabase.from('alerts').select('severity, rule_id, rule_description, agent_name', { count: 'exact' }).eq('org_id', org).gte('received_at', from).lt('received_at', to).limit(ALERT_SAMPLE),
        supabase.from('alerts').select('severity', { count: 'exact' }).eq('org_id', org).gte('received_at', prevFrom).lt('received_at', from).limit(ALERT_SAMPLE),
    ]);
    if (cur.error) limitations.push(`Alerts could not be read: ${cur.error.message.slice(0, 120)}`);
    const rows = cur.data ?? [];
    const sampled = (cur.count ?? rows.length) > rows.length;
    if (sampled) limitations.push(`Alert breakdowns use the first ${rows.length} of ${cur.count} alerts in the period; totals are exact.`);
    const ruleCounts = tally(rows, (r) => `${r.rule_id ?? ''}\u0000${r.rule_description ?? ''}`);

    // Cases
    const cases = () => supabase.from('cases').select('id', { count: 'exact', head: true }).eq('org_id', org);
    const [opened, prevOpened, resolved, openNow, overdue, openedRows] = await Promise.all([
        cases().gte('created_at', from).lt('created_at', to),
        cases().gte('created_at', prevFrom).lt('created_at', from),
        cases().gte('resolved_at', from).lt('resolved_at', to),
        cases().neq('status', 'resolved'),
        cases().neq('status', 'resolved').lt('due_at', to),
        supabase.from('cases').select('severity').eq('org_id', org).gte('created_at', from).lt('created_at', to).limit(5000),
    ]);

    // Response approvals
    const appr = await supabase.from('response_approvals').select('status').eq('org_id', org).gte('requested_at', from).lt('requested_at', to).limit(5000);
    if (appr.error) limitations.push('Response approvals are not set up (P3 SQL not applied).');

    // Vulnerability management
    let vulnerabilities: WeeklyFacts['vulnerabilities'] = null;
    const open = await supabase.from('vms_findings').select('priority, due_at').eq('org_id', org).in('status', [...OPEN_STATUSES]).limit(20_000);
    if (open.error) limitations.push('Vulnerability management is not set up (P5 SQL not applied).');
    else {
        const [newP, verified, reopened] = await Promise.all([
            supabase.from('vms_findings').select('id', { count: 'exact', head: true }).eq('org_id', org).in('priority', ['P1', 'P2']).gte('first_seen', from).lt('first_seen', to),
            supabase.from('vms_findings').select('id', { count: 'exact', head: true }).eq('org_id', org).gte('verified_at', from).lt('verified_at', to),
            supabase.from('vms_finding_events').select('id', { count: 'exact', head: true }).eq('org_id', org).eq('action', 'reopened').gte('at', from).lt('at', to),
        ]);
        const o = open.data ?? [];
        vulnerabilities = { open_now: o.length, open_by_priority: tally(o, (f) => f.priority ?? 'unscored'), new_p1_p2: n(newP), verified: n(verified), reopened: n(reopened), overdue_now: o.filter((f) => f.due_at && f.due_at < to).length };
    }

    // Threat intelligence
    let threat_intel: WeeklyFacts['threat_intel'] = null;
    const m = await supabase.from('ti_matches').select('status').eq('org_id', org).gte('first_matched_at', from).lt('first_matched_at', to).limit(5000);
    if (m.error) limitations.push('The Threat Information System is not set up (P6 SQL not applied).');
    else threat_intel = { new_matches: (m.data ?? []).length, promoted: (m.data ?? []).filter((x) => x.status === 'promoted').length };

    // Platform health now: a down pipeline means the numbers above may be incomplete.
    const health = await pipelineChecks().catch(() => []);
    for (const h of health) if (h.status === 'down' || h.status === 'degraded') limitations.push(`${h.name} is ${h.status} now (${h.detail}); figures that depend on it may be incomplete.`);

    return {
        org,
        period: { from, to, days, previous_from: prevFrom },
        alerts: {
            total: cur.count ?? rows.length, previous_total: prev.count ?? (prev.data ?? []).length,
            by_severity: tally(rows, (r) => r.severity), previous_by_severity: tally(prev.data ?? [], (r) => r.severity),
            top_rules: top(ruleCounts, 10).map(([k, c]) => { const [id, d] = k.split('\u0000'); return { rule_id: id || null, description: d || null, count: c }; }),
            top_agents: top(tally(rows, (r) => r.agent_name), 5).map(([agent, count]) => ({ agent, count })),
            sampled,
        },
        cases: { opened: n(opened), previous_opened: n(prevOpened), resolved: n(resolved), open_now: n(openNow), overdue_now: n(overdue), by_severity_opened: tally(openedRows.data ?? [], (c) => c.severity) },
        approvals: tally(appr.data ?? [], (a) => a.status),
        vulnerabilities,
        threat_intel,
        health: health.map((h) => ({ name: h.name, status: h.status, detail: h.detail })),
        limitations,
    };
}
