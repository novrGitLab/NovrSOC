import type { DemoOrgId } from './types';
import * as vms from './generators/vms';
import * as ti from './generators/ti';
import * as secops from './generators/secops';
import * as cnii from './generators/cnii';
import * as collectors from './generators/collectors';
import * as reports from './generators/reports';
import * as misc from './generators/misc';

/**
 * Answers one /api/* request from demo data only, for the given demo organisation. Returns
 * `undefined` for a path this file has no demo data for — the caller (lib/api.ts's apiFetch)
 * still answers those with a safe empty shape rather than ever reaching the real network, so an
 * unmapped widget degrades to its own honest empty state instead of crashing or leaking to
 * production.
 */
export function demoResponseFor(pathname: string, search: URLSearchParams, method: string, org: DemoOrgId): unknown {
    const m = method.toUpperCase();
    const p = pathname.replace(/\/+$/, '');

    // Mutations never reach the network in Demo Mode — a uniform, clearly-labelled synthetic
    // success/no-op for every write, rather than enumerating each one (new demo write paths never
    // need their own case added here to stay safe).
    if (m !== 'GET' && m !== 'HEAD') {
        return { ok: true, success: true, demo: true, message: 'Demo Mode: no real action was taken.' };
    }

    // ── VMS ──────────────────────────────────────────────────────────────────────────────────
    if (p === '/api/vms/findings/summary') return vms.demoFindingsSummary(org);
    if (p === '/api/vms/findings') {
        const status = search.get('status');
        const overdue = search.get('overdue') === 'true';
        let findings = vms.demoFindings(org);
        if (status === 'open_all') findings = findings.filter((f) => ['open', 'acknowledged', 'in_progress'].includes(f.status));
        else if (status) findings = findings.filter((f) => status.split(',').includes(f.status));
        if (overdue) findings = findings.filter((f) => f.overdue);
        return { findings };
    }
    if (p === '/api/vms/remediation') return vms.demoRemediationQueue(org);
    if (p === '/api/vms/ai-plans') return vms.demoAiPlans(org);
    if (p === '/api/vms/scans') return vms.demoScans(org);

    // ── Threat Intelligence ──────────────────────────────────────────────────────────────────
    if (p === '/api/ti/overview') return ti.demoTiOverview(org);
    if (p === '/api/ti/map') return ti.demoTiMap(org);
    if (p === '/api/ti/matches') return ti.demoTiMatches(org, search.get('status') ?? undefined);
    if (p === '/api/ti/vulnerabilities') return ti.demoTiVulnerabilities(org);
    if (p === '/api/ti/relevant') return ti.demoTiRelevant(org);

    // ── SecOps / Cases ───────────────────────────────────────────────────────────────────────
    if (p === '/api/cases') {
        const status = search.get('status');
        const escalated = search.get('escalated') === 'true';
        const r = secops.demoCases(org, status ?? undefined);
        if (escalated) return { ...r, cases: r.cases.filter((c) => c.escalated) };
        return r;
    }
    const caseDetailMatch = p.match(/^\/api\/cases\/([^/]+)$/);
    if (caseDetailMatch) return secops.demoCaseDetail(org, caseDetailMatch[1]) ?? { error: 'Demo case not found' };
    if (p === '/api/response-approvals') return secops.demoResponseApprovals(org);
    if (p === '/api/soar/stats') return secops.demoSoarStats(org);
    if (p === '/api/alerts') return secops.demoAlertsFeed(org, Number(search.get('limit')) || 10);
    if (p === '/api/alerts/stats') return secops.demoAlertStats(org);
    if (p === '/api/playbooks') return secops.demoPlaybooks();
    if (p === '/api/communications/recipients') return secops.demoCommunicationsRecipients(org);

    // ── CNII Watch ───────────────────────────────────────────────────────────────────────────
    if (p === '/api/cnii/sectors') return cnii.demoCniiSectors();
    if (p === '/api/cnii/organisations') return cnii.demoCniiOrganisations();
    if (p === '/api/cnii/legacy') return cnii.demoCniiLegacy();

    // ── Collector Management ─────────────────────────────────────────────────────────────────
    if (p === '/api/collectors') return { collectors: collectors.demoCollectors(org) };
    const collectorEventsMatch = p.match(/^\/api\/collectors\/([^/]+)\/events$/);
    if (collectorEventsMatch) return collectors.demoCollectorEvents(org);
    const collectorDetailMatch = p.match(/^\/api\/collectors\/([^/]+)$/);
    if (collectorDetailMatch) {
        const list = collectors.demoCollectors(org);
        const c = list.find((x) => x.id === collectorDetailMatch[1]) ?? list[0];
        return { collector: { ...c, effective_status: c.status }, ...collectors.demoCollectorDetail(org) };
    }

    // ── Reporting Center ─────────────────────────────────────────────────────────────────────
    if (p === '/api/reports/types') return reports.demoReportTypes();
    if (p === '/api/reports/schedules') return reports.demoReportSchedules(org);
    if (p === '/api/reports/recipients') return reports.demoReportRecipients(org);
    if (p === '/api/reports/history') return reports.demoReportHistory(org);
    if (p === '/api/reports/ops/health') return reports.demoReportOpsHealth();

    // ── Dashboard / platform-wide widgets ────────────────────────────────────────────────────
    if (p === '/api/platform/health') return misc.demoPlatformHealth();
    if (p === '/api/compliance') return misc.demoCompliance(org);
    if (p === '/api/novr-ai/status') return misc.demoNovrAiStatus();
    if (p === '/api/wazuh/agents') return misc.demoWazuhAgents();
    if (p === '/api/wazuh/status') return misc.demoWazuhStatus();
    if (p === '/api/wazuh/mitre-stats') return misc.demoWazuhMitreStats();
    if (p === '/api/wazuh/trend') return misc.demoWazuhTrend(org, search.get('range') ?? '7d');
    if (p === '/api/customers') return misc.demoCustomers();

    return undefined;
}
