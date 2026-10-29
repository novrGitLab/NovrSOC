import type { DemoOrgId } from './types';
import * as vms from './generators/vms';
import * as ti from './generators/ti';
import * as secops from './generators/secops';
import * as cnii from './generators/cnii';
import * as collectors from './generators/collectors';
import * as reports from './generators/reports';
import * as misc from './generators/misc';
import { setDemoOverlay, prependDemoListField } from './mutations';
import { DEMO_SCENARIOS } from './scenario';

const SIMULATED_MESSAGE = 'Presentation Mode: simulated — no real action was taken and nothing was sent anywhere.';

/** Tags a demo response with a non-200 HTTP status — lib/api.ts's demoFetch() reads and strips
 * this marker. Used for the handful of endpoints (the real AI-generation route) whose consuming
 * component already has a designed-for "AI unavailable, here's why" state that a plain 200 with
 * an empty body wouldn't trigger — reusing that existing honest-degradation UX instead of a
 * generic blob the component wasn't built to display. */
export function withStatus(status: number, body: Record<string, unknown>): Record<string, unknown> {
    return { __demoStatus: status, ...body };
}

/**
 * Answers one /api/* request from demo data only, for the given demo organisation. Returns
 * `undefined` for a GET path this file has no demo data for — the caller (lib/api.ts's apiFetch)
 * still answers those with a safe empty shape rather than ever reaching the real network, so an
 * unmapped widget degrades to its own honest empty state instead of crashing or leaking to
 * production.
 */
export function demoResponseFor(pathname: string, search: URLSearchParams, method: string, org: DemoOrgId, body: unknown): unknown {
    const m = method.toUpperCase();
    const p = pathname.replace(/\/+$/, '');

    if (m !== 'GET' && m !== 'HEAD') {
        return demoMutationFor(p, m, org, body) ?? { ok: true, success: true, demo: true, simulated: true, message: SIMULATED_MESSAGE };
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
    if (p === '/api/response-approvals') return secops.demoResponseApprovals(org, search.get('status') ?? undefined);
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

    // ── AI assistant (shared/AiPanel.tsx — used from VMS, TI, SecOps and CNII screens) ─────────
    // Empty, not undefined: AiPanel.tsx already treats "no artifact found" as its normal empty
    // state ("nothing is shown in its place"), so this is an honest answer, not a stub.
    if (p === '/api/ai/artifacts') return { artifacts: [] };

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

function asBody(body: unknown): Record<string, unknown> {
    return body && typeof body === 'object' ? (body as Record<string, unknown>) : {};
}

/**
 * The small set of writes a presenter is actually likely to click during the walkthrough — these
 * get a REAL (session-local, in-browser) effect via lib/demo/mutations.ts instead of a generic
 * stubbed success, so clicking "mark verified" or "approve" visibly changes the next read. Every
 * other write still never reaches the network; it just doesn't pretend to have changed anything
 * specific, since there's nothing specific here for it to change. Returns `undefined` for a path
 * this function doesn't specifically handle, so the caller falls back to the generic simulated
 * response.
 */
function demoMutationFor(p: string, method: string, org: DemoOrgId, body: unknown): unknown {
    const b = asBody(body);
    const now = new Date().toISOString();

    // PATCH /api/vms/findings/:id — status/owner/priority/etc. changes (VmsFindings.tsx,
    // VmsRemediationPlus.tsx "mark verified" / "request verification scan" actions).
    const findingMatch = method === 'PATCH' && p.match(/^\/api\/vms\/findings\/([^/]+)$/);
    if (findingMatch) {
        const patch: Record<string, unknown> = { ...b };
        if (b.status === 'verified') { patch.verified_at = now; patch.overdue = false; }
        if (b.status && b.status !== 'open') patch.overdue = false;
        setDemoOverlay(org, 'vms-findings', findingMatch[1], patch);
        return { ok: true, demo: true, simulated: true, message: 'Presentation Mode: finding updated for this session.', finding: { id: findingMatch[1], ...patch } };
    }

    // POST /api/ai/generate — the shared AiPanel component used across VMS, TI, SecOps and CNII
    // screens for case summaries, finding explanations, threat briefings, etc. This calls the
    // same production text-generation route, so Presentation Mode never calls it — instead it returns
    // the non-200 response AiPanel.tsx was already built to show as "AI unavailable" rather than
    // silently rendering an empty or malformed result.
    if (method === 'POST' && p === '/api/ai/generate') {
        return withStatus(503, { error: 'Presentation Mode: AI analysis is not generated here — this would call the same production text-generation service Presentation Mode intentionally never contacts.' });
    }

    // POST /api/ti/analyst/ask — the AI Q&A assistant on the TI Analyst page. Rather than
    // claiming a real cited answer, this gives an honest, clearly-labelled scripted answer tied
    // to the selected organisation's scenario, since that panel has no "unavailable" state of its
    // own to fall back on.
    if (method === 'POST' && p === '/api/ti/analyst/ask') {
        const s = DEMO_SCENARIOS[org];
        return {
            answer: `[SAMPLE] This is a scripted demonstration answer, not a real cited response. For ${org.toUpperCase()}, the relevant record is the ${s.caseNumber} case: ${s.narrative}`,
            statements: [{ statement: `[SAMPLE] ${s.findingTitle}`, basis: 'direct' as const, evidence_refs: [s.findingId] }],
            insufficient_evidence: false, suggested_follow_ups: [`What is the status of ${s.caseNumber}?`, `What indicators are linked to ${s.assetName}?`],
            confidence: 'high' as const, demo: true, simulated: true,
        };
    }

    // POST /api/vms/findings/:id/verify — VmsRemediationPlus.tsx's "Verify" button, the
    // headline IKEA scenario action (remediation → verification → risk improvement). The real
    // backend queues an async rescan; Presentation Mode has no scan worker to poll, so it verifies
    // immediately and says so, rather than claiming a scan was queued that will never complete.
    const verifyMatch = method === 'POST' && p.match(/^\/api\/vms\/findings\/([^/]+)\/verify$/);
    if (verifyMatch) {
        setDemoOverlay(org, 'vms-findings', verifyMatch[1], { status: 'verified', verified_at: now, overdue: false });
        return { queued: false, demo: true, simulated: true, message: 'Presentation Mode: verification completed immediately — finding marked verified fixed for this session (no real scan was queued).' };
    }

    // PATCH /api/cases/:id — status / due_at (CaseWorkbench.tsx updateStatus / setDeadline).
    const caseMatch = method === 'PATCH' && p.match(/^\/api\/cases\/([^/]+)$/);
    if (caseMatch) {
        const patch: Record<string, unknown> = { ...b };
        if (b.status === 'resolved') patch.resolved_at = now;
        setDemoOverlay(org, 'cases', caseMatch[1], patch);
        return { ok: true, demo: true, simulated: true, message: 'Presentation Mode: case updated for this session.', case: { id: caseMatch[1], ...patch } };
    }

    // POST /api/cases/:id/assign
    const assignMatch = method === 'POST' && p.match(/^\/api\/cases\/([^/]+)\/assign$/);
    if (assignMatch) {
        setDemoOverlay(org, 'cases', assignMatch[1], { assigned_to: b.analyst_id ?? 'SOC Analyst (Sample)' });
        return { ok: true, demo: true, simulated: true, message: 'Presentation Mode: assignment updated for this session.' };
    }

    // POST /api/cases/:id/escalate
    const escalateMatch = method === 'POST' && p.match(/^\/api\/cases\/([^/]+)\/escalate$/);
    if (escalateMatch) {
        setDemoOverlay(org, 'cases', escalateMatch[1], { escalated: true });
        prependDemoListField(org, 'cases', escalateMatch[1], 'timeline', { id: `demo-tl-${Date.now()}`, actor: 'SOC Analyst (Sample)', action: 'Case escalated', details: '[SAMPLE] Escalated for management visibility.', automated: false, created_at: now });
        return { ok: true, demo: true, simulated: true, message: 'Presentation Mode: case escalated for this session.' };
    }

    // POST /api/cases/:id/close — resolution notes
    const closeMatch = method === 'POST' && p.match(/^\/api\/cases\/([^/]+)\/close$/);
    if (closeMatch) {
        setDemoOverlay(org, 'cases', closeMatch[1], { status: 'resolved', resolved_at: now });
        prependDemoListField(org, 'cases', closeMatch[1], 'notes', { id: `demo-note-${Date.now()}`, author: 'SOC Analyst (Sample)', type: 'Resolution', content: `[SAMPLE] ${String(b.resolution_notes ?? 'Closed during walkthrough.')}`, created_at: now });
        prependDemoListField(org, 'cases', closeMatch[1], 'timeline', { id: `demo-tl-${Date.now()}`, actor: 'SOC Analyst (Sample)', action: 'Case closed', details: '[SAMPLE] Closed with resolution notes.', automated: false, created_at: now });
        return { ok: true, demo: true, simulated: true, message: 'Presentation Mode: case closed for this session.' };
    }

    // POST /api/cases/:id/notes
    const noteMatch = method === 'POST' && p.match(/^\/api\/cases\/([^/]+)\/notes$/);
    if (noteMatch) {
        prependDemoListField(org, 'cases', noteMatch[1], 'notes', { id: `demo-note-${Date.now()}`, author: 'SOC Analyst (Sample)', type: String(b.type ?? 'Update'), content: `[SAMPLE] ${String(b.content ?? '')}`, created_at: now });
        return { ok: true, demo: true, simulated: true, message: 'Presentation Mode: note added for this session.' };
    }

    // POST /api/reports/generate — ReportingCenter.tsx's "Generate" tab. The real Sample
    // Documents tab is the intended way to get a PDF in Presentation Mode; this just answers honestly if
    // a presenter clicks Generate anyway, instead of claiming a report job was actually queued.
    if (method === 'POST' && p === '/api/reports/generate') {
        return { status: 'skipped', warnings: ['Presentation Mode: no report job was generated or delivered — use the Sample Documents tab for a real downloadable PDF.'], demo: true, simulated: true };
    }

    // POST /api/response-approvals/:id/(approve|reject|cancel)
    const approvalMatch = method === 'POST' && p.match(/^\/api\/response-approvals\/([^/]+)\/(approve|reject|cancel)$/);
    if (approvalMatch) {
        const [, id, kind] = approvalMatch;
        const status = kind === 'approve' ? 'approved' : kind === 'reject' ? 'rejected' : 'cancelled';
        const result = kind === 'approve' ? 'executed (demo — no real firewall/Wazuh call was made)' : null;
        setDemoOverlay(org, 'response-approvals', id, { status, decided_by: 'SOC Manager (Sample)', decided_at: now, decision_note: b.note ?? null, result });
        return { ok: true, demo: true, simulated: true, message: `Presentation Mode: approval ${status} for this session.`, approval: { id, status, result } };
    }

    return undefined;
}
