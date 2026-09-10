import { Router, Request, Response } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { search } from '../lib/wazuh-indexer';
import {
    getCases, createCase, getCase, updateCase, getCaseTasks, createTask, getCaseComments, addComment,
    formatCaseForNovrSOC, isTheHiveConfigured, mapNovrSOCStatusToTheHive, isTheHiveStatusTerminal, deriveIncidentNumber,
    tagsForStatusChange, resolveNovrSOCStatus, ESCALATED_TAG,
} from '../services/thehive';
import { sendSlackAlert, sendSlackMessage } from '../services/slack';
import { sendEscalationEmail, isEmailEnabled } from '../services/email';

// A TheHive case id always looks like "~1234567" (confirmed live) — Wazuh-derived incident ids
// look like "INC-2026-1000" (built below). Used to route a given :id to the right backend
// without needing a separate "which source is this" flag anywhere else.
const isTheHiveId = (id: string): boolean => id.startsWith('~');

const router = Router();

// Fire-and-forget Shuffle SOAR notification on incident creation. Never blocks or fails the
// creation request — Shuffle being unreachable/unconfigured must not stop an incident from
// being recorded. No-ops silently when SHUFFLE_WEBHOOK_URL isn't set (SOAR automation is
// optional infra, not a hard dependency).
async function notifyShuffleOfIncident(incident: { id: string; title: string; severity: string }): Promise<void> {
    const webhookUrl = process.env.SHUFFLE_WEBHOOK_URL;
    if (!webhookUrl) return;

    try {
        await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                novrsoc_incident_id: incident.id,
                title: incident.title,
                severity: incident.severity,
                source: 'novrsoc',
                created_at: new Date().toISOString(),
            }),
            signal: AbortSignal.timeout(3000),
        });
    } catch (err) {
        console.error('[Shuffle] Incident notification failed (non-fatal):', err instanceof Error ? err.message : err);
    }
}

// Fire-and-forget Slack notification on incident creation. sendSlackAlert() already no-ops
// (with its own console.warn) when SLACK_WEBHOOK_URL isn't set, so this only needs to guard
// against the call itself throwing/rejecting — never blocks or fails the creation request.
async function notifySlackOfIncident(incident: { id: string; title: string; severity: string; summary: string }): Promise<void> {
    try {
        await sendSlackAlert({
            title: incident.title,
            severity: incident.severity,
            description: incident.summary || incident.title,
            affected_host: 'See case in NovrSOC',
            incident_id: incident.id,
            detected_at: new Date().toLocaleString('en-GB', { timeZone: 'Africa/Lagos' }) + ' WAT',
        });
    } catch (err) {
        console.error('[Slack] Incident notification failed (non-fatal):', err instanceof Error ? err.message : err);
    }
}

interface TimelineEntry {
    id: string;
    timestamp: string;
    actor: string;
    action: string;
    detail: string;
}

interface ContainmentAction {
    id: string;
    label: string;
    status: 'completed' | 'pending' | 'failed';
    completed_at: string | null;
}

interface AnalystNote {
    id: string;
    author: string;
    type: 'Update' | 'Evidence' | 'Decision' | 'Escalation';
    text: string;
    timestamp: string;
}

export interface Incident {
    id: string;
    // Analyst-facing display identifier — INC-{year}-{n}, same shape regardless of source.
    // `id` itself stays the real routing identifier (a raw TheHive `~1234567` for TheHive-backed
    // incidents, e.g.) used for every /api/incidents/:id call; incident_number exists so the UI
    // never has to show that raw value, which would otherwise be the one visible giveaway that
    // TheHive is involved at all. Optional because the Wazuh-derived path's `id` is already in
    // this exact format — no separate field needed there, the UI falls back to `id`.
    incident_number?: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    status: 'new' | 'investigating' | 'contained' | 'resolved' | 'escalated';
    mitre_tactic: string;
    mitre_technique: string;
    affected_assets: string[];
    assigned_analyst: string;
    opened_at: string;
    updated_at: string;
    summary: string;
    source_alert_id: string | null;
    timeline: TimelineEntry[];
    containment_actions: ContainmentAction[];
    notes: AnalystNote[];
    source?: 'wazuh' | 'thehive' | 'internal';
    rule_id?: string;
    sla_remaining?: string;
    // TheHive-backed incidents only — free-form analyst tasks (TheHive's own "Tasks" tab).
    // Wazuh-derived incidents use containment_actions instead (a fixed checklist), so this is
    // left undefined for those rather than populated with an empty array either way.
    tasks?: { _id: string; title: string; description: string; status: string }[];
}

// In-memory note and state store for Wazuh-derived incidents
const incidentStateOverrides: Record<string, { status: any; notes: AnalystNote[]; containment: ContainmentAction[] }> = {};

// Adapts a TheHive case (already run through formatCaseForNovrSOC) onto the same Incident shape
// the Wazuh-derived path below builds, so the frontend's IncidentResponse component can render
// either source without knowing which one it's looking at — formatCaseForNovrSOC's own output
// is missing several fields the frontend's Incident type requires (mitre_tactic,
// affected_assets, timeline, containment_actions, notes), and rendering that mismatch directly
// crashes the UI (e.g. `undefined.join()` on affected_assets). TheHive doesn't have Wazuh's
// MITRE/affected-host/timeline concepts at the case level, so those get honest generic defaults
// rather than fabricated data.
function toWorkbenchIncident(
    c: ReturnType<typeof formatCaseForNovrSOC>,
    extra?: { tasks?: Incident['tasks']; notes?: AnalystNote[] },
): Incident {
    return {
        id: c.id,
        incident_number: c.incident_number,
        title: c.title,
        severity: c.severity,
        // formatCaseForNovrSOC's 'open'/'investigating'/'resolved' collapses onto the frontend's
        // 5-state union — 'open' reads as 'new' there (TheHive has no separate "acknowledged but
        // not yet started" state, and this UI's own status buttons never target 'open').
        status: c.status === 'open' ? 'new' : c.status,
        mitre_tactic: c.tags.length > 0 ? c.tags.join(', ') : 'N/A',
        mitre_technique: c.thehive_status,
        affected_assets: [],
        assigned_analyst: c.assignee || 'Unassigned',
        opened_at: c.opened_at,
        updated_at: c.updated_at,
        summary: c.summary,
        source_alert_id: c.id,
        timeline: [
            { id: 't-1', timestamp: c.opened_at, actor: 'NovrSOC', action: 'Case Created', detail: `${c.incident_number} opened.` },
        ],
        containment_actions: [],
        notes: extra?.notes ?? [],
        source: 'thehive',
        tasks: extra?.tasks ?? [],
    };
}

// Helper to extract MITRE info or fallback gracefully
function getMitreInfo(source: any): { tactic: string; technique: string } {
    const mitre = source?.rule?.mitre;
    if (mitre) {
        const tactic = Array.isArray(mitre.tactic) ? mitre.tactic[0] : mitre.tactic || 'Execution';
        const technique = Array.isArray(mitre.id) ? mitre.id[0] : mitre.id || 'T1059';
        return { tactic, technique };
    }
    const desc = (source?.rule?.description || '').toLowerCase();
    if (desc.includes('ssh') || desc.includes('password') || desc.includes('login')) {
        return { tactic: 'Credential Access', technique: 'T1110 (Brute Force)' };
    }
    if (desc.includes('c2') || desc.includes('beacon') || desc.includes('connection')) {
        return { tactic: 'Command and Control', technique: 'T1071 (Application Layer Protocol)' };
    }
    if (desc.includes('malware') || desc.includes('ransomware') || desc.includes('trojan')) {
        return { tactic: 'Execution', technique: 'T1204 (User Execution)' };
    }
    return { tactic: 'Initial Access', technique: 'T1190 (Exploit Public-Facing Application)' };
}

// GET /api/incidents
router.get('/', async (_req: Request, res: Response) => {
    // Prefer TheHive when it's configured — real case management (persists across restarts,
    // shared across analysts) beats the Wazuh-derived + in-memory-overrides fallback below.
    // Any TheHive failure (unreachable VPS, bad creds, unexpected response shape) falls through
    // to that existing behaviour rather than 500ing the whole incident queue — TheHive being
    // down must not take the SecOps incident view down with it.
    if (isTheHiveConfigured()) {
        try {
            // Incidents shows HIGH (3) and CRITICAL (4) TheHive cases only — LOW (1) and MEDIUM
            // (2) still exist in TheHive and are still handled (SOAR's auto-close job resolves
            // them after 30 idle minutes, jobs/autoClose.ts), they just don't clutter this list.
            // This filter is local to this route — jobs/autoClose.ts and every other direct
            // getCases() caller elsewhere in the backend still see every severity.
            const cases = (await getCases(50)).filter((c) => c.severity >= 3);
            const incidents = cases.map((c) => toWorkbenchIncident(formatCaseForNovrSOC(c)));

            // "Resolved today" needs today's Africa/Lagos (WAT) window — same fixed +1h,
            // no-DST math as GET /automation-status below, so the two stay consistent.
            const WAT_OFFSET_MS = 60 * 60 * 1000;
            const shifted = new Date(Date.now() + WAT_OFFSET_MS);
            const startOfTodayWAT = Date.UTC(shifted.getUTCFullYear(), shifted.getUTCMonth(), shifted.getUTCDate()) - WAT_OFFSET_MS;
            const resolvedToday = cases.filter((c) => c.status && isTheHiveStatusTerminal(c.status) && (c._updatedAt ?? 0) >= startOfTodayWAT).length;

            res.json({
                incidents,
                summary: {
                    total: incidents.length,
                    open: incidents.filter((i) => i.status === 'new').length,
                    critical: incidents.filter((i) => i.severity === 'critical').length,
                    investigating: incidents.filter((i) => i.status === 'investigating').length,
                    resolved: incidents.filter((i) => i.status === 'resolved').length,
                    resolvedToday,
                },
                source: 'thehive',
            });
            return;
        } catch (err) {
            console.warn('[TheHive] getCases failed, falling back to Wazuh-derived incidents:', err instanceof Error ? err.message : err);
        }
    }

    try {
        let wazuhHits: any[] = [];
        try {
            const indexerResult = await search<any>('wazuh-alerts-4.x-*', {
                size: 20,
                sort: [{ timestamp: { order: 'desc' } }],
                query: {
                    bool: {
                        should: [
                            { range: { 'rule.level': { gte: 7 } } },
                            { terms: { 'rule.groups': ['authentication_failed', 'syscheck', 'rootcheck', 'vulnerability'] } }
                        ],
                        minimum_should_match: 1
                    }
                },
                _source: [
                    'id', 'timestamp', 'rule.description', 'rule.level', 'rule.id',
                    'rule.mitre', 'rule.groups', 'agent.name', 'agent.ip', 'agent.id',
                    'data.srcip', 'data.dstip', 'full_log'
                ],
            });
            wazuhHits = indexerResult?.hits?.hits ?? [];
        } catch (wazuhErr) {
            console.warn('[Wazuh Indexer] Incident query fallback triggered:', wazuhErr);
        }

        const incidents: Incident[] = wazuhHits.map((hit: any, index: number) => {
            const src = hit._source || {};
            const docId = hit._id || `wazuh-${index}`;
            const level = Number(src?.rule?.level ?? 7);
            
            let severity: Incident['severity'] = 'low';
            if (level >= 12) severity = 'critical';
            else if (level >= 10) severity = 'high';
            else if (level >= 7) severity = 'medium';

            const agentName = src?.agent?.name || 'DESKTOP-T082T7I';
            const agentIp = src?.agent?.ip ? ` (${src.agent.ip})` : '';
            const affectedAsset = `${agentName}${agentIp}`;
            const mitre = getMitreInfo(src);
            const override = incidentStateOverrides[docId];

            return {
                id: `INC-${new Date(src.timestamp || Date.now()).getFullYear()}-${(1000 + index).toString()}`,
                title: src?.rule?.description || 'Security Incident Flagged by Wazuh SIEM',
                severity,
                status: override?.status || (index === 0 ? 'investigating' : 'new'),
                mitre_tactic: mitre.tactic,
                mitre_technique: mitre.technique,
                affected_assets: [affectedAsset],
                assigned_analyst: index % 2 === 0 ? 'RayneOps' : 'Unassigned',
                opened_at: src.timestamp ? new Date(src.timestamp).toLocaleString() : new Date().toLocaleString(),
                updated_at: src.timestamp ? new Date(src.timestamp).toLocaleString() : new Date().toLocaleString(),
                summary: src.full_log || `Alert triggered by rule ${src?.rule?.id ?? 'N/A'}. Source IP: ${src?.data?.srcip || 'internal'}. Severity Level: ${level}/15.`,
                source_alert_id: docId,
                rule_id: src?.rule?.id,
                sla_remaining: severity === 'critical' ? '00:45:00' : severity === 'high' ? '02:00:00' : '04:00:00',
                timeline: [
                    {
                        id: 't-1',
                        timestamp: src.timestamp ? new Date(src.timestamp).toLocaleTimeString() : '12:00:00',
                        actor: 'Wazuh SIEM Engine',
                        action: 'Alert Ingested & Escalated to Incident',
                        detail: `Rule ID: ${src?.rule?.id || 'N/A'} (Level ${level}) triggered on agent ${agentName}.`
                    }
                ],
                containment_actions: override?.containment || [
                    { id: 'c-1', label: `Isolate Endpoint (${agentName})`, status: 'pending', completed_at: null },
                    { id: 'c-2', label: 'Revoke compromised active sessions', status: 'pending', completed_at: null },
                    { id: 'c-3', label: 'Block Inbound Source IP on Edge Firewall', status: 'pending', completed_at: null }
                ],
                notes: override?.notes || [],
                source: 'wazuh'
            };
        });

        // Computed metrics summary
        const summary = {
            total: incidents.length,
            critical: incidents.filter((i) => i.severity === 'critical').length,
            investigating: incidents.filter((i) => i.status === 'investigating').length,
            resolved: incidents.filter((i) => i.status === 'resolved').length,
        };

        res.json({ incidents, summary });
    } catch (err: any) {
        console.error('Incidents route failure:', err);
        res.status(500).json({ error: err.message || 'Failed to fetch incident queue' });
    }
});

// POST /api/incidents — create a new incident. Uses TheHive when configured (a real, persisted
// case); otherwise there is no durable store to create into today, so this reports that plainly
// rather than pretending to create something that vanishes on the next restart.
router.post('/', async (req: Request, res: Response) => {
    const { title, description, severity, tags } = req.body ?? {};
    if (!title) {
        res.status(400).json({ error: 'title is required' });
        return;
    }

    if (isTheHiveConfigured()) {
        const newCase = await createCase({ title, description, severity, tags });
        if (!newCase) {
            res.status(502).json({ error: 'TheHive case creation failed — see server logs' });
            return;
        }
        const incident = formatCaseForNovrSOC(newCase);
        notifyShuffleOfIncident(incident); // fire-and-forget, never blocks the response
        notifySlackOfIncident(incident); // fire-and-forget, never blocks the response
        res.status(201).json(incident);
        return;
    }

    res.status(501).json({
        error: 'No incident store configured for creation — TheHive is not configured (THEHIVE_URL/THEHIVE_USER/THEHIVE_PASSWORD), and the Wazuh-derived queue above is read-only (incidents there are generated from alerts, not created directly).',
    });
});

// GET /api/incidents/automation-status — real numbers for the SOAR Automation page's status
// panel. Registered before GET /:id below on purpose: Express matches routes in registration
// order, and /:id would otherwise swallow this path as if "automation-status" were an id.
router.get('/automation-status', async (_req: Request, res: Response) => {
    if (!isTheHiveConfigured()) {
        res.json({ active: false, cases_created_today: 0, auto_resolved_today: 0, avg_response_minutes: null });
        return;
    }

    try {
        // Capped, not exhaustive — confirmed live this instance alone can create 200+ cases in
        // a single day (a noisy low-severity Wazuh rule), so on a high-volume day these counts
        // can undercount rather than reflect every case created today. Paginating getCases()
        // to be exhaustive would need it to accept a `from` cursor, which it doesn't today.
        const cases = await getCases(500);

        // Africa/Lagos (WAT) is a fixed UTC+1 offset year-round — no DST to account for — so
        // "start of today" can be computed with plain epoch math instead of a timezone library,
        // matching the WAT convention already used elsewhere in this file (e.g. Slack/summary
        // timestamps).
        const WAT_OFFSET_MS = 60 * 60 * 1000;
        const shifted = new Date(Date.now() + WAT_OFFSET_MS);
        const startOfTodayWAT = Date.UTC(shifted.getUTCFullYear(), shifted.getUTCMonth(), shifted.getUTCDate()) - WAT_OFFSET_MS;

        const createdToday = cases.filter((c) => (c._createdAt ?? 0) >= startOfTodayWAT);

        // Best-effort, not a guaranteed count: a case the autoClose job (jobs/autoClose.ts)
        // resolved is always low/medium severity + terminal status + updated today, but a
        // manual resolve of a low/medium case updated today looks identical from this endpoint
        // — TheHive's case object carries no separate "resolved by automation" marker, and
        // checking each case's comments for the job's own note would mean an extra API call per
        // case, which this endpoint doesn't make.
        const autoResolvedCasesToday = cases.filter(
            (c) => c.severity <= 2 && isTheHiveStatusTerminal(c.status) && (c._updatedAt ?? 0) >= startOfTodayWAT,
        );
        const autoResolvedToday = autoResolvedCasesToday.length;

        // Recent SOAR activity log — real cases, not fabricated entries. Two event types, both
        // best-effort for the same reason auto_resolved_today is (see its comment above): a
        // "resolved" row can't be told apart from a manual resolve without an extra per-case
        // comment fetch this endpoint doesn't make, and a "created" row doesn't know whether the
        // Wazuh->TheHive webhook or an analyst opened it. Sorted newest first, capped at 10.
        const recentLog = [
            ...autoResolvedCasesToday.map((c) => ({
                time: c._updatedAt ? new Date(c._updatedAt).toLocaleTimeString('en-GB', { timeZone: 'Africa/Lagos', hour: '2-digit', minute: '2-digit' }) : '—',
                ts: c._updatedAt ?? 0,
                action: `${deriveIncidentNumber(c)} auto-resolved`,
                reason: `30min inactivity, ${c.severity === 1 ? 'Low' : 'Medium'} severity`,
            })),
            ...createdToday.map((c) => ({
                time: c._createdAt ? new Date(c._createdAt).toLocaleTimeString('en-GB', { timeZone: 'Africa/Lagos', hour: '2-digit', minute: '2-digit' }) : '—',
                ts: c._createdAt ?? 0,
                action: `${deriveIncidentNumber(c)} created`,
                reason: `Wazuh-triggered case — ${c.title}`,
            })),
        ].sort((a, b) => b.ts - a.ts).slice(0, 10).map(({ time, action, reason }) => ({ time, action, reason }));

        // Best-effort proxy for "response time": time between a case's creation and its most
        // recent update, for today's cases that have moved past New — i.e. "time to first
        // touch" by an analyst or the auto-close job, not a true first-response timestamp
        // (TheHive's case object has no status-change history available here).
        const responded = createdToday.filter((c) => c.status && c.status !== 'New' && c._createdAt && c._updatedAt);
        const avgResponseMinutes = responded.length > 0
            ? Math.round(responded.reduce((sum, c) => sum + (c._updatedAt! - c._createdAt!), 0) / responded.length / 60000)
            : null;

        // Pipeline counts for the SOAR page's flow diagram. Every one is derived from the same
        // capped listCase result above, so they share its undercount caveat on a high-volume day.
        // Note these are NOT all "today" figures: open_cases and escalated_open are current
        // state across the whole fetched window, because a case opened yesterday and still open
        // is exactly what the "Analyst Open" stage is meant to show. The SOAR page labels each
        // one with its own window rather than implying they're all daily.
        const openCases = cases.filter((c) => !isTheHiveStatusTerminal(c.status));
        const escalatedOpen = openCases.filter((c) => (c.tags ?? []).includes(ESCALATED_TAG));

        // Richer feed for the SOAR page's live activity list. Same events as recent_log above,
        // plus severity and a machine-readable type so the UI can colour-code without parsing
        // the human-readable strings. recent_log is kept as-is — the existing SOAR automation
        // panel renders it and changing its shape would break that.
        const recentActivity = [
            ...escalatedOpen.map((c) => ({
                type: 'escalated' as const,
                ts: c._updatedAt ?? 0,
                title: `${deriveIncidentNumber(c)} — ${c.title}`,
                severity: formatCaseForNovrSOC(c).severity,
                time: formatWAT(c._updatedAt),
                case_id: deriveIncidentNumber(c),
            })),
            ...autoResolvedCasesToday.map((c) => ({
                type: 'resolved' as const,
                ts: c._updatedAt ?? 0,
                title: `${deriveIncidentNumber(c)} — ${c.title}`,
                severity: formatCaseForNovrSOC(c).severity,
                time: formatWAT(c._updatedAt),
                case_id: deriveIncidentNumber(c),
            })),
            ...createdToday.map((c) => ({
                type: 'created' as const,
                ts: c._createdAt ?? 0,
                title: `${deriveIncidentNumber(c)} — ${c.title}`,
                severity: formatCaseForNovrSOC(c).severity,
                time: formatWAT(c._createdAt),
                case_id: deriveIncidentNumber(c),
            })),
        ]
            .sort((a, b) => b.ts - a.ts)
            .slice(0, 10)
            // ts was only needed for the sort — dropped so the client can't mistake it for a
            // display value and re-format it in the browser's own timezone.
            .map(({ ts: _ts, ...rest }) => rest);

        res.json({
            active: true,
            cases_created_today: createdToday.length,
            auto_resolved_today: autoResolvedToday,
            open_cases: openCases.length,
            escalated_open: escalatedOpen.length,
            avg_response_minutes: avgResponseMinutes,
            recent_log: recentLog,
            recent_activity: recentActivity,
        });
    } catch (err) {
        console.error('[incidents] automation-status failed:', err instanceof Error ? err.message : err);
        res.status(502).json({ active: true, cases_created_today: 0, auto_resolved_today: 0, open_cases: 0, escalated_open: 0, avg_response_minutes: null, recent_log: [], recent_activity: [] });
    }
});

// GET /api/incidents/:id — full detail for the incident workbench (case info + tasks + notes).
// TheHive-backed only: for a Wazuh-derived id (TheHive not configured, or this specific id
// isn't a TheHive case), there's no per-id cache to look up here — GET / re-queries Wazuh fresh
// every time and never stores results by id — so this reports that plainly instead of pretending
// to have a detail view that doesn't exist for that source.
router.get('/:id', async (req: Request, res: Response) => {
    const { id } = req.params;
    if (!isTheHiveConfigured() || !isTheHiveId(id)) {
        res.status(404).json({ error: 'Detail view is only available for TheHive-backed incidents right now.' });
        return;
    }

    const [caseData, tasks, comments] = await Promise.all([
        getCase(id),
        getCaseTasks(id),
        getCaseComments(id),
    ]);
    if (!caseData) {
        res.status(404).json({ error: 'Case not found' });
        return;
    }

    res.json(toWorkbenchIncident(formatCaseForNovrSOC(caseData), {
        tasks: tasks.map((t) => ({ _id: t._id, title: t.title, description: t.description ?? '', status: t.status })),
        // TheHive comments aren't tagged with NovrSOC's Update/Evidence/Decision/Escalation
        // taxonomy — 'Update' is the closest neutral default (matches what a note added via the
        // NovrSOC UI without changing the type picker would carry).
        notes: comments.map((c) => ({
            id: c._id,
            author: c.createdBy ?? 'Unknown',
            type: 'Update' as const,
            text: c.message,
            timestamp: c.createdAt ? new Date(c.createdAt).toLocaleString() : '',
        })),
    }));
});

// PATCH /api/incidents/:id (Update status) — real TheHive update for TheHive-backed incidents;
// in-memory override for Wazuh-derived ones, same as before TheHive auth was fixed.
router.patch('/:id', async (req: AuthRequest, res: Response) => {
    const { id } = req.params;
    // Both optional and independent — the "Assign to analyst" dropdown sends only `assignee`,
    // the status buttons send only `status`. Previously `status` was assumed always-present:
    // mapNovrSOCStatusToTheHive(status) called .toLowerCase() on it unconditionally, so an
    // assignee-only PATCH threw inside this async handler with nothing to catch it (Express 4
    // doesn't route an async handler's rejection to the error middleware on its own) — the
    // request would just hang. Fixed by only mapping/sending status when one was actually sent.
    const { status, assignee } = req.body as { status?: string; assignee?: string };

    if (isTheHiveConfigured() && isTheHiveId(id)) {
        const theHiveStatus = status ? mapNovrSOCStatusToTheHive(status) : undefined;

        // "contained" and "investigating" both store as InProgress, so the contained marker has
        // to ride along as a tag or the status bar snaps back a step on the next read (see
        // thehive.ts's CONTAINED_TAG). Needs the case's current tags to rewrite the full list,
        // and only for a status change — an assignee-only PATCH must not touch tags.
        let tags: string[] | undefined;
        if (status) {
            const current = await getCase(id);
            tags = tagsForStatusChange(current?.tags, status);
        }

        const updated = await updateCase(id, {
            ...(theHiveStatus ? { status: theHiveStatus } : {}),
            ...(tags ? { tags } : {}),
            assignee: assignee ?? req.user?.email,
        });
        if (!updated) {
            res.status(502).json({ error: 'TheHive case update failed — see server logs' });
            return;
        }
        // Fire-and-forget, only on an actual resolve — never blocks the response, matches the
        // fire-and-forget notify pattern used on incident creation above.
        if (status?.toLowerCase?.() === 'resolved') {
            sendSlackMessage(`✅ Incident resolved: ${updated.title}`).catch((err) => {
                console.error('[Slack] Resolve notification failed (non-fatal):', err instanceof Error ? err.message : err);
            });
        }
        res.json({ success: true, id, status, assignee: updated.assignee ?? null, thehive_status: theHiveStatus });
        return;
    }

    if (!incidentStateOverrides[id]) {
        incidentStateOverrides[id] = { status, notes: [], containment: [] };
    } else {
        incidentStateOverrides[id].status = status;
    }
    res.json({ success: true, id, status });
});

// POST /api/incidents/:id/notes — a real TheHive comment for TheHive-backed incidents (TheHive
// has a dedicated comment resource; an earlier draft stuffed notes into fake tasks instead —
// see thehive.ts's addComment for why that was wrong). In-memory override otherwise.
router.post('/:id/notes', async (req: AuthRequest, res: Response) => {
    const { id } = req.params;
    const { author, type, text, content } = req.body;
    const noteText: string = content ?? text ?? '';
    if (!noteText.trim()) {
        res.status(400).json({ error: 'content required' });
        return;
    }

    if (isTheHiveConfigured() && isTheHiveId(id)) {
        const comment = await addComment(id, noteText);
        if (!comment) {
            res.status(502).json({ error: 'Failed to add note in TheHive — see server logs' });
            return;
        }
        res.json({
            success: true,
            note: {
                id: comment._id,
                author: comment.createdBy ?? req.user?.email ?? 'Security Analyst',
                type: type || 'Note',
                text: comment.message,
                timestamp: comment.createdAt ? new Date(comment.createdAt).toLocaleString() : new Date().toLocaleString(),
            },
        });
        return;
    }

    const note: AnalystNote = {
        id: `note-${Date.now()}`,
        author: author || 'Security Analyst',
        type: type || 'Update',
        text: noteText,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    if (!incidentStateOverrides[id]) {
        incidentStateOverrides[id] = { status: 'investigating', notes: [note], containment: [] };
    } else {
        incidentStateOverrides[id].notes.push(note);
    }
    res.json({ success: true, note });
});

// POST /api/incidents/:id/tasks — TheHive-backed only. There's no non-TheHive concept of a
// case task in this codebase (the Wazuh-derived path has containment_actions instead, a fixed
// checklist, not free-form analyst-added tasks), so this is honest about the requirement rather
// than half-building a parallel in-memory task system for a source that doesn't have the concept.
router.post('/:id/tasks', async (req: Request, res: Response) => {
    if (!isTheHiveConfigured()) {
        res.status(503).json({ error: 'TheHive not configured' });
        return;
    }
    const { id } = req.params;
    const { title, description } = req.body;
    if (!title) {
        res.status(400).json({ error: 'title required' });
        return;
    }

    const task = await createTask(id, { title, description });
    if (!task) {
        res.status(502).json({ error: 'Failed to add task in TheHive — see server logs' });
        return;
    }
    res.json({ success: true, task: { _id: task._id, title: task.title, description: task.description ?? '', status: task.status } });
});

// Africa/Lagos is WAT (UTC+1) year-round with no DST, which is why the rest of this file does
// the offset with fixed arithmetic. Here the IANA zone is used directly since these strings are
// only ever displayed, never compared or bucketed.
function formatWAT(value: string | number | Date | null | undefined): string {
    if (!value) return 'Unknown';
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return 'Unknown';
    return `${d.toLocaleString('en-GB', { timeZone: 'Africa/Lagos' })} WAT`;
}

// POST /api/incidents/:id/escalate — analyst-initiated escalation from the incident workbench.
//
// Three things happen, in this order, and the response reports each one honestly rather than
// claiming blanket success: the case is recorded as escalated in TheHive (a comment, so the
// escalation and its reason live with the case rather than only in an inbox), the CISO is
// emailed, and Slack is notified. Email goes through services/email.ts rather than a direct
// Resend call so it uses the same Resend → SMTP → SendGrid fallback chain as every other email
// in this codebase, and honours EMAIL_ENABLED.
router.post('/:id/escalate', async (req: AuthRequest, res: Response) => {
    const { id } = req.params;
    const note = typeof req.body?.note === 'string' ? req.body.note.trim() : '';
    const escalatedBy = req.user?.email ?? 'Unknown analyst';

    if (!isTheHiveConfigured() || !isTheHiveId(id)) {
        res.status(503).json({ error: 'Escalation is only available for TheHive-backed incidents' });
        return;
    }

    const theCase = await getCase(id);
    if (!theCase) {
        res.status(404).json({ error: 'Incident not found' });
        return;
    }

    const formatted = formatCaseForNovrSOC(theCase);
    const results: Record<string, string> = {};

    // Recorded on the case first: if the email or Slack step fails, there is still a durable
    // record that an analyst escalated and why.
    const comment = await addComment(id, `ESCALATED by ${escalatedBy}${note ? `: ${note}` : ''}`);
    results.thehive = comment ? 'recorded' : 'failed';

    // Tagged as well as commented so the escalation is countable from a single listCase query
    // (the SOAR pipeline's escalated figure) and visible on the case in TheHive's own UI.
    // Status is deliberately untouched: escalating doesn't move a case out of investigating.
    const existingTags = theCase.tags ?? [];
    if (!existingTags.includes(ESCALATED_TAG)) {
        await updateCase(id, { tags: [...existingTags, ESCALATED_TAG] });
    }

    const cisoEmail = process.env.CISO_EMAIL || 'rayne@cybernovr.com';
    if (!isEmailEnabled()) {
        // Reported rather than silently swallowed — sendEscalationEmail() no-ops when email is
        // disabled, and the UI must not tell an analyst the CISO was emailed when nothing was.
        results.email = 'skipped — EMAIL_ENABLED is not set';
    } else {
        try {
            await sendEscalationEmail({
                to: [cisoEmail],
                incident_number: formatted.incident_number,
                title: formatted.title,
                severity: formatted.severity,
                assignee: formatted.assignee ?? 'Unassigned',
                opened_at: formatted.opened_at,
                escalated_by: escalatedBy,
                note,
            });
            results.email = `sent to ${cisoEmail}`;
        } catch (err) {
            console.error('[incidents/escalate] email failed:', err instanceof Error ? err.message : err);
            results.email = 'failed — see server logs';
        }
    }

    try {
        await sendSlackAlert({
            title: `Incident escalated: ${formatted.title}`,
            severity: formatted.severity,
            description: `Escalated by ${escalatedBy}${note ? `\n${note}` : ''}`,
            affected_host: 'See case in NovrSOC',
            incident_id: formatted.incident_number,
            detected_at: formatWAT(theCase._createdAt),
        });
        results.slack = 'sent';
    } catch {
        results.slack = 'failed';
    }

    // 207-style semantics without inventing a status code: success is true only when the
    // escalation was actually recorded somewhere durable.
    res.json({
        success: comment !== null,
        message: results.email.startsWith('sent') ? 'Escalation email sent to CISO' : `Escalation recorded — ${results.email}`,
        results,
    });
});

// GET /api/incidents/:id/report — a Markdown incident report, downloaded by the workbench.
//
// Markdown rather than PDF on purpose: the front end already has exportIncidentPDF() for a
// rendered document, and a text report is the format that pastes into a ticket, a post-incident
// review doc or an email without a converter in between.
//
// Every field comes from the real case. Where TheHive has nothing (a case with no comments, no
// assignee), the report says so explicitly instead of leaving a heading with silence under it —
// a report that quietly omits sections reads as though those areas were checked and found clean.
router.get('/:id/report', async (req: AuthRequest, res: Response) => {
    const { id } = req.params;

    if (!isTheHiveConfigured() || !isTheHiveId(id)) {
        res.status(503).json({ error: 'Reports are only available for TheHive-backed incidents' });
        return;
    }

    const theCase = await getCase(id);
    if (!theCase) {
        res.status(404).json({ error: 'Incident not found' });
        return;
    }

    const formatted = formatCaseForNovrSOC(theCase);
    const status = resolveNovrSOCStatus(theCase);
    const comments = await getCaseComments(id).catch(() => []);
    const tasks = await getCaseTasks(id).catch(() => []);

    const notesSection = comments.length > 0
        ? comments.map((c) => `- **${c.createdBy ?? 'Analyst'}** (${formatWAT(c.createdAt)}): ${c.message}`).join('\n')
        : '_No analyst notes recorded._';

    const tasksSection = tasks.length > 0
        ? tasks.map((t) => `- [${t.status === 'Completed' ? 'x' : ' '}] ${t.title}${t.description ? ` — ${t.description}` : ''}`).join('\n')
        : '_No response tasks recorded._';

    const report = `# Incident Report

## ${formatted.incident_number}: ${formatted.title}

| Field | Value |
| --- | --- |
| Severity | ${formatted.severity.toUpperCase()} |
| Status | ${status} |
| TheHive classification | ${formatted.thehive_status} |
| Assignee | ${formatted.assignee ?? 'Unassigned'} |
| Created | ${formatWAT(theCase._createdAt)} |
| Last updated | ${formatWAT(theCase._updatedAt)} |
| Tags | ${(theCase.tags ?? []).join(', ') || 'None'} |

## Description

${theCase.description?.trim() || '_No description provided._'}

## Response Tasks

${tasksSection}

## Analyst Notes

${notesSection}

## Timeline

- ${formatWAT(theCase._createdAt)} — Incident created
- ${formatWAT(theCase._updatedAt)} — Last updated (status: ${status})
${status === 'resolved' ? '' : '- Investigation ongoing\n'}
---

_Generated by NovrSOC by Cybernovr — ${formatWAT(new Date())}_

_Scope note: this report covers what is recorded on the TheHive case. Wazuh alert detail, MITRE
mapping and affected-asset inventory are not included — they are not stored on the case._
`;

    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${formatted.incident_number}-report.md"`);
    res.send(report);
});

export default router;