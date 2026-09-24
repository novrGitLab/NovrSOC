import { Router, Response } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';
import {
    createCase, addTasks, addTimeline, isCaseSeverity, isCaseStatus, isUuid, startOfTodayWAT, formatWAT,
    dbErrorMessage, DEFAULT_ORG_ID, type CaseRow,
} from '../services/cases';
import { sendSlackAlert, sendSlackMessage } from '../services/slack';
import { sendEscalationEmail, isEmailEnabled } from '../services/email';
import { logAudit } from '../lib/audit';
import { executeStep, isExecutableStep, EXECUTABLE_STEPS } from '../services/responseActions';

// Cases API — Supabase-backed.
//
// Mounted at /api/cases, and at /api/incidents as an alias so any old caller keeps working.
// Both mounts are behind requireAuth (index.ts). /api/incidents used to be open because the
// client portal rendered the same workbench with a portal_token requireAuth can't verify; case
// records now carry source IPs, host names and CISO escalations for the whole SOC, so they are
// analyst-only and the portal page shows a sign-in notice instead.

const router = Router();

const orgOf = (req: AuthRequest) => req.user?.org_id || DEFAULT_ORG_ID;
const actorOf = (req: AuthRequest) => req.user?.email || 'analyst';

// case_notes has no type column. The workbench's note types (Update/Evidence/Decision/
// Escalation) ride as a "[Type] " prefix, which also reads correctly in the Markdown report.
const NOTE_TYPES = ['Update', 'Evidence', 'Decision', 'Escalation'] as const;
type NoteType = (typeof NOTE_TYPES)[number];
const NOTE_PREFIX = /^\[(Update|Evidence|Decision|Escalation)\] /;

function decodeNote(n: { id: string; author: string; content: string; created_at: string }) {
    const m = n.content.match(NOTE_PREFIX);
    return { id: n.id, author: n.author, type: (m?.[1] ?? 'Update') as NoteType, content: m ? n.content.slice(m[0].length) : n.content, created_at: n.created_at };
}

function noStore(res: Response): boolean {
    if (getSupabase()) return false;
    res.status(503).json({ error: 'Case store not configured (SUPABASE_URL / SUPABASE_SERVICE_KEY)' });
    return true;
}

// GET /api/cases — list, filterable, with queue summary.
//   ?status=open|investigating|contained|resolved   ?severity=…   ?tier=1|2|3
//   ?exclude_auto_closed=true (analyst queue)       ?auto_closed=true (SOAR tier-1 report)
//   ?since=<ISO date>   ?limit (max 200)   ?offset
router.get('/', async (req: AuthRequest, res) => {
    if (noStore(res)) return;
    const supabase = getSupabase()!;
    const orgId = orgOf(req);
    const q = req.query as Record<string, string | undefined>;
    const limit = Math.min(Math.max(Number(q.limit) || 50, 1), 200);
    const offset = Math.max(Number(q.offset) || 0, 0);

    let query = supabase
        .from('cases')
        .select('*', { count: 'exact' })
        .eq('org_id', orgId)
        .order('created_at', { ascending: false })
        .range(offset, offset + limit - 1);

    if (q.status) {
        if (!isCaseStatus(q.status)) { res.status(400).json({ error: 'invalid status' }); return; }
        query = query.eq('status', q.status);
    }
    if (q.severity) {
        if (!isCaseSeverity(q.severity)) { res.status(400).json({ error: 'invalid severity' }); return; }
        query = query.eq('severity', q.severity);
    }
    if (q.tier) query = query.eq('tier', Number(q.tier));
    if (q.exclude_auto_closed === 'true') query = query.eq('auto_closed', false);
    if (q.auto_closed === 'true') query = query.eq('auto_closed', true);
    if (q.since && !Number.isNaN(Date.parse(q.since))) query = query.gte('created_at', new Date(q.since).toISOString());

    // Queue summary: separate head-only counts so the figures cover every case, not just the
    // page returned. Auto-closed tier-1 cases are excluded — they never needed an analyst and
    // are reported on the SOAR page instead.
    const count = async (build: (b: ReturnType<typeof base>) => ReturnType<typeof base>) => {
        const { count: c, error } = await build(base());
        if (error) throw error;
        return c ?? 0;
    };
    const base = () => supabase.from('cases').select('id', { count: 'exact', head: true }).eq('org_id', orgId).eq('auto_closed', false);

    try {
        const [{ data, error, count: total }, open, investigating, contained, critical, resolved, resolvedToday] = await Promise.all([
            query,
            count((b) => b.eq('status', 'open')),
            count((b) => b.eq('status', 'investigating')),
            count((b) => b.eq('status', 'contained')),
            count((b) => b.eq('severity', 'critical').neq('status', 'resolved')),
            count((b) => b.eq('status', 'resolved')),
            count((b) => b.eq('status', 'resolved').gte('resolved_at', startOfTodayWAT().toISOString())),
        ]);
        if (error) throw error;

        res.json({
            cases: data ?? [],
            total: total ?? 0,
            summary: { open, investigating, contained, active: open + investigating + contained, critical, resolved, resolvedToday },
        });
    } catch (err) {
        console.error('[cases] list failed:', dbErrorMessage(err));
        res.status(502).json({ error: `Could not load cases: ${dbErrorMessage(err)}` });
    }
});

// POST /api/cases — analyst-created case (dark web hit, playbook-initiated response, …).
router.post('/', async (req: AuthRequest, res) => {
    const body = req.body ?? {};
    const title = typeof body.title === 'string' ? body.title.trim() : '';
    if (!title) { res.status(400).json({ error: 'title is required' }); return; }
    const severity = isCaseSeverity(body.severity) ? body.severity : 'medium';

    const result = await createCase({
        title,
        description: typeof body.description === 'string' ? body.description : typeof body.summary === 'string' ? body.summary : null,
        severity,
        source: typeof body.source === 'string' && body.source ? body.source : 'manual',
        org_id: orgOf(req),
        agent_name: typeof body.affected_host === 'string' && body.affected_host ? body.affected_host : null,
        playbook_id: typeof body.playbook_id === 'string' && isUuid(body.playbook_id) ? body.playbook_id : null,
        tags: Array.isArray(body.tags) ? body.tags.filter((t: unknown): t is string => typeof t === 'string') : [],
    }, actorOf(req));

    if (!result.ok) { res.status(result.status).json({ error: result.error }); return; }

    // Playbook-initiated cases send their steps; they become the case's response tasks.
    if (Array.isArray(body.containment)) {
        await addTasks(result.case.id, body.containment
            .filter((s: { action?: unknown }) => typeof s?.action === 'string')
            .map((s: { action: string; description?: string }) => ({ step_id: 'playbook', title: s.action, description: s.description ?? null })));
    }

    if (result.case.severity === 'critical' || result.case.severity === 'high') {
        sendSlackAlert({
            title: result.case.title,
            severity: result.case.severity,
            description: result.case.description || result.case.title,
            affected_host: result.case.agent_name || 'See case in NovrSOC',
            incident_id: result.case.case_number,
            detected_at: formatWAT(result.case.created_at),
        }).catch(() => {});
    }

    res.status(201).json({ success: true, created: result.created, case: result.case, id: result.case.id, case_number: result.case.case_number });
});

// GET /api/cases/:id — case with notes, tasks, timeline and IOCs.
router.get('/:id', async (req: AuthRequest, res) => {
    if (noStore(res)) return;
    const { id } = req.params;
    if (!isUuid(id)) { res.status(404).json({ error: 'Case not found' }); return; }
    const supabase = getSupabase()!;

    const [caseRes, notesRes, tasksRes, timelineRes, iocsRes] = await Promise.all([
        supabase.from('cases').select('*').eq('id', id).eq('org_id', orgOf(req)).maybeSingle(),
        supabase.from('case_notes').select('*').eq('case_id', id).order('created_at', { ascending: false }),
        supabase.from('case_tasks').select('*').eq('case_id', id).order('created_at'),
        supabase.from('case_timeline').select('*').eq('case_id', id).order('created_at', { ascending: false }),
        supabase.from('case_iocs').select('*').eq('case_id', id),
    ]);

    if (caseRes.error) { res.status(502).json({ error: dbErrorMessage(caseRes.error) }); return; }
    if (!caseRes.data) { res.status(404).json({ error: 'Case not found' }); return; }

    res.json({
        case: caseRes.data,
        notes: (notesRes.data ?? []).map(decodeNote),
        tasks: tasksRes.data ?? [],
        timeline: timelineRes.data ?? [],
        iocs: iocsRes.data ?? [],
    });
});

// PATCH /api/cases/:id — status / assignee / severity.
router.patch('/:id', async (req: AuthRequest, res) => {
    if (noStore(res)) return;
    const { id } = req.params;
    if (!isUuid(id)) { res.status(404).json({ error: 'Case not found' }); return; }
    const supabase = getSupabase()!;
    const body = req.body ?? {};
    const status = body.status as unknown;
    const assignee = (body.assigned_to ?? body.assignee) as unknown;
    const severity = body.severity as unknown;

    if (status !== undefined && !isCaseStatus(status)) { res.status(400).json({ error: `status must be one of open, investigating, contained, resolved` }); return; }
    if (severity !== undefined && !isCaseSeverity(severity)) { res.status(400).json({ error: 'invalid severity' }); return; }
    if (assignee !== undefined && typeof assignee !== 'string') { res.status(400).json({ error: 'assigned_to must be a string' }); return; }

    const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
    const changes: string[] = [];
    if (isCaseStatus(status)) {
        updates.status = status;
        // Reopening clears resolved_at so "resolved today" and MTTR stay truthful.
        updates.resolved_at = status === 'resolved' ? new Date().toISOString() : null;
        changes.push(`Status changed to ${status}`);
    }
    if (typeof assignee === 'string') { updates.assigned_to = assignee || null; changes.push(assignee ? `Assigned to ${assignee}` : 'Unassigned'); }
    if (isCaseSeverity(severity)) { updates.severity = severity; changes.push(`Severity set to ${severity}`); }
    if (changes.length === 0) { res.status(400).json({ error: 'Nothing to update — send status, assigned_to or severity' }); return; }

    const { data, error } = await supabase.from('cases').update(updates).eq('id', id).eq('org_id', orgOf(req)).select().maybeSingle();
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    if (!data) { res.status(404).json({ error: 'Case not found' }); return; }
    const row = data as CaseRow;

    await addTimeline(id, actorOf(req), changes.join(' · '));

    if (isCaseStatus(status)) {
        logAudit({
            user: actorOf(req), action: 'CASE_STATUS_CHANGED', resource: 'case', resource_id: id,
            ip: req.ip ?? 'unknown', result: 'success',
            details: `${row.case_number} status set to ${status}`, severity: status === 'resolved' ? 'warning' : 'info',
        });
        if (status === 'resolved') sendSlackMessage(`✅ Case resolved: ${row.case_number} — ${row.title}`).catch(() => {});
    }

    res.json({ success: true, case: row });
});

// POST /api/cases/:id/notes — { content | text, type? }
router.post('/:id/notes', async (req: AuthRequest, res) => {
    if (noStore(res)) return;
    const { id } = req.params;
    if (!isUuid(id)) { res.status(404).json({ error: 'Case not found' }); return; }
    const raw = req.body?.content ?? req.body?.text;
    const content = typeof raw === 'string' ? raw.trim() : '';
    if (!content) { res.status(400).json({ error: 'content required' }); return; }
    const type: NoteType = (NOTE_TYPES as readonly string[]).includes(req.body?.type) ? req.body.type : 'Update';

    const { data, error } = await getSupabase()!
        .from('case_notes')
        .insert({ case_id: id, author: actorOf(req), content: type === 'Update' ? content : `[${type}] ${content}` })
        .select()
        .single();
    if (error) {
        // 23503: the case id doesn't exist (FK violation).
        res.status(error.code === '23503' ? 404 : 502).json({ error: error.code === '23503' ? 'Case not found' : dbErrorMessage(error) });
        return;
    }

    await addTimeline(id, actorOf(req), `Note added (${type}): ${content.slice(0, 60)}${content.length > 60 ? '…' : ''}`);
    res.json({ success: true, note: decodeNote(data) });
});

// POST /api/cases/:id/tasks — { title, description? }
router.post('/:id/tasks', async (req: AuthRequest, res) => {
    if (noStore(res)) return;
    const { id } = req.params;
    if (!isUuid(id)) { res.status(404).json({ error: 'Case not found' }); return; }
    const title = typeof req.body?.title === 'string' ? req.body.title.trim() : '';
    if (!title) { res.status(400).json({ error: 'title required' }); return; }

    const [task] = await addTasks(id, [{ title, description: req.body?.description ?? null }]);
    if (!task) { res.status(502).json({ error: 'Failed to add task' }); return; }
    await addTimeline(id, actorOf(req), `Task added: ${title}`);
    res.json({ success: true, task });
});

// PATCH /api/cases/:id/tasks/:taskId — { status: pending | completed | skipped }
router.patch('/:id/tasks/:taskId', async (req: AuthRequest, res) => {
    if (noStore(res)) return;
    const { id, taskId } = req.params;
    if (!isUuid(id) || !isUuid(taskId)) { res.status(404).json({ error: 'Task not found' }); return; }
    const status = req.body?.status;
    if (!['pending', 'completed', 'skipped'].includes(status)) { res.status(400).json({ error: 'status must be pending, completed or skipped' }); return; }

    const done = status !== 'pending';
    const { data, error } = await getSupabase()!
        .from('case_tasks')
        .update({ status, executed_at: done ? new Date().toISOString() : null, executed_by: done ? actorOf(req) : null })
        .eq('id', taskId)
        .eq('case_id', id)
        .select()
        .maybeSingle();
    if (error) { res.status(502).json({ error: dbErrorMessage(error) }); return; }
    if (!data) { res.status(404).json({ error: 'Task not found' }); return; }

    await addTimeline(id, actorOf(req), `Task ${status === 'pending' ? 'reopened' : status}: ${data.title}`);
    res.json({ success: true, task: data });
});

// POST /api/cases/:id/escalate — { note? }
//
// Email goes through services/email.ts rather than a direct Resend call: that is Resend first,
// then SMTP, then SendGrid, and it honours EMAIL_ENABLED. The response reports each channel
// separately and never claims the CISO was emailed when nothing was sent.
router.post('/:id/escalate', async (req: AuthRequest, res) => {
    if (noStore(res)) return;
    const { id } = req.params;
    if (!isUuid(id)) { res.status(404).json({ error: 'Case not found' }); return; }
    const supabase = getSupabase()!;
    const note = typeof req.body?.note === 'string' ? req.body.note.trim() : '';
    const by = actorOf(req);

    const { data } = await supabase.from('cases').select('*').eq('id', id).eq('org_id', orgOf(req)).maybeSingle();
    if (!data) { res.status(404).json({ error: 'Case not found' }); return; }
    const c = data as CaseRow;

    const { error: updErr } = await supabase.from('cases').update({ escalated: true, updated_at: new Date().toISOString() }).eq('id', id);
    const recorded = !updErr;
    await addTimeline(id, by, `Case escalated to CISO${note ? `. Note: ${note}` : ''}`);

    const results: Record<string, string> = { case: recorded ? 'recorded' : `failed: ${dbErrorMessage(updErr)}` };
    const cisoEmail = process.env.CISO_EMAIL || 'soc@cybernovr.com';
    if (!isEmailEnabled()) {
        results.email = 'skipped — EMAIL_ENABLED is not set';
    } else {
        try {
            await sendEscalationEmail({
                to: [cisoEmail], incident_number: c.case_number, title: c.title, severity: c.severity,
                assignee: c.assigned_to ?? 'Unassigned', opened_at: formatWAT(c.created_at), escalated_by: by, note,
            });
            results.email = `sent to ${cisoEmail}`;
            await addTimeline(id, 'NovrSOC', `Escalation email sent to ${cisoEmail}`, { automated: true });
        } catch (err) {
            console.error('[cases/escalate] email failed:', err instanceof Error ? err.message : err);
            results.email = 'failed — see server logs';
        }
    }

    const slackSent = await sendSlackAlert({
        title: `Case escalated: ${c.title}`, severity: c.severity,
        description: `Escalated by ${by}${note ? `\n${note}` : ''}`,
        affected_host: c.agent_name || 'See case in NovrSOC', incident_id: c.case_number, detected_at: formatWAT(c.created_at),
    }).catch(() => false);
    results.slack = slackSent ? 'sent' : 'not sent';

    logAudit({
        user: by, action: 'CASE_ESCALATED', resource: 'case', resource_id: id, ip: req.ip ?? 'unknown',
        result: recorded ? 'success' : 'failed', details: `${c.case_number} escalated${note ? `: ${note.slice(0, 160)}` : ''}`, severity: 'critical',
    });

    res.json({
        success: recorded,
        message: results.email.startsWith('sent') ? `Escalation email sent to ${cisoEmail}` : `Escalation recorded — email ${results.email}`,
        results,
    });
});

// POST /api/cases/:id/execute-step { step_id, task_id? } — runs one response action for this
// case (services/responseActions.ts). The matching task is marked completed ONLY on success;
// a skipped or failed action leaves it pending with the reason in `result`, so the checklist
// never shows a containment step as done when nothing happened.
router.post('/:id/execute-step', async (req: AuthRequest, res) => {
    if (noStore(res)) return;
    const { id } = req.params;
    if (!isUuid(id)) { res.status(404).json({ error: 'Case not found' }); return; }
    const stepId = req.body?.step_id;
    if (!isExecutableStep(stepId)) {
        res.status(400).json({ error: `step_id must be one of ${EXECUTABLE_STEPS.join(', ')} — other tasks are completed by ticking them off` });
        return;
    }
    const supabase = getSupabase()!;
    const { data } = await supabase.from('cases').select('*').eq('id', id).eq('org_id', orgOf(req)).maybeSingle();
    if (!data) { res.status(404).json({ error: 'Case not found' }); return; }
    const by = actorOf(req);

    const result = await executeStep(stepId, data as CaseRow, by);
    const done = result.outcome === 'success';

    const taskId = typeof req.body?.task_id === 'string' && isUuid(req.body.task_id) ? req.body.task_id : null;
    let taskUpdate = supabase.from('case_tasks').update({
        status: done ? 'completed' : 'pending',
        result: `${result.outcome.toUpperCase()}: ${result.message}`,
        executed_at: done ? new Date().toISOString() : null,
        executed_by: done ? by : null,
    }).eq('case_id', id);
    taskUpdate = taskId ? taskUpdate.eq('id', taskId) : taskUpdate.eq('step_id', stepId);
    await taskUpdate;

    await addTimeline(id, by, `Executed ${stepId}: ${result.outcome} — ${result.message}`);
    logAudit({
        user: by, action: 'CASE_STEP_EXECUTED', resource: 'case', resource_id: id, ip: req.ip ?? 'unknown',
        result: done ? 'success' : 'failed', details: `${stepId}: ${result.message}`.slice(0, 200), severity: done ? 'warning' : 'info',
    });

    // 200 for success and for a skip (the request was valid; the action didn't apply or isn't
    // configured), 502 when the remote system refused or was unreachable.
    res.status(result.outcome === 'failed' ? 502 : 200).json({
        success: done, outcome: result.outcome, result: result.message, message: result.message, affected_count: result.affected,
    });
});

// General hardening guidance per ATT&CK technique, keyed on the base technique (T1110.001 uses
// T1110's). Labelled in the report as guidance for the technique, not as findings about this
// environment — nothing here was checked against the affected host.
const REMEDIATION: Record<string, string[]> = {
    T1110: [
        'Enforce an account lockout policy (for example 5 failed attempts)',
        'Require multi-factor authentication on all accounts, remote access first',
        'Review and rotate credentials for the targeted accounts',
        'Restrict SSH/RDP exposure with IP allowlisting or a VPN',
        'Rate-limit authentication (Fail2Ban or equivalent) on exposed services',
    ],
    T1566: [
        'Run phishing awareness training for affected staff',
        'Filter email with attachment and link scanning',
        'Enforce DMARC (p=quarantine or reject), DKIM and SPF on all company domains',
        'Block Office macros from internet-sourced documents',
        "Report the phishing URL to the hosting provider's abuse contact and Google Safe Browsing",
    ],
    T1486: [
        'Keep affected systems isolated from the network until they are rebuilt',
        'Do not pay the ransom; report to law enforcement and ngCERT',
        'Restore from the last known-good backup after verifying it is clean',
        'Identify and close the initial access vector before reconnecting systems',
        'Keep offline or immutable backups (3-2-1)',
        'Deploy EDR with ransomware behaviour detection',
    ],
    T1021: [
        'Disable remote services (RDP, SSH, VNC) where they are not needed',
        'Segment the network to limit lateral movement',
        'Require MFA for all remote access',
        'Alert on unusual authentication patterns between internal hosts',
        'Review and restrict service account privileges',
    ],
    T1055: [
        'Deploy application allowlisting',
        'Enable Credential Guard on Windows hosts',
        'Monitor for process injection behaviour with EDR memory protection',
        'Keep operating systems and applications patched',
    ],
    DEFAULT: [
        'Review and update the relevant security policies',
        'Hold a post-incident review within 72 hours',
        'Update detection rules to catch similar events',
        'Document lessons learned and share them with the team',
    ],
};

// GET /api/cases/:id/report — Markdown report download. Every section comes from the case; an
// empty section says so rather than silently disappearing.
router.get('/:id/report', async (req: AuthRequest, res) => {
    if (noStore(res)) return;
    const { id } = req.params;
    if (!isUuid(id)) { res.status(404).json({ error: 'Case not found' }); return; }
    const supabase = getSupabase()!;

    const [caseRes, notesRes, tasksRes, timelineRes, iocsRes] = await Promise.all([
        supabase.from('cases').select('*').eq('id', id).eq('org_id', orgOf(req)).maybeSingle(),
        supabase.from('case_notes').select('*').eq('case_id', id).order('created_at'),
        supabase.from('case_tasks').select('*').eq('case_id', id).order('created_at'),
        supabase.from('case_timeline').select('*').eq('case_id', id).order('created_at'),
        supabase.from('case_iocs').select('*').eq('case_id', id),
    ]);
    const c = caseRes.data as CaseRow | null;
    if (!c) { res.status(404).json({ error: 'Case not found' }); return; }

    const baseTechnique = (c.mitre_technique ?? '').split('.')[0].toUpperCase();
    const remediationKey = REMEDIATION[baseTechnique] ? baseTechnique : 'DEFAULT';
    const remediation = REMEDIATION[remediationKey];
    const remediationNote = remediationKey !== 'DEFAULT'
        ? `General guidance for MITRE ATT&CK ${remediationKey}${c.mitre_technique !== remediationKey ? ` (case technique ${c.mitre_technique})` : ''} — not verified against the affected host.`
        : c.mitre_technique
            ? `No technique-specific guidance for ${c.mitre_technique}; general post-incident steps shown.`
            : 'No MITRE technique on this case; general post-incident steps shown.';

    const list = <T,>(rows: T[] | null, fmt: (r: T) => string, empty: string) => (rows && rows.length > 0 ? rows.map(fmt).join('\n') : `_${empty}_`);

    const report = `# Case Report

## ${c.case_number}: ${c.title}

| Field | Value |
| --- | --- |
| Severity | ${c.severity.toUpperCase()} |
| Status | ${c.status} |
| SOAR tier | ${c.tier}${c.auto_closed ? ' (auto-closed)' : ''} |
| Source | ${c.source} |
| Agent | ${c.agent_name || 'N/A'}${c.agent_id ? ` (${c.agent_id})` : ''} |
| Source IP | ${c.source_ip || 'N/A'} |
| Rule | ${c.rule_id ? `${c.rule_id} (level ${c.rule_level ?? 0})` : 'N/A'} |
| MITRE technique | ${c.mitre_technique || 'N/A'} |
| MITRE tactic | ${c.mitre_tactic || 'N/A'} |
| Assignee | ${c.assigned_to || 'Unassigned'} |
| Containment done | ${c.containment_done ? 'Yes' : 'No'} |
| Escalated | ${c.escalated ? 'Yes' : 'No'} |
| Created | ${formatWAT(c.created_at)} |
| Resolved | ${c.resolved_at ? formatWAT(c.resolved_at) : 'Unresolved'} |

## Description

${c.description?.trim() || '_No description provided._'}

## IOCs

${list(iocsRes.data, (i: { type: string; value: string; verdict: string | null; risk_score: number | null }) => `- ${i.type}: \`${i.value}\` — ${i.verdict || 'unknown'} (score ${i.risk_score ?? 0})`, 'No IOCs recorded.')}

## Response Tasks

${list(tasksRes.data, (t: { title: string; status: string; executed_by: string | null; result: string | null }) => `- [${t.status === 'completed' ? 'x' : ' '}] ${t.title}${t.status === 'skipped' ? ' (skipped)' : ''}${t.executed_by ? ` — ${t.executed_by}` : ''}${t.result ? ` (${t.result})` : ''}`, 'No response tasks recorded.')}

## Timeline

${list(timelineRes.data, (t: { created_at: string; actor: string; action: string; automated: boolean }) => `- ${formatWAT(t.created_at)} — ${t.actor}${t.automated ? ' (automated)' : ''}: ${t.action}`, 'No timeline entries.')}

## Analyst Notes

${list(notesRes.data, (n: { id: string; author: string; content: string; created_at: string }) => { const d = decodeNote(n); return `- **${d.author}** [${d.type}] (${formatWAT(d.created_at)}): ${d.content}`; }, 'No analyst notes recorded.')}

## Remediation Plan

**Priority:** ${c.severity === 'critical' ? 'Immediate (within 24 hours)' : c.severity === 'high' ? 'Urgent (within 72 hours)' : 'Standard (within 7 days)'}

${remediation.map((r, i) => `${i + 1}. ${r}`).join('\n')}

_${remediationNote}_

## Post-Incident Actions

- [ ] Hold the post-incident review
- [ ] Update the playbook with lessons learned
- [ ] Verify all containment measures are still in place
- [ ] Monitor for recurrence over the next 30 days
- [ ] If personal data was affected, notify the NDPC within 72 hours (NDPA 2023)

---

_Generated by NovrSOC by Cybernovr — ${formatWAT(new Date())}_
`;

    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${c.case_number}-report.md"`);
    res.send(report);
});

export default router;
