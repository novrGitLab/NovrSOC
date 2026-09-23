import { Router } from 'express';
import type { AuthRequest } from '../middleware/auth';
import { requireAuth, requireRole } from '../middleware/auth';
import { getSupabase } from '../services/geoEnrichment';
import { addTasks, addTimeline, isUuid } from '../services/cases';

// Supabase-backed playbook library — real columns confirmed live against the actual table:
// id, name, org_id, icon, severity, description, steps (jsonb array, round-trips as native
// objects — unlike org_setup's compliance_frameworks column, no per-element JSON.parse needed
// here), estimated_time, created_at, updated_at, created_by. No steps_count/avg_duration/tags/
// use_count/last_used/is_default columns, despite those being reasonable guesses.
//
// Not gated with requireAuth at the router level: GET is also read by the client portal's
// Playbooks view, whose portal_token requireAuth can't verify. /run writes to a case, and cases
// are analyst-only (routes/cases.ts), so it is gated individually; the mutating CRUD routes are
// gated to super_admin/soc_manager, since only Security Ops Management reaches them.

const router = Router();

interface PlaybookStep {
    order: number;
    title: string;
    phase: string;
    est_mins: number;
    description: string;
}
interface PlaybookRow {
    id: string;
    name: string;
    org_id: string;
    icon: string;
    severity: 'critical' | 'high' | 'medium';
    description: string;
    steps: PlaybookStep[];
    estimated_time: string;
    created_at?: string;
    updated_at?: string;
    created_by?: string;
}

const DEFAULT_ORG_ID = 'cybernovr'; // single-tenant today — see routes/secops.ts's ANALYST_EMAILS comment for the same limitation

// The 5 defaults this task asks to seed. Step time/phase weren't specified for these, unlike
// the hand-authored library already on the standalone Playbooks page (frontend/src/components/
// features/Playbooks.tsx, left untouched — see the commit message for why there are now two
// playbook sources), so every step here gets an honest generic phase/0min rather than an
// invented one.
const DEFAULT_PLAYBOOKS: Omit<PlaybookRow, 'id' | 'org_id' | 'created_at' | 'updated_at'>[] = [
    {
        name: 'Ransomware Response',
        icon: '🔒',
        severity: 'critical',
        description: 'Containment and recovery procedure for ransomware attacks.',
        estimated_time: '4-8 hours',
        created_by: 'system',
        steps: [
            { order: 1, title: 'Isolate affected systems', phase: 'Response', est_mins: 0, description: 'Disconnect from network immediately. Do not shut down — preserve memory for forensics.' },
            { order: 2, title: 'Identify patient zero', phase: 'Response', est_mins: 0, description: 'Which system was first encrypted? Check Wazuh alerts timeline.' },
            { order: 3, title: 'Assess scope', phase: 'Response', est_mins: 0, description: 'How many systems affected? Network shares? Backups?' },
            { order: 4, title: 'Notify CISO and Legal', phase: 'Response', est_mins: 0, description: 'Required within 1 hour of confirmation. Document the notification.' },
            { order: 5, title: 'Preserve evidence', phase: 'Response', est_mins: 0, description: 'Memory dump, disk image before any recovery attempt.' },
            { order: 6, title: 'Check backup integrity', phase: 'Response', est_mins: 0, description: 'Are backups clean? When was last verified backup?' },
            { order: 7, title: 'Notify regulators if required', phase: 'Response', est_mins: 0, description: 'NDPA requires notification within 72 hours if personal data affected.' },
            { order: 8, title: 'Begin recovery', phase: 'Response', est_mins: 0, description: 'Restore from clean backup. Reimage affected systems.' },
            { order: 9, title: 'Post-incident review', phase: 'Response', est_mins: 0, description: 'Document lessons learned. Update detection rules.' },
        ],
    },
    {
        name: 'Phishing Investigation',
        icon: '🎣',
        severity: 'high',
        description: 'Investigation and remediation procedure for phishing campaigns.',
        estimated_time: '1-2 hours',
        created_by: 'system',
        steps: [
            { order: 1, title: 'Quarantine the email', phase: 'Response', est_mins: 0, description: 'Remove from all mailboxes. Check how many recipients received it.' },
            { order: 2, title: 'Analyse the email', phase: 'Response', est_mins: 0, description: 'Extract headers, links, attachments. Use NovrSOC URL Scanner.' },
            { order: 3, title: 'Check for clicks', phase: 'Response', est_mins: 0, description: 'Did anyone click the link? Check proxy/firewall logs.' },
            { order: 4, title: 'Check for credential submission', phase: 'Response', est_mins: 0, description: 'Any login to the phishing page? Force password reset immediately.' },
            { order: 5, title: 'Scan affected endpoints', phase: 'Response', est_mins: 0, description: 'Run Wazuh full scan on any system that clicked.' },
            { order: 6, title: 'Block IOCs', phase: 'Response', est_mins: 0, description: 'Add domain/IP to blocklist. Update email filters.' },
            { order: 7, title: 'User awareness', phase: 'Response', est_mins: 0, description: 'Notify all staff. Send warning about the campaign.' },
        ],
    },
    {
        name: 'Brute Force Response',
        icon: '🔨',
        severity: 'high',
        description: 'Response procedure for credential brute-force attacks.',
        estimated_time: '30-60 minutes',
        created_by: 'system',
        steps: [
            { order: 1, title: 'Identify the target account', phase: 'Response', est_mins: 0, description: 'Which account is being targeted? Is it privileged?' },
            { order: 2, title: 'Check for successful login', phase: 'Response', est_mins: 0, description: 'Did any attempt succeed? Critical: check immediately.' },
            { order: 3, title: 'Block source IP', phase: 'Response', est_mins: 0, description: 'Add attacker IP to firewall block. Check if from Tor/VPN.' },
            { order: 4, title: 'Force password reset', phase: 'Response', est_mins: 0, description: 'If any chance of compromise, force reset and MFA re-enroll.' },
            { order: 5, title: 'Enable account lockout', phase: 'Response', est_mins: 0, description: 'If not already set: 5 attempts = 30 minute lockout.' },
            { order: 6, title: 'Review for lateral movement', phase: 'Response', est_mins: 0, description: 'If login succeeded, check all systems that account accessed.' },
        ],
    },
    {
        name: 'Data Breach Response',
        icon: '💾',
        severity: 'critical',
        description: 'Response procedure for confirmed or suspected data exfiltration.',
        estimated_time: '24-72 hours',
        created_by: 'system',
        steps: [
            { order: 1, title: 'Contain the breach', phase: 'Response', est_mins: 0, description: 'Stop the exfiltration. Isolate compromised systems.' },
            { order: 2, title: 'Assess what was taken', phase: 'Response', est_mins: 0, description: 'What data? How much? Personal data involved?' },
            { order: 3, title: 'Identify the method', phase: 'Response', est_mins: 0, description: 'How was data accessed? Credentials? Vulnerability? Insider?' },
            { order: 4, title: 'Notify CISO immediately', phase: 'Response', est_mins: 0, description: 'Do not delay. Legal implications start from moment of discovery.' },
            { order: 5, title: 'NDPA notification (if personal data)', phase: 'Response', est_mins: 0, description: 'Nigeria Data Protection Act requires notification within 72 hours.' },
            { order: 6, title: 'Notify affected individuals', phase: 'Response', est_mins: 0, description: 'Required under NDPA if high risk to individuals.' },
            { order: 7, title: 'Forensic investigation', phase: 'Response', est_mins: 0, description: 'Preserve all logs. Do not wipe systems before evidence collected.' },
            { order: 8, title: 'Remediate the vulnerability', phase: 'Response', est_mins: 0, description: 'Fix the root cause. Verify fix is effective.' },
        ],
    },
    {
        name: 'Malware Containment',
        icon: '🦠',
        severity: 'high',
        description: 'Containment and remediation procedure for malware infections.',
        estimated_time: '1-4 hours',
        created_by: 'system',
        steps: [
            { order: 1, title: 'Isolate infected system', phase: 'Response', est_mins: 0, description: 'Network isolation immediately. Keep powered on for forensics.' },
            { order: 2, title: 'Identify malware family', phase: 'Response', est_mins: 0, description: 'Use Wazuh alerts and VirusTotal hash lookup in NovrSOC CTI.' },
            { order: 3, title: 'Check for C2 communication', phase: 'Response', est_mins: 0, description: 'Is the malware calling home? Block C2 IPs at firewall.' },
            { order: 4, title: 'Scan for lateral movement', phase: 'Response', est_mins: 0, description: 'Check other systems for same IOCs.' },
            { order: 5, title: 'Collect forensic artifacts', phase: 'Response', est_mins: 0, description: 'Memory dump, process list, network connections, registry.' },
            { order: 6, title: 'Remediate', phase: 'Response', est_mins: 0, description: 'Reimage the system. Restore from clean backup.' },
            { order: 7, title: 'Update detection rules', phase: 'Response', est_mins: 0, description: 'Add IOCs to watchlist. Update Wazuh rules if needed.' },
        ],
    },
];

// GET /api/playbooks — lists an org's playbooks, seeding the 5 defaults first if the org has
// none yet. Seeding uses select-then-insert-if-missing, not .upsert(..., {onConflict:
// 'name,org_id'}) — confirmed live that (name, org_id) has no unique/exclusion constraint on
// this table (a real upsert 42P10s the same way org_setup's org_id did), so a real upsert isn't
// available here either.
router.get('/', async (req: AuthRequest, res) => {
    const orgId = (req.query.org_id as string) || req.user?.org_id || DEFAULT_ORG_ID;
    const supabase = getSupabase();
    if (!supabase) {
        res.status(503).json({ error: 'Supabase not configured' });
        return;
    }

    try {
        const { data: existing, error } = await supabase.from('playbooks').select('*').eq('org_id', orgId);
        if (error) throw error;

        if (!existing || existing.length === 0) {
            const seeded = DEFAULT_PLAYBOOKS.map((pb) => ({ ...pb, org_id: orgId }));
            const { data: inserted, error: insertError } = await supabase.from('playbooks').insert(seeded).select();
            if (insertError) throw insertError;
            res.json({ playbooks: inserted ?? [] });
            return;
        }

        res.json({ playbooks: existing });
    } catch (err) {
        console.error('[playbooks] GET failed:', err instanceof Error ? err.message : err);
        res.status(502).json({ error: 'Failed to load playbooks' });
    }
});

router.post('/', requireAuth, requireRole('super_admin', 'soc_manager'), async (req: AuthRequest, res) => {
    const { name, icon, severity, description, steps, estimated_time } = req.body as Partial<PlaybookRow>;
    if (!name || !severity) {
        res.status(400).json({ error: 'name and severity are required' });
        return;
    }
    const supabase = getSupabase();
    if (!supabase) {
        res.status(503).json({ error: 'Supabase not configured' });
        return;
    }

    const orgId = req.user?.org_id || DEFAULT_ORG_ID;
    const { data, error } = await supabase
        .from('playbooks')
        .insert({
            name, org_id: orgId, icon: icon || '📋', severity, description: description || '',
            steps: steps ?? [], estimated_time: estimated_time || '', created_by: req.user?.email || 'unknown',
        })
        .select()
        .single();

    if (error) {
        console.error('[playbooks] POST failed:', error.message);
        res.status(502).json({ error: 'Failed to create playbook' });
        return;
    }
    res.status(201).json({ success: true, playbook: data });
});

router.put('/:id', requireAuth, requireRole('super_admin', 'soc_manager'), async (req: AuthRequest, res) => {
    const { name, icon, severity, description, steps, estimated_time } = req.body as Partial<PlaybookRow>;
    const supabase = getSupabase();
    if (!supabase) {
        res.status(503).json({ error: 'Supabase not configured' });
        return;
    }

    const patch: Record<string, unknown> = { updated_at: new Date().toISOString() };
    if (name !== undefined) patch.name = name;
    if (icon !== undefined) patch.icon = icon;
    if (severity !== undefined) patch.severity = severity;
    if (description !== undefined) patch.description = description;
    if (steps !== undefined) patch.steps = steps; // full replace — add/remove/reorder all just send the whole new array
    if (estimated_time !== undefined) patch.estimated_time = estimated_time;

    const { data, error } = await supabase.from('playbooks').update(patch).eq('id', req.params.id).select().single();
    if (error) {
        console.error('[playbooks] PUT failed:', error.message);
        res.status(502).json({ error: 'Failed to update playbook' });
        return;
    }
    res.json({ success: true, playbook: data });
});

router.delete('/:id', requireAuth, requireRole('super_admin', 'soc_manager'), async (req: AuthRequest, res) => {
    const supabase = getSupabase();
    if (!supabase) {
        res.status(503).json({ error: 'Supabase not configured' });
        return;
    }
    const { error } = await supabase.from('playbooks').delete().eq('id', req.params.id);
    if (error) {
        console.error('[playbooks] DELETE failed:', error.message);
        res.status(502).json({ error: 'Failed to delete playbook' });
        return;
    }
    res.json({ success: true });
});

// POST /api/playbooks/:id/run { case_id } — attaches a playbook to a case: one case_tasks row per
// step, so the steps appear as Response Tasks in the case slide-over and can be ticked off
// there. Also records the playbook on the case and in its timeline.
router.post('/:id/run', requireAuth, async (req: AuthRequest, res) => {
    const { case_id, incident_id } = req.body as { case_id?: string; incident_id?: string };
    const caseId = case_id ?? incident_id; // incident_id still accepted from old callers
    if (!caseId || !isUuid(caseId)) {
        res.status(400).json({ error: 'case_id required' });
        return;
    }
    const supabase = getSupabase();
    if (!supabase) {
        res.status(503).json({ error: 'Supabase not configured' });
        return;
    }

    const { data: playbook, error } = await supabase.from('playbooks').select('*').eq('id', req.params.id).single();
    if (error || !playbook) {
        res.status(404).json({ error: 'Playbook not found' });
        return;
    }

    const steps: PlaybookStep[] = Array.isArray(playbook.steps) ? playbook.steps : [];
    const source = steps.length > 0 ? steps : [{ order: 1, title: `Follow the ${playbook.name} playbook`, phase: 'General', est_mins: 0, description: playbook.description }];
    const createdTasks = await addTasks(caseId, source.map((step) => ({
        step_id: `playbook:${playbook.id}:${step.order}`,
        title: `[${playbook.name}] ${step.title}`,
        description: step.description,
    })));
    if (createdTasks.length === 0) {
        res.status(502).json({ error: 'Could not add playbook tasks to the case' });
        return;
    }

    await supabase.from('cases').update({ playbook_id: playbook.id, updated_at: new Date().toISOString() }).eq('id', caseId);
    await addTimeline(caseId, req.user?.email || 'analyst', `Playbook attached: ${playbook.name} (${createdTasks.length} tasks)`);

    res.json({ success: true, tasks_created: createdTasks.length, tasks: createdTasks });
});

export default router;
