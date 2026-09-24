// Escalates HIGH/CRITICAL cases that are still unresolved past their SLA window.
// Run-then-interval, unref(), every error swallowed and logged — same shape as the other jobs.
//
// De-dupe is the case's own `escalated` flag, so a redeploy doesn't re-send every escalation
// (the previous version kept an in-memory set that reset on restart). A case an analyst or the
// SOAR engine already escalated is skipped too — the CISO has already been told.
import { getSupabase } from '../services/geoEnrichment';
import { sendEscalationEmail, isEmailEnabled } from '../services/email';
import { addTimeline, formatWAT, dbErrorMessage, type CaseRow } from '../services/cases';

const CHECK_INTERVAL_MS = 15 * 60 * 1000;
const HIGH_MINUTES = Number(process.env.ESCALATION_HIGH_MINUTES) || 120;
const CRITICAL_MINUTES = Number(process.env.ESCALATION_CRITICAL_MINUTES) || 30;
const CISO_EMAIL = process.env.CISO_EMAIL || 'soc@cybernovr.com';

async function runEscalationCheck(): Promise<void> {
    const supabase = getSupabase();
    if (!supabase || !isEmailEnabled()) return;

    // Only cases old enough to breach the shorter (critical) window can qualify; the per-case
    // threshold is applied below.
    const cutoff = new Date(Date.now() - CRITICAL_MINUTES * 60000).toISOString();
    const { data, error } = await supabase
        .from('cases')
        .select('*')
        .in('severity', ['high', 'critical'])
        .neq('status', 'resolved')
        .eq('escalated', false)
        .not('assigned_to', 'is', null) // "assigned to someone" is a precondition, as before
        .lte('created_at', cutoff)
        .limit(200);
    if (error) throw new Error(dbErrorMessage(error));

    for (const c of (data ?? []) as CaseRow[]) {
        const threshold = c.severity === 'critical' ? CRITICAL_MINUTES : HIGH_MINUTES;
        const ageMinutes = (Date.now() - Date.parse(c.created_at)) / 60000;
        if (ageMinutes < threshold) continue;

        const recipients = Array.from(new Set([CISO_EMAIL, c.assigned_to ?? ''].filter((e) => e.includes('@'))));
        try {
            await sendEscalationEmail({
                to: recipients,
                incident_number: c.case_number,
                title: c.title,
                severity: c.severity,
                assignee: c.assigned_to ?? 'Unassigned',
                opened_at: formatWAT(c.created_at),
            });
            await supabase.from('cases').update({ escalated: true, updated_at: new Date().toISOString() }).eq('id', c.id);
            await addTimeline(c.id, 'NovrSOC SLA', `Auto-escalated: unresolved after ${Math.round(ageMinutes)} min (SLA ${threshold} min). Email sent to ${recipients.join(', ')}`, { automated: true });
            console.log(`[Escalation] Sent for ${c.case_number}: ${c.title}`);
        } catch (err) {
            console.error(`[Escalation] Failed for ${c.case_number}:`, err instanceof Error ? err.message : err);
        }
    }
}

export function startEscalationJob(): void {
    if (!getSupabase()) {
        console.log('[Escalation] Case store not configured — job not started');
        return;
    }
    console.log('[Escalation] Job started — checking every 15 minutes');
    const tick = () => {
        runEscalationCheck().catch((err) => console.error('[Escalation] Error:', err instanceof Error ? err.message : err));
    };
    tick();
    setInterval(tick, CHECK_INTERVAL_MS).unref();
}
