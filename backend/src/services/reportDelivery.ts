// R3.3E — email delivery for a completed report job. One report_deliveries row per recipient,
// each with its own outcome: a report job that generated fine but failed to email one of three
// recipients is 'completed' as a job, with that one delivery (and only that one) 'failed' — never
// collapsed into a single pass/fail for the whole run.
//
// Honesty on delivery status (Stage 5's explicit requirement): sendReportEmail() only ever tells
// us the provider ACCEPTED the message (or threw). None of the four providers in services/email.ts
// have a webhook receiver in this codebase, so "delivered" / "bounced" are schema states this
// service can never actually reach yet — only 'queued' -> 'sent' or 'queued' -> 'failed'. This is
// stated here, in the Reporting Center UI copy, and in the R3.3E delivery report, rather than
// silently claiming more than is known.

import { getSupabase } from './geoEnrichment';
import { sendReportEmail, isEmailEnabled } from './email';
import { logAudit } from '../lib/audit';
import type { GeneratedReport } from './reportGeneration';
import { recipientsFor, type ReportRecipient } from './reportRecipients';

const STAFF_ROLES = ['super_admin', 'soc_manager', 'analyst'];

/** Staff recipients land on the admin Reporting Center; executive/portal recipients land on the
 * client one — looked up by the recipient's own platform_users role, not guessed from `kind`. */
async function linkFor(recipient: ReportRecipient, jobId: string): Promise<string> {
    const base = (process.env.FRONTEND_URL ?? '').trim().replace(/\/$/, '');
    const supabase = getSupabase();
    let staffSide = true;
    if (supabase && recipient.kind === 'portal_user') {
        const { data: org } = await supabase.from('organisations').select('id').eq('slug', recipient.org_id).maybeSingle();
        if (org) {
            const { data: user } = await supabase.from('platform_users').select('role').eq('org_id', org.id as string).ilike('email', recipient.email).maybeSingle();
            if (user) staffSide = STAFF_ROLES.includes(user.role as string);
        }
    }
    const path = staffSide ? `/admin/reports?job=${jobId}` : `/client/reports?job=${jobId}`;
    return base ? `${base}${path}` : path;
}

export interface DeliveryOutcome { recipient: string; status: 'sent' | 'failed'; error?: string }

/** Delivers one already-generated, already-stored report to every eligible recipient for its
 * type. Never throws — a provider failure for one recipient must not stop delivery to the rest;
 * every outcome (success and failure alike) is written to report_deliveries before this returns. */
export async function deliverReport(jobId: string, report: GeneratedReport, actor: string): Promise<DeliveryOutcome[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    const recipients = await recipientsFor(report.org, report.report_type);
    const outcomes: DeliveryOutcome[] = [];
    for (const r of recipients) {
        const { data: delivery } = await supabase.from('report_deliveries').insert({ report_job_id: jobId, recipient_id: r.id, recipient_email: r.email, status: 'queued' }).select('id').single();
        const deliveryId = delivery?.id as string | undefined;
        if (!isEmailEnabled()) {
            outcomes.push({ recipient: r.email, status: 'failed', error: 'Email not configured' });
            if (deliveryId) await supabase.from('report_deliveries').update({ status: 'failed', error: 'Email not configured', attempts: 1, last_attempt_at: new Date().toISOString() }).eq('id', deliveryId);
            continue;
        }
        try {
            const url = await linkFor(r, jobId);
            const sent = await sendReportEmail({ to: r.email, org: report.org_name, reportType: report.report_type, format: report.format, periodDays: report.period_days, downloadUrl: url, generatedAt: report.generated_at });
            outcomes.push({ recipient: r.email, status: 'sent' });
            if (deliveryId) await supabase.from('report_deliveries').update({ status: 'sent', provider: sent.provider, attempts: 1, last_attempt_at: new Date().toISOString() }).eq('id', deliveryId);
            logAudit({ user: actor, action: 'REPORT_DELIVERED', resource: 'report_job', resource_id: jobId, org_id: report.org, ip: 'unknown', result: 'success', details: `${report.report_type} to ${r.email} via ${sent.provider}` });
        } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            outcomes.push({ recipient: r.email, status: 'failed', error: message });
            if (deliveryId) await supabase.from('report_deliveries').update({ status: 'failed', error: message.slice(0, 500), attempts: 1, last_attempt_at: new Date().toISOString() }).eq('id', deliveryId);
            logAudit({ user: actor, action: 'REPORT_DELIVERY_FAILED', resource: 'report_job', resource_id: jobId, org_id: report.org, ip: 'unknown', result: 'failed', severity: 'warning', details: `${report.report_type} to ${r.email}: ${message.slice(0, 200)}` });
        }
    }
    return outcomes;
}

/** Re-attempts one failed delivery (Reporting Center "retry"), re-validating the recipient and
 * re-checking authorisation first — an external recipient whose authorisation was revoked since
 * the original attempt is never retried silently. */
export async function retryDelivery(deliveryId: string, org: string, actor: string): Promise<{ ok: true } | { ok: false; error: string }> {
    const supabase = getSupabase();
    if (!supabase) return { ok: false, error: 'Database not configured' };
    const { data: delivery } = await supabase.from('report_deliveries').select('*, report_jobs!inner(id, org_id, report_type)').eq('id', deliveryId).maybeSingle();
    if (!delivery || (delivery.report_jobs as { org_id: string }).org_id !== org) return { ok: false, error: 'Delivery not found' };
    if (delivery.status !== 'failed') return { ok: false, error: 'Only a failed delivery can be retried' };
    const job = delivery.report_jobs as { id: string; report_type: string };
    const eligible = await recipientsFor(org, job.report_type);
    const recipient = eligible.find((r) => r.email.toLowerCase() === (delivery.recipient_email as string).toLowerCase());
    if (!recipient) return { ok: false, error: 'This recipient is no longer eligible (disabled, unauthorised, or unsubscribed from this report type)' };
    try {
        const url = await linkFor(recipient, job.id);
        // The retry needs the same report metadata the original send used — period/format aren't
        // stored on the delivery row itself, so pull them from the job.
        const { data: jobRow } = await supabase.from('report_jobs').select('format, period_days').eq('id', job.id).maybeSingle();
        const { data: orgRow } = await supabase.from('organisations').select('name').eq('slug', org).maybeSingle();
        const sent = await sendReportEmail({
            to: recipient.email, org: (orgRow?.name as string | undefined) ?? org, reportType: job.report_type as GeneratedReport['report_type'],
            format: (jobRow?.format as GeneratedReport['format']) ?? 'executive', periodDays: (jobRow?.period_days as number) ?? 30, downloadUrl: url, generatedAt: new Date().toISOString(),
        });
        await supabase.from('report_deliveries').update({ status: 'sent', provider: sent.provider, attempts: (delivery.attempts as number) + 1, last_attempt_at: new Date().toISOString(), error: null }).eq('id', deliveryId);
        logAudit({ user: actor, action: 'REPORT_DELIVERY_RETRIED', resource: 'report_delivery', resource_id: deliveryId, org_id: org, ip: 'unknown', result: 'success' });
        return { ok: true };
    } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        await supabase.from('report_deliveries').update({ status: 'failed', error: message.slice(0, 500), attempts: (delivery.attempts as number) + 1, last_attempt_at: new Date().toISOString() }).eq('id', deliveryId);
        logAudit({ user: actor, action: 'REPORT_DELIVERY_RETRIED', resource: 'report_delivery', resource_id: deliveryId, org_id: org, ip: 'unknown', result: 'failed', severity: 'warning', details: message.slice(0, 200) });
        return { ok: false, error: message };
    }
}
