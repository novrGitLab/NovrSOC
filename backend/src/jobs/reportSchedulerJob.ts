// R3.3E — the report scheduler: turns a due report_schedules row into a queued report_jobs row,
// then processes queued jobs (generate -> render -> store -> deliver).
//
// Two layers of safety, matching this codebase's established pattern (e.g. jobs/vmsContinuousJob.ts
// alongside vms_claim_job()): an in-process `running` guard stops this one process's own tick from
// overlapping itself; the real cross-replica safety is claimDueSchedules()'s compare-and-swap and
// report_claim_job()'s `FOR UPDATE SKIP LOCKED` (sql/2026-11-09_p30_report_scheduling.sql) — two
// Render instances ticking at the same moment cannot enqueue the same due schedule twice, or
// process the same queued job twice.
//
// "Do not schedule deliveries for organisations without a valid reporting configuration" (Stage
// 2): a due schedule only becomes a queued job if the organisation still has the underlying
// module enabled (hasServiceAccess) AND at least one eligible recipient today — a schedule left
// enabled after its last recipient was removed produces no job, not a report nobody receives.

import { randomUUID } from 'crypto';
import { getSupabase } from '../services/geoEnrichment';
import { claimDueSchedules, type ReportSchedule } from '../lib/reportScheduling';
import { hasServiceAccess, type ServiceKey } from '../lib/serviceAccess';
import { recipientsFor } from '../services/reportRecipients';
import { generateReportData } from '../services/reportGeneration';
import { renderReportPdf } from '../services/reportPdf';
import { reportToCsv } from '../services/reportCsv';
import { storeArtifact } from '../services/reportArtifacts';
import { deliverReport } from '../services/reportDelivery';
import { logAudit } from '../lib/audit';

export const lastReportSchedulerRun: { at: string | null; enqueued: number; processed: number; last_error: string | null } = { at: null, enqueued: 0, processed: 0, last_error: null };

const SERVICE_FOR: Record<string, ServiceKey | null> = { vms: 'vms', cnii: 'cnii_watch', threat_intel: 'threat_intel', executive_summary: null };

async function enqueueDueSchedules(): Promise<number> {
    const supabase = getSupabase();
    if (!supabase) return 0;
    const due = await claimDueSchedules();
    let enqueued = 0;
    for (const s of due as ReportSchedule[]) {
        const service = SERVICE_FOR[s.report_type];
        if (service && !(await hasServiceAccess(s.org_id, service))) {
            await supabase.from('report_schedules').update({ last_error: `Skipped — ${service} is not enabled for this organisation`, last_failure_at: new Date().toISOString() }).eq('id', s.id);
            continue;
        }
        const recipients = await recipientsFor(s.org_id, s.report_type);
        if (recipients.length === 0) {
            await supabase.from('report_schedules').update({ last_error: 'Skipped — no eligible recipients configured', last_failure_at: new Date().toISOString() }).eq('id', s.id);
            continue;
        }
        const { error } = await supabase.from('report_jobs').insert({
            id: randomUUID(), org_id: s.org_id, report_type: s.report_type, format: s.format, period_days: 30,
            schedule_id: s.id, trigger: 'scheduled', status: 'queued',
        });
        if (!error) enqueued++;
    }
    return enqueued;
}

/** One queued job, start to finish. Never throws — a failure is recorded on the job row and
 * reported back, not left for the caller to crash on (this runs in a background loop). */
async function processOneJob(workerId: string): Promise<'processed' | 'empty'> {
    const supabase = getSupabase();
    if (!supabase) return 'empty';
    const { data: claimed, error: claimError } = await supabase.rpc('report_claim_job', { p_worker: workerId });
    if (claimError || !claimed?.length) return 'empty';
    const job = claimed[0] as { id: string; org_id: string; report_type: 'vms' | 'cnii' | 'threat_intel' | 'executive_summary'; format: 'executive' | 'technical'; period_days: number; schedule_id: string | null };

    try {
        // Scheduled and emailed reports always generate at the client (amber) TLP ceiling,
        // regardless of who the recipients turn out to be — see services/reportGeneration.ts's
        // header for why this is deliberately conservative rather than per-recipient.
        const report = await generateReportData(job.org_id, job.report_type, job.format, job.period_days, 'amber');
        const pdf = await renderReportPdf(report);
        const csv = reportToCsv(report);
        await storeArtifact(job.id, 'pdf', `${job.report_type}-${job.org_id}-${new Date().toISOString().slice(0, 10)}.pdf`, pdf);
        await storeArtifact(job.id, 'csv', `${job.report_type}-${job.org_id}-${new Date().toISOString().slice(0, 10)}.csv`, Buffer.from(csv, 'utf8'));
        const status = report.warnings.length && Object.keys(report.data).length === 0 ? 'failed' : report.warnings.length ? 'partial' : 'completed';
        await supabase.from('report_jobs').update({ status, finished_at: new Date().toISOString(), last_error: report.warnings.join('; ').slice(0, 500) || null }).eq('id', job.id);
        if (status !== 'failed') await deliverReport(job.id, report, 'scheduler');
        if (job.schedule_id) {
            if (status === 'failed') await supabase.from('report_schedules').update({ last_failure_at: new Date().toISOString(), last_error: report.warnings.join('; ').slice(0, 500) || 'Generation failed' }).eq('id', job.schedule_id);
            else await supabase.from('report_schedules').update({ last_success_at: new Date().toISOString(), last_error: report.warnings.join('; ').slice(0, 500) || null }).eq('id', job.schedule_id);
        }
        logAudit({ user: 'scheduler', action: 'REPORT_GENERATED', resource: 'report_job', resource_id: job.id, org_id: job.org_id, ip: 'unknown', result: status === 'failed' ? 'failed' : 'success', details: `${job.report_type} (${status})` });
    } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        await supabase.from('report_jobs').update({ status: 'failed', finished_at: new Date().toISOString(), last_error: message.slice(0, 500) }).eq('id', job.id);
        if (job.schedule_id) await supabase.from('report_schedules').update({ last_failure_at: new Date().toISOString(), last_error: message.slice(0, 500) }).eq('id', job.schedule_id);
        logAudit({ user: 'scheduler', action: 'REPORT_GENERATED', resource: 'report_job', resource_id: job.id, org_id: job.org_id, ip: 'unknown', result: 'failed', severity: 'warning', details: message.slice(0, 200) });
    }
    return 'processed';
}

export function startReportSchedulerJob(): void {
    if (process.env.REPORT_SCHEDULER_ENABLED === 'false') { console.log('[reports] scheduler disabled by REPORT_SCHEDULER_ENABLED=false'); return; }
    const workerId = `${process.env.RENDER_INSTANCE_ID ?? process.env.HOSTNAME ?? 'local'}-${process.pid}`;
    let running = false;
    const tick = async () => {
        if (running) return;
        running = true;
        try {
            const enqueued = await enqueueDueSchedules();
            let processed = 0;
            // Drain the queue this tick, up to a sane cap so one slow tick can't run forever.
            for (let i = 0; i < 20; i++) {
                const r = await processOneJob(workerId);
                if (r === 'empty') break;
                processed++;
            }
            lastReportSchedulerRun.at = new Date().toISOString();
            lastReportSchedulerRun.enqueued = enqueued;
            lastReportSchedulerRun.processed = processed;
            lastReportSchedulerRun.last_error = null;
            if (enqueued || processed) console.log(`[reports] scheduler: enqueued ${enqueued}, processed ${processed}`);
        } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            lastReportSchedulerRun.last_error = message;
            console.error('[reports] scheduler tick failed:', message);
        } finally {
            running = false;
        }
    };
    setTimeout(() => { void tick(); }, 60_000).unref();
    setInterval(() => { void tick(); }, 5 * 60_000).unref();
}
