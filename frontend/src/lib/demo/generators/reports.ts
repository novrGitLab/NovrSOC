import type { DemoOrgId } from '../types';
import { DEMO_ORGS } from '../orgs';

const ago = (days: number) => new Date(Date.now() - days * 86_400_000).toISOString();
const ahead = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

export function demoReportTypes() {
    return { types: [
        { report_type: 'vms', label: 'Vulnerability & Exposure', available: true, module: 'Vulnerability Management' },
        { report_type: 'cnii', label: 'CNII Watch', available: true, module: 'CNII Watch' },
        { report_type: 'threat_intel', label: 'Threat Intelligence', available: true, module: 'Threat Intelligence' },
        { report_type: 'executive_summary', label: 'Unified Executive Summary', available: true, module: null },
    ] };
}

export function demoReportSchedules(org: DemoOrgId) {
    return { schedules: [{
        id: `demo-${org}-schedule-1`, report_type: 'executive_summary', format: 'executive', cadence: 'weekly',
        day_of_week: 1, day_of_month: null, hour_local: 8, timezone: 'Africa/Lagos', enabled: true,
        next_run_at: ahead(3), last_success_at: ago(4), last_failure_at: null, last_error: null,
    }] };
}

export function demoReportRecipients(org: DemoOrgId) {
    return { recipients: [
        { id: `demo-${org}-recipient-1`, kind: 'portal_user', email: `ciso@${org}-demo.test`, display_name: 'CISO (Sample)', report_types: [], enabled: true, external_authorised_by: null, added_by: 'SOC Manager (Sample)', added_at: ago(30) },
    ] };
}

export function demoReportHistory(org: DemoOrgId) {
    const name = DEMO_ORGS[org].name;
    return { jobs: [
        { id: `demo-${org}-job-1`, report_type: 'executive_summary', format: 'executive', status: 'completed', trigger: 'scheduled', requested_at: ago(4), finished_at: ago(4), last_error: null,
            deliveries: [{ id: `demo-${org}-delivery-1`, report_job_id: `demo-${org}-job-1`, status: 'sent', recipient_email: `ciso@${org}-demo.test`, error: null }] },
        { id: `demo-${org}-job-2`, report_type: 'vms', format: 'technical', status: 'completed', trigger: 'manual', requested_at: ago(11), finished_at: ago(11), last_error: null, deliveries: [] },
    ].map((j) => ({ ...j, _demoOrgName: name })) };
}

export function demoReportOpsHealth() {
    return { scheduler: { at: new Date().toISOString(), enqueued: 0, processed: 3, last_error: null }, queue: { queued: 0, running: 0 }, stuck_jobs: [], recent_failures: [] };
}
