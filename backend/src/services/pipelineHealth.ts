// Data-pipeline health (phase P2): is data actually flowing, not just are services reachable.
// The 2026-10-13 audit found the Wazuh indexer down for four days with every service check still
// green; these checks look at the data itself. Each result is measured from the database —
// nothing here is assumed or estimated.

import { getSupabase } from './geoEnrichment';
import { pushConfig } from '../jobs/stellarPush';
import { autoCaseConfig } from '../jobs/autoCase';
import { readAuditLog } from '../lib/audit';
import { FEED_STALE_HOURS, feedConfigured } from './threatInfo';
import { loadScannerStatus } from './vmsWorkers';
import { spiderfootConfigured } from '../lib/spiderfoot';
import { openctiConfigured } from '../lib/opencti';
import { wazuhFreshness } from './wazuhVulnSync';

const H = 3_600_000;

export type PipelineStatus = 'up' | 'degraded' | 'down' | 'off';
export interface PipelineCheck { name: string; status: PipelineStatus; detail: string }

/** Minutes without a new stored alert before ingestion counts as degraded / down. */
export const ALERT_STALE_MINUTES = Number(process.env.ALERT_STALE_MINUTES) > 0 ? Number(process.env.ALERT_STALE_MINUTES) : 60;

const ago = (iso: string) => {
    const m = Math.round((Date.now() - Date.parse(iso)) / 60_000);
    return m < 120 ? `${m} min ago` : m < 2880 ? `${Math.round(m / 60)} h ago` : `${Math.round(m / 1440)} days ago`;
};

export async function pipelineChecks(): Promise<PipelineCheck[]> {
    const supabase = getSupabase();
    if (!supabase) return [{ name: 'Alert ingestion', status: 'down', detail: 'Database not configured' }];
    const out: PipelineCheck[] = [];

    const newest = await supabase.from('alerts').select('received_at').order('received_at', { ascending: false }).limit(1).maybeSingle();
    if (newest.error) out.push({ name: 'Alert ingestion', status: 'down', detail: `Alert store unreadable: ${newest.error.message.slice(0, 80)}` });
    else if (!newest.data) out.push({ name: 'Alert ingestion', status: 'down', detail: 'No alert has ever been stored' });
    else {
        const age = (Date.now() - Date.parse(newest.data.received_at)) / 60_000;
        out.push({
            name: 'Alert ingestion',
            status: age <= ALERT_STALE_MINUTES ? 'up' : age <= ALERT_STALE_MINUTES * 6 ? 'degraded' : 'down',
            detail: `Newest alert stored ${ago(newest.data.received_at)} (stale after ${ALERT_STALE_MINUTES} min)`,
        });
    }

    const q = await supabase.from('alert_quarantine').select('wazuh_alert_id', { count: 'exact', head: true });
    if (q.error) out.push({ name: 'Alert quarantine', status: 'off', detail: 'Quarantine table not created yet' });
    else out.push({ name: 'Alert quarantine', status: (q.count ?? 0) > 0 ? 'degraded' : 'up', detail: (q.count ?? 0) > 0 ? `${q.count} alert(s) held: their Wazuh group is not mapped to an organisation` : 'No alerts held' });

    const push = pushConfig();
    if ('error' in push) out.push({ name: 'Stellar push', status: 'off', detail: push.error });
    else {
        const st = await supabase.from('push_state').select('sent_count, retry_count, last_success_at, last_error, last_error_at').eq('destination', 'stellar').maybeSingle();
        if (st.error || !st.data) out.push({ name: 'Stellar push', status: 'degraded', detail: st.error ? 'push_state unreadable' : 'Enabled, no delivery recorded yet' });
        else {
            const lastOk = st.data.last_success_at ? Date.parse(st.data.last_success_at) : 0;
            const lastErr = st.data.last_error_at ? Date.parse(st.data.last_error_at) : 0;
            const failing = lastErr > lastOk;
            out.push({
                name: 'Stellar push',
                status: failing ? 'degraded' : 'up',
                detail: `${st.data.sent_count} delivered${st.data.last_success_at ? `, last ${ago(st.data.last_success_at)}` : ''}${failing ? `; failing since ${ago(st.data.last_error_at!)}: ${st.data.last_error}` : ''}`,
            });
        }
    }

    const ac = autoCaseConfig();
    out.push('error' in ac
        ? { name: 'Automatic cases', status: 'off', detail: ac.error }
        : { name: 'Automatic cases', status: 'up', detail: `Level ${ac.minLevel}+, grouped per ${ac.groupHours} h` });

    const audit = await readAuditLog(1);
    out.push({ name: 'Audit log', status: audit.source === 'database' ? 'up' : 'degraded', detail: audit.source === 'database' ? 'Stored durably' : 'In memory only: lost on restart' });

    // Threat feeds (phase P6): each enabled feed's last success and last error.
    const feeds = await supabase.from('ti_feeds').select('id, name, enabled, last_success_at, last_error');
    if (feeds.error) out.push({ name: 'Threat feeds', status: 'off', detail: 'Threat Information System tables not created yet' });
    else {
        // A feed whose connector is not configured (OpenCTI, MISP) is not running, not failing.
        const on = (feeds.data ?? []).filter((f) => f.enabled && feedConfigured(f.id));
        const bad = on.filter((f) => f.last_error || !f.last_success_at || Date.now() - Date.parse(f.last_success_at) > (FEED_STALE_HOURS[f.id] ?? 24) * 3_600_000);
        out.push({
            name: 'Threat feeds',
            status: on.length === 0 ? 'off' : bad.length === 0 ? 'up' : bad.length === on.length ? 'down' : 'degraded',
            detail: on.length === 0 ? 'No feed enabled' : bad.length === 0 ? `${on.length} feed(s) current` : `Failing or stale: ${bad.map((f) => `${f.id}${f.last_error ? ` (${String(f.last_error).slice(0, 60)})` : ''}`).join(', ')}`,
        });
    }
    out.push(...await vmsChecks());
    out.push(...await cniiChecks());
    return out;
}

/** VMS scanner, queue, schedules, CVE intelligence and Wazuh sync (phases P4, P5, P7). */
export async function vmsChecks(): Promise<PipelineCheck[]> {
    const supabase = getSupabase()!;
    const out: PipelineCheck[] = [];
    const queued = await supabase.from('vms_scan_jobs').select('requested_at').eq('status', 'queued').neq('kind', 'passive_osint').order('requested_at', { ascending: true }).limit(1).maybeSingle();
    if (queued.error) { out.push({ name: 'VMS scanner', status: 'off', detail: 'VMS tables not created yet' }); return out; }
    // Presence recorded from authenticated worker requests (services/vmsWorkers.ts), not a process check.
    const s = await loadScannerStatus();
    const oldest = queued.data?.requested_at as string | undefined;
    const via = s.source === 'job_heartbeat' ? ' (job heartbeats only: worker presence SQL not applied)' : '';
    out.push({
        name: 'VMS scanner',
        status: s.state === 'online' ? 'up' : s.state === 'never' ? (oldest ? 'down' : 'off') : oldest ? 'down' : 'degraded',
        detail: s.state === 'online' ? `${s.online_workers} worker(s) online${s.workers.length ? `: ${s.workers.filter((w) => w.online).map((w) => w.worker_id).join(', ')}` : ''}; last seen ${ago(s.last_seen_at!)}${via}`
            : s.state === 'never' ? (oldest ? 'No worker has ever connected, and scans are waiting' : 'No worker has connected yet')
                : `No worker seen for ${Math.round(s.online_window_seconds / 60)} min; last seen ${ago(s.last_seen_at!)}${via}`,
    });
    const failed = await supabase.from('vms_scan_jobs').select('id', { count: 'exact', head: true }).eq('status', 'failed').gte('finished_at', new Date(Date.now() - 24 * H).toISOString());
    const waitH = oldest ? (Date.now() - Date.parse(oldest)) / H : 0;
    // Queued kinds no connected worker runs (P12): they wait forever unless someone acts.
    const { data: waiting } = await supabase.from('vms_scan_jobs').select('kind').eq('status', 'queued').neq('kind', 'passive_osint').limit(1000);
    const orphanKinds = s.source === 'presence' ? [...new Set((waiting ?? []).map((j) => String(j.kind)))].filter((k) => !s.workers.some((w) => w.online && (w.kinds ?? []).includes(k))) : [];
    out.push({
        name: 'VMS scan queue',
        status: waitH > 6 || (failed.count ?? 0) > 0 || orphanKinds.length ? 'degraded' : 'up',
        detail: `${oldest ? `Oldest queued scan waiting ${ago(oldest).replace(' ago', '')}` : 'Nothing waiting'}; ${failed.count ?? 0} failed in 24 h${orphanKinds.length ? `; queued with no connected worker for: ${orphanKinds.join(', ')}` : ''}`,
    });
    const sched = await supabase.from('vms_scan_schedules').select('enabled, next_run_at, last_result');
    if (sched.error) out.push({ name: 'VMS schedules', status: 'off', detail: 'Schedule table not created yet' });
    else {
        const on = (sched.data ?? []).filter((x) => x.enabled);
        const late = on.filter((x) => Date.now() - Date.parse(x.next_run_at) > H);
        const stopped = (sched.data ?? []).filter((x) => !x.enabled && String(x.last_result ?? '').startsWith('Disabled:'));
        out.push({
            name: 'VMS schedules',
            status: (sched.data ?? []).length === 0 ? 'off' : late.length || stopped.length ? 'degraded' : 'up',
            detail: (sched.data ?? []).length === 0 ? 'No schedules' : `${on.length} active; ${late.length} overdue by more than an hour; ${stopped.length} stopped because their scope ended`,
        });
    }
    const intel = await supabase.from('cve_intel').select('kev_checked_at, epss_fetched_at').order('kev_checked_at', { ascending: false, nullsFirst: false }).limit(1).maybeSingle();
    if (!intel.error) {
        const k = intel.data?.kev_checked_at as string | undefined;
        out.push({ name: 'CVE intelligence', status: !intel.data ? 'off' : k && Date.now() - Date.parse(k) < 26 * H ? 'up' : 'degraded', detail: !intel.data ? 'No CVE tracked yet' : k ? `KEV last checked ${ago(k)}` : 'KEV never checked' });
    }
    const wz = await supabase.from('vms_wazuh_sync').select('org_id, last_synced_at, last_result');
    if (!wz.error && (wz.data ?? []).length) {
        // Judged on the last COMPLETE sync: a run whose indexer queries failed is not fresh data.
        const stale = (wz.data ?? []).filter((x) => { const f = wazuhFreshness(x); return !f.last_complete_at || Date.now() - Date.parse(f.last_complete_at) > 3 * H; });
        const problem = (wz.data ?? []).map((x) => wazuhFreshness(x).problem).find(Boolean);
        out.push({ name: 'Wazuh vulnerability sync', status: stale.length ? 'degraded' : 'up', detail: stale.length ? `No complete sync in 3 h: ${stale.map((x) => x.org_id).join(', ')}${problem ? ` (last problem: ${problem.slice(0, 160)})` : ''}` : `${(wz.data ?? []).length} organisation(s) synced` });
    }
    return out;
}

/**
 * True when a URL would carry credentials in clear text across a network: http:// to anything but
 * loopback or a private (RFC 1918) address.
 */
export function plaintextTransport(url: string | undefined): boolean {
    if (!url) return false;
    let u: URL;
    try { u = new URL(url); } catch { return false; }
    if (u.protocol !== 'http:') return false;
    const h = u.hostname;
    return !(h === 'localhost' || /^127\./.test(h) || /^10\./.test(h) || /^192\.168\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h) || h === '[::1]');
}

/** CNII passive collection and the connections it uses (phase P9). */
export async function cniiChecks(): Promise<PipelineCheck[]> {
    const supabase = getSupabase()!;
    const out: PipelineCheck[] = [];
    if (process.env.CNII_PASSIVE_ENABLED === 'false') out.push({ name: 'CNII passive collection', status: 'off', detail: 'Turned off (CNII_PASSIVE_ENABLED=false)' });
    else {
        const since = new Date(Date.now() - 24 * H).toISOString();
        const [last, failed, waiting] = await Promise.all([
            supabase.from('vms_scan_jobs').select('finished_at, status, error').eq('kind', 'passive_osint').not('finished_at', 'is', null).order('finished_at', { ascending: false }).limit(1).maybeSingle(),
            supabase.from('vms_scan_jobs').select('id', { count: 'exact', head: true }).eq('kind', 'passive_osint').eq('status', 'failed').gte('finished_at', since),
            supabase.from('vms_scan_jobs').select('requested_at').eq('kind', 'passive_osint').eq('status', 'queued').order('requested_at', { ascending: true }).limit(1).maybeSingle(),
        ]);
        if (last.error) out.push({ name: 'CNII passive collection', status: 'off', detail: 'CNII tables not created yet (sql/2026-10-17_p9_cnii.sql)' });
        else {
            const oldest = waiting.data?.requested_at as string | undefined;
            const late = !!oldest && Date.now() - Date.parse(oldest) > 30 * 60_000;
            const f = failed.count ?? 0;
            out.push({
                name: 'CNII passive collection',
                status: late ? 'down' : f > 0 ? 'degraded' : last.data ? 'up' : 'off',
                detail: late ? `A passive job has waited since ${ago(oldest!)}: the runner is not taking jobs`
                    : `${last.data ? `Last run ${ago(String(last.data.finished_at))} (${last.data.status})` : 'Never run'}; ${f} failed in 24 h${f && last.data?.error ? `: ${String(last.data.error).slice(0, 80)}` : ''}`,
            });
        }
    }
    const conn = (name: string, configured: boolean, envNames: string, url: string | undefined): PipelineCheck =>
        !configured ? { name, status: 'off', detail: `Not configured (${envNames})` }
            : plaintextTransport(url) ? { name, status: 'degraded', detail: 'Configured over plain http across a network: credentials and results travel unencrypted. Put it behind TLS.' }
                : { name, status: 'up', detail: 'Configured (reachability is checked when a job runs)' };
    out.push(conn('SpiderFoot (passive)', spiderfootConfigured(), 'SPIDERFOOT_URL', process.env.SPIDERFOOT_URL));
    out.push(conn('OpenCTI connection', openctiConfigured(), 'OPENCTI_URL, OPENCTI_TOKEN', process.env.OPENCTI_URL));
    return out;
}
