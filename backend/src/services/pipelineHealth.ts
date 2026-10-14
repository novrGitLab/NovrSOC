// Data-pipeline health (phase P2): is data actually flowing, not just are services reachable.
// The 2026-10-13 audit found the Wazuh indexer down for four days with every service check still
// green; these checks look at the data itself. Each result is measured from the database —
// nothing here is assumed or estimated.

import { getSupabase } from './geoEnrichment';
import { pushConfig } from '../jobs/stellarPush';
import { autoCaseConfig } from '../jobs/autoCase';
import { readAuditLog } from '../lib/audit';

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
    return out;
}
