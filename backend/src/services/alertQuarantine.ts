// Alert quarantine (phase P1, sql/2026-10-14_p1_quarantine.sql).
//
// The ingest endpoint keeps alerts whose agent groups map to no organisation (or to several) in
// `alert_quarantine`, without an org, instead of dropping them. Once a super_admin maps the group
// (PUT /api/admin/wazuh-group-map), replayQuarantine() moves every quarantined alert that now
// resolves to exactly one organisation into `alerts`, under the same rule ingest uses, and
// removes it from quarantine. Nothing is guessed: an alert still unmapped or ambiguous stays.
// Replays are idempotent — `alerts` is unique on (org_id, wazuh_alert_id), so a repeat is ignored.
//
// Quarantined content has no tenant yet, so only per-group counts ever leave this module.

import { getSupabase } from './geoEnrichment';

const PAGE = 500;
const MAX_PAGES = 40; // 20,000 alerts per call; call again for more

export interface QuarantineGroup { wazuh_group: string; alerts: number; oldest: string; newest: string; reason: string }

/** Per-group counts of quarantined alerts. Null when the table isn't there yet. */
export async function quarantineSummary(): Promise<{ total: number; groups: QuarantineGroup[] } | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const byGroup = new Map<string, QuarantineGroup>();
    let total = 0;
    for (let page = 0; page < MAX_PAGES; page++) {
        const { data, error } = await supabase.from('alert_quarantine').select('wazuh_groups, reason, received_at')
            .order('received_at', { ascending: true }).range(page * PAGE, page * PAGE + PAGE - 1);
        if (error) return null;
        for (const r of data ?? []) {
            total++;
            const groups: string[] = r.wazuh_groups?.length ? r.wazuh_groups : ['(no group)'];
            for (const g of groups) {
                const cur = byGroup.get(g);
                if (!cur) byGroup.set(g, { wazuh_group: g, alerts: 1, oldest: r.received_at, newest: r.received_at, reason: r.reason });
                else { cur.alerts++; if (r.received_at > cur.newest) cur.newest = r.received_at; if (r.received_at < cur.oldest) cur.oldest = r.received_at; }
            }
        }
        if ((data ?? []).length < PAGE) break;
    }
    return { total, groups: [...byGroup.values()].sort((a, b) => b.alerts - a.alerts) };
}

export interface ReplayResult { replayed: number; duplicates: number; still_quarantined: number }

/** Move quarantined alerts that now resolve to exactly one organisation into `alerts`. */
export async function replayQuarantine(): Promise<ReplayResult> {
    const supabase = getSupabase();
    if (!supabase) throw new Error('Database not configured');
    const map = await supabase.from('wazuh_group_org_map').select('wazuh_group, org_id');
    if (map.error) throw new Error(`group map read failed: ${map.error.message}`);
    const groupOrg = new Map((map.data ?? []).map((m) => [m.wazuh_group as string, m.org_id as string]));

    let replayed = 0, duplicates = 0, still = 0;
    let offset = 0;
    for (let page = 0; page < MAX_PAGES; page++) {
        const { data, error } = await supabase.from('alert_quarantine').select('wazuh_alert_id, wazuh_groups, alert')
            .order('received_at', { ascending: true }).range(offset, offset + PAGE - 1);
        if (error) throw new Error(`quarantine read failed: ${error.message}`);
        const rows = data ?? [];
        const ready: { id: string; row: Record<string, unknown> }[] = [];
        for (const q of rows) {
            const orgs = [...new Set((q.wazuh_groups as string[]).map((g) => groupOrg.get(g)).filter((o): o is string => !!o))];
            if (orgs.length === 1) ready.push({ id: q.wazuh_alert_id, row: { ...(q.alert as Record<string, unknown>), org_id: orgs[0] } });
            else still++;
        }
        if (ready.length) {
            const ins = await supabase.from('alerts').upsert(ready.map((r) => r.row), { onConflict: 'org_id,wazuh_alert_id', ignoreDuplicates: true }).select('id');
            if (ins.error) throw new Error(`alerts write failed: ${ins.error.message}`);
            const inserted = (ins.data ?? []).length;
            replayed += inserted;
            duplicates += ready.length - inserted;
            const del = await supabase.from('alert_quarantine').delete().in('wazuh_alert_id', ready.map((r) => r.id));
            if (del.error) throw new Error(`quarantine delete failed: ${del.error.message}`);
        }
        // Rows we left behind stay at the front of the order; skip past them on the next page.
        offset += rows.length - ready.length;
        if (rows.length < PAGE) break;
    }
    return { replayed, duplicates, still_quarantined: still };
}
