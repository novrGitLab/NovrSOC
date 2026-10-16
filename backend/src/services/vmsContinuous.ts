// VMS Release 3 (phase P7): continuous monitoring.
//   • runDueSchedules — queues each due schedule's scan through the same scope checks as a manual
//     scan; never piles up (a previous run still queued or running is waited for); a schedule
//     whose scope is no longer active is disabled with the reason.
//   • snapshotOrg / riskTrends — one measured snapshot per organisation per day, the trend over a
//     period, and recurring problems (findings reopened, rules open on many assets).
//   • periodReport — what happened in a stated period, with the sources and their limitations.
//   • notifyChanges — new internet-facing assets and services, new P1/P2 findings and reopened
//     findings since the last run, sent to the SOC mailbox as one digest (VMS_NOTIFY_ENABLED=true).
// Every number is counted from stored records at the time asked; nothing is estimated.

import { getSupabase } from './geoEnrichment';
import { queueScan } from '../routes/vms';
import { isEmailEnabled, sendVmsDigestEmail, socNotificationRecipients } from './email';
import { wazuhFreshness } from './wazuhVulnSync';

export const OPEN_STATUSES = ['open', 'acknowledged', 'in_progress', 'fixed_pending_verification', 'reopened'] as const;
const PRIORITIES = ['P1', 'P2', 'P3', 'P4'] as const;
const DAY = 86_400_000;
const isoDay = (d: Date) => d.toISOString().slice(0, 10);

// ── Schedules ─────────────────────────────────────────────────────────────────────────────────
export interface ScheduleRun { id: string; org: string; outcome: 'queued' | 'existing' | 'skipped_in_progress' | 'disabled' | 'failed'; detail: string }

/** The first run time after `now` on the schedule's cadence (missed runs are not caught up). */
export function nextRunAfter(nextRunAt: string, intervalHours: number, now = Date.now()): string {
    const step = intervalHours * 3_600_000;
    let t = Date.parse(nextRunAt);
    if (t <= now) t += Math.ceil((now - t + 1) / step) * step;
    return new Date(t).toISOString();
}

export async function runDueSchedules(now = Date.now()): Promise<ScheduleRun[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    const { data: due, error } = await supabase.from('vms_scan_schedules').select('*').eq('enabled', true).lte('next_run_at', new Date(now).toISOString()).limit(200);
    if (error) throw new Error(`schedules unreadable: ${error.message}`);
    const out: ScheduleRun[] = [];
    for (const s of due ?? []) {
        const next = nextRunAfter(s.next_run_at, s.interval_hours, now);
        const at = new Date(now).toISOString();
        if (s.last_job_id) {
            const { data: prev } = await supabase.from('vms_scan_jobs').select('status').eq('id', s.last_job_id).maybeSingle();
            if (prev && (prev.status === 'queued' || prev.status === 'running')) {
                const detail = `Skipped: the previous run is still ${prev.status}`;
                await supabase.from('vms_scan_schedules').update({ next_run_at: next, last_result: detail, updated_at: at }).eq('id', s.id);
                out.push({ id: s.id, org: s.org_id, outcome: 'skipped_in_progress', detail });
                continue;
            }
        }
        const r = await queueScan(s.org_id, `schedule:${s.id}`, { scope_id: s.scope_id, kind: s.kind, targets: s.targets?.length ? s.targets : undefined, ports: s.ports ?? undefined }, { schedule_id: s.id });
        if (r.ok) {
            const detail = r.existing ? 'The same scan was already queued; linked to it' : 'Queued';
            await supabase.from('vms_scan_schedules').update({ next_run_at: next, last_run_at: at, last_job_id: r.job.id, last_result: detail, updated_at: at }).eq('id', s.id);
            out.push({ id: s.id, org: s.org_id, outcome: r.existing ? 'existing' : 'queued', detail });
        } else if (r.status === 400 || r.status === 403) {
            // The scope no longer allows it: stop, say why, and let a person decide.
            const detail = `Disabled: ${r.error}`;
            await supabase.from('vms_scan_schedules').update({ enabled: false, last_result: detail, updated_at: at }).eq('id', s.id);
            out.push({ id: s.id, org: s.org_id, outcome: 'disabled', detail });
        } else {
            const detail = `Failed (will retry next interval): ${r.error}`;
            await supabase.from('vms_scan_schedules').update({ next_run_at: next, last_result: detail, updated_at: at }).eq('id', s.id);
            out.push({ id: s.id, org: s.org_id, outcome: 'failed', detail });
        }
    }
    return out;
}

// ── Snapshots and trends ──────────────────────────────────────────────────────────────────────
type FindingRow = { id: string; priority: string | null; status: string; due_at: string | null; cve_ids: string[] | null; asset_id: string | null; first_seen: string; verified_at: string | null; rule_id: string; title: string; asset_value: string };

async function openFindings(org: string): Promise<FindingRow[]> {
    const { data, error } = await getSupabase()!.from('vms_findings').select('id, priority, status, due_at, cve_ids, asset_id, first_seen, verified_at, rule_id, title, asset_value').eq('org_id', org).in('status', [...OPEN_STATUSES]).limit(20_000);
    if (error) throw new Error(`findings unreadable: ${error.message}`);
    return (data ?? []) as FindingRow[];
}

/** Measures today's position for one organisation and stores it (re-running the same day replaces it). */
export async function snapshotOrg(org: string, now = new Date()): Promise<Record<string, unknown>> {
    const supabase = getSupabase()!;
    const day = isoDay(now);
    const dayStart = `${day}T00:00:00.000Z`;
    const dayEnd = new Date(Date.parse(dayStart) + DAY).toISOString();
    const open = await openFindings(org);
    const byPriority: Record<string, number> = Object.fromEntries(PRIORITIES.map((p) => [p, 0]));
    for (const f of open) if (f.priority) byPriority[f.priority] = (byPriority[f.priority] ?? 0) + 1;
    const cves = [...new Set(open.flatMap((f) => f.cve_ids ?? []))];
    const kev = new Set<string>();
    for (let i = 0; i < cves.length; i += 200) {
        const { data } = await supabase.from('cve_intel').select('cve_id').eq('kev', true).in('cve_id', cves.slice(i, i + 200));
        for (const k of data ?? []) kev.add(k.cve_id);
    }
    const { data: assets } = await supabase.from('vms_assets').select('id, exposure').eq('org_id', org).eq('status', 'active').limit(20_000);
    const internetIds = new Set((assets ?? []).filter((a) => a.exposure === 'internet').map((a) => a.id));
    const count = async (q: PromiseLike<{ count: number | null }>) => (await q).count ?? 0;
    const [newF, verified, reopened] = await Promise.all([
        count(supabase.from('vms_findings').select('id', { count: 'exact', head: true }).eq('org_id', org).gte('first_seen', dayStart).lt('first_seen', dayEnd)),
        count(supabase.from('vms_findings').select('id', { count: 'exact', head: true }).eq('org_id', org).gte('verified_at', dayStart).lt('verified_at', dayEnd)),
        count(supabase.from('vms_finding_events').select('id', { count: 'exact', head: true }).eq('org_id', org).eq('action', 'reopened').gte('at', dayStart).lt('at', dayEnd)),
    ]);
    const row = {
        org_id: org, day, taken_at: now.toISOString(),
        open_total: open.length, open_by_priority: byPriority,
        overdue: open.filter((f) => f.due_at && Date.parse(f.due_at) < now.getTime()).length,
        kev_open: open.filter((f) => (f.cve_ids ?? []).some((c) => kev.has(c))).length,
        internet_open: open.filter((f) => f.asset_id && internetIds.has(f.asset_id)).length,
        assets_active: (assets ?? []).length, assets_internet: internetIds.size,
        new_findings: newF, verified, reopened,
    };
    const { error } = await supabase.from('vms_risk_snapshots').upsert(row, { onConflict: 'org_id,day' });
    if (error) throw new Error(`snapshot write failed: ${error.message}`);
    return row;
}

/** Hours from first seen to verified, by priority, for findings verified in the window. */
async function timeToRemediate(org: string, since: string, until: string): Promise<Record<string, { verified: number; mean_hours: number | null; within_deadline: number }>> {
    const { data } = await getSupabase()!.from('vms_findings').select('priority, first_seen, verified_at, due_at').eq('org_id', org).gte('verified_at', since).lt('verified_at', until).limit(20_000);
    const out: Record<string, { verified: number; mean_hours: number | null; within_deadline: number }> = {};
    for (const p of PRIORITIES) {
        const rows = (data ?? []).filter((f) => f.priority === p);
        const hours = rows.map((f) => (Date.parse(f.verified_at) - Date.parse(f.first_seen)) / 3_600_000);
        out[p] = {
            verified: rows.length,
            mean_hours: rows.length ? Math.round(hours.reduce((a, b) => a + b, 0) / rows.length) : null,
            within_deadline: rows.filter((f) => f.due_at && Date.parse(f.verified_at) <= Date.parse(f.due_at)).length,
        };
    }
    return out;
}

/** Findings reopened in the window, and rules open on several assets (a fix that is not spreading). */
async function recurring(org: string, since: string, open: FindingRow[]) {
    const supabase = getSupabase()!;
    const { data: ev } = await supabase.from('vms_finding_events').select('finding_id').eq('org_id', org).eq('action', 'reopened').gte('at', since).limit(5000);
    const times = new Map<string, number>();
    for (const e of ev ?? []) times.set(e.finding_id, (times.get(e.finding_id) ?? 0) + 1);
    const ids = [...times.keys()].slice(0, 200);
    const { data: fs } = ids.length ? await supabase.from('vms_findings').select('id, title, asset_value, status, priority').eq('org_id', org).in('id', ids) : { data: [] as { id: string; title: string; asset_value: string; status: string; priority: string | null }[] };
    const reopened = (fs ?? []).map((f) => ({ ...f, times_reopened: times.get(f.id) ?? 0 })).sort((a, b) => b.times_reopened - a.times_reopened).slice(0, 20);
    const byRule = new Map<string, { rule_id: string; title: string; assets: Set<string> }>();
    for (const f of open) {
        const cur = byRule.get(f.rule_id) ?? { rule_id: f.rule_id, title: f.title, assets: new Set<string>() };
        cur.assets.add(f.asset_value);
        byRule.set(f.rule_id, cur);
    }
    const widespread = [...byRule.values()].filter((r) => r.assets.size >= 3).sort((a, b) => b.assets.size - a.assets.size).slice(0, 20)
        .map((r) => ({ rule_id: r.rule_id, title: r.title, open_on_assets: r.assets.size }));
    return { reopened, widespread };
}

export async function riskTrends(org: string, days: number, now = new Date()) {
    const since = new Date(now.getTime() - days * DAY);
    const { data: snaps, error } = await getSupabase()!.from('vms_risk_snapshots').select('*').eq('org_id', org).gte('day', isoDay(since)).order('day', { ascending: true }).limit(800);
    if (error) throw new Error(error.message);
    const open = await openFindings(org);
    return {
        period: { from: since.toISOString(), to: now.toISOString(), days },
        snapshots: snaps ?? [],
        time_to_remediate: await timeToRemediate(org, since.toISOString(), now.toISOString()),
        recurring: await recurring(org, since.toISOString(), open),
        note: (snaps ?? []).length < 2 ? 'Trends need at least two daily snapshots; they are taken once a day from when Release 3 is running.' : null,
    };
}

// ── Period report ─────────────────────────────────────────────────────────────────────────────
export async function periodReport(org: string, days: number, now = new Date()) {
    const supabase = getSupabase()!;
    const since = new Date(now.getTime() - days * DAY).toISOString();
    const until = now.toISOString();
    const open = await openFindings(org);
    const [newF, events, jobs, assetEvents, wazuh, scopes] = await Promise.all([
        supabase.from('vms_findings').select('id, priority, source_class').eq('org_id', org).gte('first_seen', since).lt('first_seen', until).limit(20_000),
        supabase.from('vms_finding_events').select('action, to_value').eq('org_id', org).gte('at', since).lt('at', until).in('action', ['status', 'reopened', 'verified']).limit(20_000),
        supabase.from('vms_scan_jobs').select('kind, status, schedule_id').eq('org_id', org).gte('requested_at', since).lt('requested_at', until).limit(5000),
        supabase.from('vms_asset_events').select('event').eq('org_id', org).gte('at', since).lt('at', until).limit(20_000),
        supabase.from('vms_wazuh_sync').select('last_synced_at, last_result').eq('org_id', org).maybeSingle(),
        supabase.from('vms_scopes').select('id', { count: 'exact', head: true }).eq('org_id', org).eq('status', 'active').gt('expires_at', until),
    ]);
    const tally = <T,>(rows: T[] | null | undefined, key: (r: T) => string) => (rows ?? []).reduce<Record<string, number>>((acc, r) => { const k = key(r); acc[k] = (acc[k] ?? 0) + 1; return acc; }, {});
    const byPriority: Record<string, number> = Object.fromEntries(PRIORITIES.map((p) => [p, 0]));
    for (const f of open) if (f.priority) byPriority[f.priority]++;
    const limitations: string[] = [];
    if ((scopes.count ?? 0) === 0) limitations.push('No active authorised scope: no active scanning was possible at the end of the period.');
    if (!(jobs.data ?? []).some((j) => j.status === 'succeeded')) limitations.push('No scan succeeded in the period: findings reflect earlier scans and Wazuh only.');
    const wf = wazuhFreshness(wazuh.data);
    if (!wf.last_attempt_at) limitations.push('Wazuh vulnerability sync has not run for this organisation: endpoint vulnerabilities are not included.');
    else if (!wf.last_complete_at) limitations.push(`Wazuh vulnerability sync has never completed for this organisation (${wf.problem ?? 'incomplete'}): endpoint vulnerabilities may be missing.`);
    else if (!wf.complete) limitations.push(`The latest Wazuh vulnerability sync was incomplete (${wf.problem}); endpoint vulnerabilities are as of ${wf.last_complete_at}.`);
    limitations.push('Only assets inside authorised scope and endpoints with a Wazuh agent are covered; anything else is unknown, not clean.');
    return {
        period: { from: since, to: until, days },
        open_now: { total: open.length, by_priority: byPriority, overdue: open.filter((f) => f.due_at && Date.parse(f.due_at) < now.getTime()).length },
        new_in_period: { total: (newF.data ?? []).length, by_priority: tally(newF.data, (f) => f.priority ?? 'unscored'), by_source: tally(newF.data, (f) => f.source_class) },
        status_changes: tally(events.data, (e) => (e.action === 'status' ? `status:${e.to_value}` : e.action)),
        time_to_remediate: await timeToRemediate(org, since, until),
        scans: tally(jobs.data, (j) => `${j.kind}:${j.status}${j.schedule_id ? ':scheduled' : ''}`),
        attack_surface_changes: tally(assetEvents.data, (e) => e.event),
        top_open: open.filter((f) => f.priority === 'P1' || f.priority === 'P2').slice(0, 15).map((f) => ({ id: f.id, title: f.title, asset: f.asset_value, priority: f.priority, due_at: f.due_at, status: f.status })),
        recurring: await recurring(org, since, open),
        wazuh_sync: wazuh.data ?? null,
        sources: ['vms_findings', 'vms_finding_events', 'vms_scan_jobs', 'vms_asset_events', 'vms_wazuh_sync'],
        limitations,
    };
}

// ── Change notifications ──────────────────────────────────────────────────────────────────────
export function notifyEnabled(): boolean { return process.env.VMS_NOTIFY_ENABLED === 'true'; }

export async function notifyChanges(org: string, now = new Date()): Promise<{ lines: string[]; sent: boolean; detail: string }> {
    const supabase = getSupabase()!;
    const at = now.toISOString();
    const { data: st } = await supabase.from('vms_notify_state').select('*').eq('org_id', org).maybeSingle();
    if (!st) {
        // First run: start from now rather than sending the whole history.
        await supabase.from('vms_notify_state').upsert({ org_id: org, last_event_at: at, last_finding_at: at, last_run_at: at, last_result: { started: true } }, { onConflict: 'org_id' });
        return { lines: [], sent: false, detail: 'Started tracking changes from now' };
    }
    const sinceEvent = st.last_event_at ?? at;
    const sinceFinding = st.last_finding_at ?? at;
    const [events, findings, reopenedEv] = await Promise.all([
        supabase.from('vms_asset_events').select('at, event, details, asset_id, vms_assets(value, exposure)').eq('org_id', org).gt('at', sinceEvent).lte('at', at).in('event', ['asset_new', 'service_new']).order('at').limit(500),
        supabase.from('vms_findings').select('id, title, asset_value, priority, first_seen').eq('org_id', org).gt('first_seen', sinceFinding).lte('first_seen', at).in('priority', ['P1', 'P2']).order('first_seen').limit(200),
        supabase.from('vms_finding_events').select('finding_id, at').eq('org_id', org).eq('action', 'reopened').gt('at', sinceFinding).lte('at', at).limit(200),
    ]);
    const lines: string[] = [];
    for (const e of events.data ?? []) {
        const a = e.vms_assets as unknown as { value: string; exposure: string } | null;
        if (a?.exposure !== 'internet') continue;
        const d = (e.details ?? {}) as Record<string, unknown>;
        lines.push(e.event === 'asset_new' ? `New internet-facing asset: ${a.value}` : `New service on ${a.value}: ${d.port ?? '?'}/${d.protocol ?? 'tcp'} ${d.service ?? ''}`.trim());
    }
    for (const f of findings.data ?? []) lines.push(`New ${f.priority} finding on ${f.asset_value}: ${f.title}`);
    if ((reopenedEv.data ?? []).length) {
        const ids = [...new Set((reopenedEv.data ?? []).map((r) => r.finding_id))].slice(0, 50);
        const { data: rf } = await supabase.from('vms_findings').select('title, asset_value, priority').eq('org_id', org).in('id', ids);
        for (const f of rf ?? []) lines.push(`Reopened (${f.priority ?? 'unscored'}) on ${f.asset_value}: ${f.title}`);
    }
    let sent = false;
    let detail = lines.length ? '' : 'Nothing to report';
    if (lines.length) {
        const to = socNotificationRecipients();
        if (!isEmailEnabled()) detail = 'Not sent: email is not configured';
        else if (!to.length) detail = 'Not sent: no SOC notification recipient configured';
        else {
            try {
                await sendVmsDigestEmail({ to, org, lines });
                sent = true;
                detail = `Sent to ${to.length} recipient(s)`;
            } catch (err) {
                // Keep the position so the same changes are tried again next run.
                detail = `Send failed (will retry): ${err instanceof Error ? err.message : String(err)}`.slice(0, 300);
                await supabase.from('vms_notify_state').update({ last_run_at: at, last_result: { lines: lines.length, sent, detail } }).eq('org_id', org);
                return { lines, sent, detail };
            }
        }
    }
    await supabase.from('vms_notify_state').update({ last_event_at: at, last_finding_at: at, last_run_at: at, last_result: { lines: lines.length, sent, detail } }).eq('org_id', org);
    return { lines, sent, detail };
}
