// Automatic case creation from stored alerts (phase P1).
//
// The SOAR engine on the Wazuh server (integratord) was meant to open a case per alert and has
// opened none since 5 Oct 2026, while alerts keep arriving in `alerts`. This job opens cases from
// those stored alerts through the existing case service (services/cases.ts createCase) — the
// same cases, timeline and notifications analysts already use, not a second case system.
//
// Rules (configurable, defaults in brackets):
//   • An alert qualifies when rule_level >= AUTO_CASE_MIN_LEVEL [13 = critical], it has no case
//     yet (case_id null), it was stored within AUTO_CASE_LOOKBACK_HOURS [24] and is older than
//     30 s (so a batch still being written is read whole).
//   • Repeats share one case: alerts with the same organisation, rule and agent whose event_time
//     falls in the same AUTO_CASE_GROUP_HOURS [24] window go to one case
//     (source 'wazuh-auto', source_id '<rule>|<agent>|<window start>'). The case service's
//     (org_id, source, source_id) dedupe makes that safe across retries and restarts.
//   • If the SOAR engine already cased an alert (source 'wazuh', source_id = Wazuh alert id),
//     the alert is linked to that case instead.
//   • Every qualifying alert is linked (alerts.case_id), so each occurrence stays as evidence.
//     Alert status is left for the analyst: the job never triages, closes or contains anything.
//   • At most AUTO_CASE_MAX_NEW_PER_RUN [25] new cases per run; the rest wait for the next run.
//   • New high/critical cases notify the SOC mailbox exactly as a manually created case does.
// Off unless AUTO_CASE_ENABLED is exactly "true". Runs only where the mutating jobs run
// (lib/runtimeEnv.ts).

import { getSupabase } from '../services/geoEnrichment';
import { createCase, addTimeline, isCaseSeverity, type CaseSeverity } from '../services/cases';
import { isEmailEnabled, sendCaseNotificationEmail, socNotificationRecipients } from '../services/email';

const TICK_MS = 60_000;
const SETTLE_MS = 30_000;
const PAGE = 500;
export const AUTO_CASE_ACTOR = 'NovrSOC auto-case';

export interface AutoCaseConfig { minLevel: number; groupHours: number; lookbackHours: number; maxNewPerRun: number }

function intEnv(v: string | undefined, def: number, min: number, max: number): number | null {
    if (v === undefined || v.trim() === '') return def;
    const n = Number(v.trim());
    return Number.isInteger(n) && n >= min && n <= max ? n : null;
}

export function autoCaseConfig(env: NodeJS.ProcessEnv = process.env): AutoCaseConfig | { error: string } {
    if (env.AUTO_CASE_ENABLED !== 'true') return { error: 'AUTO_CASE_ENABLED is not "true"' };
    const minLevel = intEnv(env.AUTO_CASE_MIN_LEVEL, 13, 7, 16);
    const groupHours = intEnv(env.AUTO_CASE_GROUP_HOURS, 24, 1, 168);
    const lookbackHours = intEnv(env.AUTO_CASE_LOOKBACK_HOURS, 24, 1, 720);
    const maxNewPerRun = intEnv(env.AUTO_CASE_MAX_NEW_PER_RUN, 25, 1, 500);
    if (minLevel === null) return { error: 'AUTO_CASE_MIN_LEVEL must be 7-16' };
    if (groupHours === null) return { error: 'AUTO_CASE_GROUP_HOURS must be 1-168' };
    if (lookbackHours === null) return { error: 'AUTO_CASE_LOOKBACK_HOURS must be 1-720' };
    if (maxNewPerRun === null) return { error: 'AUTO_CASE_MAX_NEW_PER_RUN must be 1-500' };
    return { minLevel, groupHours, lookbackHours, maxNewPerRun };
}

interface AlertRow {
    id: string; org_id: string; wazuh_alert_id: string; rule_id: string | null; rule_level: number | null;
    rule_description: string | null; agent_id: string | null; agent_name: string | null; severity: string;
    mitre_ids: string[] | null; event_time: string; raw: unknown; raw_truncated: boolean | null;
}

/** The grouping key's window start for an event time. */
export function windowStart(eventTime: string, groupHours: number): string {
    const span = groupHours * 3_600_000;
    return new Date(Math.floor(Date.parse(eventTime) / span) * span).toISOString();
}

export const groupSourceId = (a: Pick<AlertRow, 'rule_id' | 'agent_id' | 'event_time'>, groupHours: number) =>
    `${a.rule_id ?? 'no-rule'}|${a.agent_id ?? 'no-agent'}|${windowStart(a.event_time, groupHours)}`;

function srcIp(raw: unknown, truncated: boolean | null): string | null {
    if (truncated || !raw || typeof raw !== 'object') return null;
    const v = (raw as { data?: { srcip?: unknown } }).data?.srcip;
    return typeof v === 'string' && /^[0-9a-fA-F:.]{3,45}$/.test(v) ? v : null;
}

export interface AutoCaseResult { examined: number; linked: number; created: number; deferred: number }

export async function runAutoCaseOnce(cfg: AutoCaseConfig): Promise<AutoCaseResult> {
    const supabase = getSupabase();
    if (!supabase) throw new Error('store not configured');
    const now = Date.now();
    const { data, error } = await supabase.from('alerts')
        .select('id, org_id, wazuh_alert_id, rule_id, rule_level, rule_description, agent_id, agent_name, severity, mitre_ids, event_time, raw, raw_truncated')
        .is('case_id', null).gte('rule_level', cfg.minLevel)
        .gte('received_at', new Date(now - cfg.lookbackHours * 3_600_000).toISOString())
        .lte('received_at', new Date(now - SETTLE_MS).toISOString())
        .order('received_at', { ascending: true }).limit(PAGE);
    if (error) throw new Error(`alerts read failed: ${error.message}`);
    const alerts = (data ?? []) as AlertRow[];
    const result: AutoCaseResult = { examined: alerts.length, linked: 0, created: 0, deferred: 0 };
    if (!alerts.length) return result;

    // Cases the SOAR engine already opened for these exact alerts, per org.
    const soarCase = new Map<string, string>(); // `${org}\n${wazuh_alert_id}` -> case id
    for (const org of new Set(alerts.map((a) => a.org_id))) {
        const ids = alerts.filter((a) => a.org_id === org).map((a) => a.wazuh_alert_id);
        const r = await supabase.from('cases').select('id, source_id').eq('org_id', org).eq('source', 'wazuh').in('source_id', ids);
        if (r.error) throw new Error(`cases read failed: ${r.error.message}`);
        for (const c of r.data ?? []) soarCase.set(`${org}\n${c.source_id}`, c.id);
    }

    // Group the rest by org + rule + agent + window, oldest alert first.
    const links = new Map<string, string[]>(); // case id -> alert ids
    const groups = new Map<string, AlertRow[]>();
    for (const a of alerts) {
        const existing = soarCase.get(`${a.org_id}\n${a.wazuh_alert_id}`);
        if (existing) { links.set(existing, [...(links.get(existing) ?? []), a.id]); continue; }
        const key = `${a.org_id}\n${groupSourceId(a, cfg.groupHours)}`;
        groups.set(key, [...(groups.get(key) ?? []), a]);
    }

    for (const [key, members] of groups) {
        const [org, sourceId] = key.split('\n');
        const first = members[0];
        const top = members.reduce((m, a) => ((a.rule_level ?? 0) > (m.rule_level ?? 0) ? a : m), first);
        // createCase returns an existing case for the same key without creating one, so only a
        // genuinely new case counts against the per-run cap.
        const probe = await supabase.from('cases').select('id').eq('org_id', org).eq('source', 'wazuh-auto').eq('source_id', sourceId).maybeSingle();
        if (probe.error) throw new Error(`cases read failed: ${probe.error.message}`);
        if (!probe.data && result.created >= cfg.maxNewPerRun) { result.deferred += members.length; continue; }

        const severity: CaseSeverity = isCaseSeverity(top.severity) ? top.severity : 'high';
        const r = await createCase({
            org_id: org, source: 'wazuh-auto', source_id: sourceId, severity,
            title: `${top.rule_description ?? `Wazuh rule ${top.rule_id ?? 'unknown'}`} on ${top.agent_name ?? top.agent_id ?? 'unknown agent'}`,
            description: `Opened automatically: Wazuh rule ${top.rule_id ?? 'unknown'} (level ${top.rule_level ?? '?'}) on agent ${top.agent_name ?? top.agent_id ?? 'unknown'}, `
                + `window from ${windowStart(first.event_time, cfg.groupHours)} (${cfg.groupHours} h). Every matching alert is linked to this case.`,
            agent_id: top.agent_id, agent_name: top.agent_name, source_ip: srcIp(top.raw, top.raw_truncated),
            rule_id: top.rule_id, rule_level: top.rule_level, mitre_technique: top.mitre_ids?.[0] ?? null,
            tags: ['auto-case', ...(top.rule_id ? [`rule:${top.rule_id}`] : [])],
        }, AUTO_CASE_ACTOR);
        if (!r.ok) throw new Error(r.error);
        if (r.created) {
            result.created++;
            const to = socNotificationRecipients();
            if (isEmailEnabled() && to.length && (severity === 'critical' || severity === 'high')) {
                sendCaseNotificationEmail({ to, case_number: r.case.case_number, title: r.case.title, severity, headline: 'New case (automatic)', agent: r.case.agent_name, source_ip: r.case.source_ip, detail: r.case.description })
                    .catch((err) => console.error('[auto-case] notification email failed:', err instanceof Error ? err.message : err));
            }
        }
        links.set(r.case.id, [...(links.get(r.case.id) ?? []), ...members.map((m) => m.id)]);
    }

    for (const [caseId, alertIds] of links) {
        const u = await supabase.from('alerts').update({ case_id: caseId }).in('id', alertIds).is('case_id', null).select('id');
        if (u.error) throw new Error(`alerts link failed: ${u.error.message}`);
        const n = (u.data ?? []).length;
        result.linked += n;
        if (n) await addTimeline(caseId, AUTO_CASE_ACTOR, `${n} alert${n === 1 ? '' : 's'} linked`, { details: 'Matching alerts stored by the Wazuh pipeline', automated: true });
    }
    return result;
}

export function startAutoCaseJob(): void {
    const cfg = autoCaseConfig();
    if ('error' in cfg) {
        if (process.env.AUTO_CASE_ENABLED === 'true') console.error(`[auto-case] not started: ${cfg.error}`);
        return;
    }
    console.log(`[auto-case] opening cases for level >= ${cfg.minLevel}, grouped per ${cfg.groupHours} h, max ${cfg.maxNewPerRun} new per run`);
    let running = false;
    const tick = async () => {
        if (running) return;
        running = true;
        try {
            const r = await runAutoCaseOnce(cfg);
            if (r.created || r.linked || r.deferred) console.log(`[auto-case] created ${r.created}, linked ${r.linked}, deferred ${r.deferred}`);
        } catch (err) {
            console.error(`[auto-case] ${err instanceof Error ? err.message : err}`);
        } finally {
            running = false;
        }
    };
    void tick();
    setInterval(() => { void tick(); }, TICK_MS).unref();
}
