// Security posture metrics per client organisation, computed from the real `cases` table.
//
// Definitions (shown on the pages too, so nobody has to guess what a number means):
//   • Worked cases  — cases an analyst handled: auto-closed tier-1 cases are excluded, since the
//                     SOAR engine resolves those in seconds and would inflate every figure.
//   • Close time    — resolved_at − created_at, averaged over worked cases resolved in the last
//                     30 days.
//   • SLA rate      — share of worked cases resolved in the last 30 days within the resolution
//                     target for their severity (SLA_TARGET_HOURS below, env-overridable).
//   • Response time — Wazuh alert time → case creation, for engine-created cases in the last 30
//                     days. The alert time is the epoch prefix of Wazuh's alert id.
//   • Detection time — NOT tracked. It needs the time the underlying event happened, which
//                     nothing in the pipeline records. Returned as null, never estimated.
//   • Trend         — this calendar month's SLA rate vs last month's (WAT): ±5 points or more.
//   • Posture       — Secure: SLA > 90% and open < 5 · Critical: SLA < 70% or open > 15 ·
//                     otherwise At Risk. With no measurable SLA, only open cases decide.
import { getSupabase } from './geoEnrichment';
import { dbErrorMessage } from './cases';

export const SLA_TARGET_HOURS: Record<string, number> = {
    critical: Number(process.env.SLA_RESOLVE_HOURS_CRITICAL) || 4,
    high: Number(process.env.SLA_RESOLVE_HOURS_HIGH) || 24,
    medium: Number(process.env.SLA_RESOLVE_HOURS_MEDIUM) || 72,
    low: Number(process.env.SLA_RESOLVE_HOURS_LOW) || 168,
};
export const SLA_SECURE_THRESHOLD = 90;

const DAY = 24 * 3600_000;
const WAT_OFFSET = 3600_000;

export type Posture = 'secure' | 'at_risk' | 'critical';
export type Trend = 'improving' | 'stable' | 'declining';

export interface MonthPoint { month: string; sla_rate: number | null; resolved: number }
export interface ClosedCase { id: string; case_number: string; title: string; severity: string; close_time_hrs: number; within_sla: boolean; resolved_at: string }

export interface OrgMetrics {
    org_id: string;
    org_name: string;
    detection_time_hrs: null;
    response_time_hrs: number | null;
    response_sample: number;
    close_time_hrs: number | null;
    open_cases: number;
    closed_this_month: number;
    resolved_30d: number;
    sla_rate: number | null;
    posture: Posture;
    trend: Trend | null;
    monthly: MonthPoint[];
    last_closed: ClosedCase[];
    last_updated: string | null;
}

interface WorkedRow { id: string; case_number: string; title: string; severity: string; status: string; created_at: string; resolved_at: string | null; updated_at: string | null }

/** Start (UTC ms) of the WAT calendar month `offset` months from now (0 = this month). */
function watMonthStart(offset: number): number {
    const shifted = new Date(Date.now() + WAT_OFFSET);
    return Date.UTC(shifted.getUTCFullYear(), shifted.getUTCMonth() + offset, 1) - WAT_OFFSET;
}

const hours = (ms: number) => Math.round((ms / 3600_000) * 10) / 10;
const pct = (n: number, d: number) => (d > 0 ? Math.round((n / d) * 1000) / 10 : null);
const withinSla = (r: WorkedRow) => r.resolved_at !== null
    && Date.parse(r.resolved_at) - Date.parse(r.created_at) <= (SLA_TARGET_HOURS[r.severity] ?? SLA_TARGET_HOURS.low) * 3600_000;

export function postureFor(sla: number | null, open: number): Posture {
    if ((sla !== null && sla < 70) || open > 15) return 'critical';
    if ((sla === null || sla > SLA_SECURE_THRESHOLD) && open < 5) return 'secure';
    return 'at_risk';
}

// PostgREST caps a response at 1000 rows; page through up to `max`.
async function fetchPaged<T>(build: (from: number, to: number) => PromiseLike<{ data: T[] | null; error: unknown }>, max = 20000): Promise<T[]> {
    const out: T[] = [];
    for (let from = 0; from < max; from += 1000) {
        const { data, error } = await build(from, from + 999);
        if (error) throw new Error(dbErrorMessage(error));
        out.push(...(data ?? []));
        if (!data || data.length < 1000) break;
    }
    return out;
}

export async function orgMetrics(orgSlug: string, orgName: string): Promise<OrgMetrics> {
    const supabase = getSupabase();
    if (!supabase) throw new Error('Case store not configured');
    const now = Date.now();
    const sixMonthsAgo = new Date(watMonthStart(-5)).toISOString();
    const thirtyDaysAgo = new Date(now - 30 * DAY).toISOString();

    const [worked, openCount, engineCases] = await Promise.all([
        fetchPaged<WorkedRow>((a, b) => supabase.from('cases')
            .select('id, case_number, title, severity, status, created_at, resolved_at, updated_at')
            .eq('org_id', orgSlug).eq('auto_closed', false).gte('created_at', sixMonthsAgo)
            .order('created_at', { ascending: false }).range(a, b)),
        supabase.from('cases').select('id', { count: 'exact', head: true }).eq('org_id', orgSlug).neq('status', 'resolved'),
        fetchPaged<{ source_id: string | null; created_at: string }>((a, b) => supabase.from('cases')
            .select('source_id, created_at').eq('org_id', orgSlug).eq('source', 'wazuh').gte('created_at', thirtyDaysAgo)
            .range(a, b), 10000),
    ]);
    if (openCount.error) throw new Error(dbErrorMessage(openCount.error));

    const resolved = worked.filter((r) => r.status === 'resolved' && r.resolved_at);
    const resolved30 = resolved.filter((r) => Date.parse(r.resolved_at!) >= now - 30 * DAY);
    const closeTimes = resolved30.map((r) => Date.parse(r.resolved_at!) - Date.parse(r.created_at)).filter((ms) => ms >= 0);

    const monthly: MonthPoint[] = [];
    for (let i = -5; i <= 0; i++) {
        const start = watMonthStart(i);
        const end = watMonthStart(i + 1);
        const inMonth = resolved.filter((r) => { const t = Date.parse(r.resolved_at!); return t >= start && t < end; });
        monthly.push({
            month: new Intl.DateTimeFormat('en-GB', { timeZone: 'Africa/Lagos', month: 'short', year: '2-digit' }).format(new Date(start + WAT_OFFSET)),
            sla_rate: pct(inMonth.filter(withinSla).length, inMonth.length),
            resolved: inMonth.length,
        });
    }
    const thisMonth = monthly[5].sla_rate;
    const lastMonth = monthly[4].sla_rate;
    const trend: Trend | null = thisMonth === null || lastMonth === null ? null
        : thisMonth - lastMonth >= 5 ? 'improving' : lastMonth - thisMonth >= 5 ? 'declining' : 'stable';

    // Wazuh alert ids are "<epoch seconds>.<offset>".
    const responseMs = engineCases
        .map((c) => { const m = (c.source_id ?? '').match(/^(\d{9,11})\.\d+$/); return m ? Date.parse(c.created_at) - Number(m[1]) * 1000 : NaN; })
        .filter((ms) => Number.isFinite(ms) && ms >= 0 && ms < 7 * DAY);

    const sla = pct(resolved30.filter(withinSla).length, resolved30.length);
    const open = openCount.count ?? 0;
    const lastUpdated = worked.reduce<string | null>((max, r) => {
        const t = r.updated_at ?? r.created_at;
        return max === null || t > max ? t : max;
    }, null);

    return {
        org_id: orgSlug,
        org_name: orgName,
        detection_time_hrs: null,
        response_time_hrs: responseMs.length > 0 ? hours(responseMs.reduce((s, x) => s + x, 0) / responseMs.length) : null,
        response_sample: responseMs.length,
        close_time_hrs: closeTimes.length > 0 ? hours(closeTimes.reduce((s, x) => s + x, 0) / closeTimes.length) : null,
        open_cases: open,
        closed_this_month: resolved.filter((r) => Date.parse(r.resolved_at!) >= watMonthStart(0)).length,
        resolved_30d: resolved30.length,
        sla_rate: sla,
        posture: postureFor(sla, open),
        trend,
        monthly,
        last_closed: resolved.slice().sort((a, b) => b.resolved_at!.localeCompare(a.resolved_at!)).slice(0, 10).map((r) => ({
            id: r.id, case_number: r.case_number, title: r.title, severity: r.severity,
            close_time_hrs: hours(Date.parse(r.resolved_at!) - Date.parse(r.created_at)), within_sla: withinSla(r), resolved_at: r.resolved_at!,
        })),
        last_updated: lastUpdated,
    };
}

export interface OrgRef { slug: string; name: string }

export async function activeOrgs(): Promise<OrgRef[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    const { data, error } = await supabase.from('organisations').select('slug, name, is_active').order('name');
    if (error) throw new Error(dbErrorMessage(error));
    return (data ?? []).filter((o) => o.is_active !== false && o.slug).map((o) => ({ slug: o.slug, name: o.name }));
}
