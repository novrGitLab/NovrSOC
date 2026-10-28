// R3.3E — report schedule timing and distributed claiming.
//
// Distributed safety (Stage 2's explicit requirement): claimDueSchedules() does NOT decide "is
// this due" and then separately write — a second replica racing the same tick would double-claim
// between those two steps. Instead each due schedule is claimed with a single compare-and-swap
// UPDATE (`WHERE next_run_at = <the exact value just read>`), which Postgres's read-committed
// isolation makes safe: a second replica's UPDATE re-evaluates that WHERE clause against the
// first replica's already-committed row and matches nothing, so it naturally gets 0 rows back
// rather than racing it. This is the application-level equivalent of
// sql/2026-10-14_p4_vms_asm.sql's vms_claim_job() — that one uses `FOR UPDATE SKIP LOCKED` inside
// a SQL function because it's claiming from a queue table many workers pull from one at a time;
// this is claiming calendar due-ness, which a plain CAS handles just as safely with less SQL.
// report_claim_job() (the migration) is the FOR-UPDATE-SKIP-LOCKED analogue used downstream, once
// a due schedule has produced a queued report_jobs row — see jobs/reportSchedulerJob.ts.

import { getSupabase } from '../services/geoEnrichment';

export interface ReportSchedule {
    id: string; org_id: string; report_type: 'vms' | 'cnii' | 'threat_intel' | 'executive_summary'; format: 'executive' | 'technical';
    cadence: 'weekly' | 'monthly'; day_of_week: number | null; day_of_month: number | null; hour_local: number; timezone: string;
    enabled: boolean; next_run_at: string; last_success_at: string | null; last_failure_at: string | null; last_error: string | null;
}

/** A wall-clock time in `timeZone`, converted to the UTC instant it actually represents. Pure
 * Intl, no date library: two correction passes converge for any real IANA offset, including ones
 * with DST (R3.3E's own organisations are all Africa/Lagos, which has none, but this must still
 * be correct for any timezone a schedule names). */
function zonedTimeToUtc(year: number, month: number, day: number, hour: number, minute: number, timeZone: string): Date {
    let guess = new Date(Date.UTC(year, month - 1, day, hour, minute));
    const fmt = new Intl.DateTimeFormat('en-US', { timeZone, hour12: false, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
    for (let i = 0; i < 2; i++) {
        const parts = fmt.formatToParts(guess);
        const get = (t: string) => Number(parts.find((p) => p.type === t)?.value ?? 0);
        const h = get('hour') % 24; // Intl can report 24 for midnight with hour12:false in some engines
        const asIfThatWereUtc = Date.UTC(get('year'), get('month') - 1, get('day'), h, get('minute'));
        const diff = asIfThatWereUtc - Date.UTC(year, month - 1, day, hour, minute);
        guess = new Date(guess.getTime() - diff);
    }
    return guess;
}

/** That weekday/day-of-month/hour, in `timeZone`, as year/month/day/weekday components — for
 * finding "today" and "today's weekday" in the schedule's own timezone, not the server's. */
function zonedNow(timeZone: string, from: Date): { year: number; month: number; day: number; weekday: number; hour: number; minute: number } {
    const parts = new Intl.DateTimeFormat('en-US', { timeZone, hour12: false, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', weekday: 'short' }).formatToParts(from);
    const get = (t: string) => parts.find((p) => p.type === t)?.value ?? '';
    const WD: Record<string, number> = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
    return { year: Number(get('year')), month: Number(get('month')), day: Number(get('day')), weekday: WD[get('weekday')] ?? 0, hour: Number(get('hour')) % 24, minute: Number(get('minute')) };
}

/** The next run time strictly after `from`, for a weekly or monthly cadence in the schedule's own
 * timezone. Exported and pure (takes `from` explicitly) so it's directly unit-testable without a
 * clock dependency. */
export function nextRunAt(s: Pick<ReportSchedule, 'cadence' | 'day_of_week' | 'day_of_month' | 'hour_local' | 'timezone'>, from = new Date()): Date {
    const now = zonedNow(s.timezone, from);
    if (s.cadence === 'weekly') {
        const target = ((s.day_of_week ?? 1) + 7) % 7;
        let deltaDays = (target - now.weekday + 7) % 7;
        const todayAlreadyPassed = deltaDays === 0 && now.hour >= s.hour_local;
        if (todayAlreadyPassed) deltaDays = 7;
        const base = new Date(Date.UTC(now.year, now.month - 1, now.day + deltaDays));
        return zonedTimeToUtc(base.getUTCFullYear(), base.getUTCMonth() + 1, base.getUTCDate(), s.hour_local, 0, s.timezone);
    }
    // Monthly: day_of_month is capped 1-28 at the schema level, so it exists in every month.
    const dom = Math.min(Math.max(s.day_of_month ?? 1, 1), 28);
    const thisMonthPassed = now.day > dom || (now.day === dom && now.hour >= s.hour_local);
    const month = now.month - 1 + (thisMonthPassed ? 1 : 0);
    const year = now.year + Math.floor(month / 12);
    const normalisedMonth = ((month % 12) + 12) % 12;
    return zonedTimeToUtc(year, normalisedMonth + 1, dom, s.hour_local, 0, s.timezone);
}

/** All schedules whose next_run_at has passed, each atomically claimed (next_run_at advanced to
 * its following occurrence) before being returned — see the header comment for why this is safe
 * under concurrent replicas. A schedule another replica claims first simply won't appear here. */
export async function claimDueSchedules(now = new Date()): Promise<ReportSchedule[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    const { data: due, error } = await supabase.from('report_schedules').select('*').eq('enabled', true).lte('next_run_at', now.toISOString()).limit(200);
    if (error || !due?.length) return [];
    const claimed: ReportSchedule[] = [];
    for (const s of due as ReportSchedule[]) {
        const advanced = nextRunAt(s, now).toISOString();
        const { data: updated, error: updateError } = await supabase.from('report_schedules')
            .update({ next_run_at: advanced })
            .eq('id', s.id).eq('next_run_at', s.next_run_at) // compare-and-swap
            .select('*').maybeSingle();
        if (!updateError && updated) claimed.push({ ...(s as ReportSchedule), next_run_at: advanced });
    }
    return claimed;
}
