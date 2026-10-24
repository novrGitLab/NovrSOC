// Scan windows (phase P27): when active scans may run under a scope, as approved with it.
//
//   { tz: 'Africa/Lagos', windows: [{ days: [1,2,3,4,5], start: '22:00', end: '05:00' }] }
//
// days are ISO weekdays (1 = Monday … 7 = Sunday) of the window's START; a window whose end is not
// after its start runs past midnight into the next day. Times are local to `tz` (an IANA zone,
// default Africa/Lagos), computed with the runtime's own time-zone data. NULL / no windows = any time.
// Enforced where a scan is queued (routes/vms.ts queueScan) and again where a worker is handed
// one (routes/vmsWorker.ts claim); the scheduler waits for the next window instead of queueing.

export interface ScanWindow { days: number[]; start: string; end: string }
export interface ScanWindows { tz: string; windows: ScanWindow[] }

const HHMM = /^([01]\d|2[0-3]):([0-5]\d)$/;
const minutes = (hhmm: string) => { const [h, m] = hhmm.split(':').map(Number); return h * 60 + m; };

/** A validated copy, or the reason it is not valid. */
export function parseScanWindows(input: unknown): { ok: true; value: ScanWindows | null } | { ok: false; error: string } {
    if (input === null || input === undefined) return { ok: true, value: null };
    const v = input as { tz?: unknown; windows?: unknown };
    const tz = typeof v.tz === 'string' && v.tz.trim() ? v.tz.trim() : 'Africa/Lagos';
    try { new Intl.DateTimeFormat('en-GB', { timeZone: tz }); } catch { return { ok: false, error: `Unknown time zone: ${tz.slice(0, 60)}` }; }
    if (!Array.isArray(v.windows) || v.windows.length === 0 || v.windows.length > 14) return { ok: false, error: 'scan_windows.windows must list 1 to 14 windows' };
    const windows: ScanWindow[] = [];
    for (const w of v.windows as { days?: unknown; start?: unknown; end?: unknown }[]) {
        const days = Array.isArray(w?.days) ? [...new Set(w.days.map(Number))].sort() : [];
        if (!days.length || days.some((d) => !Number.isInteger(d) || d < 1 || d > 7)) return { ok: false, error: 'Each window needs days from 1 (Monday) to 7 (Sunday)' };
        if (typeof w.start !== 'string' || !HHMM.test(w.start) || typeof w.end !== 'string' || !HHMM.test(w.end)) return { ok: false, error: 'Each window needs start and end as HH:MM' };
        if (w.start === w.end) return { ok: false, error: 'A window must not start and end at the same time' };
        windows.push({ days, start: w.start, end: w.end });
    }
    return { ok: true, value: { tz, windows } };
}

/** Local ISO weekday and minute-of-day of an instant in a time zone. */
function local(at: number, tz: string): { day: number; minute: number } {
    const parts = new Intl.DateTimeFormat('en-GB', { timeZone: tz, weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).formatToParts(new Date(at));
    const get = (t: string) => parts.find((p) => p.type === t)?.value ?? '';
    const day = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].indexOf(get('weekday')) + 1;
    return { day, minute: Number(get('hour')) * 60 + Number(get('minute')) };
}

/** Whether an instant falls inside the windows (always true without windows). */
export function inScanWindow(w: ScanWindows | null | undefined, at = Date.now()): boolean {
    if (!w || !w.windows?.length) return true;
    const { day, minute } = local(at, w.tz);
    const prev = day === 1 ? 7 : day - 1;
    return w.windows.some((x) => {
        const s = minutes(x.start), e = minutes(x.end);
        if (e > s) return x.days.includes(day) && minute >= s && minute < e;
        // Past midnight: the evening part on a listed day, or the morning part the day after one.
        return (x.days.includes(day) && minute >= s) || (x.days.includes(prev) && minute < e);
    });
}

/** The next instant (to the minute) at which a window is open, at or after `from`; null if none within 8 days. */
export function nextScanWindow(w: ScanWindows | null | undefined, from = Date.now()): number | null {
    if (inScanWindow(w, from)) return from;
    const start = Math.ceil(from / 60_000) * 60_000;
    for (let t = start; t <= from + 8 * 86_400_000; t += 60_000) if (inScanWindow(w, t)) return t;
    return null;
}

/** "Mon–Fri 22:00–05:00 (Africa/Lagos)" for messages. */
export function describeScanWindows(w: ScanWindows | null | undefined): string {
    if (!w || !w.windows?.length) return 'any time';
    const names = ['', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    return `${w.windows.map((x) => `${x.days.map((d) => names[d]).join(',')} ${x.start}–${x.end}`).join('; ')} (${w.tz})`;
}
