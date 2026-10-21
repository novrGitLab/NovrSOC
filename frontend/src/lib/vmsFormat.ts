// Pure formatting helpers for the VMS pages (redesign, phase P20). No React, so they are unit-tested
// directly (scripts/vms-format.test.mjs).

/** CSV with every cell quoted; a cell a spreadsheet would run as a formula is neutralised with a leading '. */
export function toCsv(rows: Record<string, unknown>[], columns: { key: string; header: string }[]): string {
    const cell = (v: unknown) => {
        let s = v === null || v === undefined ? '' : Array.isArray(v) ? v.join('; ') : typeof v === 'object' ? JSON.stringify(v) : String(v);
        if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
        return `"${s.replace(/"/g, '""')}"`;
    };
    return [columns.map((c) => cell(c.header)).join(','), ...rows.map((r) => columns.map((c) => cell(r[c.key])).join(','))].join('\r\n');
}

/** "3 days ago" / "in 2 days", relative to `now` (passed in so rendering stays pure). */
export function relTime(iso: string | null | undefined, now: number): string {
    if (!iso) return '—';
    const d = Date.parse(iso) - now;
    const abs = Math.abs(d);
    const [n, u] = abs < 3_600_000 ? [Math.max(1, Math.round(abs / 60_000)), 'min'] : abs < 86_400_000 ? [Math.round(abs / 3_600_000), 'hour'] : [Math.round(abs / 86_400_000), 'day'];
    const s = `${n} ${u}${n === 1 ? '' : 's'}`;
    return d < 0 ? `${s} ago` : `in ${s}`;
}

/** "21 Oct" from 'YYYY-MM-DD' or an ISO timestamp. */
export const fmtDay = (iso: string) => new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', timeZone: 'UTC' }).format(new Date(`${iso.slice(0, 10)}T12:00:00Z`));
