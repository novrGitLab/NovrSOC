// MISP synchronisation helpers (phase P26), shared by the attribute feed (threatInfo.ts) and the
// event-report feed (tiReports.ts): the incremental window and bounded, paced paging.

/** What a run knows when it fetches: the last successful sync, and a manager's one-time backfill. */
export interface FetchCtx { since: string | null; backfillDays?: number | null }
/** What the last fetch of a feed covered (window, pages, truncation) — merged into last_counts. */
export const lastFetchMeta: Record<string, Record<string, unknown>> = {};

const envInt = (name: string, dflt: number, min: number, max: number) => { const n = Number(process.env[name]); return Number.isFinite(n) && n > 0 ? Math.min(Math.max(Math.trunc(n), min), max) : dflt; };
/**
 * The window an incremental MISP fetch covers, as a Unix timestamp: the last successful sync
 * minus an hour of overlap; on the first run (or a manager's backfill) MISP_BACKFILL_DAYS
 * (default 7, at most 90). Re-reading the overlap is harmless: storage is idempotent.
 */
export function mispWindowStart(ctx: FetchCtx | undefined, now = Date.now()): { from: number; mode: 'incremental' | 'backfill' } {
    const backfill = ctx?.backfillDays ? Math.min(Math.max(Math.trunc(ctx.backfillDays), 1), 90) : null;
    if (!backfill && ctx?.since && Number.isFinite(Date.parse(ctx.since))) return { from: Math.floor((Date.parse(ctx.since) - 3_600_000) / 1000), mode: 'incremental' };
    const days = backfill ?? envInt('MISP_BACKFILL_DAYS', 7, 1, 90);
    return { from: Math.floor((now - days * 86_400_000) / 1000), mode: 'backfill' };
}

/**
 * MISP pages: each `body` page by page (limit MISP_PAGE_SIZE, default 1000) until a short page,
 * at most MISP_MAX_PAGES (default 20), pausing MISP_PAGE_DELAY_MS (default 250) between pages.
 * Returns whether it stopped at the page limit, so a truncated run is reported, never silent.
 */
export async function mispPages<T>(search: (body: Record<string, unknown>) => Promise<unknown>, body: Record<string, unknown>, rows: (json: unknown) => T[]): Promise<{ items: T[]; pages: number; truncated: boolean }> {
    const size = envInt('MISP_PAGE_SIZE', 1000, 50, 5000);
    const max = envInt('MISP_MAX_PAGES', 20, 1, 200);
    const delay = Number(process.env.MISP_PAGE_DELAY_MS ?? 250);
    const items: T[] = [];
    for (let page = 1; page <= max; page++) {
        const json = await search({ ...body, limit: size, page });
        const batch = rows(json);
        items.push(...batch);
        if (batch.length < size) return { items, pages: page, truncated: false };
        if (page < max && delay > 0) await new Promise((r) => setTimeout(r, delay));
    }
    return { items, pages: max, truncated: true };
}
