// Reading the exchange collections (phase P25): pages of STIX objects with their TAXII metadata,
// shared by the TAXII 2.1 server (routes/taxii.ts) and the STIX bundle download.
//
// The platform keeps the latest version of each object only. Its date_added is when that version
// was added — the indicator's updated_at — so a consumer polling with added_after receives new
// and changed objects alike. Order is (updated_at, id); the paging cursor is opaque to clients.

import { getSupabase } from './geoEnrichment';
import { buildIndicator, buildVulnerability, type IndicatorRow, type SourceRow, type BuiltIndicator } from './tiStix';
import type { CollectionContent, ExportCeiling } from './tiPolicy';

export const NETWORK_FILE_TYPES = ['ip', 'domain', 'url', 'md5', 'sha1', 'sha256'];
const IND_COLS = 'id, type, value, status, valid_until, created_at, updated_at, first_seen';

export interface ExchangeQuery {
    content: CollectionContent;
    ceiling: ExportCeiling;
    addedAfter?: string | null;
    cursor?: Cursor | null;
    limit: number;
    /** match[id]: the UUID part of STIX ids. */
    stixUuids?: string[] | null;
    /** match[version]: a specific modified timestamp, or null for the latest (the only one kept). */
    version?: string | null;
}
export interface ExchangeItem { object: Record<string, unknown>; date_added: string; version: string; built?: BuiltIndicator }
export interface Cursor { at: string; id: string }

export const encodeCursor = (c: Cursor) => Buffer.from(`${c.at}|${c.id}`).toString('base64url');
export function decodeCursor(s: string): Cursor | null {
    try {
        const [at, id] = Buffer.from(s, 'base64url').toString().split('|');
        return at && id && Number.isFinite(Date.parse(at)) && /^[0-9a-f-]{36}$/i.test(id) ? { at, id } : null;
    } catch { return null; }
}

export async function exchangePage(q: ExchangeQuery): Promise<{ items: ExchangeItem[]; more: boolean; next: Cursor | null }> {
    const supabase = getSupabase();
    if (!supabase) throw new Error('database not configured');
    const items: ExchangeItem[] = [];
    let cursor = q.cursor ?? null;
    const chunk = Math.min(Math.max(q.limit * 2, 100), 1000);
    for (let round = 0; round < 50; round++) {
        let query = supabase.from('ti_indicators').select(IND_COLS);
        query = q.content === 'vulnerabilities' ? query.eq('type', 'cve') : query.in('type', NETWORK_FILE_TYPES);
        if (q.addedAfter) query = query.gt('updated_at', q.addedAfter);
        if (q.stixUuids?.length) query = query.in('stix_uuid', q.stixUuids);
        if (cursor) query = query.or(`updated_at.gt."${cursor.at}",and(updated_at.eq."${cursor.at}",id.gt.${cursor.id})`);
        const { data: rows, error } = await query.order('updated_at', { ascending: true }).order('id', { ascending: true }).limit(chunk);
        if (error) throw new Error(error.message);
        const page = (rows ?? []) as IndicatorRow[];
        if (!page.length) return { items, more: false, next: null };
        const sources = await sourcesFor(page.map((r) => r.id));
        for (let i = 0; i < page.length; i++) {
            const row = page[i];
            const srcs = sources.get(row.id) ?? [];
            const built = q.content === 'vulnerabilities' ? buildVulnerability(row, srcs, q.ceiling) : buildIndicator(row, srcs, q.ceiling);
            cursor = { at: row.updated_at, id: row.id };
            if (built && (!q.version || q.version === built.object.modified)) {
                items.push({ object: built.object, date_added: new Date(row.updated_at).toISOString(), version: String(built.object.modified), built: q.content === 'indicators' ? (built as BuiltIndicator) : undefined });
            }
            if (items.length >= q.limit) {
                const more = i < page.length - 1 || page.length === chunk;
                return { items, more, next: more ? cursor : null };
            }
        }
        if (page.length < chunk) return { items, more: false, next: null };
    }
    return { items, more: true, next: cursor };
}

async function sourcesFor(ids: string[]): Promise<Map<string, SourceRow[]>> {
    const supabase = getSupabase()!;
    const out = new Map<string, SourceRow[]>();
    for (let i = 0; i < ids.length; i += 200) {
        const { data, error } = await supabase.from('ti_indicator_sources').select('indicator_id, feed_id, source_ref, confidence, first_seen, last_seen, tlp, distribution, context').in('indicator_id', ids.slice(i, i + 200));
        if (error) throw new Error(error.message);
        for (const s of data ?? []) {
            const list = out.get(s.indicator_id as string) ?? [];
            list.push(s as unknown as SourceRow);
            out.set(s.indicator_id as string, list);
        }
    }
    return out;
}
