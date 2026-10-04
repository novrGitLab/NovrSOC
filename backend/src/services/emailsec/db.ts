// Email Security storage — a deliberately small table interface over Supabase.
//
// Every emailsec service reads and writes through getDb() instead of calling supabase.from()
// directly, for two reasons:
//   1. One place decides what "the schema isn't there yet" looks like. The tables come from
//      backend/sql/2026-09-email-security.sql; until it has been run, every call throws a
//      SchemaMissingError and the routes answer 503 with that instruction, instead of each
//      caller guessing at Postgres error codes.
//   2. Tests swap in createMemoryDb() with setDb(). Production never uses the memory store —
//      getDb() only returns it when a test has explicitly installed it.
//
// Every row carries org_id and every query is expected to filter on it (tenant isolation);
// the routes derive org_id from the caller's token, never from the request body.
import { randomUUID } from 'crypto';
import { getSupabase } from '../geoEnrichment';

export type Op = 'eq' | 'neq' | 'in' | 'gte' | 'lte' | 'ilike' | 'is' | 'any_ilike';
export interface Filter { col: string; op: Op; value: unknown }
export interface Query { filters?: Filter[]; order?: { col: string; asc?: boolean }; limit?: number; select?: string }

export interface Db {
    kind: 'supabase' | 'memory';
    select<T = Row>(table: string, q?: Query): Promise<T[]>;
    count(table: string, filters?: Filter[]): Promise<number>;
    insert<T = Row>(table: string, rows: Row | Row[]): Promise<T[]>;
    update<T = Row>(table: string, filters: Filter[], patch: Row): Promise<T[]>;
    upsert<T = Row>(table: string, rows: Row | Row[], onConflict: string[]): Promise<T[]>;
    remove(table: string, filters: Filter[]): Promise<void>;
}
export type Row = Record<string, unknown>;

export const SCHEMA_FILE = 'backend/sql/2026-09-email-security.sql';

export class SchemaMissingError extends Error {
    constructor(table: string) {
        super(`Email Security tables are not set up (missing ${table}). Run ${SCHEMA_FILE} in the Supabase SQL editor.`);
        this.name = 'SchemaMissingError';
    }
}
export class DbError extends Error {
    constructor(message: string) { super(message); this.name = 'DbError'; }
}

export const f = {
    eq: (col: string, value: unknown): Filter => ({ col, op: 'eq', value }),
    neq: (col: string, value: unknown): Filter => ({ col, op: 'neq', value }),
    in: (col: string, value: unknown[]): Filter => ({ col, op: 'in', value }),
    gte: (col: string, value: unknown): Filter => ({ col, op: 'gte', value }),
    lte: (col: string, value: unknown): Filter => ({ col, op: 'lte', value }),
    ilike: (col: string, value: string): Filter => ({ col, op: 'ilike', value }),
    isNull: (col: string): Filter => ({ col, op: 'is', value: null }),
    /** col1 ILIKE p OR col2 ILIKE p … — `cols` are code constants; the pattern must be pre-sanitised. */
    anyIlike: (cols: string[], pattern: string): Filter => ({ col: cols.join(','), op: 'any_ilike', value: pattern }),
};

// ── Supabase ─────────────────────────────────────────────────────────────────────────────

// PostgREST reports an unknown table as PGRST205 ("Could not find the table") and Postgres as
// 42P01. A HEAD request (count) for an unknown table gets a bare 404 with no body, so the
// error has neither code nor message — the status is the only signal.
function raise(table: string, error: { code?: string; message?: string }, status?: number): never {
    if (error.code === 'PGRST205' || error.code === '42P01' || /could not find the table|does not exist/i.test(error.message ?? '') || (status === 404 && !error.code)) {
        throw new SchemaMissingError(table);
    }
    throw new DbError(`${table}: ${error.message ?? 'database error'}`);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function applyFilters(q: any, filters: Filter[] = []): any {
    for (const x of filters) {
        if (x.op === 'any_ilike') {
            // PostgREST or=(…): quote the pattern so it can't break out of its position.
            const v = `"${String(x.value).replace(/["\\]/g, '')}"`;
            q = q.or(x.col.split(',').map((c) => `${c}.ilike.${v}`).join(','));
        } else if (x.op === 'in') q = q.in(x.col, x.value as unknown[]);
        else if (x.op === 'is') q = q.is(x.col, x.value);
        else q = q[x.op](x.col, x.value);
    }
    return q;
}

function supabaseDb(): Db | null {
    const sb = getSupabase();
    if (!sb) return null;
    return {
        kind: 'supabase',
        async select<T>(table: string, q: Query = {}) {
            let query = applyFilters(sb.from(table).select(q.select ?? '*'), q.filters);
            if (q.order) query = query.order(q.order.col, { ascending: q.order.asc ?? false });
            query = query.limit(Math.min(q.limit ?? 500, 1000));
            const { data, error } = await query;
            if (error) raise(table, error);
            return (data ?? []) as T[];
        },
        async count(table, filters = []) {
            const { count, error, status } = await applyFilters(sb.from(table).select('id', { count: 'exact', head: true }), filters);
            if (error) raise(table, error, status);
            return count ?? 0;
        },
        async insert<T>(table: string, rows: Row | Row[]) {
            const { data, error } = await sb.from(table).insert(rows).select();
            if (error) raise(table, error);
            return (data ?? []) as T[];
        },
        async update<T>(table: string, filters: Filter[], patch: Row) {
            const { data, error } = await applyFilters(sb.from(table).update(patch), filters).select();
            if (error) raise(table, error);
            return (data ?? []) as T[];
        },
        async upsert<T>(table: string, rows: Row | Row[], onConflict: string[]) {
            const { data, error } = await sb.from(table).upsert(rows, { onConflict: onConflict.join(',') }).select();
            if (error) raise(table, error);
            return (data ?? []) as T[];
        },
        async remove(table, filters) {
            const { error } = await applyFilters(sb.from(table).delete(), filters);
            if (error) raise(table, error);
        },
    };
}

// ── Memory (tests only) ──────────────────────────────────────────────────────────────────

function matches(row: Row, x: Filter): boolean {
    const v = row[x.col];
    switch (x.op) {
        case 'eq': return v === x.value;
        case 'neq': return v !== x.value;
        case 'in': return (x.value as unknown[]).includes(v);
        case 'gte': return typeof v === 'number' ? v >= Number(x.value) : String(v ?? '') >= String(x.value);
        case 'lte': return typeof v === 'number' ? v <= Number(x.value) : String(v ?? '') <= String(x.value);
        case 'is': return v === null || v === undefined;
        case 'any_ilike': return x.col.split(',').some((c) => matches(row, { col: c, op: 'ilike', value: x.value }));
        case 'ilike': {
            const re = new RegExp(`^${String(x.value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/%/g, '.*')}$`, 'i');
            return re.test(String(v ?? ''));
        }
    }
}

export function createMemoryDb(): Db & { tables: Map<string, Row[]> } {
    const tables = new Map<string, Row[]>();
    const t = (name: string) => { if (!tables.has(name)) tables.set(name, []); return tables.get(name)!; };
    const stamp = (r: Row): Row => ({ id: randomUUID(), created_at: new Date().toISOString(), ...r });
    const select = (table: string, filters: Filter[] = []) => t(table).filter((r) => filters.every((x) => matches(r, x)));
    return {
        kind: 'memory',
        tables,
        async select<T>(table: string, q: Query = {}) {
            let rows = select(table, q.filters);
            if (q.order) {
                const { col, asc } = q.order;
                rows = [...rows].sort((a, b) => (String(a[col] ?? '') < String(b[col] ?? '') ? -1 : 1) * (asc ? 1 : -1));
            }
            return structuredClone(rows.slice(0, q.limit ?? 500)) as T[];
        },
        async count(table, filters = []) { return select(table, filters).length; },
        async insert<T>(table: string, rows: Row | Row[]) {
            const out = (Array.isArray(rows) ? rows : [rows]).map(stamp);
            t(table).push(...out);
            return structuredClone(out) as T[];
        },
        async update<T>(table: string, filters: Filter[], patch: Row) {
            const hit = select(table, filters);
            for (const r of hit) Object.assign(r, patch);
            return structuredClone(hit) as T[];
        },
        async upsert<T>(table: string, rows: Row | Row[], onConflict: string[]) {
            const out: Row[] = [];
            for (const row of Array.isArray(rows) ? rows : [rows]) {
                const existing = t(table).find((r) => onConflict.every((c) => r[c] === row[c]));
                if (existing) { Object.assign(existing, row); out.push(existing); }
                else { const n = stamp(row); t(table).push(n); out.push(n); }
            }
            return structuredClone(out) as T[];
        },
        async remove(table, filters) {
            tables.set(table, t(table).filter((r) => !filters.every((x) => matches(r, x))));
        },
    };
}

let override: Db | null = null;
/** Tests only: install a store (createMemoryDb()) or pass null to go back to Supabase. */
export function setDb(db: Db | null): void { override = db; }

/** The store, or null when Supabase isn't configured at all. */
export function getDb(): Db | null {
    return override ?? supabaseDb();
}
