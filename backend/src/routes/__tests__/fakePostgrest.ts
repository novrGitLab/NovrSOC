// A small in-memory stand-in for PostgREST, for route tests. The real supabase-js client talks to
// it over HTTP on 127.0.0.1 (set SUPABASE_URL to `url` before the first getSupabase() call), so
// routes run unchanged and no real database is ever contacted.
//
// Supports what the SecOps routers use: select (column lists and to-one embeds such as
// `cases!inner(case_number)`), eq/neq/gt/gte/lt/lte/like/ilike/in/is filters (also on embedded
// columns, `cases.org_id=eq.x`), or=(...), order, limit/offset, count=exact (GET and HEAD),
// single() objects, insert / upsert (merge or ignore duplicates on on_conflict) / update / delete.
// Not a PostgREST implementation — just enough to exercise tenant scoping honestly.

import http from 'http';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';

export type Row = Record<string, unknown>;
export interface FakePostgrest {
    url: string;
    tables: Record<string, Row[]>;
    /** Every request seen, as "METHOD table?query" — for asserting what a route asked for. */
    log: string[];
    close(): Promise<void>;
}

/** Embedded relation -> foreign-key column on the parent row, when it isn't `<singular>_id`. */
const DEFAULT_RELATIONS: Record<string, string> = { 'platform_users.organisations': 'org_id' };

function splitTop(s: string): string[] {
    const out: string[] = [];
    let depth = 0;
    let cur = '';
    for (const ch of s) {
        if (ch === '(') depth++;
        if (ch === ')') depth--;
        if (ch === ',' && depth === 0) { out.push(cur); cur = ''; continue; }
        cur += ch;
    }
    if (cur) out.push(cur);
    return out.map((x) => x.trim()).filter(Boolean);
}

const likeToRegex = (p: string, flags: string) =>
    new RegExp(`^${p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/[%*]/g, '.*')}$`, flags);

function get(row: Row, path: string): unknown {
    return path.split('.').reduce<unknown>((v, k) => (v && typeof v === 'object' ? (v as Row)[k] : undefined), row);
}

function cmp(a: unknown, b: string): number {
    const na = Number(a);
    const nb = Number(b);
    if (a !== null && a !== '' && b !== '' && !Number.isNaN(na) && !Number.isNaN(nb) && typeof a !== 'boolean') return na - nb;
    return String(a).localeCompare(b);
}

function test(row: Row, col: string, opValue: string): boolean {
    const neg = opValue.startsWith('not.');
    const ov = neg ? opValue.slice(4) : opValue;
    const dot = ov.indexOf('.');
    const op = ov.slice(0, dot);
    const val = ov.slice(dot + 1);
    const v = get(row, col);
    let r: boolean;
    switch (op) {
        case 'eq': r = v !== undefined && v !== null && String(v) === val; break;
        case 'neq': r = v === null || v === undefined || String(v) !== val; break;
        case 'gt': r = v != null && cmp(v, val) > 0; break;
        case 'gte': r = v != null && cmp(v, val) >= 0; break;
        case 'lt': r = v != null && cmp(v, val) < 0; break;
        case 'lte': r = v != null && cmp(v, val) <= 0; break;
        case 'like': r = v != null && likeToRegex(val, '').test(String(v)); break;
        case 'ilike': r = v != null && likeToRegex(val, 'i').test(String(v)); break;
        case 'in': {
            const items = splitTop(val.replace(/^\(|\)$/g, '')).map((x) => x.replace(/^"|"$/g, ''));
            r = v != null && items.includes(String(v));
            break;
        }
        case 'is': r = val === 'null' ? v === null || v === undefined : String(v) === val; break;
        default: throw new Error(`fakePostgrest: unsupported operator ${op}`);
    }
    return neg ? !r : r;
}

interface Embed { name: string; inner: boolean; cols: string[] }

function parseSelect(select: string | null): { cols: string[] | null; embeds: Embed[] } {
    if (!select) return { cols: null, embeds: [] };
    const cols: string[] = [];
    const embeds: Embed[] = [];
    let star = false;
    for (const part of splitTop(select)) {
        const m = part.match(/^([\w]+)(!inner)?\((.*)\)$/);
        if (m) embeds.push({ name: m[1], inner: !!m[2], cols: splitTop(m[3]) });
        else if (part === '*') star = true;
        else cols.push(part.split(':').pop()!.split('::')[0]);
    }
    return { cols: star ? null : cols, embeds };
}

const pick = (row: Row, cols: string[] | null) => (cols ? Object.fromEntries(cols.map((c) => [c, row[c] ?? null])) : { ...row });

export async function startFakePostgrest(tables: Record<string, Row[]> = {}, relations: Record<string, string> = {}): Promise<FakePostgrest> {
    const rel = { ...DEFAULT_RELATIONS, ...relations };
    const log: string[] = [];

    const server = http.createServer((req, res) => {
        let body = '';
        req.on('data', (c) => { body += c; });
        req.on('end', () => {
            const url = new URL(req.url ?? '/', 'http://x');
            const m = url.pathname.match(/^\/rest\/v1\/([\w]+)$/);
            const send = (status: number, payload?: unknown, headers: Record<string, string> = {}) => {
                res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
                res.end(payload === undefined || req.method === 'HEAD' ? '' : JSON.stringify(payload));
            };
            if (!m) { send(404, { message: 'not found' }); return; }
            const table = m[1];
            log.push(`${req.method} ${table}?${decodeURIComponent(url.searchParams.toString())}`);
            const rows = (tables[table] ??= []);
            const prefer = String(req.headers.prefer ?? '');
            const wantsObject = String(req.headers.accept ?? '').includes('vnd.pgrst.object+json');
            const { cols, embeds } = parseSelect(url.searchParams.get('select'));

            const withEmbeds = (r: Row): Row | null => {
                const out: Row = { ...r };
                for (const e of embeds) {
                    const fk = rel[`${table}.${e.name}`] ?? `${e.name.replace(/s$/, '')}_id`;
                    const target = (tables[e.name] ?? []).find((t) => t.id === r[fk]) ?? null;
                    if (!target && e.inner) return null;
                    out[e.name] = target ? pick(target, e.cols.includes('*') ? null : e.cols) : null;
                }
                return out;
            };
            const matches = (r: Row) => {
                for (const [k, v] of url.searchParams) {
                    if (['select', 'order', 'limit', 'offset', 'on_conflict', 'columns'].includes(k)) continue;
                    if (k === 'or') {
                        const parts = splitTop(v.replace(/^\(|\)$/g, ''));
                        if (!parts.some((p) => { const i = p.indexOf('.'); return test(r, p.slice(0, i), p.slice(i + 1)); })) return false;
                        continue;
                    }
                    if (!test(r, k, v)) return false;
                }
                return true;
            };
            const shape = (list: Row[]) => list.map((r) => {
                const projected = pick(r, cols);
                for (const e of embeds) projected[e.name] = r[e.name];
                return projected;
            });
            const respond = (list: Row[], status = 200, total?: number) => {
                const headers: Record<string, string> = {};
                if (/count=exact/.test(prefer)) headers['Content-Range'] = `${list.length ? 0 : '*'}-${Math.max(list.length - 1, 0)}/${total ?? list.length}`;
                if (wantsObject) {
                    if (list.length !== 1) { send(406, { code: 'PGRST116', message: 'JSON object requested, multiple (or no) rows returned', details: null, hint: null }); return; }
                    send(status, shape(list)[0], headers);
                    return;
                }
                send(status, shape(list), headers);
            };

            try {
                if (req.method === 'GET' || req.method === 'HEAD') {
                    let list = rows.map(withEmbeds).filter((r): r is Row => r !== null).filter(matches);
                    const order = url.searchParams.get('order');
                    if (order) {
                        const keys = order.split(',').map((o) => { const [c, dir] = o.split('.'); return { c, desc: dir === 'desc' }; });
                        list = [...list].sort((a, b) => {
                            for (const k of keys) {
                                const d = String(a[k.c] ?? '').localeCompare(String(b[k.c] ?? ''));
                                if (d) return k.desc ? -d : d;
                            }
                            return 0;
                        });
                    }
                    const total = list.length;
                    const offset = Number(url.searchParams.get('offset') ?? 0);
                    const limit = url.searchParams.get('limit');
                    list = list.slice(offset, limit ? offset + Number(limit) : undefined);
                    respond(list, 200, total);
                    return;
                }
                const payload = body ? JSON.parse(body) : null;
                const returning = /return=representation/.test(prefer);
                if (req.method === 'POST') {
                    const conflict = url.searchParams.get('on_conflict')?.split(',');
                    const ignore = /resolution=ignore-duplicates/.test(prefer);
                    const merge = /resolution=merge-duplicates/.test(prefer);
                    const out: Row[] = [];
                    for (const input of Array.isArray(payload) ? payload : [payload]) {
                        const existing = conflict ? rows.find((r) => conflict.every((c) => r[c] === input[c])) : undefined;
                        if (existing && ignore) continue;
                        if (existing && merge) { Object.assign(existing, input); out.push(existing); continue; }
                        if (existing) { send(409, { code: '23505', message: 'duplicate key value violates unique constraint', details: null, hint: null }); return; }
                        const row = { id: randomUUID(), created_at: new Date().toISOString(), ...input };
                        rows.push(row);
                        out.push(row);
                    }
                    if (returning) respond(out, 201); else send(201);
                    return;
                }
                if (req.method === 'PATCH') {
                    const hit = rows.filter(matches);
                    hit.forEach((r) => Object.assign(r, payload));
                    if (returning) respond(hit); else send(204);
                    return;
                }
                if (req.method === 'DELETE') {
                    const hit = rows.filter(matches);
                    tables[table] = rows.filter((r) => !hit.includes(r));
                    if (returning) respond(hit); else send(204);
                    return;
                }
                send(405, { message: 'method not allowed' });
            } catch (err) {
                send(400, { message: err instanceof Error ? err.message : String(err) });
            }
        });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    return {
        url: `http://127.0.0.1:${port}`,
        tables,
        log,
        close: () => new Promise<void>((resolve) => server.close(() => resolve())),
    };
}
